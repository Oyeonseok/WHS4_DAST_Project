"""Runs Coordinator end-to-end against a real approved Scope.md.

Two things this proves:
1. A RECON plan whose targets are actually in the approved scope goes
   through: Main Agent's dict instructions get turned into a real
   ReconPlan, ReconCoordinator turns that into scope-gated ReconTasks, and
   only then does the (fake) Recon Agent get called.
2. A RECON plan that names a target NOT in the approved scope is rejected
   in code before any agent runs — same guarantee `aidast recon` already
   gives today, now reused inside the bigger Attack/Validation/Report loop.
"""

from pathlib import Path

from aidast.orchestration.coordinator import (
    Coordinator,
    CoordinatorError,
    Finding,
    MainAgentPlan,
    PlanType,
    Verdict,
    ValidationResult,
)
from aidast.recon.models import ReconTask
from aidast.scope.models import ScopeDocument

# 실제로 이전 세션에서 aidast scope로 수집·승인해둔 MATLAB Online의
# Scope.json/Scope.md를 그대로 재사용한다 — 가짜 데이터가 아니다.
SCOPE_DIR = Path(__file__).resolve().parent.parent / "Scope/bugcrowd/matlab-online"


def load_scope() -> tuple[ScopeDocument, str]:
    """승인된 Scope.json은 구조화 데이터(ScopeDocument)로, Scope.md는
    Main Agent가 그대로 읽을 원문(scope_markdown)으로 각각 로드한다."""
    scope = ScopeDocument.model_validate_json(
        (SCOPE_DIR / "Scope.json").read_text(encoding="utf-8")
    )
    scope_markdown = (SCOPE_DIR / "Scope.md").read_text(encoding="utf-8")
    return scope, scope_markdown


# MATLAB Online의 실제 in-scope 자산과, 일부러 만든 스코프 밖 URL.
IN_SCOPE_ASSET = "https://matlab.mathworks.com/"
OUT_OF_SCOPE_ASSET = "https://evil-not-in-scope.example.com"


def recon_plan_instructions(asset: str) -> dict:
    """Main Agent가 낼 법한 RECON plan의 instructions를 흉내낸다.
    Coordinator._handle_recon이 이 dict를 그대로 ReconPlan(pydantic)에
    풀어 넣으므로, 필드 이름은 ReconPlanProposal 스키마와 정확히 맞아야
    한다(objective/mode/targets/global_constraints/completion_criteria)."""
    return {
        "objective": "MATLAB Online 프로덕션 스택의 표면 탐색",
        "mode": "FULL_RECON",
        "targets": [
            {
                "asset_type": "URL",
                "asset": asset,
                "steps": ["HTTP_PROBE", "ENDPOINT_DISCOVERY"],
                "constraints": [],
            }
        ],
        "global_constraints": ["X-Request-Purpose: BugcrowdResearch 헤더 필수"],
        "completion_criteria": ["모든 in-scope URL에 대해 HTTP_PROBE 완료"],
    }


class ScriptedMainAgent:
    """Stands in for the real planning LLM: a scripted sequence of plans."""

    def __init__(self, plans: list) -> None:
        # 실제 Main Agent라면 매번 scope_markdown+coverage_summary를 보고
        # 즉석에서 plan을 만들지만, 데모에서는 미리 정해둔 순서를 그대로
        # 흘려보내기만 한다 — Coordinator 쪽 로직만 검증하면 되기 때문.
        self._plans = iter(plans)

    def next_plan(self, scope_markdown: str, coverage_summary: str):
        print(f"  [Main Agent sees] {coverage_summary}")
        return next(self._plans, None)  # 플랜이 바닥나면 곧 "종료"로 처리


class FakeReconAgent:
    def run_recon(self, tasks: list[ReconTask]):
        # 여기 들어오는 tasks는 이미 ReconCoordinator가 스코프 검증까지
        # 마친 것들이다 — Recon Agent는 "이게 스코프 안인가?"를 다시
        # 물어볼 필요가 없다.
        print(f"  [Recon Agent received {len(tasks)} scope-gated task(s)]")
        for task in tasks:
            print(f"    - {task.task_type.value} on {task.target.asset}")
        return [{"path": "/rest/basket/:id"}, {"path": "/rest/products/search"}]


class FakeAttackAgent:
    def run_attack(self, origin_id, endpoints):
        # 실제로는 IDOR/XSS 등 Bug Class별 SKILL.md를 로드해 Sub Agent를
        # 스폰하지만, 여기서는 결과만 하드코딩해서 반환한다.
        return [
            Finding("fnd_1", "ep_1", "IDOR", "basket IDOR", ["evidence/req1.json"]),
            Finding("fnd_2", "ep_2", "XSS", "search reflected XSS", ["evidence/req2.json"]),
        ]


class FakeValidationAgent:
    """fnd_1 needs one CURE round before PASS; fnd_2 gets DROPped outright."""

    def __init__(self) -> None:
        self._fnd_1_attempts = 0

    def validate(self, finding, gap_ids):
        if finding.finding_id == "fnd_2":
            # XSS 후보는 CSP에 막혀 재현 불가 → 바로 DROP.
            return ValidationResult("fnd_2", Verdict.DROP, "CSP blocks the payload")
        self._fnd_1_attempts += 1
        if self._fnd_1_attempts == 1:
            # 첫 시도는 계정 A/B 교차 비교 증거가 부족해 CURE — 갭만 지목.
            return ValidationResult("fnd_1", Verdict.CURE, "missing cross-account diff", ["gap_account_b"])
        # Coordinator가 gap_ids를 넘겨 재호출한 두 번째 시도는 PASS.
        return ValidationResult("fnd_1", Verdict.PASS, "PoC reproduced with account B")


class FakeReportAgent:
    def render(self, confirmed):
        # confirmed에는 CONFIRMED 상태인 Finding만 들어온다 — REJECTED/
        # DROPPED는 애초에 이 리스트에 존재하지 않는다.
        lines = [f"# Report ({len(confirmed)} confirmed finding(s))"]
        lines += [f"- {f.finding_id}: {f.bug_class} — {f.claim}" for f in confirmed]
        return "\n".join(lines)


def run_full_flow(scope: ScopeDocument, scope_markdown: str) -> None:
    """시나리오 1: RECON → ATTACK → VALIDATION이 전부 정상적으로 흘러
    최종 리포트까지 나오는 것을 보여준다."""
    print("=== 1) 정상 플로우: in-scope 타겟으로 Recon → Attack → Validation ===")
    plans = [
        MainAgentPlan("p1", PlanType.RECON, recon_plan_instructions(IN_SCOPE_ASSET)),
        MainAgentPlan("p2", PlanType.ATTACK, {"origin_id": "origin_1"}),
        MainAgentPlan("p3", PlanType.VALIDATION, {"finding_ids": ["fnd_1", "fnd_2"]}),
    ]
    coordinator = Coordinator(
        scope=scope,
        scope_markdown=scope_markdown,
        main_agent=ScriptedMainAgent(plans),
        recon_agent=FakeReconAgent(),
        attack_agent=FakeAttackAgent(),
        validation_agent=FakeValidationAgent(),
        report_agent=FakeReportAgent(),
    )
    report = coordinator.run()

    print("\n--- changelog ---")
    for line in coordinator._changelog:
        print(" ", line)
    print("\n--- report ---")
    print(report)

    # fnd_1은 CURE 한 번 거쳐 CONFIRMED, fnd_2는 바로 REJECTED로 끝나야 한다.
    assert coordinator._findings["fnd_1"].status.value == "CONFIRMED"
    assert coordinator._findings["fnd_2"].status.value == "REJECTED"
    print("\nOK: in-scope target flowed all the way through\n")


def run_out_of_scope_rejection(scope: ScopeDocument, scope_markdown: str) -> None:
    """시나리오 2: Main Agent가 스코프 밖 URL을 제안해도, Recon Agent가
    호출되기 전에 코드(ReconCoordinator)가 거부하는 것을 보여준다."""
    print("=== 2) Main Agent가 스코프 밖 타겟을 제안하면 코드가 거부 ===")
    plans = [MainAgentPlan("p1", PlanType.RECON, recon_plan_instructions(OUT_OF_SCOPE_ASSET))]
    coordinator = Coordinator(
        scope=scope,
        scope_markdown=scope_markdown,
        main_agent=ScriptedMainAgent(plans),
        recon_agent=FakeReconAgent(),  # 아래에서 절대 호출되지 않아야 정상
        attack_agent=FakeAttackAgent(),
        validation_agent=FakeValidationAgent(),
        report_agent=FakeReportAgent(),
    )
    try:
        coordinator.run()
        raise AssertionError("expected CoordinatorError, but the plan was accepted")
    except CoordinatorError as exc:
        print(f"  Rejected in code, no agent ever ran: {exc}")
        print("\nOK: out-of-scope target never reached the Recon Agent")


if __name__ == "__main__":
    scope_document, scope_markdown_text = load_scope()
    print(f"Loaded approved scope: {scope_document.analysis.program_name} "
          f"({SCOPE_DIR})\n")
    run_full_flow(scope_document, scope_markdown_text)
    print()
    run_out_of_scope_rejection(scope_document, scope_markdown_text)
