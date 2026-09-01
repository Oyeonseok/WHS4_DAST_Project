"""Coordinator pattern sketch for the AI DAST design doc.

Shows the split the doc already implies: Main/Recon/Attack/Validation/Report
are LLM agents (Protocols here — a real implementation would call
Codex/Claude), everything else — dispatch, state transitions, retry/CURE
looping, budget limits — is plain, deterministic Python. No agent is ever
asked "what state should this move to next"; the Coordinator decides that
from the Verdict/status value alone.

The run always starts from an *approved* Scope.md — not a bare hostname.
Main Agent reads that scope_markdown to plan, but the RECON step does not
trust the plan on faith: it is handed to the existing, already-tested
ReconCoordinator, which re-derives every target against
`scope.analysis.in_scope_assets` in code and rejects anything Main Agent
proposed that isn't actually in the approved scope. That is the same
mechanism `aidast recon` already uses today — this Coordinator just extends
it past the Recon step into Attack/Validation/Report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.recon.models import ReconPlan, ReconTask
from aidast.scope.models import ScopeDocument


# Coordinator가 코드로 실패를 표현할 때 쓰는 예외. 에이전트가 던지는 예외와
# 구분해서, "이건 판단 오류가 아니라 정책/스키마 위반이다"를 명확히 한다.
class CoordinatorError(RuntimeError):
    pass


# ── Schemas (mirrors the JSON on p.8 of the design doc) ─────────────────────


# Main Agent가 Coordinator에게 넘기는 plan의 종류. 설계도 8페이지 스키마의
# "plan_type" 필드와 1:1로 대응한다. Coordinator._dispatch가 이 값만 보고
# 어느 핸들러로 보낼지 정한다 — 그 이상의 해석/판단은 하지 않는다.
class PlanType(StrEnum):
    RECON = "RECON"
    ATTACK = "ATTACK"
    VALIDATION = "VALIDATION"
    REPORT = "REPORT"


# Validation Agent가 후보(Finding)를 검증한 뒤 내리는 판정. 설계도의
# "PASS / CURE / DROP" 그대로 — 이 값에 따른 상태 전이는 전부 코드에
# 고정되어 있고(_validate_one), Validation Agent 자신은 다음 상태를
# 지정하지 않는다.
class Verdict(StrEnum):
    PASS = "PASS"
    CURE = "CURE"
    DROP = "DROP"


# Finding(공격 후보)이 거쳐가는 생명주기. CANDIDATE(Attack Agent가 갓 만든
# 상태) → IN_VALIDATION(검증 대기/재시도 중) → 최종적으로 CONFIRMED/
# REJECTED/DROPPED 중 하나로 귀결된다.
class FindingStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    IN_VALIDATION = "IN_VALIDATION"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    DROPPED = "DROPPED"


@dataclass(frozen=True)
class MainAgentPlan:
    """What Main Agent hands the Coordinator. plan_type is the only thing
    the Coordinator's dispatch table looks at — everything else is opaque
    payload for whichever agent gets spawned."""

    plan_id: str
    plan_type: PlanType
    # RECON일 때는 ReconPlan(ReconPlanProposal) 스키마를 그대로 담고,
    # ATTACK/VALIDATION일 때는 아직 정식 스키마가 없어 느슨한 dict로 둔다
    # (예: {"origin_id": ...}, {"finding_ids": [...]}). 실제 스키마가
    # 생기면 이 필드도 각 plan_type에 맞는 pydantic 모델로 바뀌어야 한다.
    instructions: dict


@dataclass
class Finding:
    """Attack Sub Agent가 만들어내는 공격 후보 하나. DB의 Findings 테이블
    (설계도 9페이지)에 대응하는 최소 필드만 담았다."""

    finding_id: str
    endpoint_id: str
    bug_class: str
    claim: str
    evidence_refs: list[str]
    status: FindingStatus = FindingStatus.CANDIDATE
    attempt_count: int = 0  # CURE 재시도 횟수 — MAX_CURE_ATTEMPTS로 상한


@dataclass
class ValidationResult:
    """Validation Agent 한 번 호출의 반환값. gap_ids는 CURE일 때만 채워지고,
    Coordinator가 그 갭만 골라 재검증을 시킨다(전체 재검증 아님)."""

    finding_id: str
    verdict: Verdict
    reason: str
    gap_ids: list[str] = field(default_factory=list)  # only set on CURE


# ── Agent Protocols (the LLM side — Codex/Claude in production) ────
#
# 아래 다섯 개는 전부 Protocol(구조적 타입)이다. 실제 구현체는 이 시그니처를
# 만족하는 Codex/Claude 호출 래퍼가 되고, Coordinator는 그 내부가 LLM인지
# 아닌지 신경 쓰지 않는다 — 테스트에서는 examples/coordinator_demo.py의
# Fake* 클래스들처럼 그냥 파이썬 객체를 넣으면 된다.


class MainAgent(Protocol):
    def next_plan(
        self, scope_markdown: str, coverage_summary: str
    ) -> MainAgentPlan | None:
        """scope_markdown is the approved Scope.md — the only place Main
        Agent may learn what's in scope. Return None when the agent decides
        the run is complete."""
        ...


class ReconAgent(Protocol):
    def run_recon(self, tasks: list[ReconTask]) -> list[dict]:
        """tasks are already scope-gated ReconTasks, not raw hostnames —
        Coordinator does the DB write for the returned endpoint dicts."""
        ...


class AttackAgent(Protocol):
    # Recon 결과(endpoints)를 받아 Bug Class를 분류하고 후보를 만든다.
    # 이 판단("이 파라미터는 IDOR일 확률이 높다") 자체는 LLM의 몫이다.
    def run_attack(self, origin_id: str, endpoints: list[dict]) -> list[Finding]:
        ...


class ValidationAgent(Protocol):
    # gap_ids가 None이면 최초 검증, 값이 있으면 CURE 이후의 "갭만" 재검증.
    # PoC 재현·claim/evidence 일치 여부 판단은 Attack Agent와 독립된
    # 컨텍스트에서 이루어져야 한다(설계도: "Finding을 만든 Agent가 자기
    # Finding을 최종 검증하지 못함").
    def validate(self, finding: Finding, gap_ids: list[str] | None) -> ValidationResult:
        ...


class ReportAgent(Protocol):
    # PASS(=CONFIRMED)된 Finding만 넘어온다 — REJECTED/DROPPED는 Coordinator
    # 단계에서 이미 걸러지고 절대 리포트에 들어가지 않는다.
    def render(self, confirmed: list[Finding]) -> str:
        ...


# ── Coordinator: everything below this line is plain code, zero LLM calls ──


# CURE 루프가 무한히 돌지 않도록 두는 상한. 설계도 Ground Rule의
# "적정 threshold를 두어 loop 방지"를 그대로 상수화한 것.
MAX_CURE_ATTEMPTS = 3


class Coordinator:
    def __init__(
        self,
        *,
        scope: ScopeDocument,  # 승인된 Scope.json 전체 (in_scope_assets 등)
        scope_markdown: str,  # Main Agent에게 그대로 보여줄 승인된 Scope.md 원문
        main_agent: MainAgent,
        recon_agent: ReconAgent,
        attack_agent: AttackAgent,
        validation_agent: ValidationAgent,
        report_agent: ReportAgent,
        # 테스트에서 가짜 ReconCoordinator를 주입할 수 있게 옵션으로 뺐다.
        # 기본값은 aidast recon이 실제로 쓰는 것과 동일한 인스턴스.
        recon_coordinator: ReconCoordinator | None = None,
    ) -> None:
        self._scope = scope
        self._scope_markdown = scope_markdown
        self._main = main_agent
        self._recon = recon_agent
        self._attack = attack_agent
        self._validation = validation_agent
        self._report = report_agent
        self._recon_coordinator = recon_coordinator or ReconCoordinator()
        # 아래 세 개가 이 실행의 "상태" 전부다 — DB 대신 메모리에 들고 있는
        # 스케치용 저장소. 실제로는 설계도 9페이지의 Origins/Endpoints/
        # Findings/Validations 테이블이 이 자리를 대신하게 된다.
        self._endpoints: list[dict] = []
        self._findings: dict[str, Finding] = {}
        self._changelog: list[str] = []  # coordinator-written, not LLM-written

    def run(self) -> str:
        # Main Agent가 plan_type=None 상당(=None 반환)으로 "이제 끝"이라고
        # 판단할 때까지, 매 사이클 coverage_summary를 다시 보여주고 다음
        # plan을 받는다. 이 while 루프 자체가 설계도 시퀀스 다이어그램의
        # "RECON_COMPLETED → 다음 뭐 할까 → Create Attack Plan → ..."
        # 왕복을 코드로 옮긴 것이다.
        coverage_summary = (
            f"program={self._scope.analysis.program_name} endpoints=0 findings=0"
        )
        while True:
            plan = self._main.next_plan(self._scope_markdown, coverage_summary)
            if plan is None:
                break
            coverage_summary = self._dispatch(plan)
        return self._report.render(self._confirmed_findings())

    # Pure routing table: plan_type -> handler. No judgment happens here —
    # Main Agent already made the judgment call when it chose plan_type.
    def _dispatch(self, plan: MainAgentPlan) -> str:
        handlers = {
            PlanType.RECON: self._handle_recon,
            PlanType.ATTACK: self._handle_attack,
            PlanType.VALIDATION: self._handle_validation,
        }
        handler = handlers.get(plan.plan_type)
        if handler is None:
            raise ValueError(f"unknown plan_type: {plan.plan_type}")
        return handler(plan)

    def _handle_recon(self, plan: MainAgentPlan) -> str:
        # Main Agent's RECON instructions are shaped like a ReconPlanProposal
        # (objective/mode/targets/global_constraints/completion_criteria).
        # Building the real pydantic ReconPlan here — rather than trusting
        # the dict — means a malformed or out-of-shape plan fails loudly
        # before it ever reaches ReconCoordinator.
        try:
            recon_plan = ReconPlan(
                plan_id=plan.plan_id,
                scope_id=self._scope.scope_id,
                **plan.instructions,
            )
        except Exception as exc:  # pydantic ValidationError, wrong keys, etc.
            raise CoordinatorError(f"malformed RECON plan {plan.plan_id}: {exc}") from exc

        # The actual scope gate: every target must already exist in
        # scope.analysis.in_scope_assets, or this raises. Same check
        # `aidast recon` already applies today — reused here, not
        # reimplemented, so there is exactly one place that decides
        # "is this target in scope."
        try:
            tasks = self._recon_coordinator.create_tasks(
                plan=recon_plan, scope=self._scope
            )
        except ReconCoordinatorError as exc:
            raise CoordinatorError(str(exc)) from exc

        # Recon Agent는 이미 스코프 게이트를 통과한 task 목록만 받는다 —
        # "이 URL이 스코프인지 아닌지"를 다시 판단할 필요도, 권한도 없다.
        new_endpoints = self._recon.run_recon(tasks)
        self._endpoints.extend(new_endpoints)
        targets = ", ".join(t.asset for t in recon_plan.targets)
        self._log(
            f"Recon 완료: {len(new_endpoints)} endpoints "
            f"({len(tasks)} scope-gated tasks over [{targets}])"
        )
        return self._coverage_summary()

    def _handle_attack(self, plan: MainAgentPlan) -> str:
        origin_id = plan.instructions["origin_id"]
        # Bug Class 분류·공격 전략 결정은 Attack Agent(LLM)의 몫. Coordinator는
        # 결과로 나온 Finding 후보들을 받아서 저장 여부만 코드로 판정한다.
        candidates = self._attack.run_attack(origin_id, self._endpoints)
        for finding in candidates:
            if not self._evidence_precheck(finding):
                continue  # dropped before it ever reaches the queue
            self._findings[finding.finding_id] = finding
            self._log(f"{finding.finding_id} {finding.bug_class} → CANDIDATE")
        return self._coverage_summary()

    def _handle_validation(self, plan: MainAgentPlan) -> str:
        # Priority Scheduler가 이미 우선순위를 매겨 넘겨준 finding_ids를
        # 순서대로 검증한다(스케줄링 로직 자체는 이 스케치에 없음 — 지금은
        # Main Agent가 고른 순서를 그대로 믿는다).
        for finding_id in plan.instructions["finding_ids"]:
            self._validate_one(self._findings[finding_id])
        return self._coverage_summary()

    # ── code-level gates (Ground Rule items, not agent judgment) ───────────

    def _evidence_precheck(self, finding: Finding) -> bool:
        """'최소 evidence 확인' — deterministic, not an LLM call."""
        return bool(finding.claim and finding.evidence_refs)

    def _validate_one(self, finding: Finding, gap_ids: list[str] | None = None) -> None:
        # 검증 자체(PoC 재현, claim-evidence 일치 확인)는 Validation Agent가
        # 하지만, 그 결과(PASS/CURE/DROP)를 Finding 상태로 바꾸는 건
        # 전적으로 여기 코드다 — 상태 전이는 코드로 고정.
        result = self._validation.validate(finding, gap_ids)
        match result.verdict:
            case Verdict.PASS:
                finding.status = FindingStatus.CONFIRMED
                self._log(f"{finding.finding_id} → CONFIRMED")
            case Verdict.DROP:
                finding.status = FindingStatus.REJECTED
                self._log(f"{finding.finding_id} → REJECTED ({result.reason})")
            case Verdict.CURE:
                finding.attempt_count += 1
                if finding.attempt_count >= MAX_CURE_ATTEMPTS:
                    # 상한 초과 → 더 이상 재시도하지 않고 DROPPED로 확정.
                    # 여기서 CoordinatorError를 던지지 않는 이유: 이건
                    # "이 Finding 하나가 결론 없이 끝났다"는 정상적인
                    # 종료 경로이지, 실행 자체의 오류가 아니기 때문이다.
                    finding.status = FindingStatus.DROPPED
                    self._log(f"{finding.finding_id} → DROPPED (CURE 한도 초과)")
                    return
                finding.status = FindingStatus.IN_VALIDATION
                self._log(
                    f"{finding.finding_id} → CURE, gap={result.gap_ids} "
                    f"(attempt {finding.attempt_count}/{MAX_CURE_ATTEMPTS})"
                )
                # 전체 재검증이 아니라 지목된 갭만 다시 채워서 재시도한다.
                self._validate_one(finding, gap_ids=result.gap_ids)  # gap-only retry

    def _confirmed_findings(self) -> list[Finding]:
        # Report Agent에게 넘길 최종 후보 — CONFIRMED 아닌 건 여기서 걸러진다.
        return [f for f in self._findings.values() if f.status == FindingStatus.CONFIRMED]

    def _coverage_summary(self) -> str:
        # 매 dispatch 이후 Main Agent에게 보여줄 "지금 상황 한 줄 요약".
        # changelog.md의 압축된 형태라고 보면 된다.
        confirmed = len(self._confirmed_findings())
        return (
            f"endpoints={len(self._endpoints)} "
            f"findings={len(self._findings)} confirmed={confirmed}"
        )

    def _log(self, line: str) -> None:
        self._changelog.append(line)  # → changelog.md, capped/compressed elsewhere
