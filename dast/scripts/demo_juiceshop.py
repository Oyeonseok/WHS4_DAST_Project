"""Codex 없이, OWASP Juice Shop(http://localhost:3000)을 실제 타겟으로
정찰 파이프라인 MVP를 끝까지 돌려보는 스크립트.

사전 준비:
    docker run --rm -p 3000:3000 bkimminich/juice-shop
    (Juice Shop이 http://localhost:3000 에서 응답해야 함)

실행:
    cd dast
    uv run python scripts/demo_juiceshop.py
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

from aidast.orchestration.recon import ReconCoordinator
from aidast.recon.executor import ReconExecutor
from aidast.recon.models import ReconPlan, ReconPlanProposal, ReconPlanTarget, ReconStep
from aidast.recon.surface import export_surface
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    ScopeDocument,
    SourceEvidence,
)

TARGET_URL = "http://localhost:3000"

# ffuf 워드리스트 경로. 환경변수로 지정: FFUF_WORDLIST=/path/to/list.txt uv run python scripts/demo_juiceshop.py
FFUF_WORDLIST = os.environ.get("FFUF_WORDLIST")

# 로그인 세션이 필요하면 Juice Shop에서 /signup으로 계정을 하나 만든 뒤
# 환경변수로 넘긴다: JUICE_EMAIL=a@a.com JUICE_PASSWORD=1234 uv run ...
# 둘 다 없으면 로그인 단계는 그냥 건너뛴다(비로그인 크롤링만 수행).
LOGIN_EMAIL = os.environ.get("JUICE_EMAIL")
LOGIN_PASSWORD = os.environ.get("JUICE_PASSWORD")


def build_fake_scope() -> ScopeDocument:
    text = f"{TARGET_URL}는 로컬 테스트용 Juice Shop 인스턴스이며 정찰이 허용됩니다."
    page = ProgramPage(
        requested_url=TARGET_URL,
        final_url=TARGET_URL,
        title="Juice Shop (local)",
        captured_at=datetime.now(timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        text=text,
    )
    analysis = ScopeAnalysis(
        program_name="Juice Shop (local)",
        program_description="로컬 MVP 검증용 인스턴스",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.URL,
                asset=TARGET_URL,
                description="로컬 Juice Shop 인스턴스",
                eligibility="eligible",
                maximum_severity="critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["정찰"],
        prohibited_activities=[],
        submission_requirements=[],
        operational_constraints=[],
        safe_harbor="해당 없음 (로컬 테스트)",
        ambiguities=[],
        source_evidence=[SourceEvidence(section="Scope", quote=TARGET_URL)],
    )
    return ScopeDocument(
        scope_id="scope_juiceshop_local",
        created_at=datetime.now(timezone.utc),
        source=page,
        analysis=analysis,
    )


def build_fake_plan(scope: ScopeDocument) -> ReconPlan:
    proposal = ReconPlanProposal(
        objective="MVP 검증: Juice Shop 대상 정찰 파이프라인 end-to-end",
        mode="standard",
        targets=[
            ReconPlanTarget(
                asset_type=AssetType.URL,
                asset=TARGET_URL,
                # URL 스코프이므로 ASSET_DISCOVERY/DNS_RESOLUTION/HOST_PORT_DISCOVERY는 생략
                steps=[ReconStep.HTTP_PROBE, ReconStep.ORIGIN_DISCOVERY, ReconStep.ENDPOINT_DISCOVERY],
                constraints=["로컬 인스턴스 전용"],
            )
        ],
        global_constraints=["로컬 테스트 목적"],
        completion_criteria=["엔드포인트 목록 확정"],
    )
    return ReconPlan(plan_id="plan_juiceshop_local", scope_id=scope.scope_id, **proposal.model_dump())


def main() -> None:
    scope = build_fake_scope()
    plan = build_fake_plan(scope)
    tasks = ReconCoordinator().create_tasks(plan=plan, scope=scope)

    # 데모 스크립트는 재실행마다 "같은 스캔을 다시 돈다"는 취지라, 이전
    # 실행 결과가 DB에 계속 누적되면 안 된다. _ensure_asset()이 DB를
    # 조회하지 않고 매 실행마다 새 asset/origin을 만들기 때문에, 재실행 전
    # 기존 DB/Surface.json을 지우고 깨끗한 상태에서 시작한다.
    db_path = Path("recon_juiceshop.db")
    surface_path = Path("Surface.json")
    db_path.unlink(missing_ok=True)
    surface_path.unlink(missing_ok=True)
    # 예전에 WAL 모드로 생성됐던 보조 파일이 남아있으면 같이 정리한다.
    Path(str(db_path) + "-wal").unlink(missing_ok=True)
    Path(str(db_path) + "-shm").unlink(missing_ok=True)

    executor = ReconExecutor(
        scan_id="scan_juiceshop_local", scope_type="url", scope_value=TARGET_URL, db_path=db_path,
        ffuf_wordlist=FFUF_WORDLIST,
        login_email=LOGIN_EMAIL, login_password=LOGIN_PASSWORD,
    )
    executor.run(tasks)

    output = export_surface(executor.conn, scan_id="scan_juiceshop_local", output_path=surface_path)
    print(f"\nSurface.json 저장: {output.resolve()}")
    print(f"DB 파일: {db_path.resolve()}")


if __name__ == "__main__":
    main()
