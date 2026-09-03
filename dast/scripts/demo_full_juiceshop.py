"""Juice Shop 전체 파이프라인: Recon -> Attack -> Validator -> Report
명령 하나로 끝까지 실행한다.

사전 준비:
    docker run --rm -p 3000:3000 bkimminich/juice-shop

실행:
    cd dast
    uv run python scripts/demo_full_juiceshop.py

환경변수 (모두 선택):
    JUICE_EMAIL      : Juice Shop 로그인 이메일 (기본: usera@test.com)
    JUICE_PASSWORD   : Juice Shop 로그인 비밀번호 (기본: Test1234!)
    JUICE_EMAIL_B    : User B 이메일 (기본: userb@test.com)
    JUICE_PASSWORD_B : User B 비밀번호 (기본: Test1234!)
    CODEX_TIMEOUT    : Codex 타임아웃 초 (기본: 300)
    FFUF_WORDLIST    : ffuf 워드리스트 경로 (선택)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from aidast.agents.main import CodexMainAgent
from aidast.attack import db as attackdb
from aidast.orchestration.attack import AttackCoordinator
from aidast.orchestration.recon import ReconCoordinator
from aidast.recon import db as dbmod
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

# 환경변수 (기본값 포함)
EMAIL_A = os.environ.get("JUICE_EMAIL", "usera@test.com")
PASSWORD_A = os.environ.get("JUICE_PASSWORD", "Test1234!")
EMAIL_B = os.environ.get("JUICE_EMAIL_B", "userb@test.com")
PASSWORD_B = os.environ.get("JUICE_PASSWORD_B", "Test1234!")
CODEX_TIMEOUT = int(os.environ.get("CODEX_TIMEOUT", "300"))
FFUF_WORDLIST = os.environ.get("FFUF_WORDLIST")

DB_PATH = Path("recon_juiceshop.db")
SCOPE_DIR = Path("scope_juiceshop")
REPORT_DIR = Path("reports")
SCAN_ID = "scan_juiceshop_local"


# ------------------------------------------------------------------
# 유틸리티
# ------------------------------------------------------------------


def check_target() -> None:
    """Juice Shop이 떠있는지 확인한다."""
    try:
        urllib.request.urlopen(TARGET_URL, timeout=5)
    except Exception:
        print(f"[오류] Juice Shop에 접속할 수 없습니다: {TARGET_URL}")
        print("먼저 실행하세요:")
        print("  docker run --rm -p 3000:3000 bkimminich/juice-shop")
        sys.exit(1)


def ensure_user(email: str, password: str) -> None:
    """Juice Shop에 계정이 없으면 생성한다."""
    data = json.dumps({
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 1},
        "securityAnswer": "test",
    }).encode()
    req = urllib.request.Request(
        f"{TARGET_URL}/api/Users/",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        print(f"  계정 생성: {email}")
    except urllib.error.HTTPError:
        print(f"  계정 확인: {email} (이미 존재)")


def get_token(email: str, password: str) -> str:
    """Juice Shop에 로그인하여 JWT 토큰을 반환한다."""
    data = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(
        f"{TARGET_URL}/rest/user/login",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read())
    return body["authentication"]["token"]


def register_sessions(conn: sqlite3.Connection, token_a: str, token_b: str) -> None:
    """JWT 토큰을 sessions 테이블에 등록한다."""
    row = conn.execute("SELECT origin_id FROM origins LIMIT 1").fetchone()
    if not row:
        print("[경고] origins 테이블이 비어있음")
        return
    origin_id = row[0]

    for target, token in [("user_a", token_a), ("user_b", token_b)]:
        auth_state = json.dumps({
            "token": token,
            "extra_headers": {"Authorization": f"Bearer {token}"},
        })
        sid = dbmod.new_id("session")
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, origin_id, target, auth_state)
               VALUES (?, ?, ?, ?)""",
            (sid, origin_id, target, auth_state),
        )
        print(f"  {target} 세션 등록: {sid[:20]}...")
    conn.commit()


def ensure_scope_md() -> None:
    """Juice Shop용 Scope.md를 생성한다."""
    SCOPE_DIR.mkdir(parents=True, exist_ok=True)
    scope_md = SCOPE_DIR / "Scope.md"
    scope_md.write_text(
        f"""\
# Juice Shop (Local Test)

## Program Information
- **Program Name**: OWASP Juice Shop
- **Platform**: Local Test
- **URL**: {TARGET_URL}

## In-scope Assets

| Asset Type | Asset | Eligibility | Max Severity |
|---|---|---|---|
| URL | {TARGET_URL} | eligible | critical |

## Out-of-scope Assets

없음 (로컬 테스트)

## Allowed Activities

- 정찰 (Reconnaissance)
- IDOR 테스트
- API 엔드포인트 취약점 분석

## Prohibited Activities

- DoS / DDoS
- 소셜 엔지니어링
- 물리적 공격

## Operational Constraints

- 로컬 인스턴스 전용 (localhost:3000)
- rate limit 없음
""",
        encoding="utf-8",
    )


def build_scope() -> ScopeDocument:
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


def build_plan(scope: ScopeDocument) -> ReconPlan:
    proposal = ReconPlanProposal(
        objective="MVP 검증: Juice Shop 대상 전체 파이프라인 end-to-end",
        mode="standard",
        targets=[
            ReconPlanTarget(
                asset_type=AssetType.URL,
                asset=TARGET_URL,
                steps=[
                    ReconStep.HTTP_PROBE,
                    ReconStep.ORIGIN_DISCOVERY,
                    ReconStep.ENDPOINT_DISCOVERY,
                ],
                constraints=["로컬 인스턴스 전용"],
            )
        ],
        global_constraints=["로컬 테스트 목적"],
        completion_criteria=["엔드포인트 목록 확정"],
    )
    return ReconPlan(
        plan_id="plan_juiceshop_local",
        scope_id=scope.scope_id,
        **proposal.model_dump(),
    )


# ------------------------------------------------------------------
# 메인
# ------------------------------------------------------------------


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # 0. 사전 확인
    print("=== Phase 0: 환경 확인 ===")
    check_target()
    print(f"Juice Shop 응답 확인: {TARGET_URL}")

    ensure_user(EMAIL_A, PASSWORD_A)
    ensure_user(EMAIL_B, PASSWORD_B)

    # 1. 이전 결과 정리
    for p in [DB_PATH, Path(f"{DB_PATH}-wal"), Path(f"{DB_PATH}-shm"), Path("Surface.json")]:
        p.unlink(missing_ok=True)

    # 2. Recon
    print("\n=== Phase 1: Recon ===")
    scope = build_scope()
    plan = build_plan(scope)
    tasks = ReconCoordinator().create_tasks(plan=plan, scope=scope)

    executor = ReconExecutor(
        scan_id=SCAN_ID,
        scope_type="url",
        scope_value=TARGET_URL,
        db_path=DB_PATH,
        ffuf_wordlist=FFUF_WORDLIST,
        login_email=EMAIL_A,
        login_password=PASSWORD_A,
        login_path="/#/login",
    )
    executor.run(tasks)

    export_surface(executor.conn, scan_id=SCAN_ID, output_path=Path("Surface.json"))

    ep_count = executor.conn.execute("SELECT count(*) FROM endpoints").fetchone()[0]
    sess_count = executor.conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
    print(f"  endpoints: {ep_count}개, sessions: {sess_count}개")

    if ep_count == 0:
        print("[오류] 엔드포인트가 발견되지 않았습니다.")
        sys.exit(1)

    # 3. 세션 토큰 발급 + 등록
    print("\n=== Phase 2: 세션 준비 ===")
    token_a = get_token(EMAIL_A, PASSWORD_A)
    token_b = get_token(EMAIL_B, PASSWORD_B)
    register_sessions(executor.conn, token_a, token_b)

    # 4. Scope.md 생성
    ensure_scope_md()
    print(f"  Scope.md: {SCOPE_DIR / 'Scope.md'}")

    # 5. Attack -> Validator -> Report
    print("\n=== Phase 3: Attack -> Validator -> Report ===")
    agent = CodexMainAgent(timeout_seconds=CODEX_TIMEOUT)
    coordinator = AttackCoordinator(
        agent=agent,
        conn=executor.conn,
        scope_dir=SCOPE_DIR,
        report_dir=REPORT_DIR,
    )
    confirmed = coordinator.run(SCAN_ID)

    # 6. 결과 출력
    print(f"\n{'=' * 50}")
    print(f"=== 전체 파이프라인 완료 ===")
    print(f"{'=' * 50}")

    all_findings = attackdb.get_findings_by_scan(executor.conn, SCAN_ID)
    print(f"\n전체 findings: {len(all_findings)}개")
    for f in all_findings:
        print(f"  [{f['status']}] {f['finding_id']}: {f['title']} ({f['severity']})")

    print(f"\nConfirmed 취약점: {len(confirmed)}개")
    for fid in confirmed:
        report_path = REPORT_DIR / f"{fid}_report.md"
        print(f"  - {fid}")
        if report_path.exists():
            print(f"    보고서: {report_path}")

    executor.conn.close()


if __name__ == "__main__":
    main()
