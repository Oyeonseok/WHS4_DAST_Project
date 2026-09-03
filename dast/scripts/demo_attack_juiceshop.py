"""Recon이 완료된 Juice Shop DB를 대상으로 Attack → Validator → Report
파이프라인을 돌려보는 스크립트.

사전 준비:
    1. Juice Shop 실행:
       docker run --rm -p 3000:3000 bkimminich/juice-shop

    2. Recon 먼저 실행 (DB 생성):
       JUICE_EMAIL=a@a.com JUICE_PASSWORD=1234 uv run python scripts/demo_juiceshop.py

    3. Attack 실행:
       uv run python scripts/demo_attack_juiceshop.py

    또는 직접 세션 토큰 지정:
       USER_A_TOKEN=<token> USER_B_TOKEN=<token> uv run python scripts/demo_attack_juiceshop.py

환경변수:
    DB_PATH          : recon DB 경로 (기본: recon_juiceshop.db)
    SCAN_ID          : scan_id (기본: scan_juiceshop_local)
    USER_A_TOKEN     : User A(소유자) JWT 토큰 (선택)
    USER_B_TOKEN     : User B(공격자) JWT 토큰 (선택)
    CODEX_TIMEOUT    : Codex 타임아웃 초 (기본: 300)
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

from aidast.agents.main import CodexMainAgent
from aidast.attack import db as attackdb
from aidast.orchestration.attack import AttackCoordinator
from aidast.recon.db import init_db, new_id

TARGET_URL = "http://localhost:3000"

DB_PATH = Path(os.environ.get("DB_PATH", "recon_juiceshop.db"))
SCAN_ID = os.environ.get("SCAN_ID", "scan_juiceshop_local")
SCOPE_DIR = Path(os.environ.get("SCOPE_DIR", "scope_juiceshop"))
REPORT_DIR = Path(os.environ.get("REPORT_DIR", "reports"))
CODEX_TIMEOUT = int(os.environ.get("CODEX_TIMEOUT", "300"))

USER_A_TOKEN = os.environ.get("USER_A_TOKEN")
USER_B_TOKEN = os.environ.get("USER_B_TOKEN")


def ensure_scope_md(scope_dir: Path) -> None:
    """Juice Shop용 Scope.md가 없으면 생성한다."""
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_md = scope_dir / "Scope.md"
    if scope_md.exists():
        print(f"기존 Scope.md 사용: {scope_md}")
        return

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
    print(f"Scope.md 생성: {scope_md}")


def register_manual_sessions(conn: sqlite3.Connection) -> None:
    """환경변수로 전달된 JWT 토큰을 sessions 테이블에 등록한다."""
    if not USER_A_TOKEN and not USER_B_TOKEN:
        print("USER_A_TOKEN / USER_B_TOKEN 환경변수 없음 — 기존 세션 사용")
        return

    # origin_id 조회
    row = conn.execute(
        "SELECT origin_id FROM origins LIMIT 1"
    ).fetchone()
    if not row:
        print("[경고] origins 테이블이 비어있음 — Recon을 먼저 실행하세요")
        return
    origin_id = row[0]

    if USER_A_TOKEN:
        auth_state = json.dumps({
            "token": USER_A_TOKEN,
            "extra_headers": {"Authorization": f"Bearer {USER_A_TOKEN}"},
        })
        sid = new_id("session")
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, origin_id, target, auth_state)
               VALUES (?, ?, ?, ?)""",
            (sid, origin_id, "user_a", auth_state),
        )
        print(f"User A 세션 등록: {sid}")

    if USER_B_TOKEN:
        auth_state = json.dumps({
            "token": USER_B_TOKEN,
            "extra_headers": {"Authorization": f"Bearer {USER_B_TOKEN}"},
        })
        sid = new_id("session")
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, origin_id, target, auth_state)
               VALUES (?, ?, ?, ?)""",
            (sid, origin_id, "user_b", auth_state),
        )
        print(f"User B 세션 등록: {sid}")

    conn.commit()


def print_db_summary(conn: sqlite3.Connection) -> None:
    """Attack 실행 전 DB 상태 요약 출력."""
    counts = {}
    for table in ("endpoints", "parameters", "sessions"):
        row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()
        counts[table] = row[0] if row else 0

    print(f"\n=== DB 상태 (scan: {SCAN_ID}) ===")
    print(f"  endpoints:  {counts['endpoints']}개")
    print(f"  parameters: {counts['parameters']}개")
    print(f"  sessions:   {counts['sessions']}개")

    if counts["endpoints"] == 0:
        print("\n[오류] endpoints가 비어있습니다. Recon을 먼저 실행하세요:")
        print("  uv run python scripts/demo_juiceshop.py")
        sys.exit(1)


def main() -> None:
    if not DB_PATH.exists():
        print(f"[오류] DB 파일 없음: {DB_PATH}")
        print("Recon을 먼저 실행하세요:")
        print("  uv run python scripts/demo_juiceshop.py")
        sys.exit(1)

    conn = init_db(DB_PATH)

    try:
        # 1. Scope.md 확인/생성
        ensure_scope_md(SCOPE_DIR)

        # 2. 수동 세션 등록 (환경변수가 있으면)
        register_manual_sessions(conn)

        # 3. DB 상태 출력
        print_db_summary(conn)

        # 4. Attack 파이프라인 실행
        print("\n=== Attack → Validator → Report 시작 ===\n")
        agent = CodexMainAgent(timeout_seconds=CODEX_TIMEOUT)
        coordinator = AttackCoordinator(
            agent=agent,
            conn=conn,
            scope_dir=SCOPE_DIR,
            report_dir=REPORT_DIR,
        )
        confirmed = coordinator.run(SCAN_ID)

        # 5. 결과 출력
        print(f"\n=== 결과 ===")
        print(f"Confirmed 취약점: {len(confirmed)}개")
        for fid in confirmed:
            report_path = REPORT_DIR / f"{fid}_report.md"
            print(f"  - {fid}")
            if report_path.exists():
                print(f"    보고서: {report_path}")

        # findings 전체 요약
        all_findings = attackdb.get_findings_by_scan(conn, SCAN_ID)
        if all_findings:
            print(f"\n전체 findings: {len(all_findings)}개")
            for f in all_findings:
                print(
                    f"  [{f['status']}] {f['finding_id']}: "
                    f"{f['title']} ({f['severity']})"
                )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
