"""Playwright 수동 로그인 + 자동 크롤 + mitmproxy 관찰 PoC 데모.

OWASP JuiceShop(http://localhost:3000)을 대상으로:
  1. visible 브라우저에서 사용자가 직접 로그인
  2. Playwright가 자동으로 링크를 따라가며 크롤링
  3. 모든 트래픽이 mitmproxy(8080)를 거쳐 JSONL에 기록
  4. JSONL을 읽어서 http_exchanges와 endpoints 테이블에 적재
  5. 크롤 중 401 발생 시 재로그인 후 이어가기

사전 준비:
    1. 터미널 1: mitmdump -s src/aidast/recon/tools/mitm_addon.py \
                   --set flow_log=mitm_flows.jsonl -p 8080
    2. 터미널 2: docker run --rm -p 3000:3000 bkimminich/juice-shop

실행:
    uv run python scripts/demo_playwright_crawl.py
"""

from __future__ import annotations

from pathlib import Path

from aidast.recon import db as dbmod
from aidast.recon.judgment import merge_and_normalize
from aidast.recon.tools.mitm_ingest import (
    extract_parameters_from_flows,
    ingest_flows_to_db,
    load_flows,
    flows_to_raw_endpoints,
)
from aidast.recon.tools.playwright_crawler import run_crawl_session

TARGET_URL = "http://localhost:3000"
PROXY_SERVER = "http://127.0.0.1:8080"
FLOW_LOG = Path("mitm_flows.jsonl")
DB_PATH = Path("recon_playwright_crawl.db")
SCAN_ID = "scan_playwright_crawl"


def main() -> None:
    # 0. 이전 실행 잔여 파일 정리
    if FLOW_LOG.exists():
        FLOW_LOG.unlink()
        print(f"기존 flow 로그 삭제: {FLOW_LOG}")
    if DB_PATH.exists():
        DB_PATH.unlink()
        print(f"기존 DB 삭제: {DB_PATH}")

    # 1. DB 초기화 + scan/asset/origin 레코드 생성
    conn = dbmod.init_db(DB_PATH)
    dbmod.insert_scan(conn, scan_id=SCAN_ID, scope_type="url", scope_value=TARGET_URL)
    asset_id = dbmod.insert_asset(conn, scan_id=SCAN_ID, identifier=TARGET_URL, asset_type="URL")
    origin_id = dbmod.upsert_origin(
        conn,
        asset_id=asset_id,
        scheme="http",
        host="localhost",
        port=3000,
        base_url=TARGET_URL,
    )
    print(f"DB 초기화 완료: {DB_PATH.resolve()}")
    print(f"  scan_id: {SCAN_ID}")
    print(f"  origin_id: {origin_id}")

    # 2. mitmproxy 연결 확인 안내
    print(f"\n프록시: {PROXY_SERVER}")
    print("  mitmdump가 떠 있는지 확인하세요:")
    print(f"  mitmdump -s src/aidast/recon/tools/mitm_addon.py --set flow_log={FLOW_LOG} -p 8080")
    print(f"  JuiceShop이 {TARGET_URL}에 떠 있는지 확인하세요.")

    # 3. 크롤 세션 실행 (수동 로그인 → 자동 크롤 → 401 시 재로그인)
    print("\n=== 크롤 세션 시작 ===")
    session = run_crawl_session(
        TARGET_URL,
        proxy=PROXY_SERVER,
        login_path="/#/login",  # JuiceShop은 Angular hash 라우팅
        flow_log=FLOW_LOG,
    )

    # 3a. 세션 정보 DB 저장
    import json as _json
    session_id = None
    if not session.is_empty():
        auth_state = _json.dumps({
            "cookie_header": session.cookie_header,
            "extra_headers": session.extra_headers,
            "raw_local_storage": session.raw_local_storage,
        }, ensure_ascii=False)
        session_id = dbmod.insert_session(
            conn,
            origin_id=origin_id,
            target=TARGET_URL,
            auth_state=auth_state,
        )
        print(f"  세션 저장 완료: {session_id}")
    else:
        print("  [경고] 세션이 비어 있어 sessions 테이블에 저장하지 않음")

    # 4. JSONL → DB 적재
    print("\n=== DB 적재 시작 ===")
    flows = load_flows(FLOW_LOG)
    print(f"JSONL에서 {len(flows)}건의 flow 로드")

    if not flows:
        print("[경고] flow가 0건 — mitmproxy가 실제로 거쳐가지 않았거나 mitm_addon.py가 안 떠 있는 것")
        conn.close()
        return

    # 4a. http_exchanges에 원본 트래픽 적재
    ingest_flows_to_db(conn, origin_id=origin_id, session_id=session_id, flows=flows)
    exchange_count = conn.execute("SELECT count(*) FROM http_exchanges").fetchone()[0]
    print(f"http_exchanges에 {exchange_count}건 적재 완료")

    # 4b. endpoints에 정규화된 엔드포인트 적재
    raw_endpoints = flows_to_raw_endpoints(flows)
    merged = merge_and_normalize(raw_endpoints)
    for item in merged:
        dbmod.upsert_endpoint(
            conn,
            origin_id=origin_id,
            method=item["method"],
            path=item["path"],
            normalized_path=item["normalized_path"],
            content_type=item.get("content_type"),
            source_tool=",".join(sorted(item["source_tools"])),
            is_excluded=item["is_excluded"],
            exclude_reason=item["exclude_reason"],
        )
    included = [e for e in merged if not e["is_excluded"]]
    excluded = [e for e in merged if e["is_excluded"]]
    print(f"endpoints에 {len(included)}건 적재 (제외 {len(excluded)}건)")

    # 4c. parameters 테이블에 파라미터 추출·적재
    endpoint_lookup: dict[tuple[str, str], str] = {}
    for row in conn.execute("SELECT endpoint_id, method, normalized_path FROM endpoints").fetchall():
        endpoint_lookup[(row[1], row[2])] = row[0]
    param_count = extract_parameters_from_flows(
        conn, flows=flows, endpoint_lookup=endpoint_lookup,
    )
    print(f"parameters에 {param_count}건 적재 완료")

    # 5. 요약
    print("\n=== 결과 요약 ===")
    print(f"DB 파일: {DB_PATH.resolve()}")
    print(f"JSONL 파일: {FLOW_LOG.resolve()}")
    print(f"http_exchanges: {exchange_count}건")
    print(f"endpoints: {len(included)}건 (제외 {len(excluded)}건)")
    print(f"parameters: {param_count}건")
    print(f"sessions: {'1 (저장됨)' if session_id else '0 (세션 없음)'}")

    # 파라미터 미리보기
    param_rows = conn.execute(
        "SELECT p.name, p.location, p.data_type, p.example_value, e.path "
        "FROM parameters p JOIN endpoints e ON p.endpoint_id = e.endpoint_id LIMIT 15"
    ).fetchall()
    if param_rows:
        print("\n  대표 파라미터 (최대 15건):")
        for name, loc, dtype, example, epath in param_rows:
            ex = (example[:30] + "...") if example and len(example) > 30 else example
            print(f"    {epath}  {loc}:{name} ({dtype}) = {ex}")

    # 대표 엔드포인트 10건 미리보기
    rows = conn.execute(
        "SELECT method, path, source_tools FROM endpoints WHERE is_excluded=0 LIMIT 10"
    ).fetchall()
    if rows:
        print("\n  대표 엔드포인트 (최대 10건):")
        for method, path, tools in rows:
            print(f"    {method} {path}  [{tools}]")

    conn.close()
    print("\n완료.")


if __name__ == "__main__":
    main()
