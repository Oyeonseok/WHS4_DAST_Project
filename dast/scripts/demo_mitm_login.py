"""mitmproxy + Playwright 관찰 캡처 데모 - 아직 미완성, 다음 담당자가 이어서
작업할 것.

지금까지 된 것: mitm_addon.py를 별도로 띄워두면 Playwright가 그 프록시를
거쳐서 로그인하고, 끝난 뒤 flow_log를 읽어서 DB(http_exchanges)에 넣는
흐름까지는 연결해놨다. 근데 실제로 한 번도 돌려본 적 없고, mitm_ingest.py
상단에 적어둔 것들(auth_required 판단, parameters 추출, 로그인 이후
상호작용을 어디까지 시킬지)이 먼저 정리돼야 결과가 의미 있어진다.

사전 준비:
    1. 터미널 1: mitmdump -s src/aidast/recon/tools/mitm_addon.py \
                   --set flow_log=mitm_flows.jsonl -p 8080
    2. 터미널 2: docker run --rm -p 3000:3000 bkimminich/juice-shop
    3. Juice Shop에 /#/register로 테스트 계정 하나 만들어두기

실행:
    JUICE_EMAIL=... JUICE_PASSWORD=... uv run python scripts/demo_mitm_login.py
"""

from __future__ import annotations

import os
from pathlib import Path

from aidast.recon import db as dbmod
from aidast.recon.tools.login import login_and_capture_session
from aidast.recon.tools.mitm_ingest import ingest_flows_to_db, load_flows

TARGET_URL = "http://localhost:3000"
PROXY_SERVER = "http://127.0.0.1:8080"
FLOW_LOG = Path("mitm_flows.jsonl")

LOGIN_EMAIL = os.environ.get("JUICE_EMAIL")
LOGIN_PASSWORD = os.environ.get("JUICE_PASSWORD")


def main() -> None:
    if not LOGIN_EMAIL or not LOGIN_PASSWORD:
        print("JUICE_EMAIL / JUICE_PASSWORD 환경변수가 필요함")
        return

    session = login_and_capture_session(
        TARGET_URL, email=LOGIN_EMAIL, password=LOGIN_PASSWORD, proxy=PROXY_SERVER,
    )
    print(f"로그인 결과: {'성공' if not session.is_empty() else '실패/미확인'}")

    # TODO: 지금은 로그인만 하고 바로 끝난다. mitmproxy가 뭔가 의미 있는
    # 걸 관찰하려면 로그인 이후 최소한의 페이지 이동/클릭이 필요할 것 -
    # login_and_capture_session()을 건드리거나, 여기서 별도 Playwright
    # 세션을 이어서 몇 스텝 더 태울지 결정할 것.

    flows = load_flows(FLOW_LOG)
    print(f"mitmproxy가 캡처한 flow {len(flows)}건")
    if not flows:
        print("0건이면 프록시가 실제로 안 거쳐갔거나 mitm_addon.py가 안 떠 있는 것 - 터미널 1 확인")
        return

    # TODO: 지금은 독립적인 데모용 DB를 새로 만든다. 실제로는 같은 스캔의
    # recon_juiceshop.db에 있는 origin_id를 그대로 써야 한다 - executor.py
    # 쪽 배선이 아직 안 돼 있음.
    db_path = Path("recon_mitm_demo.db")
    conn = dbmod.init_db(db_path)
    dbmod.insert_scan(conn, scan_id="scan_mitm_demo", scope_type="url", scope_value=TARGET_URL)
    asset_id = dbmod.insert_asset(conn, scan_id="scan_mitm_demo", identifier=TARGET_URL, asset_type="URL")
    origin_id = dbmod.upsert_origin(
        conn, asset_id=asset_id, scheme="http", host="localhost", port=3000, base_url=TARGET_URL,
    )

    ingest_flows_to_db(conn, origin_id=origin_id, session_id=None, flows=flows)
    print(f"http_exchanges에 {len(flows)}건 저장 완료 -> {db_path.resolve()}")


if __name__ == "__main__":
    main()
