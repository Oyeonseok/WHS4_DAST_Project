"""mitm_addon.py가 남긴 JSONL을 읽어서 (1) 다른 도구들과 같은 raw-endpoint
형태로 변환하고 (2) http_exchanges 테이블에 원본을 남긴다.

담당자에게 남기는 TODO (아직 결정 안 된 것들):

1. auth_required 판단 기준
   지금은 아무 판단도 안 하고 전부 is_authenticated=False로 넣는다.
   가장 간단한 방법은 login_and_capture_session()이 끝난 시각을 기준으로
   그 이후 캡처된 flow만 "인증됨"으로 치는 건데, 세션 쿠키를 이미 들고
   재방문하는 경우까지 고려하면 이걸로 충분한지는 더 생각해봐야 함.

2. parameters 테이블 채우기
   query/body에서 실제 파라미터 이름과 값을 뽑아서 parameters 테이블에
   넣는 부분은 아직 없음. 숫자/UUID처럼 생긴 값인지(is_identifier) 판단은
   judgment.py의 PARAM_PATTERN을 재사용하면 될 것 같음.

3. Gap Ratio를 mitmproxy 기준으로 다시 정의할지
   지금 judgment.py의 assess_observation_gap()은 katana 쪽 assess_gap_ratio
   랑 완전히 같은 구조로 mitmproxy 전용 발견 비율만 잰다. 이걸로 충분한지,
   아니면 katana 결과까지 다 합쳐서 하나의 지표로 만들지는 아직 안 정함.

4. Playwright가 로그인만 하고 끝나면 mitmproxy가 관찰할 트래픽 자체가
   거의 없다. 로그인 이후에 최소한의 상호작용(몇 페이지 이동, 클릭 정도)을
   추가할지 말지부터 정해야 이 파이프라인이 의미가 있음.
"""

from __future__ import annotations

import json
from pathlib import Path

from aidast.recon import db as dbmod


def load_flows(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    flows = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            flows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return flows


def flows_to_raw_endpoints(flows: list[dict]) -> list[dict]:
    """judgment.merge_and_normalize()에 바로 넣을 수 있는 형태로 변환.
    katana/ffuf 결과와 같은 shape을 쓰기 때문에 그대로 섞어서 merge할 수
    있다."""
    return [
        {
            "method": flow["method"],
            "path": flow.get("path") or "/",
            "content_type": flow.get("content_type"),
            "source": "mitmproxy",
        }
        for flow in flows
    ]


def ingest_flows_to_db(
    conn, *, origin_id: str, session_id: str | None, flows: list[dict]
) -> None:
    """원본 flow를 http_exchanges에 감사 기록으로 남긴다. is_authenticated는
    아직 항상 False로 들어간다 (위 TODO 1 참고)."""
    for flow in flows:
        dbmod.insert_http_exchange(
            conn,
            origin_id=origin_id,
            session_id=session_id,
            method=flow["method"],
            path=flow.get("path") or "/",
            query_string=json.dumps(flow.get("query", []), ensure_ascii=False),
            request_headers=json.dumps(flow.get("request_headers", {}), ensure_ascii=False),
            status_code=flow.get("status_code"),
            content_type=flow.get("content_type"),
            response_size=flow.get("response_size"),
        )
