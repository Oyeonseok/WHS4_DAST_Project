"""mitm_addon.py가 남긴 로그를 읽어서 (1) 다른 도구들과 같은 raw-endpoint
형태로 변환하고 (2) http_exchanges 테이블에 원본을 남긴다. (스켈레톤 -
구현 필요)

정해야/짜야 할 것:

1. auth_required 판단 기준
   로그인 이후에 캡처된 flow인지 어떻게 구분할지 (시각 기준? 세션
   식별자 기준?), 세션 쿠키를 이미 들고 재방문하는 경우는 어떻게 볼지.

2. parameters 테이블 채우기
   query/body에서 실제 파라미터 이름·값을 뽑아서 parameters 테이블에
   넣는 로직. judgment.py의 PARAM_PATTERN(숫자/UUID 감지)을 참고해도 됨.

3. Gap Ratio를 mitmproxy 기준으로 어떻게 쓸지
   judgment.py의 assess_observation_gap()과 맞물려서, katana 결과와
   따로 볼지 합쳐서 하나의 지표로 만들지.

4. flows_to_raw_endpoints()가 만드는 dict의 "source" 값(mitmproxy)이
   merge_and_normalize()에서 katana/ffuf와 잘 섞이는지 확인 필요.

db.py에 http_exchanges 테이블과 insert_http_exchange() 헬퍼는 이미
있음 - 그대로 쓰면 됨.
"""

from __future__ import annotations

import json
from pathlib import Path

from aidast.recon import db as dbmod


def load_flows(log_path: Path) -> list[dict]:
    """mitm_addon.py가 남긴 로그 파일을 읽어서 dict 리스트로 반환."""
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
    """judgment.merge_and_normalize()에 넣을 수 있는 형태로 변환.
    katana/ffuf 결과와 같은 shape({"method", "path", "content_type",
    "source"})을 맞춰야 섞어서 merge할 수 있다."""
    # TODO
    raise NotImplementedError


def ingest_flows_to_db(
    conn, *, origin_id: str, session_id: str | None, flows: list[dict]
) -> None:
    """원본 flow를 http_exchanges에 감사 기록으로 남긴다.
    dbmod.insert_http_exchange()를 flow마다 호출하면 되는데, is_authenticated
    값을 어떻게 채울지는 위 TODO 1 먼저 정할 것."""
    # TODO
    raise NotImplementedError
