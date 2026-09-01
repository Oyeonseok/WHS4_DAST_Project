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

from urllib.parse import parse_qs, urlparse

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
    raw_endpoints = []
    for flow in flows:
        path = flow.get("path")
        if not path:
            continue
        raw_endpoints.append(
            {
                "method": flow.get("method"),
                "path": path,
                "content_type": flow.get("content_type"),
                "source": "mitmproxy",
            }
        )
    return raw_endpoints


def ingest_flows_to_db(
    conn, *, origin_id: str, session_id: str | None, flows: list[dict]
) -> None:
    """원본 flow를 http_exchanges에 감사 기록으로 남긴다.
    dbmod.insert_http_exchange()를 flow마다 호출하면 되는데, is_authenticated
    값은 위 TODO 1이 아직 확정되지 않았으므로, 일단 요청 헤더에 Authorization/Cookie가
    있으면 인증된 요청으로 간주하는 러프 휴리스틱으로 채운다."""
    for flow in flows:
        request_headers = flow.get("request_headers") or {}
        # 헤더 이름 대소문자를 구분하지 않고 보기 위해 키를 소문자로 맞춰 비교한다.
        lowered_headers = {k.lower() for k in request_headers}
        is_authenticated = "authorization" in lowered_headers or "cookie" in lowered_headers
        dbmod.insert_http_exchange(
            conn,
            origin_id=origin_id,
            session_id=session_id,
            method=flow.get("method"),
            path=flow.get("path"),
            query_string=flow.get("query"),
            request_headers=json.dumps(request_headers, ensure_ascii=False),
            status_code=flow.get("status_code"),
            content_type=flow.get("content_type"),
            response_size=flow.get("response_size"),
            is_authenticated=is_authenticated,
        )


def extract_parameters_from_flows(
    conn,
    *,
    flows: list[dict],
    endpoint_lookup: dict[tuple[str, str], str],
) -> int:
    """flow의 query string과 request body에서 파라미터를 추출해
    parameters 테이블에 적재한다.

    endpoint_lookup: (method, normalized_path) -> endpoint_id 매핑.
    반환값: 적재된 파라미터 수.
    """
    from aidast.recon.judgment import normalize_path

    count = 0
    seen: set[tuple[str, str, str]] = set()  # (endpoint_id, name, location)

    for flow in flows:
        method = flow.get("method", "GET")
        path = flow.get("path", "")
        normalized = normalize_path(path)
        endpoint_id = endpoint_lookup.get((method, normalized))
        if not endpoint_id:
            continue

        # 1) query string 파라미터
        query = flow.get("query", "")
        if query:
            for name, values in parse_qs(query).items():
                key = (endpoint_id, name, "query")
                if key in seen:
                    continue
                seen.add(key)
                example = values[0] if values else None
                data_type = _guess_type(example)
                conn.execute(
                    """INSERT OR IGNORE INTO parameters
                       (parameter_id, endpoint_id, name, location, data_type, example_value)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (dbmod.new_id("param"), endpoint_id, name, "query", data_type, example),
                )
                count += 1

        # 2) request body 파라미터 (JSON / form-urlencoded)
        content_type = (flow.get("content_type") or "").lower()
        request_body = flow.get("request_body", "")
        if not request_body:
            continue

        body_params: dict[str, str] = {}
        if "application/json" in content_type:
            try:
                parsed = json.loads(request_body)
                if isinstance(parsed, dict):
                    body_params = {k: str(v) for k, v in parsed.items()}
            except (json.JSONDecodeError, TypeError):
                pass
        elif "x-www-form-urlencoded" in content_type:
            for name, values in parse_qs(request_body).items():
                body_params[name] = values[0] if values else ""

        for name, example in body_params.items():
            key = (endpoint_id, name, "body")
            if key in seen:
                continue
            seen.add(key)
            data_type = _guess_type(example)
            conn.execute(
                """INSERT OR IGNORE INTO parameters
                   (parameter_id, endpoint_id, name, location, data_type, example_value)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (dbmod.new_id("param"), endpoint_id, name, "body", data_type, example),
            )
            count += 1

    conn.commit()
    return count


def _guess_type(value: str | None) -> str:
    """값으로부터 대략적인 데이터 타입을 추측한다."""
    if value is None:
        return "string"
    if value.isdigit():
        return "integer"
    try:
        float(value)
        return "number"
    except ValueError:
        pass
    if value.lower() in ("true", "false"):
        return "boolean"
    # JWT나 긴 토큰 패턴
    if value.count(".") == 2 and len(value) > 20:
        return "token"
    # 이메일 패턴
    if "@" in value and "." in value:
        return "email"
    return "string"
