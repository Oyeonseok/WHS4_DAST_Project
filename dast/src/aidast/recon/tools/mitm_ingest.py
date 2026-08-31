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
from urllib.parse import parse_qsl, urlparse

from aidast.recon import db as dbmod
from aidast.recon.judgment import PARAM_PATTERN, is_static_asset, normalize_path


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


def flows_to_raw_endpoints(
    flows: list[dict], *, base_url: str | None = None
) -> list[dict]:
    """judgment.merge_and_normalize()에 넣을 수 있는 형태로 변환.
    katana/ffuf 결과와 같은 shape({"method", "path", "content_type",
    "source"})을 맞춰야 섞어서 merge할 수 있다.

    base_url을 주면 그 origin의 flow만 남긴다. 프록시는 브라우저가 보내는
    모든 트래픽을 보기 때문에, 안 거르면 폰트/애널리틱스 같은 외부 도메인
    요청까지 표적 사이트의 엔드포인트로 섞여 들어간다. katana 쪽
    _normalize_route()가 netloc을 소문자로 맞춰서 같은 origin인지 보는
    것과 같은 기준을 쓴다(호스트명은 대소문자를 구분하지 않으므로).

    상태코드로 거르지는 않는다. 401/403/404도 실제로 관찰된 엔드포인트고,
    특히 401은 "여기는 인증이 필요하다"는 신호라 정찰 입장에서 버릴 이유가
    없다. 정적 파일 제외는 merge_and_normalize()가 is_excluded 플래그로
    따로 처리한다.
    """
    want_netloc = None
    if base_url:
        want_netloc = urlparse(base_url).netloc.lower()

    results: list[dict] = []
    for flow in flows:
        method = flow.get("method")
        path = flow.get("path")
        if not method or not path:
            continue

        if want_netloc is not None:
            host = (flow.get("host") or "").lower()
            port = flow.get("port")
            # 프록시 기록에는 host와 port가 따로 있으므로 base_url의 netloc
            # 형태(host[:port])로 다시 붙여서 비교한다. 기본 포트(80/443)는
            # URL에서 생략되는 게 보통이라 두 형태를 모두 허용한다.
            candidates = {host, f"{host}:{port}"} if port else {host}
            if want_netloc not in candidates:
                continue

        results.append(
            {
                "method": method,
                "path": path or "/",
                "content_type": flow.get("content_type"),
                "source": "mitmproxy",
            }
        )
    return results


AUTH_HEADER_KEYS = ("authorization", "x-auth-token", "x-api-key")

# example_value에 남길 최대 길이. 값 자체가 목적이 아니라 "어떤 모양인지"를
# 보려는 칸이라 길면 잘라 둔다.
MAX_EXAMPLE_LEN = 200


def looks_authenticated(
    flow: dict, *, authenticated_after: float | None = None
) -> bool:
    """이 flow를 '인증된 요청'으로 볼지 판단한다. (위 TODO 1의 답)

    두 가지 신호를 순서대로 본다.

    1. 인증 헤더가 붙어 있으면 인증된 것으로 본다. mitm_addon.py가 헤더
       '값'만 가리고 키는 남기기 때문에 여기서 존재 여부를 볼 수 있다.
       Juice Shop처럼 JWT를 localStorage에 두고 Authorization 헤더로
       보내는 방식이 여기 해당한다.
    2. authenticated_after(로그인 완료 시각)를 주면 그 이후 flow도 인증된
       것으로 본다. 쿠키 기반 사이트를 위한 보완책이다 - 쿠키 헤더는 값이
       가려져 있어서 세션 쿠키인지 그냥 추적 쿠키인지 구분할 수 없고,
       Cookie 헤더의 존재 자체는 비로그인 상태에서도 흔해서 그것만으로는
       신호가 못 된다.

    시각 기준만 쓰지 않은 이유: 이미 세션을 들고 재방문하는 경우 로그인
    과정이 없어서 기준 시각 자체가 안 잡힌다. 헤더 신호는 그때도 잡힌다.
    """
    headers = {
        str(k).lower(): v for k, v in (flow.get("request_headers") or {}).items()
    }
    if any(key in headers for key in AUTH_HEADER_KEYS):
        return True

    if authenticated_after is not None:
        timestamp = flow.get("timestamp")
        if isinstance(timestamp, (int, float)) and timestamp >= authenticated_after:
            return True

    return False


def ingest_flows_to_db(
    conn,
    *,
    origin_id: str,
    session_id: str | None,
    flows: list[dict],
    base_url: str | None = None,
    authenticated_after: float | None = None,
) -> int:
    """원본 flow를 http_exchanges에 감사 기록으로 남기고, 넣은 건수를 돌려준다.

    base_url을 주면 그 origin의 flow만 넣는다. http_exchanges.origin_id는
    origins 테이블을 가리키는 외래키라서, 프록시가 같이 본 외부 도메인
    트래픽까지 넣으면 표적 사이트가 보낸 요청인 것처럼 기록이 남는다.

    body는 넣지 않는다 - insert_http_exchange()가 애초에 body 인자를 받지
    않고, mitm_addon.py도 body를 읽지 않는다.
    """
    want_netloc = urlparse(base_url).netloc.lower() if base_url else None

    inserted = 0
    for flow in flows:
        method = flow.get("method")
        path = flow.get("path")
        if not method or not path:
            continue

        if want_netloc is not None:
            host = (flow.get("host") or "").lower()
            port = flow.get("port")
            candidates = {host, f"{host}:{port}"} if port else {host}
            if want_netloc not in candidates:
                continue

        headers = flow.get("request_headers")
        dbmod.insert_http_exchange(
            conn,
            origin_id=origin_id,
            session_id=session_id,
            method=method,
            path=path,
            query_string=flow.get("query_string"),
            # TEXT 컬럼이라 dict를 그대로 못 넣는다. 헤더 값은 mitm_addon.py
            # 단계에서 이미 마스킹돼 있으므로 여기서 다시 가릴 필요는 없다.
            request_headers=(
                json.dumps(headers, ensure_ascii=False) if headers else None
            ),
            status_code=flow.get("status_code"),
            content_type=flow.get("content_type"),
            response_size=flow.get("response_size"),
            is_authenticated=looks_authenticated(
                flow, authenticated_after=authenticated_after
            ),
        )
        inserted += 1
    return inserted


def _guess_data_type(value: str) -> str:
    """값의 겉모양으로 타입을 추정한다. 공격 단계에서 페이로드 형태를
    고를 때 쓰는 힌트라 정확할 필요는 없고 일관되면 된다."""
    if value.isdigit():
        return "integer"
    if len(value) >= 8 and all(c in "0123456789abcdefABCDEF-" for c in value):
        return "uuid_or_hash"
    if value.lower() in ("true", "false"):
        return "boolean"
    return "string"


def extract_parameters(flow: dict) -> list[dict]:
    """flow 하나에서 파라미터를 뽑는다.

    두 군데를 본다.

    - query string: `?q=apple&page=2` -> name=q, name=page (location="query")
    - path 식별자: `/rest/basket/1` -> name=basket (location="path")

    body는 보지 않는다. mitm_addon.py가 애초에 body를 안 읽기 때문이다
    (로그인 토큰·입력값이 그대로 박히는 걸 막으려는 기존 정책).

    path 식별자는 judgment.PARAM_PATTERN이 `/:id`로 바꾸는 그 자리를
    그대로 쓴다. 이름은 바로 앞 세그먼트에서 따온다 - `/users/123`이면
    `users`. REST 경로가 보통 `컬렉션/식별자` 형태라 이렇게 하면 사람이
    읽을 수 있는 이름이 나오고, 앞 세그먼트가 없으면 위치 번호로 대체한다.
    """
    params: list[dict] = []

    query_string = flow.get("query_string")
    if query_string:
        for name, value in parse_qsl(query_string, keep_blank_values=True):
            params.append(
                {
                    "name": name,
                    "location": "query",
                    "data_type": _guess_data_type(value) if value else None,
                    "example_value": value[:MAX_EXAMPLE_LEN] or None,
                    "is_identifier": False,
                }
            )

    path = flow.get("path") or ""
    segments = [s for s in path.split("/") if s]
    used_names: set[str] = set()
    for index, segment in enumerate(segments):
        if not PARAM_PATTERN.fullmatch("/" + segment):
            continue
        name = segments[index - 1] if index > 0 else f"id{index}"
        # 한 경로에 식별자가 여러 개면 이름이 겹칠 수 있다. parameters의
        # UNIQUE(endpoint_id, name, location) 때문에 겹치면 뒤엣것이 조용히
        # 묻히므로 위치를 붙여 구분한다.
        if name in used_names:
            name = f"{name}_{index}"
        used_names.add(name)
        params.append(
            {
                "name": name,
                "location": "path",
                "data_type": _guess_data_type(segment),
                "example_value": segment[:MAX_EXAMPLE_LEN],
                "is_identifier": True,
            }
        )

    return params


def _assess_auth_required(flows: list[dict]) -> bool | None:
    """같은 엔드포인트에 오간 flow들을 보고 인증이 필요한 자리인지 판단한다.

    - 401/403을 한 번이라도 받았으면 인증이 필요한 자리로 본다. 서버가
      직접 그렇게 답한 것이라 가장 확실한 근거다.
    - 인증 없이 2xx가 나온 적이 있으면 인증이 필요 없는 자리로 본다.
    - 둘 다 아니면(예: 항상 인증을 달고 성공했다) 판단하지 않고 None을
      돌려준다. 인증을 달고 성공한 것만으로는 '인증 없이는 안 되는지'를
      알 수 없기 때문이다. endpoints.auth_required가 NULL을 허용하므로
      '모름'을 그대로 남긴다.
    """
    for flow in flows:
        if flow.get("status_code") in (401, 403):
            return True
    for flow in flows:
        status = flow.get("status_code")
        if isinstance(status, int) and 200 <= status < 300:
            if not looks_authenticated(flow):
                return False
    return None


def ingest_endpoints_and_parameters(
    conn,
    *,
    origin_id: str,
    flows: list[dict],
    base_url: str | None = None,
) -> tuple[int, int]:
    """관찰한 flow로 endpoints와 parameters 테이블을 채운다.
    (엔드포인트 수, 파라미터 수)를 돌려준다.

    docs/recon-status.md에 "auth_required, parameters 테이블 - 둘 다
    비어있다"고 적힌 두 칸을 여기서 채운다. katana/ffuf는 URL 문자열만
    다뤄서 실제 요청 헤더나 파라미터를 모르지만, 프록시는 요청 원본을
    보기 때문에 둘 다 알 수 있다.

    같은 엔드포인트로 묶는 기준은 (method, normalized_path)로,
    upsert_endpoint()가 쓰는 것과 같다. `/rest/basket/1`과
    `/rest/basket/2`는 한 엔드포인트로 합쳐지고 식별자만 파라미터로 남는다.
    """
    want_netloc = urlparse(base_url).netloc.lower() if base_url else None

    grouped: dict[tuple[str, str], list[dict]] = {}
    for flow in flows:
        method = flow.get("method")
        path = flow.get("path")
        if not method or not path:
            continue
        if want_netloc is not None:
            host = (flow.get("host") or "").lower()
            port = flow.get("port")
            candidates = {host, f"{host}:{port}"} if port else {host}
            if want_netloc not in candidates:
                continue
        grouped.setdefault((method, normalize_path(path)), []).append(flow)

    endpoint_count = 0
    parameter_count = 0
    for (method, norm_path), group in grouped.items():
        first = group[0]
        excluded = is_static_asset(first["path"])
        endpoint_id = dbmod.upsert_endpoint(
            conn,
            origin_id=origin_id,
            method=method,
            path=first["path"],
            normalized_path=norm_path,
            content_type=first.get("content_type"),
            auth_required=_assess_auth_required(group),
            source_tool="mitmproxy",
            is_excluded=excluded,
            exclude_reason="static_asset" if excluded else None,
        )
        endpoint_count += 1

        # 같은 엔드포인트에 온 요청 전체에서 파라미터를 모은다. 어떤 요청은
        # ?page=2를 달고 어떤 요청은 안 달고 오기 때문에, 첫 건만 보면
        # 파라미터를 놓친다.
        for flow in group:
            for param in extract_parameters(flow):
                dbmod.upsert_parameter(conn, endpoint_id=endpoint_id, **param)
                parameter_count += 1

    return endpoint_count, parameter_count
