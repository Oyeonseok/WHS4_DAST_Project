"""API SECONDARY DISCOVERY

1차 Endpoint Discovery 결과를 기반으로:

1. OpenAPI 후보 탐색
2. 실제 OpenAPI Specification인지 확인
3. GraphQL 후보 탐색
4. 실제 GraphQL Endpoint인지 확인
5. GraphQL Introspection 가능 여부 확인

확인된 경우:

OpenAPI
    -> OWASP ZAP OpenAPI Support

GraphQL
    -> OWASP ZAP GraphQL Support

를 이용하여 2차 API Discovery를 수행한다.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


# =========================================================
# Candidate Paths
# =========================================================

OPENAPI_COMMON_PATHS = {
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",

    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",

    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",

    "/swagger/v1/swagger.json",
}


GRAPHQL_COMMON_PATHS = {
    "/graphql",
    "/api/graphql",
    "/gql",
}


# =========================================================
# HTTP
# =========================================================

def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 5.0,
) -> tuple[int | None, dict[str, str], bytes]:

    request_headers = {
        "User-Agent": "aidast-recon/0.1",
    }

    if headers:
        request_headers.update(headers)

    request = Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )

    try:

        with urlopen(
            request,
            timeout=timeout,
        ) as response:

            return (
                response.status,
                dict(response.headers.items()),
                response.read(2_000_000),
            )

    except HTTPError as exc:

        data = (
            exc.read(2_000_000)
            if exc.fp
            else b""
        )

        return (
            exc.code,
            dict(exc.headers.items())
            if exc.headers
            else {},
            data,
        )

    except URLError:

        return (
            None,
            {},
            b"",
        )


# =========================================================
# Same Origin
# =========================================================

def _effective_port(parsed) -> int | None:

    if parsed.port is not None:
        return parsed.port

    if parsed.scheme == "http":
        return 80

    if parsed.scheme == "https":
        return 443

    return None


def _same_origin(
    url: str,
    base_url: str,
) -> bool:

    try:

        a = urlparse(url)
        b = urlparse(base_url)

        return (
            a.scheme.lower()
            == b.scheme.lower()

            and
            (a.hostname or "").lower()
            == (b.hostname or "").lower()

            and
            _effective_port(a)
            == _effective_port(b)
        )

    except ValueError:

        return False


# =========================================================
# OpenAPI Candidate
# =========================================================

def _build_openapi_candidates(
    base_url: str,
    endpoints: list[dict],
) -> list[str]:

    candidates: set[str] = set()

    # ---------------------------------------------
    # 일반적인 OpenAPI 위치
    # ---------------------------------------------

    for path in OPENAPI_COMMON_PATHS:

        candidates.add(
            urljoin(
                base_url.rstrip("/") + "/",
                path.lstrip("/"),
            )
        )

    # ---------------------------------------------
    # Katana / ffuf가 발견한 결과 활용
    # ---------------------------------------------

    for endpoint in endpoints:

        path = endpoint.get("path")

        if not path:
            continue

        lower = path.lower()

        if (
            "swagger" in lower
            or "openapi" in lower
            or "api-docs" in lower
        ):

            candidates.add(
                urljoin(
                    base_url.rstrip("/") + "/",
                    path.lstrip("/"),
                )
            )

    return sorted(candidates)


# =========================================================
# OpenAPI Detection
# =========================================================

def _looks_like_openapi(
    body: bytes,
) -> bool:

    if not body:
        return False

    text = body.decode(
        "utf-8",
        errors="replace",
    )

    # ---------------------------------------------
    # JSON
    # ---------------------------------------------

    try:

        payload = json.loads(text)

        if isinstance(payload, dict):

            has_version = (
                "openapi" in payload
                or "swagger" in payload
            )

            has_paths = isinstance(
                payload.get("paths"),
                dict,
            )

            if has_version and has_paths:
                return True

    except json.JSONDecodeError:
        pass

    # ---------------------------------------------
    # YAML
    #
    # YAML parser dependency 없이
    # 최소 signature만 확인
    # ---------------------------------------------

    lowered = text.lower()

    has_version = (
        "\nopenapi:" in "\n" + lowered
        or "\nswagger:" in "\n" + lowered
    )

    has_paths = (
        "\npaths:" in "\n" + lowered
    )

    return (
        has_version
        and has_paths
    )


def detect_openapi(
    base_url: str,
    endpoints: list[dict],
    *,
    headers: dict[str, str] | None = None,
) -> list[str]:

    found: list[str] = []

    candidates = (
        _build_openapi_candidates(
            base_url,
            endpoints,
        )
    )

    print(
        f"  OpenAPI 후보: "
        f"{len(candidates)}개"
    )

    for url in candidates:

        if not _same_origin(
            url,
            base_url,
        ):
            continue

        status, _, body = (
            _http_request(
                url,
                headers=headers,
            )
        )

        if status is None:
            continue

        if _looks_like_openapi(body):

            print(
                f"  [OpenAPI 확인] {url}"
            )

            found.append(url)

    return found


# =========================================================
# GraphQL Candidate
# =========================================================

def _build_graphql_candidates(
    base_url: str,
    endpoints: list[dict],
) -> list[str]:

    candidates: set[str] = set()

    # ---------------------------------------------
    # 일반적인 GraphQL Endpoint
    # ---------------------------------------------

    for path in GRAPHQL_COMMON_PATHS:

        candidates.add(
            urljoin(
                base_url.rstrip("/") + "/",
                path.lstrip("/"),
            )
        )

    # ---------------------------------------------
    # 1차 Discovery 결과
    # ---------------------------------------------

    for endpoint in endpoints:

        path = endpoint.get("path")

        if not path:
            continue

        lower = path.lower()

        if (
            "graphql" in lower
            or lower.endswith("/gql")
        ):

            candidates.add(
                urljoin(
                    base_url.rstrip("/") + "/",
                    path.lstrip("/"),
                )
            )

    return sorted(candidates)


# =========================================================
# GraphQL Detection
# =========================================================

def _graphql_request(
    url: str,
    query: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict | None:

    payload = json.dumps(
        {
            "query": query,
        }
    ).encode("utf-8")

    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if headers:
        request_headers.update(headers)

    status, _, body = _http_request(
        url,
        method="POST",
        headers=request_headers,
        body=payload,
    )

    if status is None:
        return None

    try:

        result = json.loads(
            body.decode(
                "utf-8",
                errors="replace",
            )
        )

    except json.JSONDecodeError:

        return None

    if not isinstance(result, dict):
        return None

    return result


def _confirm_graphql(
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> bool:
    """
    GraphQL 자체인지 확인한다.

    Full introspection보다 가벼운 __typename 사용.
    """

    result = _graphql_request(
        url,
        """
        query AIDASTProbe {
            __typename
        }
        """,
        headers=headers,
    )

    if result is None:
        return False

    # GraphQL 응답은 일반적으로
    # data 또는 errors를 최상위에 가진다.
    return (
        "data" in result
        or "errors" in result
    )


def _graphql_introspection_enabled(
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> bool:

    result = _graphql_request(
        url,
        """
        query AIDASTIntrospectionProbe {
            __schema {
                queryType {
                    name
                }
                mutationType {
                    name
                }
            }
        }
        """,
        headers=headers,
    )

    if not result:
        return False

    data = result.get("data")

    if not isinstance(data, dict):
        return False

    return (
        isinstance(
            data.get("__schema"),
            dict,
        )
    )


def detect_graphql(
    base_url: str,
    endpoints: list[dict],
    *,
    headers: dict[str, str] | None = None,
) -> list[dict]:

    found: list[dict] = []

    candidates = (
        _build_graphql_candidates(
            base_url,
            endpoints,
        )
    )

    print(
        f"  GraphQL 후보: "
        f"{len(candidates)}개"
    )

    for url in candidates:

        if not _same_origin(
            url,
            base_url,
        ):
            continue

        if not _confirm_graphql(
            url,
            headers=headers,
        ):
            continue

        introspection = (
            _graphql_introspection_enabled(
                url,
                headers=headers,
            )
        )

        print(
            f"  [GraphQL 확인] {url} "
            f"(introspection={introspection})"
        )

        found.append(
            {
                "url": url,
                "introspection_enabled": introspection,
            }
        )

    return found


# =========================================================
# YAML 문자열 helper
# =========================================================

def _yaml_string(
    value: str,
) -> str:
    """
    JSON string literal은 YAML에서도
    정상적인 quoted scalar로 사용할 수 있다.
    """

    return json.dumps(value)


# =========================================================
# ZAP Automation Plan
# =========================================================

def _create_zap_plan(
    *,
    base_url: str,
    output_har: Path,
    openapi_urls: list[str] | None = None,
    graphql_urls: list[str] | None = None,
    max_messages: int = 300,
) -> str:

    openapi_urls = openapi_urls or []
    graphql_urls = graphql_urls or []

    lines = [
        "env:",
        "  contexts:",
        '    - name: "target"',
        "      urls:",
        f"        - {_yaml_string(base_url)}",
        "",
        "jobs:",
    ]

    # =====================================================
    # OpenAPI
    # =====================================================

    for api_url in openapi_urls:

        lines.extend(
            [
                "  - type: openapi",
                "    parameters:",
                f"      apiUrl: {_yaml_string(api_url)}",
                f"      targetUrl: {_yaml_string(base_url)}",
                '      context: "target"',
                f"      maxMessages: {max_messages}",
            ]
        )

    # =====================================================
    # GraphQL
    # =====================================================

    for endpoint in graphql_urls:

        lines.extend(
            [
                "  - type: graphql",
                "    parameters:",
                f"      endpoint: {_yaml_string(endpoint)}",

                # Schema에서 Query 자동 생성
                "      queryGenEnabled: true",

                # 지나치게 큰 Query 생성을 방지
                "      maxQueryDepth: 5",
                "      maxArgsDepth: 3",

                # 한 Query에 너무 많이 묶지 않도록
                "      querySplitType: root_field",

                # 일반적인 JSON POST
                "      requestMethod: post_json",

                f"      maxMessages: {max_messages}",
            ]
        )

    # =====================================================
    # HAR Export
    # =====================================================

    lines.extend(
        [
            "  - type: export",
            "    parameters:",
            '      context: "target"',
            '      type: "har"',
            '      source: "all"',
            f"      fileName: "
            f"{_yaml_string(str(output_har))}",
        ]
    )

    return "\n".join(lines) + "\n"


# =========================================================
# ZAP 실행
# =========================================================

def _run_zap(
    plan_path: Path,
    *,
    zap_executable: str = "zap.sh",
    timeout: int = 300,
) -> bool:

    command = [
        zap_executable,
        "-cmd",
        "-autorun",
        str(plan_path),
    ]

    try:

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except (
        subprocess.TimeoutExpired,
        OSError,
    ) as exc:

        print(
            f"  [경고] ZAP 실행 실패: {exc}"
        )

        return False

    # ZAP Automation Framework:
    #
    # 0 = 성공
    # 1 = error
    # 2 = warning
    #
    # Warning은 결과 자체가 생성됐을 수도 있으므로
    # 실패로 취급하지 않는다.

    if completed.returncode not in (
        0,
        2,
    ):

        print(
            "  [경고] ZAP Automation 실패"
        )

        if completed.stderr:

            print(
                completed.stderr[
                    :1000
                ]
            )

        return False

    if completed.returncode == 2:

        print(
            "  [ZAP] 경고가 있었지만 "
            "Discovery 결과는 계속 사용"
        )

    return True


# =========================================================
# HAR -> Endpoint
# =========================================================

def _parse_zap_har(
    har_path: Path,
    *,
    base_url: str,
    source: str,
) -> list[dict]:

    if not har_path.exists():
        return []

    try:

        payload = json.loads(
            har_path.read_text(
                encoding="utf-8",
            )
        )

    except (
        json.JSONDecodeError,
        OSError,
    ):

        return []

    results: list[dict] = []

    entries = (
        payload
        .get("log", {})
        .get("entries", [])
    )

    for entry in entries:

        request = entry.get(
            "request",
            {},
        )

        method = request.get(
            "method",
            "GET",
        ).upper()

        url = request.get("url")

        if not url:
            continue

        if not _same_origin(
            url,
            base_url,
        ):
            continue

        parsed = urlparse(url)

        path = (
            parsed.path
            or "/"
        )

        results.append(
            {
                "method": method,
                "path": path,
                "content_type": None,
                "source": source,
            }
        )

    return results


# =========================================================
# Deduplicate
# =========================================================

def _deduplicate(
    results: list[dict],
) -> list[dict]:

    unique: dict[
        tuple[str, str],
        dict,
    ] = {}

    for result in results:

        method = (
            result
            .get("method", "GET")
            .upper()
        )

        path = result.get("path")

        if not path:
            continue

        key = (
            method,
            path,
        )

        if key not in unique:

            unique[key] = dict(result)

    return list(
        unique.values()
    )


# =========================================================
# Secondary API Discovery
# =========================================================

def discover_api_secondary(
    base_url: str,
    endpoints: list[dict],
    *,
    headers: dict[str, str] | None = None,
    zap_executable: str = "zap.sh",
    max_messages: int = 300,
) -> list[dict]:
    """
    API 2차 Discovery.

    1. OpenAPI 판단
    2. GraphQL 판단
    3. 해당되는 ZAP Add-on 실행
    4. ZAP이 생성한 요청을 Endpoint로 변환
    """

    print()
    print(
        "  =================================="
    )

    print(
        "  API Secondary Discovery"
    )

    print(
        "  =================================="
    )

    # =====================================================
    # Detect OpenAPI
    # =====================================================

    openapi_urls = detect_openapi(
        base_url,
        endpoints,
        headers=headers,
    )

    # =====================================================
    # Detect GraphQL
    # =====================================================

    graphql_info = detect_graphql(
        base_url,
        endpoints,
        headers=headers,
    )

    # ZAP이 endpoint만 가지고 introspection 할 수 있는
    # GraphQL만 2차 Query Generation 대상으로 사용
    graphql_urls = [
        item["url"]
        for item in graphql_info
        if item[
            "introspection_enabled"
        ]
    ]

    if not openapi_urls:
        print(
            "  OpenAPI 확인되지 않음"
        )

    if not graphql_info:
        print(
            "  GraphQL 확인되지 않음"
        )

    # GraphQL이 존재하지만 introspection이 막혀있음
    for item in graphql_info:

        if not item[
            "introspection_enabled"
        ]:

            print(
                "  [GraphQL] "
                f"{item['url']} "
                "introspection 비활성화 "
                "-> Schema 없이 Deep Discovery 생략"
            )

    if (
        not openapi_urls
        and not graphql_urls
    ):

        print(
            "  API 2차 Discovery 대상 없음"
        )

        return []

    results: list[dict] = []

    # =====================================================
    # Temporary Directory
    # =====================================================

    with tempfile.TemporaryDirectory() as tmp:

        tmp_dir = Path(tmp)

        # =================================================
        # OpenAPI
        #
        # GraphQL과 별도로 실행해서
        # source를 구분한다.
        # =================================================

        if openapi_urls:

            print()
            print(
                "  [ZAP] OpenAPI 2차 Discovery"
            )

            openapi_har = (
                tmp_dir
                / "openapi.har"
            )

            openapi_plan = (
                tmp_dir
                / "openapi.yaml"
            )

            plan_text = (
                _create_zap_plan(
                    base_url=base_url,
                    output_har=openapi_har,
                    openapi_urls=openapi_urls,
                    max_messages=max_messages,
                )
            )

            openapi_plan.write_text(
                plan_text,
                encoding="utf-8",
            )

            if _run_zap(
                openapi_plan,
                zap_executable=zap_executable,
            ):

                openapi_results = (
                    _parse_zap_har(
                        openapi_har,
                        base_url=base_url,
                        source="zap_openapi",
                    )
                )

                print(
                    f"  ZAP OpenAPI 발견: "
                    f"{len(openapi_results)}건"
                )

                results.extend(
                    openapi_results
                )

        # =================================================
        # GraphQL
        # =================================================

        if graphql_urls:

            print()
            print(
                "  [ZAP] GraphQL 2차 Discovery"
            )

            graphql_har = (
                tmp_dir
                / "graphql.har"
            )

            graphql_plan = (
                tmp_dir
                / "graphql.yaml"
            )

            plan_text = (
                _create_zap_plan(
                    base_url=base_url,
                    output_har=graphql_har,
                    graphql_urls=graphql_urls,
                    max_messages=max_messages,
                )
            )

            graphql_plan.write_text(
                plan_text,
                encoding="utf-8",
            )

            if _run_zap(
                graphql_plan,
                zap_executable=zap_executable,
            ):

                graphql_results = (
                    _parse_zap_har(
                        graphql_har,
                        base_url=base_url,
                        source="zap_graphql",
                    )
                )

                print(
                    f"  ZAP GraphQL 발견: "
                    f"{len(graphql_results)}건"
                )

                results.extend(
                    graphql_results
                )

    # =====================================================
    # Final Deduplication
    # =====================================================

    unique = _deduplicate(
        results
    )

    print()
    print(
        f"  API Secondary Raw: "
        f"{len(results)}건"
    )

    print(
        f"  API Secondary Unique: "
        f"{len(unique)}건"
    )

    return unique