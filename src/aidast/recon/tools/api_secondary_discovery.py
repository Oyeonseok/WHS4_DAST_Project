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
import hashlib
import re
import shutil
import subprocess
import tempfile
from collections import deque
from itertools import islice
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.recon.policy import TargetPolicy
from aidast.recon.verification import successful_response
from aidast.recon.tools.js_api_paths import extract_js_api_paths, extract_js_module_references, literal_call_method
from aidast.recon.tools.js_argument_bindings import extract_response_argument_bindings, bind_response_values
from aidast.recon.tools.js_fetch_bindings import extract_fetch_response_bindings
from aidast.recon.tools.html_scripts import declared_script_urls
from aidast.recon.tools.openapi_get import declared_get_candidates
from .observed_parameters import bind_dom_gets, observed_named_values
from .request_identity import authentication_key, has_authentication, credential_values
from .js_evidence import DocumentScripts
from .adaptive_state import AdaptiveDiscoveryState


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


@dataclass(frozen=True)
class OpenAPIDefinition:
    url: str | None = None
    document: dict | None = None
    document_url: str | None = None


class _SwaggerInitScripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        source = dict(attrs).get("src")
        if source:
            try:
                if urlparse(source).path.rsplit("/", 1)[-1] == "swagger-ui-init.js":
                    self.sources.append(source)
            except ValueError:
                pass


GRAPHQL_COMMON_PATHS = {
    "/graphql",
    "/api/graphql",
    "/gql",
}

ADAPTIVE_API_THRESHOLD = 10
ADAPTIVE_MAX_SCRIPTS = 40
ADAPTIVE_MAX_SCRIPT_BYTES = 20_000_000
ADAPTIVE_MAX_CANDIDATES = 100
ADAPTIVE_MAX_EXTRACTED_CANDIDATES = 500
ADAPTIVE_MAX_DETAIL_PROBES = 20
MAX_CANDIDATE_GET_PROBES = 20
_JS_API_PATH = re.compile(
    r"(?P<quote>[\"'`])(?P<path>/(?:api|rest)(?:/[^\"'`\\\s?#]{0,160})?)(?P=quote)",
    re.IGNORECASE,
)
_POLICY_BLOCK_BODY = b"Blocked by AI-DAST TargetPolicy\n"


# =========================================================
# HTTP
# =========================================================

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _RequiredProxy(ProxyHandler):
    """Do not let ambient NO_PROXY silently bypass the enforcement proxy."""

    def proxy_open(self, req, proxy, type):
        parsed = urlparse(proxy)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("invalid policy proxy configuration")
        original_type = req.type
        req.set_proxy(parsed.netloc, parsed.scheme)
        if original_type != parsed.scheme and original_type != "https":
            return self.parent.open(req, timeout=req.timeout)
        return None


def _request_broker(target_policy: TargetPolicy, proxy_url: str | None) -> RequestBroker:
    opener = build_opener(
        _RequiredProxy({"http": proxy_url, "https": proxy_url}) if proxy_url else ProxyHandler({}),
        _NoRedirect(),
    )
    # The required proxy owns accounting for the physical hop. Reserving here
    # as well would charge twice and self-block at shared concurrency one.
    return RequestBroker(target_policy, transport=opener.open, max_body_bytes=2_000_000,
                         governor_owner="transport" if proxy_url else "broker")


def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 5.0,
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
) -> tuple[int | None, dict[str, str], bytes]:

    if target_policy is None or not target_policy.allows_url(url, method=method):
        return (None, {}, b"")

    request_headers = {
        "User-Agent": "aidast-recon/0.1",
    }

    if headers:
        request_headers.update(headers)

    try:
        active_broker = broker or _request_broker(target_policy, proxy_url)
        if active_broker.policy != target_policy:
            raise RequestPolicyError("request broker policy mismatch")
        response = active_broker.request(
            url, method=method, headers=request_headers, data=body,
            timeout=min(timeout, target_policy.limits.timeout_seconds),
        )
        return response.status_code, response.headers, response.body

    except (URLError, RequestPolicyError, TimeoutError, ValueError):

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


def _swagger_ui_document(
    page_url: str,
    page_body: bytes,
    *,
    headers: dict[str, str] | None,
    target_policy: TargetPolicy | None,
    proxy_url: str | None,
    broker: RequestBroker | None,
) -> dict | None:
    """Read the JSON document embedded by swagger-ui-express, without running JS."""
    parser = _SwaggerInitScripts()
    parser.feed(page_body.decode("utf-8", errors="replace"))
    page_path = urlparse(page_url).path.lower()
    relative_base = (
        page_url if page_path.endswith((".html", ".htm"))
        else page_url.rstrip("/") + "/"
    )
    for source in parser.sources[:3]:
        try:
            script_url = urljoin(relative_base, source)
        except ValueError:
            continue
        if not _same_origin(script_url, page_url):
            continue
        if target_policy is not None and not target_policy.allows_url(script_url, method="GET"):
            continue
        status, _, body = _http_request(
            script_url, headers=headers,
            timeout=(target_policy.limits.timeout_seconds if target_policy else 5.0),
            target_policy=target_policy, proxy_url=proxy_url, broker=broker,
        )
        if status != 200:
            continue
        text = body.decode("utf-8", errors="replace")
        match = re.search(r"\bvar\s+options\s*=\s*", text)
        if match is None:
            continue
        try:
            options, _ = json.JSONDecoder().raw_decode(text[match.end():].lstrip())
        except json.JSONDecodeError:
            continue
        document = options.get("swaggerDoc") if isinstance(options, dict) else None
        if isinstance(document, dict) and _looks_like_openapi(json.dumps(document).encode()):
            return document
    return None


def _openapi_server_url(
    document: dict, base_url: str, target_policy: TargetPolicy | None,
    *, document_url: str | None = None,
) -> str:
    servers = document.get("servers")
    server_url = None
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_url = servers[0].get("url")
    elif document.get("swagger") and isinstance(document.get("basePath"), str):
        server_url = document["basePath"]
    if not isinstance(server_url, str):
        return urljoin(base_url, "/") if document_url else base_url
    try:
        candidate = urljoin(document_url or base_url.rstrip("/") + "/", server_url)
        parsed = urlparse(candidate)
    except ValueError:
        return base_url
    if (parsed.username or parsed.password or parsed.query or parsed.fragment
            or not _same_origin(candidate, base_url)):
        return base_url
    if target_policy is not None and not target_policy.allows_url(candidate, method="GET"):
        return base_url
    return candidate


def detect_openapi(
    base_url: str,
    endpoints: list[dict],
    *,
    headers: dict[str, str] | None = None,
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
) -> list[OpenAPIDefinition]:

    found: list[OpenAPIDefinition] = []
    if broker is None and target_policy is not None:
        broker = _request_broker(target_policy, proxy_url)

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
        if target_policy is not None and not target_policy.allows_url(url, method="GET"):
            continue

        status, _, body = (
            _http_request(
                url,
                headers=headers,
                timeout=(target_policy.limits.timeout_seconds if target_policy else 5.0),
                target_policy=target_policy,
                proxy_url=proxy_url,
                broker=broker,
            )
        )

        if status is None:
            continue

        if _looks_like_openapi(body):

            print(
                f"  [OpenAPI 확인] {url}"
            )

            found.append(OpenAPIDefinition(url=url))
            continue

        if status == 200:
            document = _swagger_ui_document(
                url, body, headers=headers, target_policy=target_policy,
                proxy_url=proxy_url, broker=broker,
            )
            if document is not None:
                print(f"  [OpenAPI 확인] {url} (Swagger UI 내장 명세)")
                found.append(OpenAPIDefinition(document=document, document_url=url))

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
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
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
        timeout=(target_policy.limits.timeout_seconds if target_policy else 5.0),
        target_policy=target_policy,
        proxy_url=proxy_url,
        broker=broker,
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
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
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
        target_policy=target_policy,
        proxy_url=proxy_url,
        broker=broker,
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
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
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
        target_policy=target_policy,
        proxy_url=proxy_url,
        broker=broker,
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
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
) -> list[dict]:

    found: list[dict] = []
    if broker is None and target_policy is not None:
        broker = _request_broker(target_policy, proxy_url)

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
        if target_policy is not None and not target_policy.allows_graphql_probe_url(url):
            print(f"  [GraphQL 건너뜀] 정책에서 능동 probe 경로를 허용하지 않음: {url}")
            continue

        if not _confirm_graphql(
            url,
            headers=headers,
            target_policy=target_policy,
            proxy_url=proxy_url,
            broker=broker,
        ):
            continue

        introspection = (
            _graphql_introspection_enabled(
                url,
                headers=headers,
                target_policy=target_policy,
                proxy_url=proxy_url,
                broker=broker,
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
    openapi_files: list[tuple[Path, str]] | None = None,
    graphql_urls: list[str] | None = None,
    max_messages: int = 300,
    headers: dict[str, str] | None = None,
) -> str:

    openapi_urls = openapi_urls or []
    openapi_files = openapi_files or []
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

    if headers:
        parsed = urlparse(base_url)
        # Exact origin including port; credentials must never follow another
        # server declared by a specification or an external redirect.
        # ZAP uses Matcher.matches(), not a prefix search. Consume the path
        # while retaining the slash boundary after the exact authority.
        origin_pattern = '^' + re.escape(f'{parsed.scheme}://{parsed.netloc}') + r'(?:/.*)?$'
        lines.extend(['  - type: replacer', '    rules:'])
        for name, value in headers.items():
            if (not re.fullmatch(r'[A-Za-z0-9-]+', name)
                    or any(c in str(value) for c in '\r\n')):
                continue
            lines.extend([
                f'      - description: {_yaml_string("recon " + name)}',
                f'        url: {_yaml_string(origin_pattern)}',
                '        matchType: req_header',
                f'        matchString: {_yaml_string(name)}',
                '        matchRegex: false',
                f'        replacementString: {_yaml_string(str(value))}',
            ])

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

    for api_file, target_url in openapi_files:
        lines.extend(
            [
                "  - type: openapi",
                "    parameters:",
                f"      apiFile: {_yaml_string(str(api_file))}",
                f"      targetUrl: {_yaml_string(target_url)}",
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
    proxy_url: str | None = None,
) -> bool:

    command = [
        zap_executable,
        "-cmd",
        "-autorun",
        str(plan_path),
    ]
    if proxy_url is not None:
        proxy = urlparse(proxy_url)
        if proxy.scheme not in {"http", "https"} or not proxy.hostname or not proxy.port:
            raise ValueError(f"invalid policy proxy URL: {proxy_url}")
        command.extend(
            [
                "-config", "connection.proxyChain.enabled=true",
                "-config", f"connection.proxyChain.hostName={proxy.hostname}",
                "-config", f"connection.proxyChain.port={proxy.port}",
            ]
        )

    try:

        # Replacer parameters are persisted in ZAP's config and INFO log.
        # Isolate both, including proxy state and credentials, per invocation.
        # Preserve installed addon versions without copying user config/history.
        with tempfile.TemporaryDirectory(prefix='aidast-zap-profile-') as private:
            profile = Path(private)
            for existing in (Path.home() / 'Library/Application Support/ZAP',
                             Path.home() / '.ZAP', Path.home() / 'AppData/Roaming/ZAP'):
                packages = existing / 'plugin'
                if not packages.is_dir():
                    continue
                destination = profile / 'plugin'
                destination.mkdir(mode=0o700)
                for package in packages.glob('*.zap'):
                    if package.is_file():
                        shutil.copy2(package, destination / package.name)
                break
            command.extend(['-dir', str(profile)])
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

        # Tool stderr may contain a serialized request or replacer secret.

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
    target_policy: TargetPolicy | None = None,
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
        if target_policy is not None and not target_policy.allows_url(
            url, method=method
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
                "url": url,
                "content_type": None,
                "source": source,
                "discovery_kind": "api_spec_candidate",
                "verification_status": "candidate",
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
            result.get("url") or path,
        )

        if key not in unique:

            unique[key] = dict(result)

    return list(
        unique.values()
    )


# =========================================================
# Secondary API Discovery
# =========================================================

def _fingerprint(
    status: int | None, headers: dict[str, str], body: bytes, *, request_url: str = "",
) -> tuple:
    if request_url:
        # Missing-route handlers often reflect the requested URL in a 200
        # JSON response. Compare response templates, not just exact bytes.
        normalized = body.decode("utf-8", errors="replace")
        normalized = normalized.replace(request_url, "{requested_url}")
        normalized = normalized.replace(urlparse(request_url).path, "{requested_path}")
        body = normalized.encode("utf-8")
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"), ""
    ).split(";", 1)[0].strip().lower()
    return status, content_type, len(body), hashlib.sha256(body).hexdigest()


def _media_type(headers: dict[str, str]) -> str:
    return next(
        (value for key, value in headers.items() if key.lower() == "content-type"), ""
    ).split(";", 1)[0].strip().lower()


def _looks_like_html_body(body: bytes) -> bool:
    """Recognize an HTML document after whitespace, comments or XML headers."""
    cursor = 3 if body.startswith(b'\xef\xbb\xbf') else 0
    while cursor < len(body):
        while cursor < len(body) and body[cursor] in b' \t\r\n\f\v':
            cursor += 1
        if body.startswith(b'<!--', cursor):
            end = body.find(b'-->', cursor + 4)
            if end < 0:
                return False
            cursor = end + 3
        elif body.startswith(b'<?xml', cursor):
            end = body.find(b'?>', cursor + 5)
            if end < 0:
                return False
            cursor = end + 2
        else:
            break
    return bool(re.match(rb'(?:<!doctype\s+html\b|<html\b|<head\b|<body\b|<script\b)',
                         body[cursor:cursor + 64], re.I))


def _positive_json_response(status: int | None, headers: dict[str, str], body: bytes) -> bool:
    if not successful_response(status):
        return False
    media_type = _media_type(headers)
    if media_type != "application/json" and not media_type.endswith("+json"):
        return False
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return False
    if isinstance(payload, dict):
        if payload.get("error") or payload.get("errors"):
            return False
        if str(payload.get("status", "")).lower() in {"error", "fail", "failed"}:
            return False
        if set(payload) <= {"message", "status", "code"}:
            return False
    return isinstance(payload, (dict, list))


def _same_authentication(record, headers):
    key = record.get('authentication_key')
    if key is None and isinstance(record.get('request_headers'), dict):
        key = authentication_key(record['request_headers'])
    return key == authentication_key(headers) if key is not None else not has_authentication(headers)


def _observed_documents(responses, base_url, target_policy):
    documents = []
    for record in islice(responses, 150):
        if not isinstance(record, dict):
            continue
        url, body = record.get('url'), record.get('response_body')
        if (record.get('method') != 'GET' or record.get('capture_bodies') is not True
                or record.get('policy_blocked') or type(record.get('response_status')) is not int
                or not successful_response(record['response_status'])
                or not isinstance(record.get('response_headers'), dict)
                or _media_type(record['response_headers']) not in {'text/html', 'application/xhtml+xml'}
                or not isinstance(url, str) or not _same_origin(url, base_url)
                or not isinstance(body, (str, bytes)) or len(body) > 2_000_000
                or (target_policy is not None and not target_policy.allows_url(url, method='GET'))):
            continue
        documents.append((url, body.decode('utf-8', errors='replace') if isinstance(body, bytes) else body))
    return documents


def _verify_get_candidates(
    candidates: list[dict], *, base_url: str,
    target_policy: TargetPolicy | None, headers: dict[str, str] | None,
    broker: RequestBroker | None, proxy_url: str | None,
    max_probes: int = MAX_CANDIDATE_GET_PROBES,
    captured_responses: dict | None = None,
    request_fn=None,
) -> list[dict]:
    """Probe a bounded set of spec candidates using GET and a sibling missing-route control."""
    if target_policy is None or not proxy_url or max_probes <= 0:
        return candidates
    request = request_fn or _http_request

    def retained(item: dict, reason: str, status: int | None = None,
                 response_headers: dict[str, str] | None = None) -> dict:
        result = dict(item)
        evidence = dict(item.get("evidence") or {})
        evidence["verification_reason"] = reason
        if status is not None:
            evidence["response_status"] = status
        if response_headers:
            evidence["content_type"] = next(
                (value for key, value in response_headers.items()
                 if key.lower() == "content-type"), "",
            )
        result["evidence"] = evidence
        return result

    results: list[dict] = []
    controls: dict[str, tuple[int | None, dict[str, str], bytes]] = {}
    probe_headers = dict(headers or {})
    probe_headers["X-AIDAST-Phase"] = "candidate_probe"
    attempted = 0
    for item in candidates:
        url = item.get("url")
        if item.get("verification_status") != "candidate":
            results.append(item)
            continue
        if str(item.get("method", "GET")).upper() != "GET":
            results.append(retained(item, "non_get_method"))
            continue
        if (not isinstance(url, str) or not _same_origin(url, base_url)
                or not target_policy.allows_url(url, method="GET")):
            results.append(retained(item, "out_of_scope"))
            continue
        if attempted >= max_probes:
            results.append(retained(item, "probe_limit"))
            continue
        parsed = urlparse(url)
        parent = parsed.path.rpartition("/")[0]
        control_url = parsed._replace(
            path=parent + "/__aidast_missing_control__", query="", fragment="",
        ).geturl()
        if not target_policy.allows_url(control_url, method="GET"):
            results.append(retained(item, "control_out_of_scope"))
            continue
        attempted += 1
        if control_url not in controls:
            controls[control_url] = request(
                control_url, headers=probe_headers, target_policy=target_policy,
                proxy_url=proxy_url, broker=broker,
            )
        control_status, control_headers, control_body = controls[control_url]
        if (control_status is None or control_status >= 500
                or (control_status == 403 and control_body == _POLICY_BLOCK_BODY)):
            results.append(retained(item, "control_unavailable"))
            continue
        if captured_responses is not None and url in captured_responses:
            status, response_headers, body = captured_responses[url]
        else:
            status, response_headers, body = request(
                url, headers=probe_headers, target_policy=target_policy,
                proxy_url=proxy_url, broker=broker,
            )
        if not _positive_json_response(status, response_headers, body):
            results.append(retained(item, "non_positive_json", status, response_headers))
            continue
        if (_fingerprint(status, response_headers, body, request_url=url)
                == _fingerprint(control_status, control_headers, control_body,
                                request_url=control_url)):
            results.append(retained(item, "fallback_match", status, response_headers))
            continue
        verified = dict(item)
        verified["verification_status"] = "verified"
        verified["discovery_kind"] = "api_get_verified"
        verified["content_type"] = next(
            (value for key, value in response_headers.items() if key.lower() == "content-type"), None,
        )
        verified["evidence"] = dict(item.get("evidence") or {}, response_status=status)
        results.append(verified)
    return results


def recover_observed_json_gets(
    base_url: str, endpoints: list[dict], *, observed_responses=(),
    headers: dict[str, str] | None = None, target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None, broker: RequestBroker | None = None,
    max_probes: int = MAX_CANDIDATE_GET_PROBES,
    state: AdaptiveDiscoveryState | None = None,
) -> list[dict]:
    """Associate positive captured GETs only after a missing-route control check."""
    if target_policy is None or not proxy_url or max_probes <= 0:
        return []
    from aidast.core.http_safety import merge_hackerone_identity
    headers = merge_hackerone_identity(headers, target_policy.hackerone_username,
                                      required_identity_headers=target_policy.required_identity_headers)
    known = {urljoin(base_url, str(item.get("url") or item.get("path") or ""))
             for item in endpoints if str(item.get("method", "GET")).upper() == "GET"
             and item.get("verification_status") != "candidate"}
    captured = {}
    candidates = []
    for record in islice(observed_responses, 150):
        if not isinstance(record, dict):
            continue
        url, body = record.get("url"), record.get("response_body")
        status, response_headers = record.get("response_status"), record.get("response_headers")
        if (record.get("method") != "GET" or record.get("capture_bodies") is not True
                or any(record.get(flag) for flag in ("policy_blocked", "candidate_probe", "static_resource", "duplicate"))
                or not _same_authentication(record, headers)
                or not isinstance(url, str) or url in known or url in captured
                or not _same_origin(url, base_url) or not target_policy.allows_url(url, method="GET")
                or not isinstance(body, (str, bytes)) or len(body) > 2_000_000
                or not isinstance(status, int) or isinstance(status, bool)
                or not isinstance(response_headers, dict)):
            continue
        body = body.encode("utf-8") if isinstance(body, str) else body
        if not _positive_json_response(status, response_headers, body):
            continue
        captured[url] = (status, response_headers, body)
        candidates.append(dict(method="GET", path=urlparse(url).path or "/", url=url,
                               source="observed_json_recovery", discovery_kind="api_spec_candidate",
                               verification_status="candidate", evidence={"captured_response": True}))
    if broker is None:
        broker = _request_broker(target_policy, proxy_url)
    return _verify_get_candidates(candidates, base_url=base_url, target_policy=target_policy,
                                  headers=headers, broker=broker, proxy_url=proxy_url,
                                  max_probes=max_probes, captured_responses=captured,
                                  request_fn=(lambda url, **options: state.request(_http_request, url, **options))
                                  if state is not None else None)


def _collection_detail_url(
    collection_url: str,
    status: int,
    response_headers: dict[str, str],
    body: bytes,
    target_policy: TargetPolicy | None,
) -> str | None:
    """Use one literal item ID from a successful /api collection response."""
    segments = urlparse(collection_url).path.strip("/").split("/")
    if (len(segments) != 2 or segments[0].lower() != "api"
            or not _positive_json_response(status, response_headers, body)):
        return None
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    items = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return None
    item_id = next((str(item["id"]) for item in items
                    if isinstance(item, dict)
                    and isinstance(item.get("id"), (int, str))
                    and not isinstance(item["id"], bool)
                    and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(item["id"]))), None)
    if item_id is None:
        return None
    parsed = urlparse(collection_url)
    detail_url = parsed._replace(path=parsed.path.rstrip("/") + "/" + item_id,
                                 query="", fragment="").geturl()
    if target_policy is not None and not target_policy.allows_url(detail_url, method="GET"):
        return None
    return detail_url


def _verified_collection_detail(
    detail_url: str,
    collection_url: str,
    status: int | None,
    response_headers: dict[str, str],
    body: bytes,
    *,
    missing_control: tuple[int, dict[str, str], bytes, str] | None = None,
) -> dict | None:
    """Verify matching IDs; retain distinct denied probes as observed only."""
    if status in {401, 403} and body != _POLICY_BLOCK_BODY and missing_control is not None:
        control_status, control_headers, control_body, control_url = missing_control
        detail_path = urlparse(detail_url).path
        collection_path = urlparse(collection_url).path.rstrip("/")
        if (not _same_origin(detail_url, collection_url)
                or not detail_path.startswith(collection_path + "/")):
            return None
        candidate_fp = _fingerprint(status, response_headers, body, request_url=detail_url)
        control_fp = _fingerprint(control_status, control_headers, control_body, request_url=control_url)
        if candidate_fp == control_fp or (control_status >= 500 and candidate_fp[1:] == control_fp[1:]):
            return None
        return {
            "method": "GET", "path": urlparse(detail_url).path, "url": detail_url,
            "source": "adaptive_collection_detail", "discovery_kind": "collection_detail_access_denied",
            "verification_status": "observed", "content_type": _media_type(response_headers),
            "evidence": {"response_status": status, "collection_url": collection_url,
                         "access_status": "authentication_required" if status == 401 else "forbidden",
                         "verification_reason": "observed_id_access_denied", "control_status": control_status},
        }
    if not _positive_json_response(status, response_headers, body):
        return None
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    item = payload.get("data", payload) if isinstance(payload, dict) else None
    item_id = item.get("id") if isinstance(item, dict) else None
    if (not isinstance(item_id, (int, str)) or isinstance(item_id, bool)
            or str(item_id) != detail_url.rsplit("/", 1)[-1]):
        return None
    return {
        "method": "GET", "path": urlparse(detail_url).path, "url": detail_url,
        "source": "adaptive_collection_detail", "discovery_kind": "collection_detail",
        "content_type": next((value for key, value in response_headers.items()
                              if key.lower() == "content-type"), None),
        "evidence": {"response_status": status, "collection_url": collection_url},
    }


_literal_call_method = literal_call_method


def _bind_collection_template(template: str, collection_detail_url: str) -> str | None:
    """Bind one complete path segment using an ID from the same named resource."""
    match = re.fullmatch(r"/(?:api|rest)/(?P<resource>[^/]+)/\$\{[\w.$]+\}(?P<suffix>(?:/[^{}?#]*)?)", template, re.I)
    segments = urlparse(collection_detail_url).path.strip("/").split("/")
    if match is None or len(segments) != 3 or segments[1].casefold() != match.group("resource").casefold():
        return None
    return re.sub(r"\$\{[\w.$]+\}", segments[2], template, count=1)


def _round_robin_argument_jobs(bindings, responses, templates):
    """Give each evidenced GET template a turn before trying its next value."""
    def jobs(binding):
        seen = set()
        for source_url, payload in responses.items():
            for bound in bind_response_values(binding, source_url, payload):
                if bound not in seen:
                    seen.add(bound)
                    yield binding, source_url, bound
    pending = deque(jobs(binding) for binding in bindings if binding.template in templates)
    while pending:
        iterator = pending.popleft()
        try:
            job = next(iterator)
        except StopIteration:
            continue
        pending.append(iterator)
        yield job


@dataclass(frozen=True)
class _DetailProbeJob:
    kind: str
    url: str
    source_url: str
    template: str | None = None
    source_scripts: tuple[str, ...] = ()
    argument_field: str | None = None


def _round_robin_detail_jobs(*sources, is_ready):
    """Give distinct path templates a turn before another ID of one route."""
    source_groups = []
    for source in sources:
        grouped = {}
        for job in source:
            path = urlparse(job.template or job.url).path
            if job.kind == 'collection':
                path = path.rpartition('/')[0] + '/${item}'
            key = re.sub(r'\$\{[^{}]+\}', '{value}', path)
            grouped.setdefault(key, deque()).append(job)
        source_groups.append(iter(grouped.items()))
    pending = deque(source_groups)
    groups = {}
    while pending:
        iterator = pending.popleft()
        for key, jobs in iterator:
            groups.setdefault(key, deque()).extend(jobs)
            pending.append(iterator)
            break
    pending = deque(groups.values())
    while pending:
        jobs = pending.popleft()
        while jobs:
            job = jobs.popleft()
            if is_ready(job):
                if jobs:
                    pending.append(jobs)
                yield job
                break


def discover_adaptive_js_api_candidates(
    base_url: str,
    endpoints: list[dict],
    *,
    headers: dict[str, str] | None = None,
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    broker: RequestBroker | None = None,
    diagnostic_callback=None,
    api_threshold: int = ADAPTIVE_API_THRESHOLD,
    max_scripts: int = ADAPTIVE_MAX_SCRIPTS,
    max_script_bytes: int = ADAPTIVE_MAX_SCRIPT_BYTES,
    max_candidates: int = ADAPTIVE_MAX_CANDIDATES,
    observed_responses=(),
    ai_pattern_planner=None,
    state: AdaptiveDiscoveryState | None = None,
) -> list[dict]:
    """Check bounded first-party JS GET candidates absent from observed traffic."""
    if target_policy is not None and not proxy_url:
        raise ValueError("adaptive JS discovery requires a policy proxy")
    if target_policy is not None:
        from aidast.core.http_safety import merge_hackerone_identity
        headers = merge_hackerone_identity(headers, target_policy.hackerone_username,
                                          required_identity_headers=target_policy.required_identity_headers)
    observed_get_urls = {
        urlparse(urljoin(base_url, str(item.get("url") or item.get("path") or "")))
        ._replace(fragment="").geturl()
        for item in endpoints if str(item.get("method") or "GET").upper() == "GET"
    }

    scripts: list[str] = []
    script_limit = max(1, int(max_scripts))
    retained_scripts = state.parsed_scripts(headers) if state is not None else {}
    # The allowance applies to new work, independently of retained modules.
    selection_limit = script_limit + len(retained_scripts)
    # Materialize once: captured documents and collection binding share this
    # bounded input, including callers providing a generator.
    observed_responses = list(islice(observed_responses, 150))
    if state is not None:
        state.observe(observed_responses, headers)
        observed_responses = state.observations(headers)
        if not state.begin(endpoints, headers):
            return []

    def request(url, **options):
        return state.request(_http_request, url, **options) if state is not None else _http_request(url, **options)
    # Surface paths do not prove success with these credentials and values.
    successful_observed_urls = {
        record['url'] for record in observed_responses
        if isinstance(record, dict) and isinstance(record.get('url'), str)
        and type(record.get('response_status')) is int and successful_response(record['response_status'])
        and _same_authentication(record, headers)
    }
    if not has_authentication(headers):
        failed_urls = {r.get('url') for r in observed_responses if isinstance(r, dict)
                       and type(r.get('response_status')) is int and not successful_response(r['response_status'])}
        successful_observed_urls.update(observed_get_urls - failed_urls)
    document_scripts = 0
    binding_documents = []
    dom_documents = []
    inline_sources = {}
    for record in observed_responses:
        if not isinstance(record, dict):
            continue
        url, body = record.get("url"), record.get("response_body")
        status, response_headers = record.get("response_status"), record.get("response_headers")
        if (record.get("method") != "GET" or record.get("capture_bodies") is not True
                or record.get("policy_blocked") or not isinstance(url, str)
                or not isinstance(body, (str, bytes)) or len(body) > 2_000_000
                or not isinstance(status, int) or isinstance(status, bool)
                or not successful_response(status) or not isinstance(response_headers, dict)
                or _media_type(response_headers) not in {"text/html", "application/xhtml+xml"}
                or not _same_origin(url, base_url)
                or urlparse(url)._replace(fragment="").geturl() not in observed_get_urls
                or (target_policy is not None and not target_policy.allows_url(url, method="GET"))):
            continue
        text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        binding_documents.append(text)
        dom_documents.append((url, text))
        for candidate in declared_script_urls(text, url):
            if len(scripts) >= selection_limit:
                break
            if (_same_origin(candidate, base_url) and candidate not in scripts
                    and (target_policy is None or target_policy.allows_url(candidate, method="GET"))):
                scripts.append(candidate)
                document_scripts += 1
        document = DocumentScripts(include_event_handlers=False)
        document.feed(text)
        for index, item in enumerate(document.items):
            source_url = url + f'#inline-dom-{index}'
            inline_sources[source_url] = item['text']
    for item in endpoints:
        if len(scripts) >= selection_limit:
            break
        path = str(item.get("path") or "")
        candidate = str(item.get("url") or urljoin(base_url, path))
        parsed = urlparse(candidate)
        if not parsed.path.lower().endswith((".js", ".mjs")) or parsed.username or parsed.password:
            continue
        if (_same_origin(candidate, base_url) and candidate not in scripts
                and (target_policy is None or target_policy.allows_url(candidate, method="GET"))):
            scripts.append(candidate)
    for source_url in inline_sources:
        if len(scripts) >= selection_limit:
            break
        scripts.append(source_url)
    if state is not None:
        state.prune_inline_scripts({url for url, text in dom_documents}, inline_sources, headers)
        retained_scripts = state.parsed_scripts(headers)
        new_scripts = [url for url in scripts if url not in retained_scripts][:script_limit]
        scripts = list(retained_scripts) + new_scripts
    if not scripts and not (ai_pattern_planner is not None and binding_documents):
        return []

    if broker is None and target_policy is not None:
        broker = _request_broker(target_policy, proxy_url)

    candidates: dict[str, int] = {}
    candidate_scripts: dict[str, list[str]] = {}
    templates: set[str] = set()
    template_scripts: dict[str, list[str]] = {}
    analyzed_source: dict[str, str] = {}
    attempted_scripts = 0
    initial_script_requests = state.request_count if state is not None else 0
    analyzed_scripts = 0
    analyzed_bytes = 0
    module_references = 0
    suppressed_modules = 0
    byte_limit_reached = False
    script_byte_limit = max(0, int(max_script_bytes))
    new_script_count = len([url for url in scripts if url not in retained_scripts])
    while attempted_scripts < len(scripts) and analyzed_bytes < script_byte_limit:
        script_url = scripts[attempted_scripts]
        attempted_scripts += 1
        cached = retained_scripts.get(script_url)
        if cached is not None:
            # Parsed code survives transport-cache eviction. A newer observed
            # body invalidates the parsed version without another HTTP request.
            newer = state.responses.get(('GET', script_url, authentication_key(headers)))
            if ((script_url in inline_sources and inline_sources[script_url] != cached[0])
                    or (newer is not None and newer[2].decode('utf-8', errors='replace') != cached[0])):
                cached = None
        if cached is not None:
            script, module_paths, api_paths = cached
            status, script_headers, body = 200, {'content-type': 'application/javascript'}, script.encode()
        elif script_url in inline_sources:
            status, script_headers, body = 200, {'content-type': 'application/javascript'}, inline_sources[script_url].encode()
        else:
            status, script_headers, body = request(
                script_url, headers=headers, target_policy=target_policy,
                proxy_url=proxy_url, broker=broker, timeout=5.0,
            )
        if not successful_response(status) or not body or _media_type(script_headers) not in {
            "application/javascript", "text/javascript", "application/ecmascript",
            "text/ecmascript", "application/x-javascript", "text/plain",
        }:
            continue
        if re.match(rb'\s*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b|<script\b)',
                    body.removeprefix(b'\xef\xbb\xbf')[:1024], re.I):
            continue
        if cached is None and analyzed_bytes + len(body) > script_byte_limit:
            byte_limit_reached = True
            break
        if cached is None:
            analyzed_bytes += len(body)
        analyzed_scripts += 1
        if cached is not None:
            pass
        elif state is None:
            script = body.decode("utf-8", errors="replace")
            module_paths = extract_js_module_references(script)
            api_paths = extract_js_api_paths(script, _literal_call_method)
        else:
            script, module_paths, api_paths = state.script(script_url, body, headers, lambda text: (
                extract_js_module_references(text), extract_js_api_paths(text, _literal_call_method)))
        analyzed_source[script_url] = script
        for reference in module_paths:
            module_url = urlparse(urljoin(script_url, reference))._replace(fragment="").geturl()
            if (not _same_origin(module_url, base_url)
                    or (target_policy is not None and not target_policy.allows_url(module_url, method="GET"))):
                continue
            if module_url in scripts:
                continue
            module_references += 1
            if new_script_count >= script_limit:
                suppressed_modules += 1
                continue
            scripts.append(module_url)
            new_script_count += 1
        if diagnostic_callback is not None:
            diagnostic_callback("js_module_analyzed", component="adaptive_js",
                                script_path=urlparse(script_url).path, body_bytes=len(body))
        if script_url in inline_sources:
            # Use inline code for grounded parameter bindings. Static inline
            # discovery keeps its existing AI scheduling and verification.
            for path, method in api_paths:
                if method == 'GET' and '${' in path and len(templates) < ADAPTIVE_MAX_EXTRACTED_CANDIDATES:
                    templates.add(path)
                    template_scripts.setdefault(path, []).append(script_url)
            continue
        for path, method in api_paths:
            if method not in {None, "GET"}:
                continue
            if "{" in path or "}" in path:
                if method == "GET" and len(templates) < ADAPTIVE_MAX_EXTRACTED_CANDIDATES:
                    templates.add(path)
                    template_scripts.setdefault(path, []).append(script_url)
                continue
            candidate_url = urljoin(base_url, path)
            if urlparse(candidate_url)._replace(fragment="").geturl() in successful_observed_urls:
                continue
            rank = 0 if method == "GET" else 1
            candidates[candidate_url] = min(rank, candidates.get(candidate_url, rank))
            sources = candidate_scripts.setdefault(candidate_url, [])
            if script_url not in sources:
                sources.append(script_url)
            if len(candidates) > ADAPTIVE_MAX_EXTRACTED_CANDIDATES:
                # Retain explicit GET evidence even when another bundle filled
                # the bounded pool with unclassified string literals.
                worst = max(candidates, key=lambda url: (candidates[url], url))
                del candidates[worst]
                candidate_scripts.pop(worst, None)
    script_requests = state.request_count - initial_script_requests if state is not None else attempted_scripts
    selected_candidates = sorted(candidates, key=lambda url: (candidates[url], url))[
        :max(1, int(max_candidates))
    ]
    argument_bindings = extract_response_argument_bindings(analyzed_source)
    fetch_bindings = extract_fetch_response_bindings(analyzed_source, documents=binding_documents)
    argument_bindings.extend(binding for binding in fetch_bindings if binding not in argument_bindings)
    argument_source_paths = {urlparse(binding.source_path).path.rstrip('/') for binding in argument_bindings}
    argument_responses: dict[str, object] = {}

    def remember_argument_response(url, status, response_headers, body):
        if (urlparse(url).path.rstrip('/') in argument_source_paths
                and len(argument_responses) < 100
                and _positive_json_response(status, response_headers, body)):
            argument_responses[url] = json.loads(body)

    controls: dict[str, tuple[int, dict[str, str], bytes, str]] = {}
    for prefix in ("/api", "/rest"):
        control_url = urljoin(base_url, prefix + "/__aidast_missing_control__")
        status, response_headers, body = request(
            control_url, headers=headers, target_policy=target_policy,
            proxy_url=proxy_url, broker=broker, timeout=5.0,
        )
        if status is not None and not (status == 403 and body == _POLICY_BLOCK_BODY):
            controls[prefix] = (status, response_headers, body, control_url)

    results: list[dict] = []
    unverified_count = 0
    detail_probes = state.detail_probes if state is not None else 0
    detail_probes_by_source = {"collection": 0, "template": 0, "response_argument": 0}
    detail_duplicates_skipped = 0
    detail_response_reuses = 0
    detail_control_probes = 0
    detail_controls_suppressed = 0
    collection_jobs: list[_DetailProbeJob] = []
    detail_responses: dict[str, tuple[int | None, dict[str, str], bytes]] = {}
    collection_details: dict[str, str] = {}
    probed_urls = set(successful_observed_urls)
    observed_details: dict[str, str] = {}
    fetched_response_urls: set[str] = set()
    for record in observed_responses:
        if not isinstance(record, dict):
            continue
        url = record.get("url")
        status = record.get("response_status")
        body = record.get("response_body")
        response_headers = record.get("response_headers")
        if (record.get("method") != "GET" or record.get("policy_blocked")
                or record.get("capture_bodies") is not True
                or not isinstance(url, str) or not _same_origin(url, base_url)
                or not isinstance(status, int) or isinstance(status, bool)
                or not isinstance(response_headers, dict)
                or not isinstance(body, (str, bytes)) or len(body) > 2_000_000):
            continue
        if target_policy is not None and not target_policy.allows_url(url, method="GET"):
            continue
        response_body = body.encode() if isinstance(body, str) else body
        if not _same_authentication(record, headers):
            continue
        detail_responses[url] = (status, response_headers, response_body)
        remember_argument_response(url, status, response_headers, response_body)
        detail = _collection_detail_url(url, status, response_headers,
                                        body.encode() if isinstance(body, str) else body,
                                        target_policy)
        if detail is not None:
            resource = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1].casefold()
            observed_details.setdefault(resource, detail)
            collection_details.setdefault(resource, detail)
    for url in selected_candidates:
        if not _same_origin(url, base_url):
            continue
        if target_policy is not None and not target_policy.allows_url(url, method="GET"):
            continue
        probed_urls.add(url)
        status, response_headers, body = request(
            url, headers=headers, target_policy=target_policy,
            proxy_url=proxy_url, broker=broker, timeout=5.0,
        )
        detail_responses[url] = (status, response_headers, body)
        fetched_response_urls.add(url)
        if status is None or status == 404 or status >= 500:
            continue
        if body == _POLICY_BLOCK_BODY:
            continue
        content_type = _media_type(response_headers)
        if content_type == "text/html":
            continue
        path = urlparse(url).path
        prefix = next((p for p in ("/api", "/rest")
                       if path.lower() == p or path.lower().startswith(p + "/")), None)
        if prefix is None:
            if _looks_like_html_body(body):
                continue
            prefix = path.rpartition("/")[0] or "/"
            if prefix not in controls:
                control_url = urljoin(base_url, prefix.rstrip("/") + "/__aidast_missing_control__")
                if target_policy is None or target_policy.allows_url(control_url, method="GET"):
                    control_status, control_headers, control_body = request(
                        control_url, headers=headers, target_policy=target_policy,
                        proxy_url=proxy_url, broker=broker, timeout=5.0,
                    )
                    if control_status is not None and control_body != _POLICY_BLOCK_BODY:
                        controls[prefix] = (control_status, control_headers, control_body, control_url)
        if prefix not in controls:
            unverified_count += 1
            continue
        control_status, control_headers, control_body, control_url = controls[prefix]
        candidate_fingerprint = _fingerprint(
            status, response_headers, body, request_url=url,
        )
        control_fingerprint = _fingerprint(
            control_status, control_headers, control_body, request_url=control_url,
        )
        if control_status >= 500:
            # An explicit first-party GET call plus a distinct access-denied
            # response is useful route evidence even when the missing-route
            # handler is broken. Preserve it as observed, never verified.
            restricted_get = status in {401, 403} and candidates[url] == 0
            if not (200 <= status < 300 or restricted_get):
                unverified_count += 1
                continue
            if candidate_fingerprint[1:] == control_fingerprint[1:]:
                continue
        elif candidate_fingerprint == control_fingerprint:
            continue
        evidence = {"response_status": status, "source_scripts": candidate_scripts[url]}
        if status in {401, 403}:
            evidence.update(
                access_status="authentication_required" if status == 401 else "forbidden",
                verification_reason="explicit_get_access_denied" if candidates[url] == 0 else "distinct_access_denied",
                control_status=control_status,
            )
        results.append({
            "method": "GET", "path": urlparse(url).path or "/", "url": url,
            "source": "adaptive_js", "discovery_kind": "js_api_candidate",
            "content_type": next((v for k, v in response_headers.items() if k.lower() == "content-type"), None),
            "evidence": evidence,
        })
        remember_argument_response(url, status, response_headers, body)

        # Probe one real item per collection within the global request cap.
        detail_url = _collection_detail_url(
            url, status, response_headers, body, target_policy,
        )
        if detail_url is None:
            continue
        resource = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1].casefold()
        collection_details.setdefault(resource, detail_url)
        collection_jobs.append(_DetailProbeJob("collection", detail_url, url))
    for detail_url in observed_details.values():
        collection_url = detail_url.rpartition("/")[0]
        collection_jobs.append(_DetailProbeJob("collection", detail_url, collection_url))
    template_controls: dict[str, tuple[int | None, dict[str, str], bytes]] = {}
    template_jobs: list[_DetailProbeJob] = []
    for template in sorted(templates):
        if not re.match(r'/\b(?:api|rest)/[^/]+/', template, re.I):
            continue
        resource = template.strip("/").split("/")[1].casefold()
        detail_url = collection_details.get(resource)
        if detail_url is None:
            continue
        bound = _bind_collection_template(template, detail_url)
        if bound is None:
            continue
        template_jobs.append(_DetailProbeJob("template", urljoin(base_url, bound),
                                            detail_url.rpartition("/")[0], template,
                                            tuple(template_scripts[template])))

    def argument_jobs():
        for binding, source_url, bound in _round_robin_argument_jobs(argument_bindings, argument_responses, templates):
            yield _DetailProbeJob("response_argument", urljoin(base_url, bound), source_url,
                                  binding.template, binding.source_scripts, binding.field)
        for binding in bind_dom_gets(analyzed_source, dom_documents):
            yield _DetailProbeJob('response_argument', urljoin(base_url, binding.path),
                                 binding.document_url, binding.template, (binding.source_script,), binding.field)

    def detail_control(job):
        nonlocal detail_control_probes, detail_controls_suppressed
        parsed = urlparse(job.url)
        control_url = parsed._replace(path=parsed.path.rpartition('/')[0] + '/__aidast_missing_control__',
                                      query='', fragment='').geturl()
        if control_url not in template_controls:
            if detail_control_probes >= ADAPTIVE_MAX_DETAIL_PROBES:
                detail_controls_suppressed += 1
                return control_url, (None, {}, b"")
            detail_control_probes += 1
            template_controls[control_url] = request(
                control_url, headers=headers, target_policy=target_policy,
                proxy_url=proxy_url, broker=broker, timeout=5.0,
            )
        return control_url, template_controls[control_url]

    def retain_detail_evidence(job, response):
        status, response_headers, body = response
        if job.kind == "collection":
            detail = _verified_collection_detail(job.url, job.source_url, status, response_headers, body,
                                                 missing_control=controls.get("/api"))
            if detail is not None:
                results.append(detail)
            return
        if not _positive_json_response(status, response_headers, body):
            return
        control_url, (control_status, control_headers, control_body) = detail_control(job)
        if control_status is None or control_body == _POLICY_BLOCK_BODY:
            return
        candidate_fp = _fingerprint(status, response_headers, body, request_url=job.url)
        control_fp = _fingerprint(control_status, control_headers, control_body, request_url=control_url)
        if candidate_fp == control_fp or (control_status >= 500 and candidate_fp[1:] == control_fp[1:]):
            return
        evidence = {"response_status": status, "path_template": job.template,
                    "source_scripts": list(job.source_scripts)}
        if job.kind == "template":
            evidence["id_source"] = job.source_url
        else:
            evidence.update(argument_source=job.source_url, argument_field=job.argument_field)
        results.append({
            "method": "GET", "path": urlparse(job.url).path, "url": job.url,
            "source": "adaptive_js_template" if job.kind == "template" else "adaptive_js_response_argument",
            "discovery_kind": "js_template_bound" if job.kind == "template" else "js_response_argument_bound",
            "content_type": _media_type(response_headers), "evidence": evidence,
        })

    evidence_jobs = set()
    deferred_detail_urls = set()
    detail_route_templates = set()

    def is_ready(job):
        nonlocal detail_duplicates_skipped, detail_response_reuses
        url = job.url
        if (not _same_origin(url, base_url)
                or (target_policy is not None and not target_policy.allows_url(url, method="GET"))):
            return False
        evidence_key = (job.kind, url, job.source_url, job.template, job.argument_field)
        if evidence_key in evidence_jobs:
            detail_duplicates_skipped += 1
            return False
        evidence_jobs.add(evidence_key)
        route = urlparse(job.template or job.url).path
        if job.kind == 'collection':
            route = route.rpartition('/')[0] + '/${item}'
        detail_route_templates.add(re.sub(r'\$\{[^{}]+\}', '{value}', route))
        # Reuse transport evidence for each applicable discovery relationship.
        # Duplicate/observed jobs do not consume a slot OR their source's turn.
        if url in probed_urls:
            detail_duplicates_skipped += 1
            response = detail_responses.get(url)
            if response is not None:
                # A cached body still needs a turn if its verification would
                # issue a new control request. Only fully cached evidence is free.
                parsed = urlparse(url)
                control_url = parsed._replace(path=parsed.path.rpartition('/')[0] + '/__aidast_missing_control__',
                                              query='', fragment='').geturl()
                if (job.kind != "collection" and control_url not in template_controls
                        and _positive_json_response(*response)):
                    return True
                detail_response_reuses += 1
                retain_detail_evidence(job, response)
            return False
        if detail_probes >= ADAPTIVE_MAX_DETAIL_PROBES:
            if url not in deferred_detail_urls:
                deferred_detail_urls.add(url)
                results.append(dict(method='GET', path=urlparse(url).path, url=url,
                    source='adaptive_js_detail_candidate', discovery_kind='js_api_candidate',
                    verification_status='candidate', evidence=dict(
                        verification_reason='detail_probe_limit', path_template=job.template,
                        argument_source=job.source_url, argument_field=job.argument_field,
                        source_scripts=list(job.source_scripts))))
            return False
        return True

    argument_probes = 0
    for job in _round_robin_detail_jobs(collection_jobs, template_jobs, argument_jobs(), is_ready=is_ready):
        # A new control request spends this source's turn even when it fails.
        # Its independent cap bounds retries without charging a detail request.
        if job.kind != "collection":
            _, (control_status, _, control_body) = detail_control(job)
            if control_status is None or control_body == _POLICY_BLOCK_BODY:
                continue
        if job.url in probed_urls:
            detail_response_reuses += 1
            retain_detail_evidence(job, detail_responses[job.url])
            continue
        # Deduplicate the resolved request, not its source collection: queries
        # can produce different item IDs and retain their own responses.
        probed_urls.add(job.url)
        detail_probes += 1
        if state is not None:
            state.detail_probes = detail_probes
        detail_probes_by_source[job.kind] += 1
        argument_probes += int(job.kind == "response_argument")
        response = request(
            job.url, headers=headers, target_policy=target_policy,
            proxy_url=proxy_url, broker=broker, timeout=5.0,
        )
        detail_responses[job.url] = response
        fetched_response_urls.add(job.url)
        retain_detail_evidence(job, response)
    if ai_pattern_planner is not None and target_policy is not None and proxy_url:
        from .ai_patterns import build_pattern_evidence, resolve_pattern_plan
        try:
            # Newly fetched positive bodies join the original bounded capture
            # input; existing observed bodies retain their source and flags.
            response_rows = []
            for response_url, (status,response_headers,body) in detail_responses.items():
                if response_url in fetched_response_urls and _positive_json_response(status,response_headers,body):
                    response_rows.append(dict(method='GET',url=response_url,response_status=status,
                        response_headers=response_headers,response_body=body,capture_bodies=True))
            response_rows.extend(observed_responses)
            evidence = build_pattern_evidence(base_url,analyzed_source,response_rows,target_policy=target_policy,
                                              sensitive_values=credential_values(headers))
            if evidence.context['literals']:
                if diagnostic_callback is not None:
                    diagnostic_callback('evidence',component='ai_patterns',context=evidence.context)
                plan = ai_pattern_planner.propose(evidence.context)
                known = set(probed_urls)
                candidates, decisions = resolve_pattern_plan(evidence,plan,target_policy=target_policy,known_urls=known)
                verified = _verify_get_candidates(candidates,base_url=base_url,target_policy=target_policy,
                    headers=headers,broker=broker,proxy_url=proxy_url,captured_responses=detail_responses, request_fn=request)
                results.extend(verified)
                if diagnostic_callback is not None:
                    diagnostic_callback('completed',component='ai_patterns',plan=plan.model_dump(mode='json'),
                        decisions=decisions,candidate_count=len(candidates),
                        verified_count=sum(r.get('verification_status')=='verified' for r in verified),
                        results=verified)
            elif diagnostic_callback is not None:
                diagnostic_callback('skipped',component='ai_patterns',reason='no_eligible_evidence')
        except Exception as exc:
            if diagnostic_callback is not None:
                diagnostic_callback('phase_error',component='ai_patterns',error_type=type(exc).__name__)
    if diagnostic_callback is not None:
        diagnostic_callback(
            "completed", component="adaptive_js",
            accepted_count=len(results), unverified_count=unverified_count,
            script_requests=script_requests, analyzed_scripts=analyzed_scripts,
            document_scripts=document_scripts,
            analyzed_script_bytes=analyzed_bytes, module_references=module_references,
            suppressed_modules=suppressed_modules, byte_limit_reached=byte_limit_reached,
            script_limit=script_limit, script_byte_limit=script_byte_limit,
            extracted_templates=len(templates), response_argument_bindings=len(argument_bindings),
            fetch_response_argument_bindings=len(fetch_bindings),
            response_argument_probes=argument_probes,
            detail_probes=detail_probes, detail_probes_by_source=detail_probes_by_source,
            detail_probe_limit=ADAPTIVE_MAX_DETAIL_PROBES,
            detail_deferred_candidates=len(deferred_detail_urls),
            detail_route_templates=len(detail_route_templates),
            detail_duplicates_skipped=detail_duplicates_skipped, detail_response_reuses=detail_response_reuses,
            detail_control_probes=detail_control_probes, detail_controls_suppressed=detail_controls_suppressed,
        )
    return results


def discover_api_secondary(
    base_url: str,
    endpoints: list[dict],
    *,
    headers: dict[str, str] | None = None,
    zap_executable: str = "zap.sh",
    max_messages: int = 300,
    target_policy: TargetPolicy | None = None,
    proxy_url: str | None = None,
    diagnostic_callback=None,
    observed_responses=(),
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

    if target_policy is not None:
        if proxy_url is None:
            raise ValueError("policy-enforced API discovery requires a proxy")
        if not target_policy.allows_url(base_url, method="GET"):
            raise ValueError(f"TargetPolicy가 API base URL을 허용하지 않음: {base_url}")
        max_messages = min(max_messages, target_policy.limits.max_requests)

    def activity(event: str, phase: str, **details: object) -> None:
        if diagnostic_callback is not None:
            diagnostic_callback(event, phase=phase, **details)

    broker = _request_broker(target_policy, proxy_url) if target_policy is not None else None
    activity("phase_started", "openapi_detection")
    openapi_definitions = detect_openapi(
        base_url,
        endpoints,
        headers=headers,
        target_policy=target_policy,
        proxy_url=proxy_url,
        broker=broker,
    )
    activity("phase_completed", "openapi_detection", count=len(openapi_definitions))

    # =====================================================
    # Detect GraphQL
    # =====================================================

    activity("phase_started", "graphql_detection")
    graphql_info = detect_graphql(
        base_url,
        endpoints,
        headers=headers,
        target_policy=target_policy,
        proxy_url=proxy_url,
        broker=broker,
    )
    activity("phase_completed", "graphql_detection", count=len(graphql_info))

    # ZAP이 endpoint만 가지고 introspection 할 수 있는
    # GraphQL만 2차 Query Generation 대상으로 사용
    graphql_urls = [
        item["url"]
        for item in graphql_info
        if item[
            "introspection_enabled"
        ]
    ]

    if not openapi_definitions:
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
        not openapi_definitions
        and not graphql_urls
    ):

        print(
            "  API 2차 Discovery 대상 없음"
        )
        activity("phase_skipped", "zap_openapi")
        activity("phase_skipped", "zap_graphql")

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

        if openapi_definitions:
            activity("phase_started", "zap_openapi")

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

            observed_values = observed_named_values(
                _observed_documents(observed_responses, base_url, target_policy))
            fallback = []
            openapi_files = []
            for index, definition in enumerate(openapi_definitions[:10]):
                document = definition.document
                document_url = definition.document_url or definition.url or base_url
                if document is None and definition.url:
                    if (not _same_origin(document_url, base_url)
                            or (target_policy is not None and not target_policy.allows_url(document_url, method='GET'))):
                        continue
                    status, _, body = _http_request(document_url, headers=headers,
                        target_policy=target_policy, proxy_url=proxy_url, broker=broker)
                    if not successful_response(status) or len(body) > 2_000_000:
                        continue
                    try:
                        document = json.loads(body)
                    except (ValueError, UnicodeDecodeError):
                        continue
                fallback.extend(declared_get_candidates(document, document_url=document_url,
                    base_url=base_url, target_policy=target_policy, observed_values=observed_values))
                # ZAP imports only parameter-free, literal, allowed GETs. Its
                # generated schema examples/IDs are not observed user data.
                simple = declared_get_candidates(document, document_url=document_url,
                    base_url=base_url, target_policy=target_policy)
                paths = {urlparse(row['url']).path: {'get': {'responses': {
                    '200': {'description': 'Observed schema declares GET'}}}} for row in simple}
                if paths:
                    parsed = urlparse(base_url)
                    spec = {'openapi': '3.0.0', 'info': {'title': 'Recon GET declarations', 'version': '1'},
                            'servers': [{'url': f'{parsed.scheme}://{parsed.netloc}'}], 'paths': paths}
                    spec_path = tmp_dir / f'read-openapi-{index}.json'
                    spec_path.write_text(json.dumps(spec), encoding='utf-8')
                    spec_path.chmod(0o600)
                    openapi_files.append((spec_path, base_url))

            plan_text = (
                _create_zap_plan(
                    base_url=base_url,
                    output_har=openapi_har,
                    openapi_files=openapi_files,
                    max_messages=max_messages,
                    headers=headers,
                )
            )

            openapi_plan.write_text(
                plan_text,
                encoding="utf-8",
            )
            openapi_plan.chmod(0o600)

            if _run_zap(
                openapi_plan,
                zap_executable=zap_executable,
                proxy_url=proxy_url,
            ):

                openapi_results = (
                    _parse_zap_har(
                        openapi_har,
                        base_url=base_url,
                        source="zap_openapi",
                        target_policy=target_policy,
                    )
                )

                print(
                    f"  ZAP OpenAPI 발견: "
                    f"{len(openapi_results)}건"
                )

                results.extend(
                    openapi_results
                )
                activity("phase_completed", "zap_openapi", count=len(openapi_results))
            else:
                activity("phase_error", "zap_openapi")
            results.extend(fallback)
            activity("phase_completed", "openapi_get_fallback", count=len(fallback))
        else:
            activity("phase_skipped", "zap_openapi")

        # =================================================
        # GraphQL
        # =================================================

        if graphql_urls:
            activity("phase_started", "zap_graphql")

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
                    headers=headers,
                )
            )

            graphql_plan.write_text(
                plan_text,
                encoding="utf-8",
            )
            graphql_plan.chmod(0o600)

            if _run_zap(
                graphql_plan,
                zap_executable=zap_executable,
                proxy_url=proxy_url,
            ):

                graphql_results = (
                    _parse_zap_har(
                        graphql_har,
                        base_url=base_url,
                        source="zap_graphql",
                        target_policy=target_policy,
                    )
                )

                print(
                    f"  ZAP GraphQL 발견: "
                    f"{len(graphql_results)}건"
                )

                results.extend(
                    graphql_results
                )
                activity("phase_completed", "zap_graphql", count=len(graphql_results))
            else:
                activity("phase_error", "zap_graphql")
        else:
            activity("phase_skipped", "zap_graphql")

    # =====================================================
    # Final Deduplication
    # =====================================================

    unique = _deduplicate(
        results
    )

    activity("phase_started", "api_get_verification")
    unique = _verify_get_candidates(
        unique, base_url=base_url, target_policy=target_policy,
        headers=headers, broker=broker, proxy_url=proxy_url,
    )
    activity(
        "phase_completed", "api_get_verification",
        candidate_count=sum(item.get("verification_status") == "candidate" for item in unique),
        verified_count=sum(item.get("verification_status") == "verified" for item in unique),
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
