"""Recover literal GET declarations without depending on whole-spec validation."""
from itertools import islice
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit
from .observed_parameters import field_key, scalar
from .request_identity import sensitive_field


def _origin(url):
    p = urlsplit(url)
    return p.scheme.lower(), (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)


def _safe_url(url, base_url, *, allow_query=False):
    try:
        p = urlsplit(url)
        return (p.scheme in {"http", "https"} and not p.username and not p.password
                and (allow_query or not p.query) and not p.fragment and _origin(url) == _origin(base_url)
                and not any(c in url for c in "{}\\\r\n\t"))
    except ValueError:
        return False


def _servers(document, path_item, operation, document_url):
    if document.get("swagger") == "2.0":
        parsed = urlsplit(document_url)
        host = document.get("host", parsed.netloc)
        path = document.get("basePath", "/")
        schemes = operation.get("schemes", document.get("schemes", [parsed.scheme]))
        if not isinstance(host, str) or not isinstance(path, str) or not path.startswith("/") or not isinstance(schemes, list):
            return []
        return [f"{scheme}://{host}{path}" for scheme in schemes[:5]
                if isinstance(scheme, str) and scheme in {"http", "https"}]
    servers = operation.get("servers", path_item.get("servers", document.get("servers", [])))
    if not isinstance(servers, list):
        return []
    if not servers:
        servers = [{"url": "/"}]
    urls = []
    for server in servers[:5]:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            continue
        try:
            urls.append(urljoin(document_url, server["url"]))
        except ValueError:
            continue
    return urls


def declared_get_candidates(document: dict, *, document_url: str, base_url: str,
                            target_policy=None, limit: int = 100, observed_values=None) -> list[dict]:
    if (not isinstance(document, dict)
            or not (str(document.get("openapi", "")).startswith("3.") or document.get("swagger") == "2.0")
            or not isinstance(document.get("paths"), dict)):
        return []
    results, seen = [], set()
    for path, item in islice(document["paths"].items(), 500):
        if not isinstance(path, str) or not isinstance(item, dict) or "$ref" in item:
            continue
        decoded = unquote(path)
        if (not path.startswith("/") or path.startswith("//")
                or any(c in decoded for c in "{}?#\\\r\n\t")
                or any(segment in {".", ".."} for segment in decoded.split("/"))):
            continue
        operation = item.get("get")
        if not isinstance(operation, dict) or "$ref" in operation:
            continue
        # Do not invent required parameter values or resolve remote references.
        parameters = [item.get("parameters", []), operation.get("parameters", [])]
        if any(not isinstance(group, list) or any(not isinstance(p, dict) or "$ref" in p
               for p in group) for group in parameters):
            continue
        query, unresolved = [], False
        # Schema examples/defaults describe types; they are not observations.
        merged = {}
        for group in parameters:
            for parameter in group:
                merged[(parameter.get('in'), parameter.get('name'))] = parameter
        for parameter in merged.values():
            if parameter.get('required') is not True:
                continue
            name = parameter.get('name')
            values = (observed_values or {}).get(name, []) if isinstance(name, str) else []
            if not values and isinstance(name, str):
                values = (observed_values or {}).get(field_key(name), [])
            if (not isinstance(name, str) or sensitive_field(name)
                    or parameter.get('in') != 'query' or not isinstance(values, (list, tuple))
                    or len(values) != 1 or scalar(values[0]) is None
                    or parameter.get('style', 'form') != 'form'
                    or parameter.get('content') is not None):
                unresolved = True
                break
            query.append((name, str(values[0])))
        if unresolved:
            continue
        try:
            servers = _servers(document, item, operation, document_url)
        except ValueError:
            continue
        for server in servers:
            if not _safe_url(server, base_url):
                continue
            url = server.rstrip("/") + path
            if query:
                url += '?' + urlencode(query, quote_via=quote)
            if (not _safe_url(url, base_url, allow_query=True) or url in seen
                    or (target_policy is not None and not target_policy.allows_url(url, method="GET"))):
                continue
            seen.add(url)
            results.append({"method": "GET", "url": url, "path": urlsplit(url).path,
                            "source": "openapi_get_fallback", "discovery_kind": "api_spec_candidate",
                            "verification_status": "candidate",
                            "evidence": {"parent_url": document_url, "seed_paths": [path]}})
            if len(results) >= max(1, limit):
                return results
    return results
