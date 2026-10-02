"""Inventory routes declared in captured documents, without making requests.

These records prove a declaration, not a successful endpoint response. All
records remain passive candidates, including GETs and unresolved path templates.
No code, schema references, form actions, or sitemap entries are executed here.
"""
from __future__ import annotations

import re
import hashlib
from html.parser import HTMLParser
from itertools import islice
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree
import json

from .js_api_paths import _literals, extract_js_api_paths, literal_call_method
from .openapi_get import _safe_url, _servers
from .request_identity import sensitive_field

METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
MAX_DECLARATIONS = 500
MAX_DOCUMENT_SIZE = 2 * 1024 * 1024
_SCRIPT_TYPES = frozenset({"", "module", "text/javascript", "application/javascript",
                           "text/ecmascript", "application/ecmascript"})
_NAME = re.compile(r"[A-Za-z_$][\w$.-]{0,127}\Z")
_TEMPLATE = re.compile(r"\$\{([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\}")


def _route_url(reference, *, document_url, base_url, target_policy=None):
    if (not isinstance(reference, str) or len(reference) > 2048
            or any(c.isspace() or ord(c) < 32 for c in reference)
            or "\\" in reference or reference.startswith(("${", "{"))):
        return None
    reference = _TEMPLATE.sub(lambda m: "{" + m[1].split(".")[-1] + "}", reference)
    try:
        if any(unquote(unquote(segment)) in {".", ".."} for segment in urlsplit(reference).path.split("/")):
            return None
        parsed = urlsplit(urljoin(document_url, reference))
        origin = urlsplit(base_url)
        effective_port = lambda p: p.port or (443 if p.scheme.lower() == "https" else 80)
        if (parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password
                or parsed.fragment or (parsed.scheme.lower(), (parsed.hostname or "").lower(), effective_port(parsed))
                != (origin.scheme.lower(), (origin.hostname or "").lower(), effective_port(origin))):
            return None
        path = parsed.path or "/"
        for segment in path.split("/"):
            decoded = unquote(unquote(segment))
            if decoded in {".", ".."} or any(c in decoded for c in "\\\r\n\t"):
                return None
            if any(c in segment for c in "{}$") and not re.fullmatch(r"\{[A-Za-z_$][\w$.-]{0,127}\}", segment):
                return None
            if any(c in decoded for c in "{}") and "{" not in segment:
                return None
        # A declaration contributes query names, never embedded credentials or
        # literal query values. Templates stay in paths and cannot become hosts.
        names = dict.fromkeys(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
                             if _NAME.fullmatch(name) and not sensitive_field(name))
        url = urlunsplit(parsed._replace(path=path, query=urlencode([(name, "") for name in names]), fragment=""))
        if target_policy is not None and not target_policy.allows_observed_url(url):
            return None
        return url
    except (ValueError, TypeError):
        return None


def _candidate(reference, method, *, document_url, base_url, kind, source="passive_declaration",
               target_policy=None, parameters=()):
    method = str(method or "").upper()
    if method not in METHODS:
        return None
    url = _route_url(reference, document_url=document_url, base_url=base_url, target_policy=target_policy)
    if url is None:
        return None
    path = urlsplit(url).path or "/"
    row = dict(method=method, path=path, url=url, source=source, discovery_kind=kind,
               verification_status="candidate", traffic_class="passive",
               evidence={"parent_url": document_url, "seed_paths": [path],
                         "verification_reason": "declared_route_unrequested"},
               context={"context_key": f"{source}:declaration:{document_url}",
                        "page_url": document_url, "action_type": "document_parse",
                        "association_method": "document_declaration", "auth_state": "unknown"})
    safe_parameters = []
    for parameter in islice(parameters, 100):
        if not isinstance(parameter, dict):
            continue
        name, location = parameter.get("name"), parameter.get("location")
        if (isinstance(name, str) and _NAME.fullmatch(name) and isinstance(location, str)
                and location in {"path", "query", "json", "form", "header"}):
            data_type = parameter.get("data_type")
            item = {"name": name, "location": location,
                    "data_type": data_type if isinstance(data_type, str) and data_type in {
                        "string", "integer", "number", "boolean", "array", "object"} else "string"}
            if item not in safe_parameters:
                safe_parameters.append(item)
    if safe_parameters:
        row["declared_parameters"] = safe_parameters
    return row


def _unique(rows, limit):
    cap = max(0, min(MAX_DECLARATIONS, int(limit)))
    if cap == 0:
        return []
    result, seen = [], {}
    for row in rows:
        if row is None:
            continue
        key = row["method"], row["url"]
        if key not in seen:
            if len(result) >= cap:
                continue
            seen[key] = row
            result.append(row)
        elif row.get("declared_parameters"):
            parameters = seen[key].setdefault("declared_parameters", [])
            for parameter in row.get("declared_parameters", []):
                if parameter not in parameters and len(parameters) < 100:
                    parameters.append(parameter)
    return result


def _arguments(script, opening, tokens):
    """Bounded lexical argument splitting; quoted content is never parsed as code."""
    stack, begin, index, result = [script[opening]], opening + 1, opening + 1, []
    end = min(len(script), opening + 8192)
    while index < end:
        token = tokens.get(index)
        if token is not None:
            index = token.end
            continue
        char = script[index]
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack.pop() != {")": "(", "]": "[", "}": "{"}[char]:
                return []
            if not stack:
                result.append((begin, index))
                return result
        elif char == "," and len(stack) == 1:
            result.append((begin, index))
            begin = index + 1
        index += 1
    return []


def _trim(script, span, tokens):
    begin, end = span
    while begin < end:
        token = tokens.get(begin)
        if token is not None and token.value is None:
            begin = token.end
        elif script[begin].isspace():
            begin += 1
        else:
            break
    return begin, end


def _literal(script, span, tokens):
    begin, end = _trim(script, span, tokens)
    token = tokens.get(begin)
    if token is None or token.value is None:
        return None
    cursor, _ = _trim(script, (token.end, end), tokens)
    if cursor != end:
        return None
    return token.value.replace("\\/", "/")


def _path_expression(script, span, tokens):
    """Read literal URL concatenations with named path segments, without evaluation."""
    cursor, end = _trim(script, span, tokens)
    parts = []
    for _ in range(32):
        token = tokens.get(cursor)
        if token is not None and token.value is not None:
            parts.append(token.value.replace("\\/", "/"))
            cursor = token.end
        else:
            # A literal prefix anchors the origin. Only simple member names
            # become placeholders; calls, indexing and computed values stop it.
            name = re.match(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*", script[cursor:end])
            if (not parts or name is None
                    or name[0] in {"true", "false", "null", "undefined", "NaN", "Infinity"}):
                return None
            parts.append("{" + re.split(r"\s*\.\s*", name[0])[-1] + "}")
            cursor += name.end()
        cursor, _ = _trim(script, (cursor, end), tokens)
        if cursor == end:
            return "".join(parts)
        if script[cursor] != "+":
            return None
        cursor, _ = _trim(script, (cursor + 1, end), tokens)
    return None


def _object_fields(script, span, tokens):
    begin, end = _trim(script, span, tokens)
    if begin >= end or script[begin] != "{":
        return None
    fields = _arguments(script, begin, tokens)
    if not fields:
        return None
    closing = fields[-1][1]
    cursor, _ = _trim(script, (closing + 1, end), tokens)
    if cursor != end or script[closing] != "}":
        return None
    result = {}
    for field in fields:
        start, stop = _trim(script, field, tokens)
        if start == stop:
            continue
        key = re.match(r"(?:([A-Za-z_$][\w$]*)|['\"]([A-Za-z_$][\w$]*)['\"])\s*:", script[start:stop])
        # Spreads/computed/shorthand properties can override method or URL.
        if key is None:
            return None
        result[key[1] or key[2]] = (start + key.end(), stop)
    return result


def declared_js_routes(script: str, *, document_url: str, base_url: str,
                       target_policy=None, limit: int = MAX_DECLARATIONS) -> list[dict]:
    """Read direct fetch/client methods, Request, axios configs and XHR.open."""
    if limit <= 0:
        return []
    rows = []
    def add(path, method):
        if not isinstance(method, str) or method.upper() not in METHODS:
            return
        # fetch/XHR relative URLs resolve against the embedding document, not
        # the external script URL. Keep only unambiguous references here.
        if not isinstance(path, str) or not (path.startswith("/") or re.match(r"^https?://", path, re.I)):
            return
        row = _candidate(path, method, document_url=document_url, base_url=base_url,
                         target_policy=target_policy, kind="js_http_call", source="adaptive_js")
        if row is not None:
            row["evidence"]["source_scripts"] = [document_url]
            rows.append(row)

    literals = _literals(script)
    tokens = {token.start: token for token in literals}
    def direct(path, method, begin, end):
        cursor, _ = _trim(script, (end, len(script)), tokens)
        if (cursor < len(script) and script[cursor] in ",)"
                and method in METHODS and literal_call_method(script, begin, end) == method):
            add(path, method)
    extract_js_api_paths(script, literal_call_method, location_callback=direct,
                         include_explicit_writes=True)
    parts, cursor = [], 0
    for token in literals:
        parts.extend((script[cursor:token.start], " " * (token.end - token.start)))
        cursor = token.end
    parts.append(script[cursor:])
    code = "".join(parts)
    xhr = set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+XMLHttpRequest\s*\(\s*\)", code))
    calls = re.compile(r"\b(?:(?P<request>new\s+Request)|(?P<axios>axios(?:\s*\.\s*request)?)|(?P<fetch>fetch)|(?P<xhr>[A-Za-z_$][\w$]*)\s*\.\s*open|[A-Za-z_$][\w$]*\s*\.\s*(?P<verb>get|post|put|patch|delete|head|options))\s*\(", re.I)
    for call in islice(calls.finditer(code), 1000):
        arguments = _arguments(script, call.end() - 1, tokens)
        if not arguments:
            continue
        if call["xhr"]:
            if call["xhr"] in xhr and len(arguments) >= 2:
                add(_path_expression(script, arguments[1], tokens), _literal(script, arguments[0], tokens))
            continue
        if call["verb"]:
            add(_path_expression(script, arguments[0], tokens), call["verb"].upper())
            continue
        fields = None
        path = _path_expression(script, arguments[0], tokens)
        if path is None and call["axios"]:
            fields = _object_fields(script, arguments[0], tokens)
            if fields is not None and "url" in fields:
                path = _path_expression(script, fields["url"], tokens)
        elif len(arguments) >= 2:
            fields = _object_fields(script, arguments[1], tokens)
            if fields is None:
                continue
        if path is None:
            continue
        method = "GET"
        if fields is not None and "method" in fields:
            method = _literal(script, fields["method"], tokens)
            if method is None:
                continue
        if fields is not None and "baseURL" in fields:
            prefix = _literal(script, fields["baseURL"], tokens)
            if prefix is None:
                continue
            # axios combines baseURL with relative references, including a
            # leading slash. An absolute URL overrides baseURL.
            if not re.match(r"^(?:[A-Za-z][\w+.-]*:|//)", path):
                path = prefix.rstrip("/") + "/" + path.lstrip("/")
        add(path, method)
    return _unique(rows, limit)


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.base = None
        self.forms = []
        self.active = None
        self.overrides = []
        self.detached_fields = []
        self.scripts = []
        self._script_parts = None

    def handle_starttag(self, tag, attrs):
        values = {}
        for key, value in attrs:
            values.setdefault(key, value)
        if tag == "base" and self.base is None and "href" in values:
            self.base = values["href"] or ""
        if (tag == "script" and "src" not in values
                and str(values.get("type") or "").strip().lower() in _SCRIPT_TYPES):
            self._script_parts = []
        if tag == "form" and len(self.forms) < 200:
            self.active = dict(action=values.get("action") or "", method=values.get("method") or "GET",
                               id=values.get("id"), fields=[])
            self.forms.append(self.active)
        if tag not in {"input", "select", "textarea", "button"} or "disabled" in values:
            return
        target = values.get("form") or self.active
        if values.get("name") and isinstance(target, dict) and len(target["fields"]) < 100:
            target["fields"].append(values["name"])
        elif values.get("name") and isinstance(target, str) and len(self.detached_fields) < 1000:
            self.detached_fields.append((target, values["name"]))
        if "formaction" in values or "formmethod" in values:
            self.overrides.append((target, values.get("formaction"), values.get("formmethod")))

    def handle_endtag(self, tag):
        if tag == "form":
            self.active = None
        if tag == "script" and self._script_parts is not None:
            self.scripts.append("".join(self._script_parts))
            self._script_parts = None

    def handle_data(self, data):
        if self._script_parts is not None:
            self._script_parts.append(data)


def declared_form_routes(body: str, *, document_url: str, base_url: str,
                         target_policy=None, limit: int = MAX_DECLARATIONS) -> list[dict]:
    if limit <= 0:
        return []
    parser = _Forms()
    try:
        parser.feed(body)
    except (AssertionError, ValueError):
        # A malformed declaration must not discard forms parsed before it.
        pass
    try:
        relative_base = urljoin(document_url, parser.base) if parser.base is not None else document_url
    except ValueError:
        relative_base = document_url
    declarations = [(form, None, None) for form in parser.forms]
    declarations.extend(parser.overrides[:200])
    for identifier, name in parser.detached_fields:
        owners = [item for item in parser.forms if item.get("id") == identifier]
        if len(owners) == 1 and len(owners[0]["fields"]) < 100:
            owners[0]["fields"].append(name)
    rows = []
    for form, override_action, override_method in declarations:
        if isinstance(form, str):
            owners = [item for item in parser.forms if item.get("id") == form]
            form = owners[0] if len(owners) == 1 else None
        if not isinstance(form, dict):
            continue
        method = (override_method if override_method is not None else form["method"]).strip().upper()
        action = override_action if override_action is not None else form["action"]
        try:
            reference = urljoin(relative_base, action) if action else document_url
        except ValueError:
            continue
        parameters = [{"name": name, "location": "query" if method == "GET" else "form"}
                      for name in form["fields"]]
        row = _candidate(reference, method, document_url=document_url, base_url=base_url,
                         target_policy=target_policy, kind="form_action", parameters=parameters)
        if row is not None:
            row["evidence"].update(html_tag="form", html_attribute="action")
            rows.append(row)
    return _unique(rows, limit)


def declared_html_routes(body: str, *, document_url: str, base_url: str,
                         target_policy=None, limit: int = MAX_DECLARATIONS) -> list[dict]:
    """Combine forms with inline HTTP calls declared by one HTML document."""
    if limit <= 0:
        return []
    forms = declared_form_routes(body, document_url=document_url, base_url=base_url,
                                 target_policy=target_policy, limit=limit)
    parser = _Forms()
    try:
        parser.feed(body)
    except (AssertionError, ValueError):
        pass
    calls = _unique((row for script in parser.scripts for row in declared_js_routes(
        script, document_url=document_url, base_url=base_url,
        target_policy=target_policy, limit=limit)), limit)
    writes = [row for row in calls if row["method"] not in {"GET", "HEAD", "OPTIONS"}]
    fields = []
    for row in forms:
        for field in row.get("declared_parameters", []):
            if field not in fields:
                fields.append(field)
    executable_scripts = "\n".join(parser.scripts)
    if (len(writes) == 1 and len(parser.forms) == 1 and fields
            and "new FormData" in executable_scripts):
        location = ("json" if re.search(
            r"Content-Type['\"]?\s*:\s*['\"]application/json", executable_scripts) else "form")
        writes[0]["declared_parameters"] = [
            {**field, "location": location} for field in fields
        ]
    return _unique([*forms, *calls], limit)


def declarations_from_captured_responses(rows, *, base_url: str, target_policy=None,
                                         limit: int = MAX_DECLARATIONS) -> list[dict]:
    """Rebuild passive declarations from durable response rows."""
    cap = max(0, min(MAX_DECLARATIONS, int(limit)))
    if cap == 0:
        return []
    declarations, inferences, documents_seen = [], [], set()
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) != 3:
            continue
        document_url, content_type, response_body = row
        if (not isinstance(document_url, str) or not isinstance(response_body, (str, bytes))
                or len(response_body) > MAX_DOCUMENT_SIZE):
            continue
        document_url = _route_url(document_url, document_url=base_url, base_url=base_url,
                                  target_policy=target_policy)
        if document_url is None:
            continue
        text = (response_body.decode("utf-8", errors="replace")
                if isinstance(response_body, bytes) else response_body)
        media = str(content_type or "").split(";", 1)[0].strip().lower()
        identity = document_url, media, hashlib.sha256(text.encode("utf-8", errors="replace")).digest()
        if identity in documents_seen:
            continue
        documents_seen.add(identity)
        options = dict(document_url=document_url, base_url=base_url,
                       target_policy=target_policy, limit=cap)
        captured = []
        if media in {"text/html", "application/xhtml+xml"}:
            captured = declared_html_routes(text, **options)
        elif media in {"application/javascript", "text/javascript", "application/x-javascript"}:
            captured = declared_js_routes(text, **options)
        elif media in {"application/json", "application/openapi+json"}:
            try:
                document = json.loads(text)
                captured = declared_openapi_routes(document, **options)
                inferences = _unique([*inferences, *inferred_openapi_routes(document, **options)], cap)
            except (ValueError, TypeError, RecursionError):
                pass
        elif media in {"text/plain", "application/xml", "text/xml", "application/sitemap+xml"}:
            captured = declared_index_routes(text, **options)
        # Count unique method/URL pairs after every document. Repeated captures
        # must not consume the route cap or erase parameters declared later.
        declarations = _unique([*declarations, *captured], cap)
    # Guessed conventions cannot displace declarations from a later capture.
    return _unique([*declarations, *inferences], cap)


def declared_openapi_routes(document: dict, *, document_url: str, base_url: str,
                            target_policy=None, limit: int = MAX_DECLARATIONS) -> list[dict]:
    """Keep every declared method and template without resolving refs or values."""
    if (limit <= 0 or not isinstance(document, dict) or not isinstance(document.get("paths"), dict)
            or not (str(document.get("openapi", "")).startswith("3.") or document.get("swagger") == "2.0")):
        return []
    rows = []
    for path, item in islice(document["paths"].items(), 500):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or not isinstance(item, dict):
            continue
        if "$ref" in item or "?" in path or "#" in path:
            continue
        for method, operation in item.items():
            if str(method).upper() not in METHODS or not isinstance(operation, dict) or "$ref" in operation:
                continue
            parameters = []
            path_enums = {}
            for group in (item.get("parameters", []), operation.get("parameters", [])):
                if not isinstance(group, list):
                    continue
                for parameter in group[:100]:
                    if isinstance(parameter, dict) and "$ref" not in parameter:
                        schema = parameter.get("schema", parameter)
                        location = {"formData": "form", "body": "json"}.get(parameter.get("in"), parameter.get("in")) if isinstance(parameter.get("in"), str) else None
                        parameters.append(dict(name=parameter.get("name"), location=location,
                                               data_type=schema.get("type") if isinstance(schema, dict) else None))
                        enum = schema.get("enum") if isinstance(schema, dict) else None
                        name = parameter.get("name")
                        if (location == "path" and isinstance(name, str)
                                and isinstance(enum, list) and 0 < len(enum) <= 10):
                            values = []
                            for value in enum:
                                if isinstance(value, bool) or not isinstance(value, (str, int, float)):
                                    continue
                                rendered = str(value)
                                if (not rendered or len(rendered) > 64 or "/" in rendered
                                        or any(ord(char) < 32 for char in rendered)):
                                    continue
                                values.append(rendered)
                            if values:
                                path_enums[name] = values
            request_body = operation.get("requestBody")
            if isinstance(request_body, dict) and "$ref" not in request_body:
                content = request_body.get("content", {})
                for media_type, media in list(content.items())[:5] if isinstance(content, dict) else []:
                    if not isinstance(media_type, str):
                        continue
                    location = "form" if media_type in {"application/x-www-form-urlencoded", "multipart/form-data"} else "json" if media_type == "application/json" or media_type.endswith("+json") else None
                    schema = media.get("schema", {}) if isinstance(media, dict) else {}
                    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                    for name, field in islice(properties.items(), 100) if isinstance(properties, dict) else []:
                        parameters.append(dict(name=name, location=location, data_type=field.get("type") if isinstance(field, dict) else None))
            try:
                servers = _servers(document, item, operation, document_url)
            except (ValueError, TypeError):
                continue
            safe_servers = [server for server in servers if _safe_url(server, base_url)]
            # A specification served by the target can retain its canonical
            # production server while the same application is running on a
            # local/staging origin.  Active OpenAPI probing must never rewrite
            # that destination, but passive inventory can safely attach the
            # declared path to the origin that supplied the document.  The
            # resulting row remains an unverified candidate and makes no
            # request.
            server_scope_fallback = not safe_servers
            for server in safe_servers or [base_url]:
                path_variants = [path]
                expanded = False
                for name, values in path_enums.items():
                    marker = "{" + name + "}"
                    if marker not in path_variants[0]:
                        continue
                    path_variants = [candidate.replace(marker, value)
                                     for candidate in path_variants for value in values][:25]
                    expanded = True
                for declared_path in path_variants:
                    row = _candidate(server.rstrip("/") + declared_path, method,
                                     document_url=document_url, base_url=base_url,
                                     target_policy=target_policy,
                                     kind="api_spec_declaration", parameters=parameters)
                    if row is not None:
                        if server_scope_fallback:
                            row["evidence"]["server_scope_fallback"] = True
                        if expanded:
                            row["evidence"]["path_enum_expansion"] = True
                        rows.append(row)
            if len(rows) >= min(MAX_DECLARATIONS, max(0, limit)):
                return _unique(rows, limit)
    return _unique(rows, limit)


_AUTH_UI_ACTIONS = frozenset({"login", "register", "forgot-password", "reset-password"})
_API_PREFIX_EXCLUSIONS = frozenset({"admin", "api", "internal", "latest", "static"})
_IMDS_COMMON_PATHS = (
    "/latest/meta-data/ami-id",
    "/latest/meta-data/hostname",
    "/latest/meta-data/iam",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/security-groups",
)


def inferred_openapi_routes(document: dict, *, document_url: str, base_url: str,
                            target_policy=None, limit: int = MAX_DECLARATIONS) -> list[dict]:
    """Derive bounded route-family candidates from an observed API contract.

    These candidates are conventions supported by a captured declaration. They
    are never requested here and remain distinguishable from contract routes.
    Only route structure, operation metadata, and well-known protocol paths are
    used; benchmark and Recon Wiki comparison data are not inputs.
    """
    if (limit <= 0 or not isinstance(document, dict) or not isinstance(document.get("paths"), dict)
            or not (str(document.get("openapi", "")).startswith("3.") or document.get("swagger") == "2.0")):
        return []
    rows = []

    def add(path, method, rule, declared_path):
        row = _candidate(path, method, document_url=document_url, base_url=base_url,
                         target_policy=target_policy, kind="api_convention_candidate",
                         source="passive_route_inference")
        if row is not None:
            row["evidence"].update(
                derivation_rule=rule,
                inferred_from=declared_path,
            )
            rows.append(row)

    has_metadata_family = False
    for path, item in islice(document["paths"].items(), 500):
        if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                or not isinstance(item, dict) or "?" in path or "#" in path):
            continue
        has_metadata_family = has_metadata_family or path.rstrip("/").startswith("/latest/meta-data")
        segments = [segment for segment in path.split("/") if segment]
        for method, operation in item.items():
            method = str(method).upper()
            if method not in METHODS or not isinstance(operation, dict) or "$ref" in operation:
                continue

            # Web applications commonly expose a controller both as an HTML
            # route and below /api. Preserve templates and method identity.
            first = segments[0].lower() if segments else ""
            if segments and first not in _API_PREFIX_EXCLUSIONS:
                add("/api" + path, method, "api_prefix_alias", path)
                if method == "GET" and re.search(r"/\{[^/{}]+\}/?$", path):
                    collection = re.sub(r"/\{[^/{}]+\}/?$", "", path)
                    add("/api" + collection, method, "api_collection_alias", path)

            tags = operation.get("tags")
            tag_values = (str(value).lower() for value in tags if isinstance(value, str)) \
                if isinstance(tags, list) else ()
            semantic = " ".join((
                *tag_values,
                str(operation.get("summary") or "").lower(),
                str(operation.get("description") or "").lower(),
            ))
            action = segments[-1].lower() if segments else ""
            if action in _AUTH_UI_ACTIONS and (
                    "auth" in semantic or "password" in semantic or "log in" in semantic
                    or "login" in semantic or "register" in semantic):
                ui_segments = list(segments)
                if ui_segments and ui_segments[0].lower() == "api":
                    ui_segments.pop(0)
                version_segment = bool(ui_segments and re.fullmatch(
                    r"v(?:\d+|\{[A-Za-z_$][\w$.-]*\})", ui_segments[0], re.I))
                if version_segment:
                    ui_segments.pop(0)
                if ui_segments and ui_segments[0].lower() == "merchants":
                    ui_segments[0] = "merchant"
                if ui_segments:
                    ui_path = "/" + "/".join(ui_segments)
                    add(ui_path, "GET", "authentication_ui_companion", path)
                    # A versioned API action often retains an unversioned
                    # compatibility route. Limit this to a single action segment
                    # so resource APIs do not create broad method aliases.
                    if (method not in {"GET", "HEAD", "OPTIONS"}
                            and len(ui_segments) == 1
                            and len(segments) >= 3
                            and segments[0].lower() == "api"
                            and version_segment):
                        add(ui_path, method, "versionless_api_action", path)
                    if len(ui_segments) > 1:
                        resource = "/" + ui_segments[0]
                        add(resource, "GET", "authenticated_resource_landing", path)
                        add(resource + "/dashboard", "GET", "authenticated_resource_dashboard", path)

    if has_metadata_family:
        for path in _IMDS_COMMON_PATHS:
            add(path, "GET", "well_known_imds_family", "/latest/meta-data/")
    return _unique(rows, limit)


def declared_index_routes(body: str, *, document_url: str, base_url: str,
                          target_policy=None, limit: int = MAX_DECLARATIONS) -> list[dict]:
    """Read captured robots rules and sitemap locations without following them."""
    if limit <= 0:
        return []
    references = []
    if urlsplit(document_url).path.lower().endswith("/robots.txt"):
        for line in body.splitlines()[:2000]:
            match = re.match(r"\s*(?:allow|disallow|sitemap)\s*:\s*([^#\s]+)", line, re.I)
            if match and not any(char in match[1] for char in "*$"):
                references.append(match[1])
        kind = "robots_declaration"
    else:
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", body, re.I):
            return []
        try:
            root = ElementTree.fromstring(body)
        except (ElementTree.ParseError, ValueError):
            return []
        if root.tag.rsplit("}", 1)[-1] not in {"urlset", "sitemapindex"}:
            return []
        references = [element.text.strip() for element in islice(root.iter(), 5000)
                      if element.tag.rsplit("}", 1)[-1] == "loc" and element.text]
        kind = "sitemap_declaration"
    return _unique((_candidate(reference, "GET", document_url=document_url, base_url=base_url,
                               target_policy=target_policy, kind=kind) for reference in references), limit)
