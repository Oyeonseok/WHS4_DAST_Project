"""mitmdump가 로드하는 addon 스크립트.

mitmdump -s tools/mitm_addon.py -p 8080 \\
    --set out_file=mitm_capture.jsonl \\
    --set scope_file=/path/to/scope_rules.json

역할 두 가지:
1. 지나가는 모든 요청/응답을 한 쌍으로 JSONL 파일에 append(관찰)
2. scope_file이 주어지면 그 안의 allowed_hosts에 없는 호스트로 가는
   요청을 막는다(스코프 강제). 필수 설정이 없거나 잘못되면 요청을 막는다.

이 파일은 mitmdump 자체 파이썬 프로세스 안에서 실행되므로(우리 aidast
패키지가 깔린 venv가 아님), aidast 쪽 코드를 import하지 않는다.
"""

from __future__ import annotations

import json
import hmac
import hashlib
import os
import runpy
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import ctx, http

# mitmdump may use a different Python environment; load only the dependency-free
# shared helpers, without importing aidast's Pydantic-dependent package modules.
_safety = runpy.run_path(str(Path(__file__).resolve().parents[2] / "core" / "http_safety.py"))
_governor = runpy.run_path(str(Path(__file__).resolve().parents[2] / "core" / "request_governor.py"))
RequestGovernor = _governor["RequestGovernor"]
GovernorError = _governor["GovernorError"]
sanitize_headers = _safety["sanitize_headers"]
merge_hackerone_identity = _safety["merge_hackerone_identity"]
validate_scope_rules = _safety["validate_scope_rules"]
BROWSER_TOKEN_HEADER = _safety["BROWSER_TOKEN_HEADER"]
BROWSER_MODE_HEADER = _safety["BROWSER_MODE_HEADER"]
BROWSER_SUPPORT_MODES = _safety["BROWSER_SUPPORT_MODES"]
scope_uses_loopback_host = _safety["scope_uses_loopback_host"]
require_request_admission = _safety['require_request_admission']
has_request_exclusions = _safety['has_request_exclusions']
_receipt = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'core' / 'capture_receipt.py'))
_authentication_key = runpy.run_path(str(Path(__file__).with_name('request_identity.py')))['authentication_key']


def _wire_headers(request):
    try:
        return list(request.headers.items(multi=True))
    except TypeError:
        return dict(request.headers)


def _protocol_exchange(request):
    """A handshake cannot certify the future frames/control of a tunnel."""
    if request.method.upper() == 'CONNECT':
        return True
    headers = _wire_headers(request)
    items = headers.items() if isinstance(headers, dict) else headers
    for name, value in items:
        name = name.lower()
        if name in {'upgrade', ':protocol'}:
            return True
        if name == 'connection' and 'upgrade' in {part.strip().lower() for part in value.split(',')}:
            return True
    return bool(getattr(request, 'protocol', None) or getattr(getattr(request, 'data', None), 'protocol', None))


def _physical_url(request):
    url = getattr(request, 'url', request.pretty_url)
    actual, pretty = urlsplit(url), urlsplit(request.pretty_url)
    def authority(parsed):
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)
    if authority(actual) != authority(pretty):
        raise ValueError('proxy destination and displayed authority differ')
    if getattr(request, 'host', actual.hostname) != actual.hostname or getattr(request, 'port', authority(actual)[2]) != authority(actual)[2]:
        raise ValueError('proxy connection authority differs')
    host_header = next((v for k,v in request.headers.items() if k.lower() == 'host'), None)
    if host_header is not None and host_header.lower() != actual.netloc.lower():
        raise ValueError('proxy Host differs from destination')
    return url


def _canonical_request_key(method: str, parsed, body: bytes | None = None, *, headers=None) -> tuple[str, ...]:
    """Keep distinct query/body requests separate without retaining their values."""
    query = parsed.query or ""
    query_digest = hashlib.sha256(query.encode()).hexdigest() if query else ""
    body_digest = hashlib.sha256(body).hexdigest() if body else ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (method.upper(), parsed.scheme.lower(), (parsed.hostname or "").lower().rstrip("."),
            str(port), parsed.path or "/", query_digest, body_digest, _authentication_key(headers))


def _host_matches(host: str, pattern: str) -> bool:
    normalized = pattern.lower().rstrip(".")
    root = normalized.removeprefix("*.")
    return host == root or (
        normalized.startswith("*.") and host.endswith("." + root)
    )


class ScopeAndCaptureAddon:
    def __init__(self) -> None:
        self.allowed_hosts: set[str] = set()
        self.scope_loaded = False
        self.out_path: Path | None = None
        self.rules: dict = {}
        self.request_count = 0
        self.pending_request_count = 0
        self.blocked_request_count = 0
        self.budget_used_before = 0
        self._last_progress_write = 0.0
        self.seen_requests: set[tuple[str, ...]] = set()
        self.enforcement_required = True
        self.governor = RequestGovernor(None)
        self.governor_invalid = False
        self.auth_path: Path | None = None
        self._auth_mtime_ns = -1
        self._auth_headers: dict[str, str] = {}

    def load(self, loader) -> None:
        loader.add_option(
            name="scope_file",
            typespec=str,
            default="",
            help="승인된 Scope에서 뽑은 allow-list JSON 경로.",
        )
        loader.add_option(name="enforcement_required", typespec=bool, default=True,
                          help="정책 설정이 없거나 잘못되면 요청 차단.")
        loader.add_option(
            name="out_file",
            typespec=str,
            default="mitm_capture.jsonl",
            help="캡처한 요청/응답을 append하는 JSONL 경로.",
        )
        loader.add_option(
            name="auth_file",
            typespec=str,
            default="",
            help="외부 도구 인증 헤더용 private JSON 경로.",
        )

    def configure(self, updated) -> None:
        if "enforcement_required" in updated:
            self.enforcement_required = ctx.options.enforcement_required
        if "scope_file" in updated:
            self.scope_loaded = False
            self.allowed_hosts = set()
            self.rules = {}
            try:
                if not ctx.options.scope_file:
                    raise ValueError("scope_file is missing")
                path = Path(ctx.options.scope_file)
                data = validate_scope_rules(json.loads(path.read_text(encoding="utf-8")))
                self.allowed_hosts = set(data.get("allowed_hosts", []))
                self.governor_invalid = data.get("request_governor") is not None
                self.governor = RequestGovernor(data.get("request_governor"))
                self.governor_invalid = False
                self.rules = data
                self.budget_used_before = max(0, int(data.get("budget_used_before", 0)))
                self.scope_loaded = True
                ctx.log.info(f"[scope] {len(self.allowed_hosts)}개 호스트 로드됨")
            except (OSError, ValueError, TypeError):
                ctx.log.warn("[scope] 유효한 scope_file 설정 없음")

        if "out_file" in updated and ctx.options.out_file:
            self.out_path = Path(ctx.options.out_file)

        if "auth_file" in updated:
            self.auth_path = Path(ctx.options.auth_file) if ctx.options.auth_file else None
            self._auth_mtime_ns = -1
            self._auth_headers = {}

    def _read_tool_auth(self) -> dict[str, str]:
        path = self.auth_path
        if path is None:
            return {}
        try:
            details = path.stat()
            if details.st_uid != os.geteuid() or details.st_mode & 0o077:
                raise ValueError("auth_file permissions are not private")
            if details.st_mtime_ns == self._auth_mtime_ns:
                return self._auth_headers
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or document.get("version") != 1:
                raise ValueError("auth_file version is invalid")
            headers = document.get("headers")
            if not isinstance(headers, dict):
                raise ValueError("auth_file headers are invalid")
            validated: dict[str, str] = {}
            forbidden = {
                "host", "content-length", "transfer-encoding", "connection",
                "proxy-connection", "upgrade", "te", "trailer",
                "x-aidast-source", "x-aidast-phase",
            }
            for name, value in headers.items():
                if (not isinstance(name, str) or not isinstance(value, str)
                        or not name or len(name) > 128
                        or any(ord(char) <= 32 or ord(char) >= 127
                               or char in "()<>@,;:\\\"/[]?={}"
                               for char in name)
                        or len(value) > 16384 or "\r" in value or "\n" in value
                        or name.casefold() in forbidden):
                    raise ValueError("auth_file contains an unsafe header")
                validated[name] = value
            self._auth_mtime_ns = details.st_mtime_ns
            self._auth_headers = validated
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            # Fail closed for authentication handoff.  The request still runs
            # without credentials and cannot inherit a stale/partially written
            # secret file.
            self._auth_mtime_ns = -1
            self._auth_headers = {}
        return self._auth_headers

    def _inject_tool_auth(self, request) -> None:
        headers = self._read_tool_auth()
        for name, value in headers.items():
            for existing in list(request.headers):
                if existing.casefold() == name.casefold():
                    request.headers.pop(existing, None)
            request.headers[name] = value

    async def request(self, flow: http.HTTPFlow) -> None:
        if not self.scope_loaded:
            if self.enforcement_required or self.governor_invalid:
                self._block(flow)
            return
        execution_methods = self.rules.get("execution_allowed_methods")
        if execution_methods is not None and (
            not isinstance(execution_methods, list)
            or any(method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
                   for method in execution_methods)
            or flow.request.method.upper() not in execution_methods
        ):
            self._block(flow)
            return
        try:
            physical_url = _physical_url(flow.request)
            parsed = urlsplit(physical_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            self._block(flow)
            return
        host = (parsed.hostname or "").lower().rstrip(".")
        allowed_hosts = {value.lower().rstrip(".") for value in self.allowed_hosts}
        excluded_hosts = self.rules.get("excluded_hosts", [])
        include_subdomains = bool(self.rules.get("include_subdomains", False))
        host_excluded = any(_host_matches(host, pattern) for pattern in excluded_hosts)
        host_allowed = not host_excluded and (host in allowed_hosts or (
            include_subdomains
            and any(host.endswith("." + root) for root in allowed_hosts)
        ))
        path = parsed.path or "/"
        allowed_paths = self.rules.get("allowed_path_prefixes", ["/"])
        excluded_paths = self.rules.get("excluded_path_prefixes", [])
        allowed_methods = self.rules.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
        max_requests = int(self.rules.get("max_requests", 3000))
        budget_total = max(1, int(self.rules.get("budget_total", max_requests)))
        browser_reserve = max(1, int(budget_total * 0.20))
        noncritical_limit = max(0, budget_total - browser_reserve)
        self.active_request_limit = noncritical_limit
        support_mode = self._authorized_browser_support(
            flow, parsed, host_allowed, host_excluded
        )
        phase_hint = str(flow.request.headers.pop("X-AIDAST-Phase", "")).lower()
        source_hint = str(flow.request.headers.pop("X-AIDAST-Source", "")).lower()
        flow.metadata["aidast_candidate_probe"] = phase_hint == "candidate_probe"
        method = flow.request.method.upper()
        boundary_allowed = (
            host_allowed
            and not (parsed.username or parsed.password)
            and parsed.scheme in self.rules.get("allowed_schemes", ["https"])
            and port in self.rules.get("allowed_ports", [443])
            and method in allowed_methods
            and any(self._path_matches(path, prefix) for prefix in allowed_paths)
            and not any(self._path_matches(path, prefix) for prefix in excluded_paths)
        )
        if boundary_allowed and source_hint in {"katana", "ffuf"}:
            self._inject_tool_auth(flow.request)
        # Prioritize browser API/document traffic over crawler noise. Every
        # forwarded request still consumes the finite total budget, including
        # static resources and duplicates from browser reloads.
        resource = str(flow.request.headers.get("Sec-Fetch-Dest", "")).lower()
        is_static = path.rsplit("/", 1)[-1].split("?", 1)[0].lower().endswith(
            (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map")
        ) or resource in {"script", "style", "image", "font", "media"}
        request_key = _canonical_request_key(
            method, parsed, getattr(flow.request, "content", b"") or b"", headers=flow.request.headers
        )
        duplicate = request_key in self.seen_requests
        fetch_mode = str(flow.request.headers.get("Sec-Fetch-Mode", "")).lower()
        if support_mode and (
            method not in {"GET", "HEAD"}
            or resource in {"empty", "xhr", "fetch"}
            or fetch_mode in {"cors", "same-origin"}
        ):
            priority = 1
        elif support_mode and resource == "document":
            priority = 2
        elif source_hint == "ffuf":
            priority = 5
        elif source_hint == "katana" or phase_hint == "headless":
            priority = 4
        elif method in {"GET", "HEAD"} and resource == "document":
            priority = 2
        elif method in {"GET", "HEAD"}:
            priority = 4
        else:
            priority = 3
        if is_static or duplicate:
            priority = 6
        flow.metadata["aidast_priority"] = priority
        flow.metadata["aidast_static_resource"] = is_static
        flow.metadata["aidast_duplicate"] = duplicate
        flow.metadata["aidast_deferred_candidate"] = False
        request_allowed = bool(boundary_allowed or support_mode)
        counts_against_budget = request_allowed
        # Evaluate against the count that would result if this request is
        # admitted. A rejected candidate is deferred, not consumed: otherwise
        # a flood of low-priority traffic beyond its quota could also exhaust
        # the reserved capacity for browser/API and document observations.
        candidate_request_count = self.request_count + self.pending_request_count + int(counts_against_budget)
        global_request_count = self.budget_used_before + candidate_request_count
        allowed = request_allowed and (
            global_request_count <= (budget_total if priority <= 2 else noncritical_limit)
        )
        if support_mode:
            flow.metadata["aidast_browser_support"] = support_mode
        flow.metadata["aidast_traffic_class"] = (
            "static_resource" if is_static else
            "duplicate" if duplicate else
            "browser_api" if support_mode and priority == 1 else
            "browser_document" if support_mode and priority == 2 else
            "ffuf" if source_hint == "ffuf" else
            "katana" if source_hint == "katana" or phase_hint == "headless" else
            "browser_observation" if support_mode else "active"
        )
        required_headers = self.rules.get("required_identity_headers", {})
        if allowed and host_allowed and (required_headers or self.rules.get("hackerone_username")):
            trusted = merge_hackerone_identity(dict(flow.request.headers), self.rules.get("hackerone_username"),
                                               required_identity_headers=required_headers)
            for name in list(flow.request.headers):
                if name.casefold() in {key.casefold() for key in required_headers} or name.casefold() == "x-hackerone":
                    flow.request.headers.pop(name, None)
            flow.request.headers.update(trusted)
        elif allowed and not host_allowed:
            for name in list(flow.request.headers):
                if name.casefold() in {key.casefold() for key in required_headers}:
                    flow.request.headers.pop(name, None)
        def admit():
            if _protocol_exchange(flow.request) and has_request_exclusions(self.rules):
                raise ValueError('exclusion hold: protocol exchange has no complete enforceable descriptor')
            raw = getattr(flow.request, 'raw_content', None)
            require_request_admission(self.rules, url=_physical_url(flow.request),
                method=flow.request.method, headers=_wire_headers(flow.request), body=raw,
                body_available=isinstance(raw, bytes) and not getattr(flow.request, 'stream', False))
        if allowed:
            try:
                admit()
            except ValueError:
                allowed = False
        if allowed:
            permit = None
            self.pending_request_count += 1
            try:
                timeout = self.rules.get("timeout_seconds", 30)
                # A browser emits many concurrent subresource requests.  The
                # response timeout is not an admission timeout: at a strict
                # rate such as 0.5 rps, compliant requests may legitimately
                # wait much longer before their turn.  Bound the queue by the
                # remaining finite request budget while preserving the
                # original timeout for the physical request.
                rate = float(self.rules.get("requests_per_second", 1.0))
                queue_units = max(1, budget_total - global_request_count + 1)
                admission_timeout = max(float(timeout), min(3600.0, queue_units / rate + float(timeout)))
                permit = await self.governor.acquire_async(flow.request.pretty_url,
                    timeout_seconds=timeout, wait_timeout_seconds=admission_timeout)
                admit()
                flow.metadata["aidast_governor_permit"] = permit
            except (GovernorError, ValueError):
                if permit is not None:
                    await permit.complete_async()
                allowed = False
            finally:
                self.pending_request_count -= 1
        if allowed:
            self.request_count += 1
            self.seen_requests.add(request_key)
            flow.metadata['aidast_forwarded'] = True
            flow.metadata['aidast_captured_at'] = time.time()
        if not allowed:
            flow.metadata["aidast_deferred_candidate"] = True
            self.blocked_request_count += 1
            self._block(flow)
        self._write_progress()

    def _write_progress(self, *, force: bool = False) -> None:
        if self.out_path is None or (not force and self._last_progress_write
                                     and time.monotonic() - self._last_progress_write < 1):
            return
        path = self.out_path.with_suffix(".progress.json")
        temporary = path.with_suffix(".progress.tmp")
        payload = {
            "version": 1,
            "allowed_requests": self.request_count,
            "blocked_requests": self.blocked_request_count,
            "used_before": self.budget_used_before,
            "active_requests_remaining": (max(0, self.active_request_limit - self.budget_used_before - self.request_count)
                                          if hasattr(self, 'active_request_limit') else None),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            temporary.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            temporary.replace(path)
            self._last_progress_write = time.monotonic()
        except OSError:
            pass

    def done(self) -> None:
        self._write_progress(force=True)

    def _authorized_browser_support(
        self, flow, parsed, host_allowed: bool, host_excluded: bool
    ) -> str | None:
        expected = self.rules.get("browser_context_token")
        supplied = flow.request.headers.pop(BROWSER_TOKEN_HEADER, "")
        mode = flow.request.headers.pop(BROWSER_MODE_HEADER, "")
        if (
            not expected
            or not supplied
            or not hmac.compare_digest(str(expected), str(supplied))
            or mode not in BROWSER_SUPPORT_MODES
            or host_excluded
            or parsed.username
            or parsed.password
        ):
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        method = flow.request.method.upper()
        if mode == "same-origin":
            excluded = self.rules.get("excluded_path_prefixes", [])
            return mode if (
                host_allowed
            and parsed.scheme in self.rules.get("allowed_schemes", ["https"])
            and port in self.rules.get("allowed_ports", [443])
            and (method in self.rules.get("allowed_methods", ["GET", "HEAD", "OPTIONS"]) or method == "POST")
                and not any(
                    self._path_matches(parsed.path or "/", path)
                    for path in excluded
                )
            ) else None
        return mode if (
            not scope_uses_loopback_host(self.allowed_hosts)
            and method in {"GET", "HEAD"}
            and parsed.scheme == "https"
            and port == 443
        ) else None

    @staticmethod
    def _block(flow: http.HTTPFlow) -> None:
        ctx.log.warn("[scope 차단] TargetPolicy가 요청을 허용하지 않음")
        flow.metadata["aidast_policy_blocked"] = True
        flow.response = http.Response.make(
            403, b"Blocked by AI-DAST TargetPolicy\n",
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    @staticmethod
    def _path_matches(path: str, prefix: str) -> bool:
        if prefix == "/":
            return True
        normalized = prefix.rstrip("/")
        return path == normalized or path.startswith(normalized + "/")

    @staticmethod
    async def _release_permit(flow):
        permit = flow.metadata.pop("aidast_governor_permit", None)
        if permit is not None:
            await permit.complete_async()

    async def error(self, flow: http.HTTPFlow) -> None:
        flow.metadata['aidast_incomplete'] = True
        await self._release_permit(flow)

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._release_permit(flow)
        if self.out_path is None:
            return
        support_mode = flow.metadata.get("aidast_browser_support")
        response_media = str(flow.response.headers.get('content-type', '') if flow.response else '').split(';', 1)[0].strip().lower()
        script_evidence = response_media in {'application/javascript', 'text/javascript', 'application/ecmascript',
                                           'text/ecmascript', 'application/x-javascript'}
        capture_bodies = (
            self.scope_loaded
            and self.rules.get("mitm_capture_bodies", False) is True
            and support_mode != "passive"
            and (script_evidence or not flow.metadata.get("aidast_static_resource"))
            and (script_evidence or not flow.metadata.get("aidast_duplicate"))
        )
        record = {
            "source": "mitmproxy",
            "authentication_key": _authentication_key(flow.request.headers),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": sanitize_headers(dict(flow.request.headers), identity_headers=self.rules.get("required_identity_headers", {})),
            "request_body": flow.request.get_text(strict=False) if capture_bodies and flow.request.content else None,
            "response_status": flow.response.status_code if flow.response else None,
            "response_headers": sanitize_headers(dict(flow.response.headers), identity_headers=self.rules.get("required_identity_headers", {})) if flow.response else None,
            "response_body": (
                flow.response.get_text(strict=False)
                if capture_bodies and flow.response and flow.response.content
                else None
            ),
            "content_type": flow.response.headers.get("content-type") if flow.response else None,
            "priority": flow.metadata.get("aidast_priority"),
            "static_resource": bool(flow.metadata.get("aidast_static_resource")),
            "duplicate": bool(flow.metadata.get("aidast_duplicate")),
            "deferred_candidate": bool(flow.metadata.get("aidast_deferred_candidate")),
            "traffic_class": flow.metadata.get("aidast_traffic_class", "active"),
            "policy_blocked": bool(
                flow.metadata.get("aidast_policy_blocked", False)
            ),
            "capture_bodies": capture_bodies,
            "browser_support": support_mode,
            "candidate_probe": bool(flow.metadata.get("aidast_candidate_probe")),
        }
        # Only a completed forwarded exchange can attest an observed request.
        raw = getattr(flow.request, 'raw_content', None)
        response_raw = getattr(flow.response, 'raw_content', None) if flow.response else None
        if (flow.metadata.get('aidast_forwarded') and not flow.metadata.get('aidast_incomplete')
                and not any(record.get(k) for k in ('policy_blocked', 'deferred_candidate', 'candidate_probe', 'duplicate', 'static_resource'))
                and capture_bodies and isinstance(raw, bytes) and isinstance(response_raw, bytes)
                and not getattr(flow.request, 'stream', False) and not getattr(flow.response, 'stream', False)
                and isinstance(record['response_body'], str)):
            try:
                record['request_receipt'] = _receipt['make_capture_receipt'](
                    url=_physical_url(flow.request), method=flow.request.method,
                    headers=_wire_headers(flow.request), body=raw,
                    response_body=record['response_body'].encode('utf-8'),
                    captured_at=flow.metadata['aidast_captured_at'])
                record['captured_at'] = flow.metadata['aidast_captured_at']
            except (ValueError, TypeError):
                pass
        with self.out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [ScopeAndCaptureAddon()]
