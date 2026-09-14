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
import runpy
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import ctx, http

# mitmdump may use a different Python environment; load only the dependency-free
# shared helpers, without importing aidast's Pydantic-dependent package modules.
_safety = runpy.run_path(str(Path(__file__).resolve().parents[2] / "core" / "http_safety.py"))
sanitize_headers = _safety["sanitize_headers"]
validate_scope_rules = _safety["validate_scope_rules"]
BROWSER_TOKEN_HEADER = _safety["BROWSER_TOKEN_HEADER"]
BROWSER_MODE_HEADER = _safety["BROWSER_MODE_HEADER"]
BROWSER_SUPPORT_MODES = _safety["BROWSER_SUPPORT_MODES"]


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
        self.budget_used_before = 0
        self.seen_requests: set[tuple[str, str, str]] = set()
        self.enforcement_required = True

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
                self.rules = data
                self.budget_used_before = max(0, int(data.get("budget_used_before", 0)))
                self.scope_loaded = True
                ctx.log.info(f"[scope] {len(self.allowed_hosts)}개 호스트 로드됨")
            except (OSError, ValueError, TypeError):
                ctx.log.warn("[scope] 유효한 scope_file 설정 없음")

        if "out_file" in updated and ctx.options.out_file:
            self.out_path = Path(ctx.options.out_file)

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.scope_loaded:
            if self.enforcement_required:
                self._block(flow)
            return
        try:
            parsed = urlsplit(flow.request.pretty_url)
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
        support_mode = self._authorized_browser_support(
            flow, parsed, host_allowed, host_excluded
        )
        phase_hint = str(flow.request.headers.pop("X-AIDAST-Phase", "")).lower()
        method = flow.request.method.upper()
        # Prioritize browser API/document traffic over crawler noise. Static
        # resources and duplicate requests do not consume the finite budget.
        resource = str(flow.request.headers.get("Sec-Fetch-Dest", "")).lower()
        is_static = path.rsplit("/", 1)[-1].split("?", 1)[0].lower().endswith(
            (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map")
        ) or resource in {"script", "style", "image", "font", "media"}
        request_key = (method, host, path)
        duplicate = request_key in self.seen_requests
        self.seen_requests.add(request_key)
        if support_mode or phase_hint == "headless":
            priority = 1 if method not in {"GET", "HEAD"} or resource in {"", "empty", "document"} else 1
        elif method in {"GET", "HEAD"} and resource == "document":
            priority = 2
        elif method in {"GET", "HEAD"}:
            priority = 4
        else:
            priority = 3
        if is_static:
            priority = 6
        flow.metadata["aidast_priority"] = priority
        flow.metadata["aidast_deferred_candidate"] = False
        boundary_allowed = (
            host_allowed
            and not (parsed.username or parsed.password)
            and parsed.scheme in self.rules.get("allowed_schemes", ["https"])
            and port in self.rules.get("allowed_ports", [443])
            and flow.request.method.upper() in allowed_methods
            and any(self._path_matches(path, prefix) for prefix in allowed_paths)
            and not any(self._path_matches(path, prefix) for prefix in excluded_paths)
        )
        counts_against_budget = (boundary_allowed or support_mode) and not duplicate and priority < 6
        if counts_against_budget:
            self.request_count += 1
        global_request_count = self.budget_used_before + self.request_count
        allowed = (boundary_allowed or support_mode) and (
            not counts_against_budget
            or global_request_count <= (budget_total if priority <= 2 else noncritical_limit)
        )
        if support_mode:
            flow.metadata["aidast_browser_support"] = support_mode
        flow.metadata["aidast_traffic_class"] = (
            "browser_observation" if support_mode else
            "passive" if priority >= 6 else
            "active"
        )
        if not allowed:
            flow.metadata["aidast_deferred_candidate"] = True
            self._block(flow)

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
            method in {"GET", "HEAD"}
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

    def response(self, flow: http.HTTPFlow) -> None:
        if self.out_path is None:
            return
        support_mode = flow.metadata.get("aidast_browser_support")
        capture_bodies = (
            self.scope_loaded
            and self.rules.get("mitm_capture_bodies", False) is True
            and support_mode != "passive"
        )
        record = {
            "source": "mitmproxy",
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": sanitize_headers(dict(flow.request.headers)),
            "request_body": flow.request.get_text(strict=False) if capture_bodies and flow.request.content else None,
            "response_status": flow.response.status_code if flow.response else None,
            "response_headers": sanitize_headers(dict(flow.response.headers)) if flow.response else None,
            "response_body": (
                flow.response.get_text(strict=False)
                if capture_bodies and flow.response and flow.response.content
                else None
            ),
            "content_type": flow.response.headers.get("content-type") if flow.response else None,
            "priority": flow.metadata.get("aidast_priority"),
            "deferred_candidate": bool(flow.metadata.get("aidast_deferred_candidate")),
            "traffic_class": flow.metadata.get("aidast_traffic_class", "active"),
            "policy_blocked": bool(
                flow.metadata.get("aidast_policy_blocked", False)
            ),
            "capture_bodies": capture_bodies,
            "browser_support": support_mode,
        }
        with self.out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [ScopeAndCaptureAddon()]
