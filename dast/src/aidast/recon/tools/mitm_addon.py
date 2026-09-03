"""Policy-enforcing mitmproxy addon for recon tool traffic.

The main process starts mitmdump with ``policy_file``, ``flow_log`` and
``run_id`` options. This addon blocks requests outside the compiled policy
before they reach the destination and writes redacted JSONL audit records.
The main process ingests those records into SQLite after mitmdump stops.
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import TextIO

from mitmproxy import ctx, http

from aidast.recon.policy import (
    INTERNAL_EXECUTION_HEADER,
    PolicyError,
    ReconPolicy,
    ScopeGuard,
    load_policy,
)


LOGGER = logging.getLogger(__name__)
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}
REDACTED = "<redacted>"


def _safe_headers(headers, *, extra_sensitive: set[str] | None = None) -> dict[str, str]:
    sensitive = SENSITIVE_HEADERS | {
        name.casefold() for name in (extra_sensitive or set())
    }
    result: dict[str, str] = {}
    for key, value in headers.items():
        result[key] = REDACTED if key.casefold() in sensitive else value
    return result


class PolicyEnforcer:
    def __init__(self) -> None:
        self._fp: TextIO | None = None
        self._policy: ReconPolicy | None = None
        self._guard: ScopeGuard | None = None
        self._request_times: deque[float] = deque()
        self._count = 0

    def load(self, loader) -> None:
        loader.add_option(
            name="flow_log",
            typespec=str,
            default="mitm_flows.jsonl",
            help="Path to the redacted JSONL flow audit log",
        )
        loader.add_option(
            name="policy_file",
            typespec=str,
            default="",
            help="Path to recon-policy.json",
        )
        loader.add_option(
            name="run_id",
            typespec=str,
            default="",
            help="Policy run ID attached to audit records",
        )

    def running(self) -> None:
        if not ctx.options.policy_file:
            raise PolicyError("policy_file is required")
        if not ctx.options.run_id:
            raise PolicyError("run_id is required")
        self._policy = load_policy(Path(ctx.options.policy_file))
        self._guard = ScopeGuard(self._policy)
        flow_log = Path(ctx.options.flow_log)
        flow_log.parent.mkdir(parents=True, exist_ok=True)
        self._fp = flow_log.open("a", encoding="utf-8")
        LOGGER.info("policy flow log: %s", flow_log)

    def done(self) -> None:
        if self._fp is not None:
            self._fp.close()
            self._fp = None
        LOGGER.info("policy flows recorded: %d", self._count)

    def request(self, flow: http.HTTPFlow) -> None:
        execution_id = flow.request.headers.pop(INTERNAL_EXECUTION_HEADER, None)
        flow.metadata["aidast_execution_id"] = execution_id

        if self._policy is None or self._guard is None:
            self._block(flow, "policy is not loaded")
            return

        allowed, reason = self._guard.evaluate_url(flow.request.pretty_url)
        if not allowed:
            self._block(flow, reason)
            return

        missing_headers = [
            requirement.name
            for requirement in self._policy.global_controls.required_headers
            if requirement.required and requirement.name not in flow.request.headers
        ]
        if missing_headers:
            self._block(
                flow,
                "missing required headers: " + ", ".join(sorted(missing_headers)),
            )
            return

        maximum_rps = self._policy.global_controls.maximum_requests_per_second or 1
        now = time.monotonic()
        while self._request_times and self._request_times[0] <= now - 1:
            self._request_times.popleft()
        if len(self._request_times) >= maximum_rps:
            self._block(flow, f"global rate limit exceeded: {maximum_rps}/s", status=429)
            return
        self._request_times.append(now)
        flow.metadata["aidast_decision"] = "allow"
        flow.metadata["aidast_reason"] = reason

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def _block(self, flow: http.HTTPFlow, reason: str, *, status: int = 403) -> None:
        flow.metadata["aidast_decision"] = "block"
        flow.metadata["aidast_reason"] = reason
        flow.response = http.Response.make(
            status,
            b"Request blocked by AIDAST recon policy.\n",
            {
                "Content-Type": "text/plain; charset=utf-8",
                "X-AIDAST-Blocked": "true",
            },
        )

    def _record(self, flow: http.HTTPFlow) -> None:
        if self._fp is None or flow.metadata.get("aidast_recorded"):
            return
        flow.metadata["aidast_recorded"] = True
        request = flow.request
        response = flow.response
        content_length = response.headers.get("content-length") if response else None
        record = {
            "run_id": ctx.options.run_id,
            "execution_id": flow.metadata.get("aidast_execution_id"),
            "timestamp": time.time(),
            "scheme": request.scheme,
            "host": request.host,
            "port": request.port,
            "method": request.method,
            "path": request.path.split("?", 1)[0],
            "query_string": request.path.partition("?")[2] or None,
            "request_headers": _safe_headers(
                request.headers,
                extra_sensitive={
                    requirement.name
                    for requirement in (
                        self._policy.global_controls.required_headers
                        if self._policy is not None
                        else []
                    )
                },
            ),
            "status_code": response.status_code if response else None,
            "content_type": response.headers.get("content-type") if response else None,
            "response_size": (
                int(content_length)
                if content_length and content_length.isdigit()
                else None
            ),
            "decision": flow.metadata.get("aidast_decision", "block"),
            "reason": flow.metadata.get("aidast_reason", "request hook was not evaluated"),
        }
        try:
            self._fp.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fp.flush()
            self._count += 1
        except OSError as exc:
            LOGGER.error("failed to write policy flow: %s", exc)


addons = [PolicyEnforcer()]
