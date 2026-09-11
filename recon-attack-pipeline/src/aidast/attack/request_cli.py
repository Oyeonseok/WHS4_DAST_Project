"""Policy-enforced one-request transport for the native Attack Agent.

The Attack Agent chooses every request.  This helper is deliberately unaware
of vulnerability classes: it validates the durable task and TargetPolicy,
reserves shared rate/concurrency/request budgets, sends exactly one HTTP hop,
and records the outcome in the shared pipeline database.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4


MAX_REQUEST_BODY_BYTES = 200_000
MAX_RESPONSE_BODY_BYTES = 200_000
MAX_OUTPUT_CHARS = 250_000
SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"
}


class RequestGuardError(ValueError):
    """The policy boundary rejected a request before it was dispatched."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _load_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RequestGuardError("JSON input must be one object")
    return value


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _policy_allows(policy: dict, url: str, method: str) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment:
            return False
        host = (parsed.hostname or "").casefold().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    allowed_hosts = {
        str(value).casefold().rstrip(".") for value in policy.get("allowed_hosts", [])
    }
    host_allowed = host in allowed_hosts or (
        policy.get("include_subdomains") is True
        and any(host.endswith("." + root) for root in allowed_hosts)
    )
    allowed_paths = policy.get("allowed_path_prefixes", [])
    excluded_paths = policy.get("excluded_path_prefixes", [])
    path = parsed.path or "/"
    return (
        parsed.scheme in policy.get("allowed_schemes", [])
        and host_allowed
        and port in policy.get("allowed_ports", [])
        and method in policy.get("allowed_methods", [])
        and any(_path_matches(path, str(prefix)) for prefix in allowed_paths)
        and not any(_path_matches(path, str(prefix)) for prefix in excluded_paths)
    )


def _select_policy(policy_path: Path, url: str, method: str) -> dict:
    document = _load_object(policy_path)
    policies = document.get("policies")
    if not isinstance(policies, list) or not policies:
        raise RequestGuardError("TargetPolicy document has no policies")
    matches = [item for item in policies if isinstance(item, dict) and _policy_allows(item, url, method)]
    if len(matches) != 1:
        raise RequestGuardError(
            "request must match exactly one TargetPolicy destination and method"
        )
    policy = matches[0]
    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise RequestGuardError("TargetPolicy limits are missing")
    policy_id = policy.get("policy_id")
    rps = limits.get("requests_per_second")
    concurrency = limits.get("concurrency")
    timeout = limits.get("timeout_seconds")
    maximum = limits.get("max_requests")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise RequestGuardError("TargetPolicy policy_id is missing")
    if isinstance(rps, bool) or not isinstance(rps, (int, float)) or not 0 < rps <= 50:
        raise RequestGuardError("invalid TargetPolicy requests_per_second")
    if type(concurrency) is not int or not 1 <= concurrency <= 20:
        raise RequestGuardError("invalid TargetPolicy concurrency")
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise RequestGuardError("invalid TargetPolicy timeout_seconds")
    if type(maximum) is not int or not 1 <= maximum <= 100_000:
        raise RequestGuardError("invalid TargetPolicy max_requests")
    return policy


def _request_data(item: dict) -> tuple[dict[str, str], bytes | None]:
    raw_headers = item.get("headers", {})
    if not isinstance(raw_headers, dict) or len(raw_headers) > 100:
        raise RequestGuardError("headers must be a bounded object")
    headers: dict[str, str] = {}
    for name, value in raw_headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise RequestGuardError("header names and values must be strings")
        if not name.strip() or "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise RequestGuardError("invalid HTTP header")
        if len(name) > 256 or len(value) > 16_384:
            raise RequestGuardError("HTTP header is too large")
        headers[name] = value
    if "body" in item and "body_base64" in item:
        raise RequestGuardError("provide body or body_base64, not both")
    if "body_base64" in item:
        raw = item["body_base64"]
        if not isinstance(raw, str):
            raise RequestGuardError("body_base64 must be a string")
        try:
            body = base64.b64decode(raw, validate=True)
        except ValueError as exc:
            raise RequestGuardError("invalid body_base64") from exc
    elif "body" in item:
        raw = item["body"]
        if not isinstance(raw, str):
            raise RequestGuardError("body must be a string")
        body = raw.encode("utf-8")
    else:
        body = None
    if body is not None and len(body) > MAX_REQUEST_BODY_BYTES:
        raise RequestGuardError("request body exceeds the bounded size")
    return headers, body


def _value_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scalar(value: object, *, label: str) -> object:
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise RequestGuardError(f"{label} must be a JSON scalar")
    if isinstance(value, str) and len(value) > 16_384:
        raise RequestGuardError(f"{label} is too large")
    if isinstance(value, float) and not math.isfinite(value):
        raise RequestGuardError(f"{label} must be finite")
    return value


def _json_path(document: object, path: object) -> object:
    if not isinstance(path, list) or len(path) > 16:
        raise RequestGuardError("JSON capture/assertion path must be a bounded list")
    current = document
    for part in path:
        if isinstance(current, dict) and isinstance(part, str) and part in current:
            current = current[part]
        elif (
            isinstance(current, list) and type(part) is int
            and 0 <= part < len(current)
        ):
            current = current[part]
        else:
            raise RequestGuardError("JSON capture/assertion path was not present")
    return _scalar(current, label="captured JSON value")


def _binding_hashes(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    bindings: object, url: str, headers: dict[str, str], body: bytes | None,
) -> dict[str, str]:
    if bindings is None:
        return {}
    if not isinstance(bindings, list) or len(bindings) > 16:
        raise RequestGuardError("bindings must be a bounded list")
    haystacks = [url, *(f"{name}: {value}" for name, value in headers.items())]
    if body is not None:
        haystacks.append(body.decode("utf-8", errors="replace"))
    consumed: dict[str, str] = {}
    with closing(sqlite3.connect(db_path)) as conn:
        for raw in bindings:
            if not isinstance(raw, dict):
                raise RequestGuardError("binding entries must be objects")
            name = raw.get("name")
            source_request_id = raw.get("source_request_id")
            capture_name = raw.get("capture_name")
            if not all(isinstance(value, str) and value.strip() for value in (
                name, source_request_id, capture_name,
            )) or name in consumed:
                raise RequestGuardError("binding identifiers are invalid or duplicated")
            value = _scalar(raw.get("value"), label="binding value")
            digest = _value_hash(value)
            source = conn.execute(
                """SELECT result_json FROM attack_http_requests
                   WHERE request_id=? AND scan_id=? AND stage_run_id=? AND task_id=?
                     AND status='completed'""",
                (source_request_id, scan_id, stage_run_id, task_id),
            ).fetchone()
            if source is None:
                raise RequestGuardError("binding source is not a completed request in this task")
            try:
                expected = json.loads(source[0]).get("capture_hashes", {}).get(capture_name)
            except (AttributeError, TypeError, json.JSONDecodeError) as exc:
                raise RequestGuardError("binding source metadata is invalid") from exc
            if expected != digest:
                raise RequestGuardError("binding value does not match the source capture")
            rendered = value if isinstance(value, str) else json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            )
            encoded = quote(rendered, safe="")
            if not any(rendered in haystack or encoded in haystack for haystack in haystacks):
                raise RequestGuardError("binding value is not used by the outgoing request")
            consumed[name] = digest
    return consumed


def _response_metadata(
    item: dict, *, status_code: int, response_headers: object,
    response_body: bytes,
) -> tuple[dict, dict[str, object], list[dict]]:
    raw_captures = item.get("captures", [])
    raw_assertions = item.get("assertions", [])
    if not isinstance(raw_captures, list) or len(raw_captures) > 16:
        raise RequestGuardError("captures must be a bounded list")
    if not isinstance(raw_assertions, list) or len(raw_assertions) > 16:
        raise RequestGuardError("assertions must be a bounded list")
    body_text = response_body.decode("utf-8", errors="replace")
    parsed_body: object | None = None

    def json_body() -> object:
        nonlocal parsed_body
        if parsed_body is None:
            try:
                parsed_body = json.loads(body_text)
            except json.JSONDecodeError as exc:
                raise RequestGuardError("response body is not valid JSON") from exc
        return parsed_body

    header_map = {
        str(name).casefold(): str(value) for name, value in response_headers.items()
    }
    captures: dict[str, object] = {}
    for raw in raw_captures:
        if not isinstance(raw, dict):
            raise RequestGuardError("capture entries must be objects")
        name, source = raw.get("name"), raw.get("source")
        if not isinstance(name, str) or not name.strip() or name in captures:
            raise RequestGuardError("capture names are invalid or duplicated")
        if source == "json_body":
            value = _json_path(json_body(), raw.get("path", []))
        elif source == "header":
            header = raw.get("header")
            if not isinstance(header, str) or header.casefold() not in header_map:
                raise RequestGuardError("captured response header is missing")
            value = _scalar(header_map[header.casefold()], label="captured header")
        else:
            raise RequestGuardError("unsupported capture source")
        captures[name] = value

    assertions: list[dict] = []
    for raw in raw_assertions:
        if not isinstance(raw, dict):
            raise RequestGuardError("assertion entries must be objects")
        name, kind = raw.get("name"), raw.get("kind")
        terminal = raw.get("terminal", False)
        if not isinstance(name, str) or not name.strip() or type(terminal) is not bool:
            raise RequestGuardError("assertion metadata is invalid")
        expected = _scalar(raw.get("expected"), label="assertion expected value")
        if kind == "status_equals":
            actual = status_code
        elif kind == "json_equals":
            actual = _json_path(json_body(), raw.get("path", []))
        elif kind == "header_equals":
            header = raw.get("header")
            if not isinstance(header, str):
                raise RequestGuardError("header assertion requires a header name")
            actual = header_map.get(header.casefold())
        elif kind == "body_contains":
            if not isinstance(expected, str) or not expected:
                raise RequestGuardError("body_contains requires non-empty text")
            actual = expected if expected in body_text else None
        else:
            raise RequestGuardError("unsupported response assertion")
        assertions.append({
            "name": name,
            "kind": kind,
            "terminal": terminal,
            "passed": actual == expected,
            "actual_sha256": _value_hash(actual),
            "expected_sha256": _value_hash(expected),
        })
    metadata = {
        "response_sha256": hashlib.sha256(response_body).hexdigest(),
        "capture_hashes": {name: _value_hash(value) for name, value in captures.items()},
        "assertions": assertions,
    }
    return metadata, captures, assertions


def _sanitized_headers(headers: object) -> dict[str, str]:
    if not headers:
        return {}
    items = headers.items()
    return {
        str(name): "[REDACTED]" if (
            str(name).casefold().replace("_", "-") in SENSITIVE_HEADERS
            or any(part in str(name).casefold().replace("_", "-")
                   for part in ("token", "secret", "api-key", "apikey"))
        ) else str(value)
        for name, value in items
    }


def _redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode([(name, "[REDACTED]") for name, _ in pairs])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _reserve(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy: dict, method: str, url: str, fingerprint: str,
) -> tuple[str, float]:
    limits = policy["limits"]
    now = time.time()
    request_id = "http_" + uuid4().hex
    with closing(sqlite3.connect(db_path, isolation_level=None)) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("BEGIN IMMEDIATE")
        try:
            task = conn.execute(
                """SELECT s.status,t.status,t.scan_id,t.stage_run_id
                   FROM attack_tasks t JOIN stage_runs s ON s.stage_run_id=t.stage_run_id
                   WHERE t.task_id=?""",
                (task_id,),
            ).fetchone()
            if task != ("running", "running", scan_id, stage_run_id):
                raise RequestGuardError("HTTP requests require the configured running Attack task")
            policy_id = policy["policy_id"]
            used = conn.execute(
                "SELECT COUNT(*) FROM attack_http_requests WHERE scan_id=? AND policy_id=?",
                (scan_id, policy_id),
            ).fetchone()[0]
            if used >= limits["max_requests"]:
                raise RequestGuardError("TargetPolicy HTTP request budget exhausted")
            active = conn.execute(
                """SELECT COUNT(*) FROM attack_http_requests r
                   JOIN stage_runs s ON s.stage_run_id=r.stage_run_id
                   WHERE r.scan_id=? AND r.policy_id=? AND s.status='running'
                     AND r.status IN ('reserved','running')""",
                (scan_id, policy_id),
            ).fetchone()[0]
            if active >= limits["concurrency"]:
                raise RequestGuardError("TargetPolicy HTTP concurrency limit reached")
            previous = conn.execute(
                "SELECT MAX(scheduled_at) FROM attack_http_requests WHERE scan_id=? AND policy_id=?",
                (scan_id, policy_id),
            ).fetchone()[0]
            interval = 1.0 / float(limits["requests_per_second"])
            scheduled = max(now, (float(previous) + interval) if previous is not None else now)
            conn.execute(
                """INSERT INTO attack_http_requests
                   (request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                    request_fingerprint,status,scheduled_at)
                   VALUES (?,?,?,?,?,?,?,?, 'reserved',?)""",
                (
                    request_id, scan_id, stage_run_id, task_id, policy_id, method,
                    _redacted_url(url), fingerprint, scheduled,
                ),
            )
            conn.execute("COMMIT")
            return request_id, scheduled
        except Exception:
            conn.execute("ROLLBACK")
            raise


def _set_status(db_path: Path, request_id: str, *, status: str, **values: object) -> None:
    allowed = {
        "response_status", "response_bytes", "result_json", "error_message",
        "dispatched_at", "finished_at",
    }
    if status not in {"running", "completed", "failed", "outcome_unknown"} or set(values) - allowed:
        raise ValueError("invalid request ledger update")
    assignments = ["status=?"] + [f"{name}=?" for name in values]
    parameters = [status, *values.values(), request_id]
    with closing(sqlite3.connect(db_path)) as conn, conn:
        cursor = conn.execute(
            f"UPDATE attack_http_requests SET {','.join(assignments)} WHERE request_id=?",
            parameters,
        )
        if cursor.rowcount != 1:
            raise RequestGuardError("request reservation disappeared")


def guarded_request(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy_path: Path, payload_path: Path,
) -> dict:
    item = _load_object(payload_path)
    method = str(item.get("method", "GET")).upper()
    url = item.get("url")
    if not isinstance(url, str) or not url.strip() or len(url) > 8192:
        raise RequestGuardError("request URL is invalid")
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
        raise RequestGuardError("unsupported HTTP method")
    policy = _select_policy(policy_path, url, method)
    headers, body = _request_data(item)
    consumed_bindings = _binding_hashes(
        db_path, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        bindings=item.get("bindings"), url=url, headers=headers, body=body,
    )
    timeout_value = item.get("timeout_seconds", policy["limits"]["timeout_seconds"])
    if isinstance(timeout_value, bool) or not isinstance(timeout_value, (int, float)):
        raise RequestGuardError("timeout_seconds must be numeric")
    timeout = min(float(timeout_value), float(policy["limits"]["timeout_seconds"]))
    if not math.isfinite(timeout) or timeout <= 0:
        raise RequestGuardError("timeout_seconds must be positive")
    fingerprint = hashlib.sha256(json.dumps(
        [method, url, sorted((name.casefold(), value) for name, value in headers.items()),
         base64.b64encode(body or b"").decode("ascii")],
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    request_id, scheduled = _reserve(
        db_path, scan_id=scan_id, stage_run_id=stage_run_id, task_id=task_id,
        policy=policy, method=method, url=url, fingerprint=fingerprint,
    )
    delay = scheduled - time.time()
    if delay > 0:
        time.sleep(delay)
    with closing(sqlite3.connect(db_path)) as conn:
        state = conn.execute(
            """SELECT s.status,t.status FROM attack_http_requests r
               JOIN stage_runs s ON s.stage_run_id=r.stage_run_id
               JOIN attack_tasks t ON t.task_id=r.task_id WHERE r.request_id=?""",
            (request_id,),
        ).fetchone()
    if state != ("running", "running"):
        _set_status(
            db_path, request_id, status="failed",
            error_message="stage or task stopped before dispatch", finished_at=time.time(),
        )
        raise RequestGuardError("Attack stage or task stopped before dispatch")
    _set_status(db_path, request_id, status="running", dispatched_at=time.time())
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    request = Request(url, data=body, headers=headers, method=method)
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as exc:
            response = exc
        try:
            response_body = response.read(MAX_RESPONSE_BODY_BYTES + 1)
            truncated = len(response_body) > MAX_RESPONSE_BODY_BYTES
            response_body = response_body[:MAX_RESPONSE_BODY_BYTES]
            status_code = int(response.code if isinstance(response, HTTPError) else response.status)
            response_headers = _sanitized_headers(response.headers)
            final_url = str(response.geturl())
        finally:
            response.close()
    except Exception as exc:
        _set_status(
            db_path, request_id, status="outcome_unknown",
            error_message=type(exc).__name__, finished_at=time.time(),
        )
        raise RequestGuardError("HTTP request outcome is unknown") from exc
    try:
        result_metadata, captures, assertions = _response_metadata(
            item, status_code=status_code, response_headers=response.headers,
            response_body=response_body,
        )
    except Exception as exc:
        _set_status(
            db_path, request_id, status="failed", response_status=status_code,
            response_bytes=len(response_body), error_message=type(exc).__name__,
            finished_at=time.time(),
        )
        raise
    result_metadata["consumed_binding_hashes"] = consumed_bindings
    _set_status(
        db_path, request_id, status="completed", response_status=status_code,
        response_bytes=len(response_body),
        result_json=json.dumps(result_metadata, ensure_ascii=False, allow_nan=False),
        finished_at=time.time(),
    )
    text = response_body.decode("utf-8", errors="replace")
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS]
        truncated = True
    return {
        "request_id": request_id,
        "request_fingerprint": fingerprint,
        "status": status_code,
        "url": final_url,
        "response_headers": response_headers,
        "response_body": text,
        "response_bytes": len(response_body),
        "body_truncated": truncated,
        "redirect_followed": False,
        "captures": captures,
        "capture_hashes": result_metadata["capture_hashes"],
        "assertions": assertions,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("request", choices=["request"])
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--stage-run-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = guarded_request(
            args.db, scan_id=args.scan_id, stage_run_id=args.stage_run_id,
            task_id=args.task_id, policy_path=args.policy, payload_path=args.payload,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"aidast-request: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
