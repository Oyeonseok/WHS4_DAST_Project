"""Allowlisted external-tool contracts dispatched only through the Attack broker."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import uuid4

from aidast.core.http_safety import is_sensitive_header

from .request_cli import RequestGuardError, guarded_request


class ToolAdapterError(ValueError):
    pass


@dataclass(frozen=True)
class CompiledToolRun:
    adapter_id: str
    manifest_sha256: str
    requests: tuple[dict[str, Any], ...]
    summary: dict[str, Any]


_ADAPTERS = frozenset({"nuclei-http-template-v1", "sqlmap-payload-family-v1"})
_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
_BANNED_KEYS = frozenset({
    "args", "command", "exec", "executable", "interactsh", "network", "proxy",
    "raw", "script", "shell", "subprocess", "workflow",
})
_REQUEST_KEYS = frozenset({
    "method", "url", "headers", "body", "credential_reference_id",
    "risk_class", "authorization_envelope_id", "captures", "assertions",
})


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _reject_executable_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in _BANNED_KEYS:
                raise ToolAdapterError(f"external tool field is not allowed: {key}")
            _reject_executable_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_executable_fields(child)


def _request(item: object) -> dict[str, Any]:
    if not isinstance(item, dict) or not set(item) <= _REQUEST_KEYS:
        raise ToolAdapterError("adapter request has unsupported fields")
    method = str(item.get("method") or "GET").upper()
    url = item.get("url")
    if method not in _METHODS or not isinstance(url, str) or not 1 <= len(url) <= 8192:
        raise ToolAdapterError("adapter request method or URL is invalid")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ToolAdapterError("adapter request URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ToolAdapterError("adapter request URL must be an absolute credential-free HTTP URL")
    headers = item.get("headers") or {}
    if not isinstance(headers, dict) or len(headers) > 32:
        raise ToolAdapterError("adapter headers must be a bounded object")
    safe_headers: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str) or len(name) > 128 or len(value) > 4096:
            raise ToolAdapterError("adapter header is invalid")
        if is_sensitive_header(name):
            raise ToolAdapterError("adapter manifests cannot contain credential headers")
        safe_headers[name] = value
    body = item.get("body")
    if body is not None and (not isinstance(body, str) or len(body.encode()) > 16_384):
        raise ToolAdapterError("adapter request body is invalid")
    request: dict[str, Any] = {"method": method, "url": url}
    if safe_headers:
        request["headers"] = safe_headers
    if body is not None:
        request["body"] = body
    for key in (
        "credential_reference_id", "risk_class", "authorization_envelope_id",
        "captures", "assertions",
    ):
        if key in item:
            request[key] = item[key]
    return request


def compile_tool_manifest(manifest: object) -> CompiledToolRun:
    if not isinstance(manifest, dict):
        raise ToolAdapterError("tool manifest must be one object")
    raw = _canonical(manifest)
    if len(raw.encode()) > 100_000:
        raise ToolAdapterError("tool manifest exceeds the byte limit")
    _reject_executable_fields(manifest)
    adapter_id = manifest.get("adapter_id")
    if adapter_id not in _ADAPTERS:
        raise ToolAdapterError("tool adapter is not allowlisted")
    requests: list[dict[str, Any]] = []
    summary: dict[str, Any]
    if adapter_id == "nuclei-http-template-v1":
        rows = manifest.get("requests")
        template_id = manifest.get("template_id")
        if not isinstance(template_id, str) or not 1 <= len(template_id) <= 160:
            raise ToolAdapterError("nuclei adapter requires a bounded template_id")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 20:
            raise ToolAdapterError("nuclei adapter requires 1-20 requests")
        requests = [_request(row) for row in rows]
        summary = {"template_id": template_id, "request_count": len(requests)}
    else:
        family = manifest.get("payload_family")
        payloads = manifest.get("payloads")
        base = manifest.get("request")
        if family not in {"boolean", "error", "union", "time"}:
            raise ToolAdapterError("sqlmap adapter payload family is invalid")
        if not isinstance(payloads, list) or not 1 <= len(payloads) <= 12:
            raise ToolAdapterError("sqlmap adapter requires 1-12 payload variants")
        base_request = _request(base)
        if base_request["url"].count("{{PAYLOAD}}") != 1:
            raise ToolAdapterError("sqlmap adapter URL requires one {{PAYLOAD}} slot")
        for payload in payloads:
            if not isinstance(payload, str) or not payload or len(payload.encode()) > 512:
                raise ToolAdapterError("sqlmap payload variant is invalid")
            requests.append({
                **base_request,
                "url": base_request["url"].replace("{{PAYLOAD}}", quote(payload, safe="")),
            })
        summary = {"payload_family": family, "request_count": len(requests)}
    return CompiledToolRun(
        adapter_id=str(adapter_id),
        manifest_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        requests=tuple(requests), summary=summary,
    )


def execute_tool_adapter(
    db_path: Path, *, scan_id: str, stage_run_id: str, task_id: str,
    policy_path: Path, manifest: object,
) -> dict[str, Any]:
    """Run compiled requests sequentially; no subprocess or direct socket exists here."""
    compiled = compile_tool_manifest(manifest)
    tool_run_id = "tool_run_" + uuid4().hex
    database = Path(db_path).expanduser().resolve(strict=True)
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        owner = conn.execute(
            """SELECT s.status,t.status FROM stage_runs s JOIN attack_tasks t
                 ON t.stage_run_id=s.stage_run_id AND t.scan_id=s.scan_id
               WHERE s.stage_run_id=? AND s.scan_id=? AND t.task_id=?""",
            (stage_run_id, scan_id, task_id),
        ).fetchone()
        if owner != ("running", "running"):
            raise ToolAdapterError("tool adapter requires a running Attack task")
        conn.execute(
            """INSERT INTO attack_tool_runs
               (tool_run_id,scan_id,stage_run_id,task_id,adapter_id,
                manifest_sha256,planned_request_count,result_summary_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                tool_run_id, scan_id, stage_run_id, task_id, compiled.adapter_id,
                compiled.manifest_sha256, len(compiled.requests), _canonical(compiled.summary),
            ),
        )
        conn.commit()

    def broker_dispatch(request: dict[str, Any]) -> dict[str, Any]:
        # The temporary file only bridges the existing hardened CLI contract;
        # no external executable receives target network access.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".json", dir=database.parent,
            delete=False,
        ) as handle:
            handle.write(_canonical(request))
            payload_path = Path(handle.name)
        try:
            return guarded_request(
                database, scan_id=scan_id, stage_run_id=stage_run_id,
                task_id=task_id, policy_path=policy_path, payload_path=payload_path,
            )
        finally:
            payload_path.unlink(missing_ok=True)

    request_ids: list[str] = []
    statuses: list[int] = []
    try:
        for request in compiled.requests:
            result = broker_dispatch(dict(request))
            request_id = result.get("request_id") if isinstance(result, dict) else None
            status = result.get("status") if isinstance(result, dict) else None
            if not isinstance(request_id, str) or type(status) is not int:
                raise ToolAdapterError("broker adapter returned an invalid receipt")
            request_ids.append(request_id)
            statuses.append(status)
            with sqlite3.connect(database) as conn:
                conn.execute(
                    """UPDATE attack_tool_runs SET completed_request_count=?,
                       request_ids_json=? WHERE tool_run_id=?""",
                    (len(request_ids), _canonical(request_ids), tool_run_id),
                )
                conn.commit()
    except Exception as exc:
        with sqlite3.connect(database) as conn:
            unknown = conn.execute(
                """SELECT 1 FROM attack_http_requests
                   WHERE stage_run_id=? AND task_id=? AND status='outcome_unknown'
                   ORDER BY rowid DESC LIMIT 1""", (stage_run_id, task_id),
            ).fetchone()
            conn.execute(
                """UPDATE attack_tool_runs SET status=?,request_ids_json=?,
                   result_summary_json=?,error_code=?,finished_at=CURRENT_TIMESTAMP
                   WHERE tool_run_id=?""",
                (
                    "outcome_unknown" if unknown else "failed", _canonical(request_ids),
                    _canonical({**compiled.summary, "status_counts": {
                        str(code): statuses.count(code) for code in sorted(set(statuses))
                    }}), type(exc).__name__, tool_run_id,
                ),
            )
            conn.commit()
        if isinstance(exc, (ToolAdapterError, RequestGuardError)):
            raise
        raise ToolAdapterError("broker tool execution failed") from exc
    result_summary = {
        **compiled.summary,
        "status_counts": {str(code): statuses.count(code) for code in sorted(set(statuses))},
    }
    with sqlite3.connect(database) as conn:
        conn.execute(
            """UPDATE attack_tool_runs SET status='completed',completed_request_count=?,
               request_ids_json=?,result_summary_json=?,finished_at=CURRENT_TIMESTAMP
               WHERE tool_run_id=?""",
            (len(request_ids), _canonical(request_ids), _canonical(result_summary), tool_run_id),
        )
        conn.commit()
    return {
        "tool_run_id": tool_run_id, "adapter_id": compiled.adapter_id,
        "request_ids": request_ids, "summary": result_summary,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--stage-run-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = execute_tool_adapter(
            args.db, scan_id=args.scan_id, stage_run_id=args.stage_run_id,
            task_id=args.task_id, policy_path=args.policy, manifest=manifest,
        )
        print(_canonical(result))
        return 0
    except (OSError, json.JSONDecodeError, sqlite3.Error, ToolAdapterError, RequestGuardError) as exc:
        print(f"aidast-tool-adapter: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
