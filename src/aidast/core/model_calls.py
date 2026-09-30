"""Metadata-only Codex invocation history, independent of pipeline audit events."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import subprocess
import time
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Protocol, TypeVar

_FIELDS = (
    "call_id", "state", "occurred_at", "scan_id", "stage", "stage_run_id",
    "task_id", "case_id", "scope_job_id", "operation_code", "invocation_kind",
    "requested_model", "elapsed_ms", "error_code", "input_tokens",
    "cached_input_tokens", "output_tokens", "usage_status",
)
_CORRELATION = ("scan_id", "stage", "stage_run_id", "task_id", "case_id", "scope_job_id")
_OPERATIONS = {
    "Scope collection": "scope_collection",
    "Scope page navigation": "scope_navigation",
    "Recon Plan generation": "recon_plan",
    "target policy generation": "target_policy",
    "offline Recon evidence review": "recon_review",
    "captured Scope interpretation": "scope_interpretation",
    "captured Scope grounding correction": "scope_grounding",
    "offline finding validation": "finding_validation",
    "offline report drafting": "report_draft",
    "legacy offline report drafting": "legacy_report_draft",
    "Attack hypothesis planning": "attack_hypotheses",
    "Attack evidence assessment": "attack_assessment",
    "blind Validation assessment": "validation_assessment",
    "Validation claim comparison": "validation_comparison",
    "Validation scope eligibility assessment": "validation_eligibility",
    "impact development planning": "impact_planning",
    "ffuf root selection": "ffuf_root_selection",
    "endpoint annotation": "endpoint_annotation",
}
_OPERATION_CODES = frozenset(_OPERATIONS.values()) | {
    "structured_other", "attack_orchestrator", "chaining_orchestrator",
}
_KINDS = {"structured", "session", "attack_orchestrator", "chaining_orchestrator"}
_USAGE_STATES = {"not_captured", "absent", "reported", "partial", "invalid", "ambiguous"}
_ERROR_CODES = {"timeout", "tool_unavailable", "io_error", "agent_error"}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS codex_call_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('started','success','error')),
    occurred_at TEXT NOT NULL,
    scan_id TEXT,
    stage TEXT,
    stage_run_id TEXT,
    task_id TEXT,
    case_id TEXT,
    scope_job_id TEXT,
    operation_code TEXT NOT NULL,
    invocation_kind TEXT NOT NULL,
    requested_model TEXT,
    elapsed_ms INTEGER,
    error_code TEXT,
    input_tokens INTEGER,
    cached_input_tokens INTEGER,
    output_tokens INTEGER,
    usage_status TEXT NOT NULL,
    UNIQUE(call_id,state)
);
CREATE UNIQUE INDEX IF NOT EXISTS codex_call_terminal
    ON codex_call_events(call_id) WHERE state IN ('success','error');
CREATE INDEX IF NOT EXISTS codex_call_scan ON codex_call_events(scan_id,event_id DESC);
CREATE TRIGGER IF NOT EXISTS codex_call_no_update BEFORE UPDATE ON codex_call_events
BEGIN SELECT RAISE(ABORT,'Codex call history is append-only'); END;
CREATE TRIGGER IF NOT EXISTS codex_call_no_delete BEFORE DELETE ON codex_call_events
BEGIN SELECT RAISE(ABORT,'Codex call history is append-only'); END;
"""
_logger = logging.getLogger(__name__)


def _validate_row(row: Mapping[str, object]) -> None:
    if not isinstance(row["call_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", row["call_id"]):
        raise ValueError("invalid model call ID")
    if row["state"] not in {"started", "success", "error"}:
        raise ValueError("invalid model call state")
    occurred = row["occurred_at"]
    if not isinstance(occurred, str) or len(occurred) > 40:
        raise ValueError("invalid model call time")
    try:
        timestamp = datetime.fromisoformat(occurred)
    except ValueError as exc:
        raise ValueError("invalid model call time") from exc
    if timestamp.tzinfo is None:
        raise ValueError("invalid model call time")
    for name in _CORRELATION:
        value = row[name]
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)
        ):
            raise ValueError("invalid model call identifier")
    model = row["requested_model"]
    if model is not None and (
        not isinstance(model, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", model)
        or "://" in model
    ):
        raise ValueError("invalid model identifier")
    if row["operation_code"] not in _OPERATION_CODES or row["invocation_kind"] not in _KINDS:
        raise ValueError("invalid model call operation")
    if row["usage_status"] not in _USAGE_STATES:
        raise ValueError("invalid model call usage")
    if row["error_code"] is not None and row["error_code"] not in _ERROR_CODES:
        raise ValueError("invalid model call error")
    for name in ("elapsed_ms", "input_tokens", "cached_input_tokens", "output_tokens"):
        value = row[name]
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("invalid model call count")


@dataclass(frozen=True)
class ModelCallEvent:
    call_id: str
    state: str
    occurred_at: str
    scan_id: str | None
    stage: str | None
    stage_run_id: str | None
    task_id: str | None
    case_id: str | None
    scope_job_id: str | None
    operation_code: str
    invocation_kind: str
    requested_model: str | None
    elapsed_ms: int | None
    error_code: str | None
    input_tokens: int | None
    cached_input_tokens: int | None
    output_tokens: int | None
    usage_status: str


class ModelCallSink(Protocol):
    def append(self, event: ModelCallEvent) -> None: ...


class SQLiteModelCallSink:
    def __init__(self, result_root: Path) -> None:
        self.path = Path(result_root) / "logs" / "CodexCalls.db"

    def append(self, event: ModelCallEvent) -> None:
        values = tuple(getattr(event, field) for field in _FIELDS)
        _validate_row(dict(zip(_FIELDS, values)))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=3) as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                f"INSERT INTO codex_call_events ({','.join(_FIELDS)}) "
                f"VALUES ({','.join('?' for _ in _FIELDS)})",
                values,
            )


_sink: ContextVar[ModelCallSink | None] = ContextVar("model_call_sink", default=None)
_context: ContextVar[dict[str, str | None] | None] = ContextVar("model_call_context", default=None)
_usage: ContextVar[dict[str, int | str | None] | None] = ContextVar("model_call_usage", default=None)


@contextmanager
def using_model_call_sink(sink: ModelCallSink | None) -> Iterator[None]:
    token = _sink.set(sink)
    try:
        yield
    finally:
        _sink.reset(token)


@contextmanager
def model_call_context(**identifiers: str | None) -> Iterator[None]:
    if set(identifiers) - set(_CORRELATION):
        raise ValueError("unknown model call correlation")
    current = _context.get() or {}
    values = dict(current)
    if "scan_id" in identifiers and identifiers["scan_id"] != current.get("scan_id"):
        values.update({name: None for name in _CORRELATION if name != "scan_id"})
    elif "stage" in identifiers and identifiers["stage"] != current.get("stage"):
        values.update({name: None for name in ("stage_run_id", "task_id", "case_id")})
    values.update(identifiers)
    token = _context.set(values)
    try:
        yield
    finally:
        _context.reset(token)


def record_session_usage(events: list[dict], *, resumed: bool = False) -> None:
    usage = _usage.get()
    if usage is None:
        return
    completed = [event.get("usage") for event in events if event.get("type") == "turn.completed"]
    if len(completed) > 1:
        usage["usage_status"] = "ambiguous"
        return
    if not completed:
        usage["usage_status"] = "absent"
        return
    if resumed:
        # Codex reports thread totals on resume; without the prior thread
        # baseline this invocation cannot be added without double counting.
        usage["usage_status"] = "ambiguous"
        return
    raw = completed[0]
    if not isinstance(raw, dict):
        usage["usage_status"] = "invalid"
        return
    names = ("input_tokens", "cached_input_tokens", "output_tokens")
    for name in names:
        value = raw.get(name)
        if value is not None and (type(value) is not int or value < 0):
            usage["usage_status"] = "invalid"
            return
    usage.update({name: raw.get(name) for name in names})
    usage["usage_status"] = "reported" if all(raw.get(name) is not None for name in names) else "partial"


def record_jsonl_usage(lines: Iterable[str]) -> None:
    completed = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("type") == "turn.completed":
            completed.append({"type": "turn.completed", "usage": event.get("usage")})
    record_session_usage(completed)


def _append(sink: ModelCallSink, event: ModelCallEvent) -> None:
    try:
        sink.append(event)
    except (OSError, sqlite3.Error, ValueError):
        _logger.warning("Model call telemetry unavailable")


ResultT = TypeVar("ResultT")


def logged_model_call(kind: str, *, model_attribute: str) -> Callable[[Callable[..., ResultT]], Callable[..., ResultT]]:
    def decorate(method: Callable[..., ResultT]) -> Callable[..., ResultT]:
        @wraps(method)
        def invoke(self: object, *args: object, **kwargs: object) -> ResultT:
            sink = _sink.get()
            if sink is None:
                return method(self, *args, **kwargs)
            context = dict(_context.get() or {})
            if kind in {"attack_orchestrator", "chaining_orchestrator"}:
                context.update({
                    "stage": "Attack" if kind == "attack_orchestrator" else "Chaining",
                    "task_id": None, "case_id": None, "scope_job_id": None,
                })
            for name in ("scan_id", "stage_run_id"):
                if isinstance(kwargs.get(name), str):
                    context[name] = kwargs[name]
            operation = kwargs.get("operation")
            code = (
                "attack_orchestrator" if kind == "attack_orchestrator"
                else "chaining_orchestrator" if kind == "chaining_orchestrator"
                else _OPERATIONS.get(operation, "structured_other")
            )
            model = getattr(self, model_attribute, None)
            model = model if isinstance(model, str) else None
            call_id = uuid.uuid4().hex
            started = time.monotonic_ns()
            timing: dict[str, int | str | None] = {"usage_status": "not_captured"}
            token = _usage.set(timing)

            def event(state: str, error_code: str | None = None) -> ModelCallEvent:
                return ModelCallEvent(
                    call_id=call_id, state=state,
                    occurred_at=datetime.now(UTC).isoformat(),
                    scan_id=context.get("scan_id"), stage=context.get("stage"),
                    stage_run_id=context.get("stage_run_id"), task_id=context.get("task_id"),
                    case_id=context.get("case_id"), scope_job_id=context.get("scope_job_id"),
                    operation_code=code, invocation_kind=kind, requested_model=model,
                    elapsed_ms=(time.monotonic_ns() - started) // 1_000_000 if state != "started" else None,
                    error_code=error_code,
                    input_tokens=timing.get("input_tokens") if state != "started" else None,
                    cached_input_tokens=timing.get("cached_input_tokens") if state != "started" else None,
                    output_tokens=timing.get("output_tokens") if state != "started" else None,
                    usage_status=str(timing["usage_status"]) if state != "started" else "not_captured",
                )

            try:
                _append(sink, event("started"))
                try:
                    result = method(self, *args, **kwargs)
                except Exception as exc:
                    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
                        reason = "timeout"
                    elif isinstance(exc, FileNotFoundError):
                        reason = "tool_unavailable"
                    elif isinstance(exc, OSError):
                        reason = "io_error"
                    else:
                        reason = "agent_error"
                    _append(sink, event("error", reason))
                    raise
                _append(sink, event("success"))
                return result
            finally:
                _usage.reset(token)

        return invoke
    return decorate


def read_model_call_events(
    result_root: Path, *, before: int | None = None, limit: int = 100,
) -> tuple[list[dict], int | None]:
    if not 1 <= limit <= 200 or before is not None and (type(before) is not int or before < 1):
        raise ValueError("invalid model call cursor")
    database = Path(result_root) / "logs" / "CodexCalls.db"
    if not database.is_file():
        return [], None
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=3) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT event_id,{','.join(_FIELDS)} FROM codex_call_events "
            "WHERE (? IS NULL OR event_id < ?) ORDER BY event_id DESC LIMIT ?",
            (before, before, limit + 1),
        ).fetchall()
    events = [dict(row) for row in rows[:limit]]
    try:
        for event in events:
            _validate_row(event)
    except ValueError as exc:
        raise sqlite3.DatabaseError("invalid model call history") from exc
    next_before = events[-1]["event_id"] if len(rows) > limit else None
    return events, next_before


_SCAN_STAGES = ("Recon", "Attack", "Chaining", "Validation", "Report")
_TOKEN_FIELDS = (
    "input_tokens", "output_tokens", "total_tokens", "measured_calls", "unreported_calls",
)


def read_scan_token_usage(result_root: Path, scan_id: str) -> dict:
    def empty() -> dict[str, int]:
        return {field: 0 for field in _TOKEN_FIELDS}

    stages = {stage: empty() for stage in _SCAN_STAGES}
    unattributed = empty()
    database = Path(result_root) / "logs" / "CodexCalls.db"
    if database.is_file():
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=3) as conn:
            rows = conn.execute(
                """SELECT stage,
                    SUM(CASE WHEN input_tokens IS NOT NULL AND output_tokens IS NOT NULL
                        THEN input_tokens ELSE 0 END) AS input_tokens,
                    SUM(CASE WHEN input_tokens IS NOT NULL AND output_tokens IS NOT NULL
                        THEN output_tokens ELSE 0 END) AS output_tokens,
                    SUM(CASE WHEN input_tokens IS NOT NULL AND output_tokens IS NOT NULL
                        THEN input_tokens + output_tokens ELSE 0 END) AS total_tokens,
                    SUM(CASE WHEN input_tokens IS NOT NULL AND output_tokens IS NOT NULL
                        THEN 1 ELSE 0 END) AS measured_calls,
                    SUM(CASE WHEN input_tokens IS NULL OR output_tokens IS NULL
                        THEN 1 ELSE 0 END) AS unreported_calls
                FROM codex_call_events AS event
                JOIN (
                    SELECT call_id, MAX(event_id) AS event_id
                    FROM codex_call_events WHERE scan_id=? GROUP BY call_id
                ) AS latest ON event.event_id=latest.event_id
                WHERE event.stage IS NULL OR event.stage != 'Scope'
                GROUP BY event.stage""",
                (scan_id,),
            ).fetchall()
        for stage, *values in rows:
            if any(type(value) is not int or value < 0 for value in values):
                raise sqlite3.DatabaseError("invalid scan token usage")
            bucket = stages.get(stage, unattributed)
            bucket.update(zip(_TOKEN_FIELDS, values))
    total = {field: sum(bucket[field] for bucket in (*stages.values(), unattributed))
             for field in _TOKEN_FIELDS}
    return {
        "scan_id": scan_id, "total": total,
        "stages": stages, "unattributed": unattributed,
    }
