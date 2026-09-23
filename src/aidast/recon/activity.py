"""Small allowlisted Recon activity records for the operator dashboard."""

from __future__ import annotations

from typing import Any


TASK_PHASES = frozenset({
    "asset_discovery", "dns_resolution", "host_port_discovery",
    "http_probe", "origin_discovery", "endpoint_discovery",
})
TOOL_PHASES = frozenset({
    "subfinder", "dnsx", "naabu", "nmap",
    "playwright_bootstrap", "playwright_priority", "katana_standard",
    "katana_headless", "playwright_interaction", "ffuf",
    "api_secondary", "openapi_detection", "graphql_detection",
    "zap_openapi", "zap_graphql", "mitm_capture",
})
PHASES = TASK_PHASES | TOOL_PHASES
STATES = frozenset({"started", "finished", "skipped", "failed", "planned"})
STOP_REASONS = frozenset({"time_limit", "action_limit", "page_limit", "completed"})


def _bounded_number(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


def activity_from_diagnostic(event: str, details: dict[str, object]) -> dict[str, str | int] | None:
    """Discard URLs, headers, errors and arbitrary tool output before persistence."""
    phase: object = details.get("phase")
    state: str | None = None
    if event in {"task_started", "task_completed", "task_failed"}:
        phase = details.get("task_type")
        if not isinstance(phase, str):
            return None
        phase = phase.lower()
        if phase not in TASK_PHASES:
            return None
        state = {"task_started": "started", "task_completed": "finished", "task_failed": "failed"}[event]
    elif event in {"phase_started", "phase_completed", "phase_skipped", "phase_error"}:
        if not isinstance(phase, str) or phase not in TOOL_PHASES:
            return None
        state = {"phase_started": "started", "phase_completed": "finished", "phase_skipped": "skipped", "phase_error": "failed"}[event]
    elif event == "proxy_started":
        phase = "mitm_capture"
        state = "started" if details.get("available") is True else "failed"
    elif event == "proxy_capture_ingested":
        phase, state = "mitm_capture", "finished"
    elif event == "ffuf_roots":
        phase, state = "ffuf", "planned"
    elif event in {"ffuf_root_started", "ffuf_root_finished"}:
        phase = "ffuf"
        state = "started" if event == "ffuf_root_started" else "finished"
    else:
        return None
    if not isinstance(phase, str) or phase not in PHASES or state not in STATES:
        return None
    record: dict[str, str | int] = {"phase": str(phase), "state": state}
    for key in ("count", "root_count", "index", "total", "allowed_count", "blocked_count", "duplicate_count"):
        value = _bounded_number(details.get(key))
        if value is not None:
            record[key] = value
    reason = details.get("reason")
    if phase in {"playwright_priority", "playwright_interaction"} and isinstance(reason, str) and reason in STOP_REASONS:
        record["reason"] = reason
    return record


def validated_activity(value: Any) -> dict[str, str | int] | None:
    """Revalidate persisted details before exposing them through the API."""
    if not isinstance(value, dict):
        return None
    phase, state = value.get("phase"), value.get("state")
    if not isinstance(phase, str) or phase not in PHASES or not isinstance(state, str) or state not in STATES:
        return None
    record: dict[str, str | int] = {"phase": value["phase"], "state": value["state"]}
    for key in ("count", "root_count", "index", "total", "allowed_count", "blocked_count", "duplicate_count"):
        number = _bounded_number(value.get(key))
        if number is not None:
            record[key] = number
    reason = value.get("reason")
    if phase in {"playwright_priority", "playwright_interaction"} and isinstance(reason, str) and reason in STOP_REASONS:
        record["reason"] = reason
    return record
