"""Private failure artifacts and read-only comparisons of persisted stage work.

These comparisons are diagnostic only. Unchanged task/attempt/finding records
do not establish that no HTTP requests or tools ran, and never authorize retries.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any


_TABLES = ("attack_tasks", "attack_attempts", "findings")

_MODEL_POLICY_REFUSAL_MARKERS = (
    "cybersecurity safety rejection",
    "cybersecurity review rejected",
    "flagged for possible cybersecurity risk",
    "model policy refusal",
    "safety policy refusal",
)

_MODEL_CAPACITY_MARKERS = (
    "selected model is at capacity",
    "selected model was at capacity",
    "selected model reached capacity",
    "selected model has reached capacity",
    "model is at capacity",
    "model was at capacity",
    "model reached capacity",
    "model has reached capacity",
    "model capacity is temporarily unavailable",
    "model capacity was temporarily unavailable",
)


def is_model_policy_refusal(message: str) -> bool:
    """Recognize bounded model safety refusals across transport summaries."""
    normalized = message.casefold()
    if any(marker in normalized for marker in _MODEL_POLICY_REFUSAL_MARKERS):
        return True
    # Native sub-agents sometimes paraphrase the transport error instead of
    # copying it verbatim.  Require both concepts so an ordinary application
    # safety-review finding is not mistaken for a model refusal.
    return (
        "cybersecurity risk" in normalized
        and "safety review" in normalized
        and any(marker in normalized for marker in ("flagged", "rejected", "refused"))
    )


def is_model_capacity_error(message: str) -> bool:
    """Recognize transient model-capacity failures without matching app limits."""
    normalized = message.casefold()
    return any(marker in normalized for marker in _MODEL_CAPACITY_MARKERS)


def persisted_work_snapshot(database: Path, *, scan_id: str, stage_run_id: str) -> dict[str, Any]:
    """Hash a consistent DB snapshot without retaining captured values or writing."""
    try:
        with closing(sqlite3.connect(Path(database).resolve(strict=True).as_uri() + "?mode=ro",
                                     uri=True, timeout=2)) as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            result: dict[str, Any] = {}
            for table in _TABLES:
                columns = tuple(row[1] for row in conn.execute(f"PRAGMA table_info({table})"))
                required = {"scan_id", "stage_run_id"} if table == "attack_tasks" else {"scan_id"}
                if not required.issubset(columns):
                    return {"available": False, "reason": "unsupported_schema"}
                where = "scan_id=?"
                parameters = (scan_id,)
                if table == "attack_tasks":
                    where += " AND stage_run_id=?"
                    parameters += (stage_run_id,)
                # Scan-wide attempt/finding comparison is conservative: work
                # committed by another stage also prevents a no-change claim.
                rows = conn.execute(f"SELECT * FROM {table} WHERE {where}", parameters)
                hashes = sorted(hashlib.sha256(json.dumps(
                    list(row), ensure_ascii=False, separators=(",", ":"),
                    default=lambda value: {"bytes_hex": value.hex()},
                ).encode()).hexdigest() for row in rows)
                payload = json.dumps([columns, hashes], separators=(",", ":")).encode()
                result[table] = {"count": len(hashes), "sha256": hashlib.sha256(payload).hexdigest()}
        return {"available": True, "tables": result}
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return {"available": False, "reason": "snapshot_unavailable"}


def compare_persisted_work(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Report persisted changes, keeping unavailable reads distinct from no change."""
    if not before.get("available") or not after.get("available"):
        return {"classification": "unknown", "changed_tables": []}
    changes = [table for table in _TABLES if before["tables"][table] != after["tables"][table]]
    return {"classification": "persisted_state_changed" if changes else "no_persisted_progress",
            "changed_tables": changes}


def preserve_native_failure(
    database: Path, *, scan_id: str, stage_run_id: str, event_text: str, stderr: str,
    failure_code: str, before: dict[str, Any], exit_code: int | None = None,
) -> dict[str, Any]:
    """Persist complete raw outputs privately; storage failure is diagnostic only."""
    after = persisted_work_snapshot(database, scan_id=scan_id, stage_run_id=stage_run_id)
    progress = compare_persisted_work(before, after)
    summary: dict[str, Any] = {"failure_code": failure_code, "exit_code": exit_code, **progress}
    try:
        root = Path(database).resolve(strict=True).parent / ".private-diagnostics"
        if root.is_symlink():
            raise OSError("diagnostic directory is a symlink")
        root.mkdir(mode=0o700, exist_ok=True)
        root.chmod(0o700)
        directory = Path(tempfile.mkdtemp(prefix="native-attack-", dir=root))
        artifacts: dict[str, Any] = {}
        for name, text in (("events.jsonl", event_text), ("stderr.txt", stderr)):
            raw = text.encode("utf-8")
            path = directory / name
            handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(handle, "wb") as output:
                output.write(raw)
            artifacts[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        manifest = {"schema_version": 1, "scan_id": scan_id, "stage_run_id": stage_run_id,
                    **summary, "comparison_scope": "stage_tasks_and_scan_attempts_findings",
                    "before": before, "after": after, "artifacts": artifacts}
        handle = os.open(directory / "failure.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(manifest, output, ensure_ascii=False, indent=2)
        # Paths are internal exception attributes, never part of the public error.
        return {"summary": summary, "directory": directory, "storage_error": None}
    except (OSError, ValueError, TypeError) as exc:
        return {"summary": summary, "directory": None, "storage_error": type(exc).__name__}
