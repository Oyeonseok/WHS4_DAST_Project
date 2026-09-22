"""Project persisted AI DAST state into the WebUI snapshot/event contract.

The projector never writes to Recon.db or Pipeline.db.  A separate derived
event ledger provides durable, per-scan replay cursors for WebSocket clients.
It is an observability cache, not an execution state machine.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STAGES = ("Scope", "Recon", "Attack", "Chaining", "Validation", "Report")
_RECON_ACTIVITY = {
    "ASSET_DISCOVERY": "Asset discovery",
    "DNS_RESOLUTION": "DNS resolution",
    "HOST_PORT_DISCOVERY": "Host and port discovery",
    "HTTP_PROBE": "HTTP probing",
    "ORIGIN_DISCOVERY": "Origin discovery",
    "ENDPOINT_DISCOVERY": "Endpoint discovery",
}
_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_STAGE_MAP = {
    "scope": "Scope",
    "recon": "Recon",
    "tagging": "Recon",
    "handoff": "Recon",
    "offline_review": "Attack",
    "attack": "Attack",
    "chaining": "Chaining",
    "validation": "Validation",
    "report": "Report",
}
_STATUS_MAP = {
    "pending": "pending",
    "created": "pending",
    "ready": "pending",
    "awaiting_approval": "pending",
    "running": "running",
    "planning": "running",
    "verifying_handoff": "running",
    "completed": "completed",
    "completed_with_errors": "completed",
    "failed": "failed",
    "blocked": "failed",
    "paused": "cancelled",
    "cancelled": "cancelled",
    "skipped": "completed",
}


class ProjectionError(RuntimeError):
    """Base error for safe dashboard projections."""


class ScanNotFoundError(ProjectionError):
    """The selected scan has no supported persisted database."""


@dataclass(frozen=True)
class ScopeInfo:
    approved: bool = False
    scope_id: str = ""
    program_name: str = ""
    program_id: str = ""
    budget: int = 0


def _utc(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if raw.endswith("Z"):
        return raw
    try:
        parsed = datetime.fromisoformat(raw.replace(" ", "T"))
    except ValueError:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_object(value: Any) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _stage(value: Any) -> str:
    return _STAGE_MAP.get(str(value or "").strip().lower(), "Recon")


def _status(value: Any) -> str:
    return _STATUS_MAP.get(str(value or "").strip().lower(), "pending")


def _level(event_type: str) -> str:
    lowered = event_type.lower()
    if any(word in lowered for word in ("failed", "invalid", "error")):
        return "error"
    if any(word in lowered for word in ("cancelled", "blocked", "denied", "expired")):
        return "warning"
    if any(word in lowered for word in ("completed", "confirmed", "approved")):
        return "success"
    return "info"


def _audit_message(event_type: str) -> str:
    # Never interpolate details_json, URLs, headers, bodies, or credentials.
    readable = event_type.replace("_", " ").replace(".", " · ").strip()
    return f"Pipeline event · {readable[:180]}"


class DashboardProjector:
    """Read source databases and maintain a sanitized replay ledger."""

    def __init__(
        self,
        result_root: Path,
        *,
        event_database: Path | None = None,
        database: Path | None = None,
    ) -> None:
        self.result_root = result_root.expanduser().resolve()
        self.event_database = (
            event_database or self.result_root / ".webui" / "events.db"
        ).expanduser().resolve()
        self.database = database.expanduser().resolve() if database else None
        self._lock = threading.RLock()
        self.event_database.parent.mkdir(parents=True, exist_ok=True)
        self._init_events()

    def _init_events(self) -> None:
        with closing(sqlite3.connect(self.event_database)) as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=DELETE;
                CREATE TABLE IF NOT EXISTS web_events (
                    scan_id TEXT NOT NULL,
                    event_id INTEGER NOT NULL CHECK(event_id > 0),
                    source_key TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
                    PRIMARY KEY(scan_id, event_id),
                    UNIQUE(scan_id, source_key)
                );
                CREATE TABLE IF NOT EXISTS web_projection_state (
                    scan_id TEXT PRIMARY KEY NOT NULL,
                    state_json TEXT NOT NULL CHECK(json_valid(state_json)),
                    updated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def validate_scan_id(scan_id: str) -> str:
        if not _SCAN_ID.fullmatch(scan_id):
            raise ScanNotFoundError("invalid scan identifier")
        return scan_id

    def _inside_root(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.result_root)
            return True
        except ValueError:
            return False

    def locate_database(self, scan_id: str) -> Path:
        self.validate_scan_id(scan_id)
        candidates: list[Path] = []
        if self.database is not None:
            candidates.append(self.database)
        candidates.extend(
            (
                self.result_root / "AttackRuns" / scan_id / "Pipeline.db",
                self.result_root / "Runs" / scan_id / "Pipeline.db",
                self.result_root / "Runs" / scan_id / "Recon.db",
                self.result_root / "ValidationRuns" / scan_id / "Pipeline.db",
            )
        )
        for candidate in candidates:
            if not candidate.is_file():
                continue
            if self.database is None and not self._inside_root(candidate):
                continue
            try:
                with closing(self._source(candidate)) as conn:
                    if conn.execute(
                        "SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)
                    ).fetchone():
                        return candidate.resolve()
            except sqlite3.Error:
                continue
        raise ScanNotFoundError(f"scan database not found: {scan_id}")

    def _source(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _scope_info(self, scope_id: str) -> ScopeInfo:
        if not scope_id:
            return ScopeInfo()
        scope_root = self.result_root / "Scope"
        if not scope_root.is_dir():
            return ScopeInfo(scope_id=scope_id)
        for scope_path in scope_root.glob("*/*/Scope.json"):
            try:
                raw = scope_path.read_bytes()
                document = json.loads(raw)
                if document.get("scope_id") != scope_id:
                    continue
                approval_path = scope_path.with_name("Approval.json")
                approval = json.loads(approval_path.read_text(encoding="utf-8"))
                digest = hashlib.sha256(raw).hexdigest()
                approved = (
                    approval.get("scope_id") == scope_id
                    and approval.get("scope_json_sha256") == digest
                )
                policy_path = scope_path.with_name("TargetPolicy.json")
                budget = 0
                if policy_path.is_file():
                    policy = json.loads(policy_path.read_text(encoding="utf-8"))
                    values = [
                        int(item.get("limits", {}).get("max_requests", 0))
                        for item in policy.get("policies", [])
                        if isinstance(item, dict)
                    ]
                    budget = sum(value for value in values if value > 0)
                relative = scope_path.relative_to(scope_root)
                platform, slug = relative.parts[:2]
                platform_prefix = {
                    "hackerone": "h1",
                    "yeswehack": "ywh",
                }.get(platform, platform)
                program_id = f"{platform_prefix}-{slug.replace('_', '-')}"
                program_name = (
                    "PRISM VDP"
                    if program_id == "h1-prism-vdp"
                    else str(document.get("analysis", {}).get("program_name") or slug)[:160]
                )
                return ScopeInfo(approved, scope_id, program_name, program_id, budget)
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return ScopeInfo(scope_id=scope_id)

    def _read_state(
        self, conn: sqlite3.Connection, scan_id: str
    ) -> tuple[dict[str, Any], list[sqlite3.Row]]:
        tables = _tables(conn)
        if "scans" not in tables:
            raise ScanNotFoundError("database has no scans table")
        scan = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if scan is None:
            raise ScanNotFoundError(f"unknown scan: {scan_id}")
        scan_columns = set(scan.keys())
        scope = self._scope_info(str(scan["scope_value"]) if "scope_value" in scan_columns else "")

        stages: list[sqlite3.Row] = []
        if "stage_runs" in tables:
            stages = list(
                conn.execute(
                    """SELECT rowid,* FROM stage_runs WHERE scan_id=?
                    ORDER BY COALESCE(started_at,created_at),rowid""",
                    (scan_id,),
                )
            )
        active = next((row for row in reversed(stages) if row["status"] == "running"), None)
        current = active or (stages[-1] if stages else None)
        stage_name = _stage(current["stage"] if current else "recon")
        activity: str | None = None
        if stage_name == "Recon" and current is not None and current["status"] == "running":
            activity = "Preparing Recon"
            if "pipeline_runs" in tables:
                active_task = conn.execute(
                    """SELECT p.stage FROM pipeline_runs p
                    WHERE p.scan_id=? AND p.status='running' AND p.task_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM pipeline_runs terminal
                        WHERE terminal.scan_id=p.scan_id AND terminal.task_id=p.task_id
                        AND terminal.rowid>p.rowid
                        AND terminal.status IN ('success','failed','skipped','completed')
                    ) ORDER BY p.rowid DESC LIMIT 1""",
                    (scan_id,),
                ).fetchone()
                if active_task is not None:
                    activity = _RECON_ACTIVITY.get(str(active_task["stage"]).upper(), "Running Recon task")
                elif conn.execute(
                    "SELECT 1 FROM pipeline_runs WHERE scan_id=? LIMIT 1", (scan_id,)
                ).fetchone():
                    activity = "Processing Recon results"

        task_total = task_done = 0
        if current is not None and "attack_tasks" in tables:
            task_total = int(
                conn.execute(
                    "SELECT count(*) FROM attack_tasks WHERE stage_run_id=?",
                    (current["stage_run_id"],),
                ).fetchone()[0]
            )
            task_done = int(
                conn.execute(
                    """SELECT count(*) FROM attack_tasks WHERE stage_run_id=?
                    AND status IN ('completed','skipped')""",
                    (current["stage_run_id"],),
                ).fetchone()[0]
            )
        if current is not None and current["status"] in {"completed", "skipped"}:
            progress = 100
        elif task_total:
            progress = round(task_done / task_total * 100)
        else:
            progress = 0

        requests = 0
        for table in ("http_transactions", "attack_http_requests", "validation_http_requests"):
            if table in tables:
                columns = _columns(conn, table)
                if "scan_id" in columns:
                    requests += int(
                        conn.execute(f"SELECT count(*) FROM {table} WHERE scan_id=?", (scan_id,)).fetchone()[0]
                    )
                elif (
                    table == "http_transactions"
                    and "endpoint_id" in columns
                    and {"endpoints", "origins", "assets"}.issubset(tables)
                ):
                    requests += int(
                        conn.execute(
                            """SELECT count(*) FROM http_transactions h
                            JOIN endpoints e ON e.endpoint_id=h.endpoint_id
                            JOIN origins o ON o.origin_id=e.origin_id
                            JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?""",
                            (scan_id,),
                        ).fetchone()[0]
                    )

        endpoints = 0
        if "endpoints" in tables:
            if "assets" in tables and "origins" in tables:
                endpoints = int(
                    conn.execute(
                        """SELECT count(*) FROM endpoints e
                        JOIN origins o ON o.origin_id=e.origin_id
                        JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?""",
                        (scan_id,),
                    ).fetchone()[0]
                )
            else:
                endpoints = int(conn.execute("SELECT count(*) FROM endpoints").fetchone()[0])

        findings: list[dict[str, Any]] = []
        if "findings" in tables:
            has_endpoints = "endpoints" in tables
            query = """SELECT f.finding_id,f.title,f.severity,f.status,f.cwe_id,f.endpoint_id"""
            if has_endpoints:
                query += ",e.method,e.normalized_path FROM findings f LEFT JOIN endpoints e ON e.endpoint_id=f.endpoint_id"
            else:
                query += ",NULL AS method,NULL AS normalized_path FROM findings f"
            query += " WHERE f.scan_id=? ORDER BY f.created_at DESC LIMIT 500"
            for row in conn.execute(query, (scan_id,)):
                endpoint = " ".join(
                    part for part in (str(row["method"] or ""), str(row["normalized_path"] or "")) if part
                ) or str(row["endpoint_id"] or "unavailable")
                findings.append(
                    {
                        "id": str(row["finding_id"])[:256],
                        "title": str(row["title"])[:500],
                        "severity": str(row["severity"]),
                        "status": str(row["status"]),
                        "endpoint": endpoint[:1000],
                        "cwe": str(row["cwe_id"] or "Unclassified")[:128],
                    }
                )

        audits: list[sqlite3.Row] = []
        if "audit_events" in tables:
            audits = list(
                conn.execute(
                    """SELECT a.rowid,a.audit_event_id,a.event_type,a.created_at,
                    COALESCE(s.stage,'recon') AS stage
                    FROM audit_events a LEFT JOIN stage_runs s
                    ON s.stage_run_id=a.stage_run_id
                    WHERE a.scan_id=? ORDER BY a.rowid""",
                    (scan_id,),
                )
            )

        state = {
            "version": 1,
            "scan_id": scan_id,
            "status": _status(
                current["status"] if current is not None and stage_name == "Report"
                else scan["status"] if "status" in scan_columns else "pending"
            ),
            "stage": stage_name,
            "progress": progress,
            "activity": activity,
            "requests": requests,
            "budget": scope.budget,
            "endpoints": endpoints,
            "findings": findings,
            "scope_approved": scope.approved,
            "scope_id": scope.scope_id,
            "program_id": scope.program_id,
            "program_name": scope.program_name,
        }
        return state, audits

    def audit_log(self, scan_id: str) -> list[dict[str, str]]:
        """Return an authoritative, deliberately metadata-only audit view."""
        database = self.locate_database(scan_id)
        with closing(self._source(database)) as conn:
            _state, audits = self._read_state(conn, scan_id)
        return [
            {
                "id": str(row["audit_event_id"])[:256],
                "event_type": str(row["event_type"])[:256],
                "stage": _stage(row["stage"]),
                "created_at": _utc(row["created_at"]),
            }
            for row in reversed(audits[-500:])
        ]

    @staticmethod
    def _next_id(conn: sqlite3.Connection, scan_id: str) -> int:
        return int(
            conn.execute(
                "SELECT COALESCE(max(event_id),0)+1 FROM web_events WHERE scan_id=?",
                (scan_id,),
            ).fetchone()[0]
        )

    def _append(
        self,
        conn: sqlite3.Connection,
        *,
        scan_id: str,
        source_key: str,
        occurred_at: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        conn.execute(
            """INSERT OR IGNORE INTO web_events
            (scan_id,event_id,source_key,occurred_at,event_type,payload_json)
            VALUES (?,?,?,?,?,?)""",
            (
                scan_id,
                self._next_id(conn, scan_id),
                source_key,
                occurred_at,
                event_type,
                json.dumps(payload, ensure_ascii=False, allow_nan=False),
            ),
        )

    def record_event(
        self,
        scan_id: str,
        *,
        source_key: str,
        event_type: str,
        payload: dict[str, Any],
        occurred_at: str | None = None,
    ) -> None:
        """Append a pre-projection event whose payload is already sanitized."""
        self.validate_scan_id(scan_id)
        with self._lock, closing(sqlite3.connect(self.event_database)) as conn, conn:
            self._append(
                conn,
                scan_id=scan_id,
                source_key=source_key,
                occurred_at=_utc(occurred_at),
                event_type=event_type,
                payload=payload,
            )

    def stored_events_after(self, scan_id: str, after: int) -> list[dict[str, Any]]:
        """Replay durable events without requiring a pipeline database yet."""
        self.validate_scan_id(scan_id)
        if after < 0:
            raise ProjectionError("event cursor must be non-negative")
        with self._lock, closing(sqlite3.connect(self.event_database)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT event_id,occurred_at,event_type,payload_json FROM web_events
                WHERE scan_id=? AND event_id>? ORDER BY event_id LIMIT 256""",
                (scan_id, after),
            ).fetchall()
        return [
            {
                "version": 1,
                "event_id": int(row["event_id"]),
                "scan_id": scan_id,
                "occurred_at": row["occurred_at"],
                "type": row["event_type"],
                "payload": _json_object(row["payload_json"]),
            }
            for row in rows
        ]

    def _sync(
        self,
        event_conn: sqlite3.Connection,
        scan_id: str,
        state: dict[str, Any],
        audits: list[sqlite3.Row],
    ) -> None:
        for row in audits:
            self._append(
                event_conn,
                scan_id=scan_id,
                source_key=f"audit:{row['audit_event_id']}",
                occurred_at=_utc(row["created_at"]),
                event_type="log.appended",
                payload={
                    "stage": _stage(row["stage"]),
                    "level": _level(str(row["event_type"])),
                    "message": _audit_message(str(row["event_type"])),
                },
            )

        previous_row = event_conn.execute(
            "SELECT state_json FROM web_projection_state WHERE scan_id=?", (scan_id,)
        ).fetchone()
        previous = _json_object(previous_row[0]) if previous_row else {}
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if previous:
            changes: list[tuple[str, dict[str, Any]]] = []
            if state["stage"] != previous.get("stage"):
                changes.append(("stage.status.changed", {"stage": state["stage"]}))
            if state["status"] != previous.get("status"):
                changes.append(("scan.status.changed", {"status": state["status"]}))
            if (state["progress"], state["requests"], state["activity"]) != (
                previous.get("progress"), previous.get("requests"), previous.get("activity")
            ):
                changes.append(
                    (
                        "task.progress.updated",
                        {"progress": state["progress"], "requests": state["requests"], "activity": state["activity"]},
                    )
                )
            old_findings = {item.get("id"): item for item in previous.get("findings", [])}
            for finding in state["findings"]:
                if old_findings.get(finding["id"]) != finding:
                    changes.append(("finding.updated", finding))
            for event_type, payload in changes:
                sequence = self._next_id(event_conn, scan_id)
                self._append(
                    event_conn,
                    scan_id=scan_id,
                    source_key=f"projection:{sequence}",
                    occurred_at=now,
                    event_type=event_type,
                    payload=payload,
                )
        serialized = json.dumps(state, ensure_ascii=False, allow_nan=False, sort_keys=True)
        event_conn.execute(
            """INSERT INTO web_projection_state(scan_id,state_json,updated_at)
            VALUES (?,?,?) ON CONFLICT(scan_id) DO UPDATE SET
            state_json=excluded.state_json,updated_at=excluded.updated_at""",
            (scan_id, serialized, now),
        )

    def snapshot(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            database = self.locate_database(scan_id)
            with closing(self._source(database)) as source:
                state, audits = self._read_state(source, scan_id)
            with closing(sqlite3.connect(self.event_database)) as events, events:
                events.row_factory = sqlite3.Row
                self._sync(events, scan_id, state, audits)
                last_event_id = int(
                    events.execute(
                        "SELECT COALESCE(max(event_id),0) FROM web_events WHERE scan_id=?",
                        (scan_id,),
                    ).fetchone()[0]
                )
                logs = [
                    {
                        "id": int(row["event_id"]),
                        "time": row["occurred_at"],
                        "stage": _json_object(row["payload_json"]).get("stage", "Recon"),
                        "level": _json_object(row["payload_json"]).get("level", "info"),
                        "message": _json_object(row["payload_json"]).get("message", "Pipeline event"),
                    }
                    for row in events.execute(
                        """SELECT event_id,occurred_at,payload_json FROM web_events
                        WHERE scan_id=? AND event_type='log.appended'
                        ORDER BY event_id DESC LIMIT 500""",
                        (scan_id,),
                    ).fetchall()[::-1]
                ]
            return {**state, "last_event_id": last_event_id, "logs": logs}

    def events_after(self, scan_id: str, after: int) -> list[dict[str, Any]]:
        if after < 0:
            raise ProjectionError("event cursor must be non-negative")
        self.snapshot(scan_id)
        return self.stored_events_after(scan_id, after)

    def cursor(self, scan_id: str) -> int:
        with self._lock, closing(sqlite3.connect(self.event_database)) as conn:
            return int(
                conn.execute(
                    "SELECT COALESCE(max(event_id),0) FROM web_events WHERE scan_id=?",
                    (scan_id,),
                ).fetchone()[0]
            )

    def list_scans(self) -> list[dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        roots = (
            (self.result_root / "Runs", ("Pipeline.db", "Recon.db")),
            (self.result_root / "AttackRuns", ("Pipeline.db",)),
            (self.result_root / "ValidationRuns", ("Pipeline.db",)),
        )
        for root, names in roots:
            if not root.is_dir():
                continue
            for directory in root.iterdir():
                if not directory.is_dir() or not _SCAN_ID.fullmatch(directory.name):
                    continue
                for name in names:
                    database = directory / name
                    if not database.is_file() or not self._inside_root(database):
                        continue
                    try:
                        with closing(self._source(database)) as conn:
                            row = conn.execute(
                                "SELECT scan_id,status,started_at,finished_at FROM scans WHERE scan_id=?",
                                (directory.name,),
                            ).fetchone()
                            if row:
                                report_row = None
                                if "stage_runs" in _tables(conn):
                                    report_row = conn.execute(
                                        """SELECT status,finished_at FROM stage_runs
                                        WHERE scan_id=? AND lower(stage)='report'
                                        ORDER BY rowid DESC LIMIT 1""",
                                        (directory.name,),
                                    ).fetchone()
                                status = report_row["status"] if report_row else row["status"]
                                finished_at = report_row["finished_at"] if report_row else row["finished_at"]
                                found[row["scan_id"]] = {
                                    "scan_id": row["scan_id"],
                                    "status": _status(status),
                                    "started_at": _utc(row["started_at"]),
                                    "finished_at": _utc(finished_at) if finished_at else None,
                                }
                                break
                    except sqlite3.Error:
                        continue
        return sorted(found.values(), key=lambda item: item["started_at"], reverse=True)
