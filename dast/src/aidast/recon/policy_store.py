"""SQLite audit storage for policy-gated recon tool executions."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
PRAGMA journal_mode=DELETE;

CREATE TABLE IF NOT EXISTS policy_runs (
    run_id TEXT PRIMARY KEY,
    policy_path TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (run_id) REFERENCES policy_runs(run_id)
);

CREATE TABLE IF NOT EXISTS proxy_flows (
    flow_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    execution_id TEXT,
    timestamp REAL,
    scheme TEXT,
    host TEXT,
    port INTEGER,
    method TEXT,
    path TEXT,
    query_string TEXT,
    request_headers_json TEXT,
    status_code INTEGER,
    content_type TEXT,
    response_size INTEGER,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES policy_runs(run_id),
    FOREIGN KEY (execution_id) REFERENCES tool_executions(execution_id)
);
"""

MAX_CAPTURE_CHARS = 200_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PolicyRunStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def start_run(self, *, policy_path: Path, target: str) -> str:
        run_id = "policy_run_" + uuid.uuid4().hex
        self.conn.execute(
            "INSERT INTO policy_runs VALUES (?, ?, ?, 'running', ?, NULL)",
            (run_id, str(policy_path), target, _now()),
        )
        self.conn.commit()
        return run_id

    def finish_run(self, run_id: str, *, status: str) -> None:
        self.conn.execute(
            "UPDATE policy_runs SET status=?, finished_at=? WHERE run_id=?",
            (status, _now(), run_id),
        )
        self.conn.commit()

    def start_execution(
        self,
        *,
        run_id: str,
        tool_id: str,
        redacted_arguments: list[str],
        execution_id: str | None = None,
    ) -> str:
        execution_id = execution_id or "tool_exec_" + uuid.uuid4().hex
        self.conn.execute(
            """INSERT INTO tool_executions
               (execution_id, run_id, tool_id, arguments_json, status, started_at)
               VALUES (?, ?, ?, ?, 'running', ?)""",
            (
                execution_id,
                run_id,
                tool_id,
                json.dumps(redacted_arguments, ensure_ascii=False),
                _now(),
            ),
        )
        self.conn.commit()
        return execution_id

    def finish_execution(
        self,
        execution_id: str,
        *,
        status: str,
        exit_code: int | None,
        stdout: str,
        stderr: str,
    ) -> None:
        self.conn.execute(
            """UPDATE tool_executions
               SET status=?, exit_code=?, stdout=?, stderr=?, finished_at=?
               WHERE execution_id=?""",
            (
                status,
                exit_code,
                stdout[:MAX_CAPTURE_CHARS],
                stderr[:MAX_CAPTURE_CHARS],
                _now(),
                execution_id,
            ),
        )
        self.conn.commit()

    def ingest_flow_log(self, path: Path, *, run_id: str) -> int:
        if not path.exists():
            return 0
        valid_execution_ids = {
            row[0]
            for row in self.conn.execute(
                "SELECT execution_id FROM tool_executions WHERE run_id=?", (run_id,)
            )
        }
        inserted = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                flow = json.loads(line)
            except json.JSONDecodeError:
                continue
            if flow.get("run_id") != run_id:
                continue
            execution_id = flow.get("execution_id")
            if execution_id not in valid_execution_ids:
                execution_id = None
            self.conn.execute(
                """INSERT INTO proxy_flows
                   (flow_id, run_id, execution_id, timestamp, scheme, host, port,
                    method, path, query_string, request_headers_json, status_code,
                    content_type, response_size, decision, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "flow_" + uuid.uuid4().hex,
                    run_id,
                    execution_id,
                    flow.get("timestamp"),
                    flow.get("scheme"),
                    flow.get("host"),
                    flow.get("port"),
                    flow.get("method"),
                    flow.get("path"),
                    flow.get("query_string"),
                    json.dumps(flow.get("request_headers"), ensure_ascii=False),
                    flow.get("status_code"),
                    flow.get("content_type"),
                    flow.get("response_size"),
                    flow.get("decision", "block"),
                    flow.get("reason", "missing decision"),
                ),
            )
            inserted += 1
        self.conn.commit()
        return inserted

    def count_execution_flows(self, execution_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) FROM proxy_flows WHERE execution_id=?", (execution_id,)
        ).fetchone()
        return int(row[0]) if row else 0
