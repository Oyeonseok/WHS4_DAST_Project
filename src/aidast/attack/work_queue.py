"""Coverage-floor plus evidence-led Attack scheduling."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Any


def _identifier(scan_id: str, source_node_id: str, coverage_id: str) -> str:
    raw = "\x00".join((scan_id, source_node_id, coverage_id)).encode()
    return "lead_queue_" + hashlib.sha256(raw).hexdigest()[:32]


@dataclass(frozen=True)
class QueueSelection:
    preferred_coverage_ids: tuple[str, ...]
    lead_queue_ids: tuple[str, ...]
    lead_slots: int
    coverage_slots: int


def refresh_lead_queue(conn: sqlite3.Connection, scan_id: str) -> int:
    """Derive bounded follow-up work from new graph evidence.

    Each row still points at an ordinary coverage item, preserving the coverage
    ledger as the completion floor while allowing evidence-led work to run first.
    """
    conn.row_factory = sqlite3.Row
    revision = conn.execute(
        """SELECT revision_id FROM attack_graph_revisions
           WHERE scan_id=? ORDER BY rowid DESC LIMIT 1""",
        (scan_id,),
    ).fetchone()
    revision_id = revision[0] if revision else None
    sources = conn.execute(
        """SELECT node_id,node_kind,node_key,priority,metadata_json
           FROM attack_graph_nodes
           WHERE scan_id=? AND state='active'
             AND node_kind IN ('lead','finding','credential','object','identity','fact')
           ORDER BY priority DESC,updated_at,node_id""",
        (scan_id,),
    ).fetchall()
    inserted = 0
    for source in sources:
        kind = str(source["node_kind"])
        if kind == "credential":
            predicate = "c.status IN ('pending','error_retryable') AND c.required_identity_role!='unauthenticated'"
            parameters: tuple[Any, ...] = (scan_id,)
            reason = "credential evidence can satisfy an authenticated coverage prerequisite"
        elif kind in {"object", "identity"}:
            predicate = "c.status IN ('pending','error_retryable') AND c.vuln_class IN ('idor','business_logic','auth_bypass','race_condition','session')"
            parameters = (scan_id,)
            reason = "owned identity or object evidence enables a boundary follow-up"
        elif kind == "finding":
            predicate = "c.status IN ('pending','error_retryable') AND c.endpoint_id=json_extract(?,'$.endpoint_id')"
            parameters = (scan_id, source["metadata_json"])
            reason = "a finding on this endpoint enables an immediate related hypothesis"
        elif kind == "lead":
            predicate = "c.status IN ('pending','error_retryable') AND c.last_task_id=json_extract(?,'$.task_id')"
            parameters = (scan_id, source["metadata_json"])
            reason = "a reproducible lead should be resolved before breadth-only work"
        else:
            predicate = "c.status IN ('pending','error_retryable') AND c.endpoint_id=json_extract(?,'$.source_endpoint_id')"
            parameters = (scan_id, source["metadata_json"])
            reason = "a new endpoint fact changes the next attack hypothesis"
        rows = conn.execute(
            f"""SELECT c.coverage_id,c.endpoint_id,c.vuln_class,c.skill_name
                FROM attack_coverage_items c WHERE c.scan_id=? AND {predicate}
                ORDER BY c.attempt_count,c.updated_at,c.coverage_id LIMIT 32""",
            parameters,
        ).fetchall()
        for coverage in rows:
            priority = min(100, max(int(source["priority"]), 70))
            cursor = conn.execute(
                """INSERT OR IGNORE INTO attack_lead_queue
                   (lead_queue_id,scan_id,source_node_id,coverage_id,endpoint_id,
                    vuln_class,skill_name,priority,state,reason,source_revision_id)
                   VALUES (?,?,?,?,?,?,?,?,'queued',?,?)""",
                (
                    _identifier(scan_id, source["node_id"], coverage["coverage_id"]),
                    scan_id, source["node_id"], coverage["coverage_id"],
                    coverage["endpoint_id"], coverage["vuln_class"], coverage["skill_name"],
                    priority, reason, revision_id,
                ),
            )
            inserted += cursor.rowcount
    return inserted


def select_dual_queue(
    conn: sqlite3.Connection, scan_id: str, *, batch_size: int,
) -> QueueSelection:
    """Reserve a dynamic lead share while guaranteeing breadth progress."""
    if not 1 <= batch_size <= 50:
        raise ValueError("batch size must be between 1 and 50")
    queued = conn.execute(
        """SELECT q.lead_queue_id,q.coverage_id,q.priority
           FROM attack_lead_queue q JOIN attack_coverage_items c
             ON c.coverage_id=q.coverage_id
           WHERE q.scan_id=? AND q.state='queued'
             AND c.status IN ('pending','error_retryable')
           ORDER BY q.priority DESC,q.created_at,q.lead_queue_id""",
        (scan_id,),
    ).fetchall()
    if not queued or batch_size == 1:
        lead_slots = min(len(queued), batch_size)
    else:
        urgent = any(int(row["priority"]) >= 95 for row in queued)
        target = (batch_size + 1) // 2 if urgent else max(1, batch_size // 3)
        lead_slots = min(len(queued), target, batch_size - 1)
    selected = queued[:lead_slots]
    return QueueSelection(
        preferred_coverage_ids=tuple(dict.fromkeys(row["coverage_id"] for row in selected)),
        lead_queue_ids=tuple(row["lead_queue_id"] for row in selected),
        lead_slots=lead_slots, coverage_slots=batch_size - lead_slots,
    )


def mark_claimed_leads(
    conn: sqlite3.Connection, *, scan_id: str, stage_run_id: str,
    tasks: list[dict[str, Any]], selection: QueueSelection,
) -> None:
    task_by_coverage = {str(task["coverage_id"]): str(task["task_id"]) for task in tasks}
    for queue_id in selection.lead_queue_ids:
        row = conn.execute(
            "SELECT coverage_id FROM attack_lead_queue WHERE lead_queue_id=? AND scan_id=?",
            (queue_id, scan_id),
        ).fetchone()
        task_id = task_by_coverage.get(str(row[0])) if row else None
        if task_id is None:
            continue
        conn.execute(
            """UPDATE attack_lead_queue SET state='claimed',stage_run_id=?,task_id=?,
                   claimed_at=CURRENT_TIMESTAMP WHERE lead_queue_id=? AND state='queued'""",
            (stage_run_id, task_id, queue_id),
        )


def reconcile_lead_queue(
    conn: sqlite3.Connection, scan_id: str, *, stage_run_id: str,
) -> None:
    """Return retryable leads to the queue and close durable dispositions."""
    rows = conn.execute(
        """SELECT q.lead_queue_id,c.status FROM attack_lead_queue q
           JOIN attack_coverage_items c ON c.coverage_id=q.coverage_id
           WHERE q.scan_id=? AND q.stage_run_id=? AND q.state='claimed'""",
        (scan_id, stage_run_id),
    ).fetchall()
    for row in rows:
        if row["status"] in {"pending", "error_retryable"}:
            state, finished = "queued", None
        elif row["status"] == "running":
            state, finished = "claimed", None
        elif row["status"] in {"blocked_auth"}:
            state, finished = "deferred", "CURRENT_TIMESTAMP"
        else:
            state, finished = "completed", "CURRENT_TIMESTAMP"
        if finished is None:
            conn.execute(
                """UPDATE attack_lead_queue SET state=?,stage_run_id=NULL,task_id=NULL,
                       claimed_at=NULL WHERE lead_queue_id=?""",
                (state, row["lead_queue_id"]),
            )
        else:
            conn.execute(
                f"""UPDATE attack_lead_queue SET state=?,finished_at={finished}
                    WHERE lead_queue_id=?""",
                (state, row["lead_queue_id"]),
            )
