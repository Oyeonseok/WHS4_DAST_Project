"""Create bounded follow-up work as soon as Attack evidence is committed."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass


def _id(prefix: str, *parts: str) -> str:
    return f"{prefix}_{hashlib.sha256(chr(0).join(parts).encode()).hexdigest()[:32]}"


@dataclass(frozen=True)
class OnlineChainRefresh:
    inserted: int
    queued: int
    completed: int


_BOUNDARY_CLASSES = frozenset({
    "auth_bypass", "idor", "jwt_crypto", "session", "business_logic",
})
_IDENTIFIER_CLASSES = frozenset({"idor", "business_logic", "race_condition"})
_TERMINAL_COVERAGE = frozenset({
    "tested_negative", "candidate", "confirmed", "blocked_auth",
    "policy_excluded", "unsupported", "error_terminal",
})


def refresh_online_chain_leads(
    conn: sqlite3.Connection, scan_id: str, *, stage_run_id: str | None = None,
    per_finding_limit: int = 8,
) -> OnlineChainRefresh:
    """Link proven findings to existing follow-up coverage without inventing evidence.

    This stage only reprioritizes hypotheses already derived from Recon. The
    post-Attack Chaining stage remains responsible for replaying and proving a
    complete multi-finding chain.
    """
    if not 1 <= per_finding_limit <= 32:
        raise ValueError("online chain follow-up limit must be between 1 and 32")
    conn.row_factory = sqlite3.Row
    inserted = queued = completed = 0
    findings = conn.execute(
        """SELECT f.finding_id,f.endpoint_id,f.vuln_type,e.origin_id,
                  (SELECT t.stage_run_id FROM attack_attempts a
                   LEFT JOIN attack_tasks t ON t.task_id=a.task_id
                   WHERE a.finding_id=f.finding_id AND a.outcome='confirmed'
                   ORDER BY a.created_at DESC,a.attempt_id DESC LIMIT 1) source_stage
           FROM findings f JOIN endpoints e ON e.endpoint_id=f.endpoint_id
           WHERE f.scan_id=? AND f.status IN ('unreviewed','confirmed')
             AND EXISTS (SELECT 1 FROM attack_attempts a
                         WHERE a.finding_id=f.finding_id AND a.outcome='confirmed')
           ORDER BY f.created_at,f.finding_id""",
        (scan_id,),
    ).fetchall()
    for finding in findings:
        candidates = conn.execute(
            """SELECT c.coverage_id,c.vuln_class,c.status,c.endpoint_id,
                      CASE WHEN c.endpoint_id=? THEN 1 ELSE 0 END same_endpoint,
                      EXISTS(SELECT 1 FROM parameters p
                             WHERE p.endpoint_id=c.endpoint_id AND p.is_identifier=1)
                        has_identifier
               FROM attack_coverage_items c
               JOIN endpoints e ON e.endpoint_id=c.endpoint_id
               WHERE c.scan_id=? AND e.origin_id=?
                 AND c.status IN ('pending','error_retryable')
                 AND NOT (c.endpoint_id=? AND c.vuln_class=?)
               ORDER BY same_endpoint DESC,has_identifier DESC,c.coverage_id""",
            (
                finding["endpoint_id"], scan_id, finding["origin_id"],
                finding["endpoint_id"], finding["vuln_type"],
            ),
        ).fetchall()
        ranked: list[tuple[int, str, sqlite3.Row]] = []
        for coverage in candidates:
            if coverage["same_endpoint"]:
                ranked.append((100, "same_endpoint_followup", coverage))
            elif finding["vuln_type"] in _BOUNDARY_CLASSES and coverage["vuln_class"] in _BOUNDARY_CLASSES:
                ranked.append((96, "credential_boundary_followup", coverage))
            elif coverage["has_identifier"] and coverage["vuln_class"] in _IDENTIFIER_CLASSES:
                ranked.append((90, "same_origin_identifier_followup", coverage))
        for priority, relationship, coverage in sorted(
            ranked, key=lambda item: (-item[0], str(item[2]["coverage_id"])),
        )[:per_finding_limit]:
            chain_lead_id = _id(
                "chain_lead", scan_id, str(finding["finding_id"]),
                str(coverage["coverage_id"]),
            )
            before = conn.total_changes
            conn.execute(
                """INSERT OR IGNORE INTO attack_chain_leads
                   (chain_lead_id,scan_id,source_finding_id,followup_coverage_id,
                    relationship,priority,source_stage_run_id)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    chain_lead_id, scan_id, finding["finding_id"],
                    coverage["coverage_id"], relationship, priority,
                    finding["source_stage"] or stage_run_id,
                ),
            )
            inserted += int(conn.total_changes > before)

    rows = conn.execute(
        """SELECT l.chain_lead_id,l.source_finding_id,l.followup_coverage_id,
                  l.relationship,l.priority,l.state,c.status,c.endpoint_id,
                  c.vuln_class,c.skill_name,n.node_id
           FROM attack_chain_leads l
           JOIN attack_coverage_items c ON c.coverage_id=l.followup_coverage_id
           LEFT JOIN attack_graph_nodes n ON n.scan_id=l.scan_id
             AND n.node_kind='finding' AND n.node_key=l.source_finding_id
           WHERE l.scan_id=? ORDER BY l.priority DESC,l.chain_lead_id""",
        (scan_id,),
    ).fetchall()
    for row in rows:
        next_state = (
            "completed" if row["status"] in _TERMINAL_COVERAGE
            else "running" if row["status"] == "running" else "queued"
        )
        if next_state != row["state"]:
            conn.execute(
                """UPDATE attack_chain_leads SET state=?,updated_at=CURRENT_TIMESTAMP
                   WHERE chain_lead_id=?""", (next_state, row["chain_lead_id"]),
            )
        completed += int(next_state == "completed" and row["state"] != "completed")
        if next_state != "queued" or not row["node_id"]:
            continue
        before = conn.total_changes
        conn.execute(
            """INSERT OR IGNORE INTO attack_lead_queue
               (lead_queue_id,scan_id,source_node_id,coverage_id,endpoint_id,
                vuln_class,skill_name,priority,reason)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                _id("lead_queue", scan_id, str(row["node_id"]), str(row["followup_coverage_id"])),
                scan_id, row["node_id"], row["followup_coverage_id"], row["endpoint_id"],
                row["vuln_class"], row["skill_name"], row["priority"],
                f"during-Attack chain: {row['relationship']}",
            ),
        )
        queued += int(conn.total_changes > before)
        conn.execute(
            """UPDATE attack_lead_queue SET priority=MAX(priority,?),reason=?
               WHERE scan_id=? AND source_node_id=? AND coverage_id=?
                 AND state IN ('queued','deferred')""",
            (
                row["priority"], f"during-Attack chain: {row['relationship']}",
                scan_id, row["node_id"], row["followup_coverage_id"],
            ),
        )
    return OnlineChainRefresh(inserted=inserted, queued=queued, completed=completed)
