from __future__ import annotations

import sqlite3

from aidast.attack.coverage import ensure_coverage_manifest
from aidast.attack.graph import synchronize_attack_graph
from aidast.attack.online_chaining import refresh_online_chain_leads
from test_attack_coverage import imported_pipeline


def _confirmed_finding(conn: sqlite3.Connection, scan_id: str) -> tuple[str, str, str]:
    rows = conn.execute(
        """SELECT coverage_id,endpoint_id,vuln_class,skill_name
           FROM attack_coverage_items ORDER BY endpoint_id,vuln_class"""
    ).fetchall()
    source = next(
        row for row in rows
        if any(other[1] == row[1] and other[2] != row[2] for other in rows)
    )
    finding_id = "finding_online_chain"
    conn.execute(
        """INSERT INTO findings
           (finding_id,scan_id,endpoint_id,vuln_type,title,severity,status)
           VALUES (?,?,?,?,?,'HIGH','unreviewed')""",
        (finding_id, scan_id, source[1], source[2], "confirmed source"),
    )
    conn.execute(
        """INSERT INTO attack_attempts
           (attempt_id,scan_id,endpoint_id,skill_name,request_fingerprint,
            identity_role,payload_variant,outcome,finding_id)
           VALUES ('attempt_online_chain',?,?,?,?,?,'proof','confirmed',?)""",
        (scan_id, source[1], source[3], "online-chain-proof", "authenticated", finding_id),
    )
    return finding_id, str(source[0]), str(source[1])


def test_confirmed_finding_queues_existing_followup_during_attack(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        finding_id, source_coverage, endpoint_id = _confirmed_finding(
            conn, imported.scan_id,
        )
        synchronize_attack_graph(conn, imported.scan_id, trigger_kind="finding.committed")

        first = refresh_online_chain_leads(conn, imported.scan_id)
        second = refresh_online_chain_leads(conn, imported.scan_id)
        synchronize_attack_graph(conn, imported.scan_id, trigger_kind="chains.changed")

        assert first.inserted >= 1
        assert second.inserted == 0
        lead = conn.execute(
            """SELECT source_finding_id,followup_coverage_id,relationship,state
               FROM attack_chain_leads ORDER BY priority DESC LIMIT 1"""
        ).fetchone()
        assert lead["source_finding_id"] == finding_id
        assert lead["followup_coverage_id"] != source_coverage
        assert lead["relationship"] == "same_endpoint_followup"
        assert lead["state"] == "queued"
        assert conn.execute(
            """SELECT count(*) FROM attack_lead_queue
               WHERE coverage_id=? AND reason LIKE 'during-Attack chain:%'""",
            (lead["followup_coverage_id"],),
        ).fetchone()[0] == 1
        assert conn.execute(
            """SELECT count(*) FROM attack_graph_nodes
               WHERE scan_id=? AND node_kind='chain'""", (imported.scan_id,),
        ).fetchone()[0] >= 1
        assert conn.execute(
            """SELECT count(*) FROM attack_graph_edges e
               JOIN attack_graph_nodes n ON n.node_id=e.from_node_id
               WHERE e.scan_id=? AND n.node_kind='finding'
                 AND e.relationship='opens_chain_branch'""", (imported.scan_id,),
        ).fetchone()[0] >= 1


def test_online_chain_lead_closes_when_followup_reaches_terminal_state(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        _confirmed_finding(conn, imported.scan_id)
        synchronize_attack_graph(conn, imported.scan_id, trigger_kind="finding.committed")
        refresh_online_chain_leads(conn, imported.scan_id)
        coverage_id = conn.execute(
            "SELECT followup_coverage_id FROM attack_chain_leads LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            """UPDATE attack_coverage_items
               SET status='tested_negative',disposition_reason='bounded differential controls'
               WHERE coverage_id=?""", (coverage_id,),
        )

        result = refresh_online_chain_leads(conn, imported.scan_id)

        assert result.completed == 1
        assert conn.execute(
            "SELECT state FROM attack_chain_leads WHERE followup_coverage_id=?",
            (coverage_id,),
        ).fetchone()[0] == "completed"
