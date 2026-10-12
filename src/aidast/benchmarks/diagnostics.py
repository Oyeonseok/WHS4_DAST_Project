"""Read-only, post-scan diagnostics for comparing scanner evidence fairly.

This module neither loads a reference vulnerability catalog nor changes scan
state. It can inspect both legacy Attack.db files and live Pipeline.db files.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


def inspect_scan(database: Path, scan_id: str) -> dict[str, Any]:
    """Summarize persisted evidence without interpreting absent tests as misses.

    Counts refer to the supplied scan only. Validation decisions are deduplicated
    by finding and use the latest persisted case, matching coverage exports.
    Missing tables mean unavailable information rather than a measured zero.
    """
    database = Path(database).expanduser().resolve(strict=True)
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        tables = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        # A legacy database may omit scans; its run record still identifies it.
        identity_tables = [
            table for table in ("scans", "attack_runs") if table in tables
        ]
        if not identity_tables or not any(
            conn.execute(
                f"SELECT 1 FROM {table} WHERE scan_id=? LIMIT 1", (scan_id,),
            ).fetchone() for table in identity_tables
        ):
            raise ValueError(f"unknown scan: {scan_id}")

        def count(table: str, condition: str = "1") -> int | None:
            if table not in tables:
                return None
            return conn.execute(
                f"SELECT count(*) FROM {table} WHERE scan_id=? AND ({condition})",
                (scan_id,),
            ).fetchone()[0]

        def statuses(table: str, column: str) -> dict[str, int] | None:
            if table not in tables:
                return None
            return {
                str(status) if status is not None else "UNDECIDED": total
                for status, total in conn.execute(
                    f"SELECT {column},count(*) FROM {table} "
                    f"WHERE scan_id=? GROUP BY {column} ORDER BY {column}",
                    (scan_id,),
                )
            }

        attempt_count = count("attack_attempts")
        finding_count = count("findings")
        response_count = count("attack_attempts", "response_status IS NOT NULL")
        attempted_endpoints = None
        if "attack_attempts" in tables:
            attempted_endpoints = conn.execute(
                "SELECT count(DISTINCT endpoint_id) FROM attack_attempts "
                "WHERE scan_id=?", (scan_id,),
            ).fetchone()[0]

        validation_statuses = None
        validation_finding_count = None
        confirmed_finding_count = None
        if "validation_cases" in tables:
            validation_statuses = {
                str(status) if status is not None else "UNDECIDED": total
                for status, total in conn.execute(
                    """SELECT v.current_status,count(*) FROM validation_cases v
                       JOIN (
                           SELECT finding_id,max(rowid) latest_rowid
                           FROM validation_cases
                           WHERE scan_id=? AND finding_id IS NOT NULL
                           GROUP BY finding_id
                       ) latest ON latest.latest_rowid=v.rowid
                       GROUP BY v.current_status ORDER BY v.current_status""",
                    (scan_id,),
                )
            }
            validation_finding_count = sum(validation_statuses.values())
            confirmed_finding_count = validation_statuses.get("CONFIRMED", 0)

        coverage_total = count("attack_coverage_items")
        coverage_statuses = statuses("attack_coverage_items", "status")
        coverage_attempted = count("attack_coverage_items", "attempt_count > 0")
        source_annotation_count = None
        catalog_annotation_count = None
        if {"endpoint_annotations", "annotation_runs"} <= tables:
            categories = dict(conn.execute(
                """SELECT a.category,count(*) FROM endpoint_annotations a
                   JOIN annotation_runs r ON r.annotation_run_id=a.annotation_run_id
                   WHERE r.scan_id=? GROUP BY a.category""", (scan_id,),
            ))
            source_annotation_count = categories.get("source_vulnerability", 0)
            catalog_annotation_count = categories.get("benchmark_catalog_vulnerability", 0)
        source_endpoint_count = None
        available_endpoint_count = None
        if {"endpoints", "origins", "assets"} <= tables:
            available_endpoint_count = conn.execute(
                """SELECT count(DISTINCT e.endpoint_id) FROM endpoints e
                   JOIN origins r ON r.origin_id=e.origin_id
                   JOIN assets a ON a.asset_id=r.asset_id
                   WHERE a.scan_id=?""", (scan_id,),
            ).fetchone()[0]
        if {"endpoint_observations", "endpoints", "origins", "assets"} <= tables:
            source_endpoint_count = conn.execute(
                """SELECT count(DISTINCT e.endpoint_id)
                   FROM endpoint_observations o
                   JOIN endpoints e ON e.endpoint_id=o.endpoint_id
                   JOIN origins r ON r.origin_id=e.origin_id
                   JOIN assets a ON a.asset_id=r.asset_id
                   WHERE a.scan_id=? AND o.source_tool IN
                       ('flask_source_import', 'source', 'source_import')""",
                (scan_id,),
            ).fetchone()[0]
        provenance_counts = (
            source_annotation_count, catalog_annotation_count, source_endpoint_count,
        )
        source_assisted = (
            True if any(value for value in provenance_counts)
            else False if any(value is not None for value in provenance_counts)
            else None
        )
        stage_count = count("stage_runs")
        weak_negative_dispositions = None
        if "attack_coverage_items" in tables:
            columns = {
                row[1] for row in conn.execute(
                    "PRAGMA table_info(attack_coverage_items)"
                )
            }
            if "disposition_reason" in columns:
                weak_negative_dispositions = conn.execute(
                    """SELECT count(*) FROM attack_coverage_items
                       WHERE scan_id=? AND lower(COALESCE(disposition_reason,''))
                         LIKE '%negative evidence quality%'""",
                    (scan_id,),
                ).fetchone()[0]
        initialized_only = (
            attempt_count == 0 and finding_count == 0 and stage_count == 0
            if all(value is not None for value in (attempt_count, finding_count, stage_count))
            else None
        )
        return {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "execution": {
                "initialized_only": initialized_only,
                "run_statuses": statuses("attack_runs", "status"),
                "stage_statuses": statuses("stage_runs", "status"),
                "attempt_count": attempt_count,
                "response_count": response_count,
                "attempted_endpoint_count": attempted_endpoints,
                "available_endpoint_count": available_endpoint_count,
            },
            "provenance": {
                "source_assisted": source_assisted,
                "source_endpoint_count": source_endpoint_count,
                "source_annotation_count": source_annotation_count,
                "catalog_annotation_count": catalog_annotation_count,
                "black_box_verified": False,
            },
            "findings": {
                "total": finding_count,
                "independently_confirmed": confirmed_finding_count,
                "latest_validation_finding_count": validation_finding_count,
                "latest_validation_statuses": validation_statuses,
            },
            "coverage": {
                "total": coverage_total,
                "attempted_item_count": coverage_attempted,
                "statuses": coverage_statuses,
                "confirmed_item_count": (
                    coverage_statuses.get("confirmed", 0)
                    if coverage_statuses is not None else None
                ),
            },
            "catalog": {
                "total": count("benchmark_catalog_items"),
                "persisted_assessment_statuses": statuses(
                    "benchmark_catalog_items", "assessment_status",
                ),
            },
            "adaptive_attack": {
                "graph_revision_count": count("attack_graph_revisions"),
                "graph_node_states": statuses("attack_graph_nodes", "state"),
                "lead_queue_states": statuses("attack_lead_queue", "state"),
                "precondition_states": statuses("attack_preconditions", "state"),
                "operator_action_statuses": statuses(
                    "attack_operator_actions", "status",
                ),
                "online_chain_states": statuses("attack_chain_leads", "state"),
                "synthetic_ui_candidate_states": statuses(
                    "synthetic_ui_candidates", "state",
                ),
                "external_tool_statuses": statuses("attack_tool_runs", "status"),
                "intent_checkpoint_quality": statuses(
                    "attack_intent_checkpoints", "evidence_quality",
                ),
                "insufficient_negative_quality_dispositions": (
                    weak_negative_dispositions
                ),
            },
            "semantics": (
                "Initialized databases are not completed negative scans. Attempt "
                "counts include recorded errors and rejections; response counts "
                "identify attempts with HTTP observations. Coverage items and "
                "catalog claims are hypotheses and may share findings. Only the "
                "latest independent Validation decision counts a finding as "
                "confirmed. No black-box recall is inferred from these counts; "
                "absence of recognized source provenance does not prove isolation."
                " Adaptive Attack counts describe persisted scheduling and evidence "
                "state; they do not by themselves establish vulnerability recall."
            ),
        }
