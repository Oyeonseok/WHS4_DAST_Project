from __future__ import annotations

import json
import sqlite3

from aidast.attack.coverage import ensure_coverage_manifest
from aidast.attack.graph import synchronize_attack_graph
from aidast.attack.work_queue import refresh_lead_queue, select_dual_queue
from aidast.orchestration.coverage_attack import ExhaustiveAttackCoordinator
from test_attack_coverage import imported_pipeline


def _add_owned_object(conn, scan_id: str, endpoint_id: str) -> None:
    conn.execute(
        """INSERT INTO attack_facts
           (fact_id,scan_id,fact_type,fact_key,fact_value,confidence,source_endpoint_id)
           VALUES ('owned-object',?,'owned_test_object','identity-a.user-id',?,1.0,?)""",
        (scan_id, json.dumps({"object_id": "scanner-owned"}), endpoint_id),
    )


def test_lead_queue_is_derived_idempotently_from_new_graph_facts(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id LIMIT 1"
        ).fetchone()[0]
        _add_owned_object(conn, imported.scan_id, endpoint_id)
        synchronize_attack_graph(conn, imported.scan_id, trigger_kind="fact.committed")

        first = refresh_lead_queue(conn, imported.scan_id)
        second = refresh_lead_queue(conn, imported.scan_id)
        selected = select_dual_queue(conn, imported.scan_id, batch_size=3)

        assert first > 0
        assert second == 0
        assert selected.lead_slots == 1
        assert selected.coverage_slots == 2
        assert len(selected.preferred_coverage_ids) == 1


def test_attack_batch_mixes_one_lead_with_coverage_floor(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id LIMIT 1"
        ).fetchone()[0]
        _add_owned_object(conn, imported.scan_id, endpoint_id)

    coordinator = ExhaustiveAttackCoordinator(
        agent=object(), db_path=imported.pipeline_database,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=3,
    )
    _, tasks = coordinator._start_batch(imported.scan_id)

    assert len(tasks) == 3
    assert sum(bool(task["lead_queue_ids"]) for task in tasks) == 1
    assert sum(not task["lead_queue_ids"] for task in tasks) == 2
