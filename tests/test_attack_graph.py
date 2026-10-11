from __future__ import annotations

import json
import sqlite3

from aidast.attack.coverage import ensure_coverage_manifest
from aidast.attack.graph import graph_context_for_endpoint, synchronize_attack_graph
from test_attack_coverage import imported_pipeline


def test_online_attack_graph_revisions_only_for_new_durable_evidence(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    ensure_coverage_manifest(imported.pipeline_database, imported.scan_id)
    with sqlite3.connect(imported.pipeline_database) as conn, conn:
        conn.row_factory = sqlite3.Row
        first = synchronize_attack_graph(
            conn, imported.scan_id, trigger_kind="coverage.manifest.ready",
        )
        same = synchronize_attack_graph(
            conn, imported.scan_id, trigger_kind="poll.without.change",
        )
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints ORDER BY endpoint_id LIMIT 1"
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO attack_facts
               (fact_id,scan_id,fact_type,fact_key,fact_value,confidence,source_endpoint_id)
               VALUES ('fact-owned',?,'owned_test_object','user-a.object',?,1.0,?)""",
            (imported.scan_id, json.dumps({"secret": "must-not-enter-graph"}), endpoint_id),
        )
        changed = synchronize_attack_graph(
            conn, imported.scan_id, trigger_kind="fact.committed",
        )
        context = graph_context_for_endpoint(conn, imported.scan_id, endpoint_id)

        assert first.changed is True
        assert same.changed is False
        assert changed.changed is True
        assert changed.nodes == first.nodes + 1
        assert context["revision_id"] == changed.revision_id
        rendered = json.dumps(context, ensure_ascii=False)
        assert "fact-owned" in rendered
        assert "must-not-enter-graph" not in rendered
        assert conn.execute(
            "SELECT count(*) FROM attack_graph_revisions WHERE scan_id=?",
            (imported.scan_id,),
        ).fetchone()[0] == 2
        assert conn.execute(
            "SELECT count(*) FROM attack_graph_events WHERE event_kind='planner.revision'",
        ).fetchone()[0] == 2


def test_claimed_attack_task_receives_bounded_graph_context(tmp_path) -> None:
    imported = imported_pipeline(tmp_path)
    coordinator_db = imported.pipeline_database
    ensure_coverage_manifest(coordinator_db, imported.scan_id)
    from aidast.orchestration.coverage_attack import ExhaustiveAttackCoordinator

    coordinator = ExhaustiveAttackCoordinator(
        agent=object(), db_path=coordinator_db,
        scope_path=imported.recon_database.parent / "Scope.md",
        policy_path=imported.recon_database.parent / "TargetPolicy.json",
        batch_size=2,
    )
    stage_run_id, tasks = coordinator._start_batch(imported.scan_id)

    assert stage_run_id
    assert len(tasks) == 2
    assert all(task["attack_graph_context"]["revision_id"] for task in tasks)
    assert all(len(task["attack_graph_context"]["nodes"]) <= 32 for task in tasks)
