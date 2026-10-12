from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aidast.benchmarks.diagnostics import inspect_scan


def _legacy_database(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE attack_runs (scan_id TEXT, status TEXT);
            CREATE TABLE stage_runs (scan_id TEXT, status TEXT);
            CREATE TABLE attack_attempts
                (scan_id TEXT, endpoint_id TEXT, response_status INTEGER);
            CREATE TABLE findings (scan_id TEXT, finding_id TEXT);
            INSERT INTO attack_runs VALUES ('scan_a', 'created');
        """)


def test_initialized_legacy_scan_is_not_a_completed_negative_scan(tmp_path: Path) -> None:
    database = tmp_path / "Attack.db"
    _legacy_database(database)
    before = database.read_bytes()
    result = inspect_scan(database, "scan_a")
    assert result["execution"]["initialized_only"] is True
    assert result["execution"]["run_statuses"] == {"created": 1}
    assert result["execution"]["attempt_count"] == 0
    assert result["findings"]["independently_confirmed"] is None
    assert result["coverage"]["total"] is None
    assert result["provenance"]["source_assisted"] is None
    assert database.read_bytes() == before
    assert sorted(path.name for path in tmp_path.iterdir()) == ["Attack.db"]


def test_diagnostics_separate_duplicate_coverage_from_latest_validation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "Pipeline.db"
    _legacy_database(database)
    with sqlite3.connect(database) as conn:
        conn.executescript("""
            CREATE TABLE validation_cases
                (scan_id TEXT, finding_id TEXT, current_status TEXT);
            CREATE TABLE attack_coverage_items
                (scan_id TEXT, status TEXT, attempt_count INTEGER);
            CREATE TABLE annotation_runs
                (scan_id TEXT, annotation_run_id TEXT);
            CREATE TABLE endpoint_annotations
                (annotation_run_id TEXT, category TEXT);
            INSERT INTO stage_runs VALUES ('scan_a', 'completed');
            INSERT INTO findings VALUES ('scan_a', 'finding_1');
            INSERT INTO findings VALUES ('scan_a', 'finding_2');
            INSERT INTO findings VALUES ('scan_b', 'other_finding');
            INSERT INTO attack_attempts VALUES ('scan_a', 'endpoint_1', 200);
            INSERT INTO attack_attempts VALUES ('scan_a', 'endpoint_1', NULL);
            INSERT INTO attack_attempts VALUES ('scan_b', 'endpoint_2', 200);
            INSERT INTO validation_cases VALUES ('scan_a', 'finding_1', 'INCONCLUSIVE');
            INSERT INTO validation_cases VALUES ('scan_a', 'finding_1', 'CONFIRMED');
            INSERT INTO validation_cases VALUES ('scan_a', 'finding_2', 'CONFIRMED');
            INSERT INTO validation_cases VALUES ('scan_a', 'finding_2', 'CONTESTED');
            INSERT INTO validation_cases VALUES ('scan_a', NULL, 'CONFIRMED');
            INSERT INTO validation_cases VALUES ('scan_b', 'other_finding', 'CONFIRMED');
            INSERT INTO attack_coverage_items VALUES ('scan_a', 'confirmed', 2);
            INSERT INTO attack_coverage_items VALUES ('scan_a', 'confirmed', 2);
            INSERT INTO attack_coverage_items VALUES ('scan_a', 'unsupported', 0);
            INSERT INTO attack_coverage_items VALUES ('scan_b', 'confirmed', 1);
            INSERT INTO annotation_runs VALUES ('scan_a', 'run_a');
            INSERT INTO annotation_runs VALUES ('scan_b', 'run_b');
            INSERT INTO endpoint_annotations VALUES ('run_a', 'source_vulnerability');
            INSERT INTO endpoint_annotations VALUES ('run_a', 'benchmark_catalog_vulnerability');
            INSERT INTO endpoint_annotations VALUES ('run_b', 'source_vulnerability');
        """)
    before = database.read_bytes()
    result = inspect_scan(database, "scan_a")
    assert result["execution"] == {
        "initialized_only": False,
        "run_statuses": {"created": 1},
        "stage_statuses": {"completed": 1},
        "attempt_count": 2,
        "response_count": 1,
        "attempted_endpoint_count": 1,
        "available_endpoint_count": None,
    }
    assert result["findings"] == {
        "total": 2,
        "independently_confirmed": 1,
        "latest_validation_finding_count": 2,
        "latest_validation_statuses": {"CONFIRMED": 1, "CONTESTED": 1},
    }
    assert result["coverage"]["confirmed_item_count"] == 2
    assert result["coverage"]["attempted_item_count"] == 2
    assert result["coverage"]["total"] == 3
    assert result["provenance"]["source_assisted"] is True
    assert result["provenance"]["source_annotation_count"] == 1
    assert result["provenance"]["catalog_annotation_count"] == 1
    assert database.read_bytes() == before
    json.dumps(result)  # Diagnostics are directly serializable as an artifact.


def test_source_import_endpoints_are_flagged_without_annotations(tmp_path: Path) -> None:
    database = tmp_path / "Pipeline.db"
    _legacy_database(database)
    with sqlite3.connect(database) as conn:
        conn.executescript("""
            CREATE TABLE assets (asset_id TEXT, scan_id TEXT);
            CREATE TABLE origins (origin_id TEXT, asset_id TEXT);
            CREATE TABLE endpoints (endpoint_id TEXT, origin_id TEXT);
            CREATE TABLE endpoint_observations (endpoint_id TEXT, source_tool TEXT);
            INSERT INTO assets VALUES ('asset_a', 'scan_a');
            INSERT INTO assets VALUES ('asset_b', 'scan_b');
            INSERT INTO origins VALUES ('origin_a', 'asset_a');
            INSERT INTO origins VALUES ('origin_b', 'asset_b');
            INSERT INTO endpoints VALUES ('endpoint_a', 'origin_a');
            INSERT INTO endpoints VALUES ('endpoint_b', 'origin_b');
            INSERT INTO endpoint_observations VALUES ('endpoint_a', 'flask_source_import');
            INSERT INTO endpoint_observations VALUES ('endpoint_a', 'flask_source_import');
            INSERT INTO endpoint_observations VALUES ('endpoint_b', 'source_import');
        """)
    result = inspect_scan(database, "scan_a")
    assert result["provenance"]["source_assisted"] is True
    assert result["provenance"]["source_endpoint_count"] == 1
    assert result["provenance"]["black_box_verified"] is False
    assert result["execution"]["available_endpoint_count"] == 1


def test_adaptive_attack_diagnostics_report_persisted_states_only(tmp_path: Path) -> None:
    database = tmp_path / "Pipeline.db"
    _legacy_database(database)
    with sqlite3.connect(database) as conn:
        conn.executescript("""
            CREATE TABLE attack_graph_revisions (scan_id TEXT);
            CREATE TABLE attack_graph_nodes (scan_id TEXT, state TEXT);
            CREATE TABLE attack_lead_queue (scan_id TEXT, state TEXT);
            CREATE TABLE attack_preconditions (scan_id TEXT, state TEXT);
            CREATE TABLE attack_operator_actions (scan_id TEXT, status TEXT);
            CREATE TABLE attack_chain_leads (scan_id TEXT, state TEXT);
            CREATE TABLE synthetic_ui_candidates (scan_id TEXT, state TEXT);
            CREATE TABLE attack_tool_runs (scan_id TEXT, status TEXT);
            CREATE TABLE attack_intent_checkpoints
                (scan_id TEXT, evidence_quality TEXT);
            CREATE TABLE attack_coverage_items
                (scan_id TEXT, status TEXT, attempt_count INTEGER,
                 disposition_reason TEXT);
            INSERT INTO attack_graph_revisions VALUES ('scan_a');
            INSERT INTO attack_graph_nodes VALUES ('scan_a','active');
            INSERT INTO attack_lead_queue VALUES ('scan_a','queued');
            INSERT INTO attack_preconditions VALUES ('scan_a','required');
            INSERT INTO attack_operator_actions VALUES ('scan_a','pending');
            INSERT INTO attack_chain_leads VALUES ('scan_a','completed');
            INSERT INTO synthetic_ui_candidates VALUES ('scan_a','verified');
            INSERT INTO attack_tool_runs VALUES ('scan_a','completed');
            INSERT INTO attack_intent_checkpoints VALUES ('scan_a','adequate');
            INSERT INTO attack_coverage_items VALUES
                ('scan_a','error_retryable',1,
                 'negative evidence quality is insufficient');
        """)
    before = database.read_bytes()

    adaptive = inspect_scan(database, "scan_a")["adaptive_attack"]

    assert adaptive == {
        "graph_revision_count": 1,
        "graph_node_states": {"active": 1},
        "lead_queue_states": {"queued": 1},
        "precondition_states": {"required": 1},
        "operator_action_statuses": {"pending": 1},
        "online_chain_states": {"completed": 1},
        "synthetic_ui_candidate_states": {"verified": 1},
        "external_tool_statuses": {"completed": 1},
        "intent_checkpoint_quality": {"adequate": 1},
        "insufficient_negative_quality_dispositions": 1,
    }
    assert database.read_bytes() == before


def test_zero_attempts_after_failed_stage_are_not_initialized_only(tmp_path: Path) -> None:
    database = tmp_path / "Attack.db"
    _legacy_database(database)
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO stage_runs VALUES ('scan_a', 'failed')")
    assert inspect_scan(database, "scan_a")["execution"]["initialized_only"] is False


def test_unknown_scan_and_missing_database_do_not_create_or_modify_files(
    tmp_path: Path,
) -> None:
    database = tmp_path / "Attack.db"
    _legacy_database(database)
    before = database.read_bytes()
    with pytest.raises(ValueError, match="unknown scan"):
        inspect_scan(database, "scan_unknown")
    with pytest.raises(FileNotFoundError):
        inspect_scan(tmp_path / "missing.db", "scan_a")
    assert database.read_bytes() == before
    assert not (tmp_path / "missing.db").exists()
