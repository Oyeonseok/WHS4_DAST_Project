"""Failure observations preserve private outputs and never launch a retry."""

import asyncio
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from aidast.agents.failure_diagnostics import (
    compare_persisted_work, is_model_capacity_error, is_model_policy_refusal,
    persisted_work_snapshot, preserve_native_failure,
)
from aidast.agents.native_pipeline import CodexMainAgent, MainAgentError
from aidast.core.codex_process import CodexProcessTimeout
from aidast.web.server import create_app


SCAN_ID = "scan_fixture"
STAGE_ID = "stage_fixture"


@pytest.mark.parametrize("message", [
    "This content was flagged for possible cybersecurity risk.",
    "Automatic cybersecurity review rejected its task.",
    "Automatic safety review flagged the delegated task for cybersecurity risk.",
])
def test_model_policy_refusal_recognizes_transport_and_agent_summaries(message: str) -> None:
    assert is_model_policy_refusal(message)


def test_application_safety_review_is_not_a_model_policy_refusal() -> None:
    assert not is_model_policy_refusal(
        "The application safety review flagged a missing transaction control."
    )


def test_model_capacity_error_is_distinct_from_application_capacity() -> None:
    assert is_model_capacity_error(
        "Selected model is at capacity. Please try a different model."
    )
    assert is_model_capacity_error(
        "The single Attack Agent ended with a model-capacity error."
    )
    assert not is_model_capacity_error("request governor has no remaining capacity")


@pytest.fixture
def database(tmp_path: Path) -> Path:
    directory = tmp_path / "Runs" / SCAN_ID
    directory.mkdir(parents=True)
    path = directory / "Pipeline.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE scans (scan_id TEXT, status TEXT);
            CREATE TABLE stage_runs (stage_run_id TEXT, scan_id TEXT, stage TEXT, status TEXT,
                                     error_message TEXT);
            CREATE TABLE attack_tasks (task_id TEXT, scan_id TEXT, stage_run_id TEXT, status TEXT,
                                      payload_json TEXT);
            CREATE TABLE attack_attempts (attempt_id TEXT, scan_id TEXT, outcome TEXT, response BLOB);
            CREATE TABLE findings (finding_id TEXT, scan_id TEXT, title TEXT, severity TEXT, status TEXT);
            CREATE TABLE audit_events (audit_event_id TEXT, scan_id TEXT, stage_run_id TEXT, event_type TEXT);
        """)
        conn.execute("INSERT INTO scans VALUES (?, 'running')", (SCAN_ID,))
        conn.execute("INSERT INTO stage_runs VALUES (?, ?, 'attack', 'running', NULL)", (STAGE_ID, SCAN_ID))
        conn.execute("INSERT INTO attack_tasks VALUES ('task', ?, ?, 'pending', '{}')", (SCAN_ID, STAGE_ID))
        conn.execute("INSERT INTO attack_attempts VALUES ('previous_attempt', ?, 'observed', ?)",
                     (SCAN_ID, b"private-session-token"))
    return path


def _snapshot(database: Path) -> dict:
    return persisted_work_snapshot(database, scan_id=SCAN_ID, stage_run_id=STAGE_ID)


def test_unchanged_persisted_work_is_read_only_and_contains_no_captured_values(database: Path) -> None:
    original = database.read_bytes()
    before = _snapshot(database)
    assert before["available"] is True
    assert compare_persisted_work(before, _snapshot(database)) == {
        "classification": "no_persisted_progress", "changed_tables": [],
    }
    assert database.read_bytes() == original
    assert "private-session-token" not in json.dumps(before)


@pytest.mark.parametrize("table,mutation", [
    ("attack_tasks", "UPDATE attack_tasks SET status='running' WHERE task_id='task'"),
    ("attack_tasks", "UPDATE attack_tasks SET payload_json='{\"updated\":true}' WHERE task_id='task'"),
    ("attack_attempts", "UPDATE attack_attempts SET outcome='rejected' WHERE attempt_id='previous_attempt'"),
    ("attack_attempts", "INSERT INTO attack_attempts VALUES ('new_attempt','scan_fixture','observed',NULL)"),
    ("attack_attempts", "DELETE FROM attack_attempts WHERE attempt_id='previous_attempt'"),
    ("findings", "INSERT INTO findings VALUES ('finding','scan_fixture','Offline observation','INFO','unreviewed')"),
])
def test_persisted_updates_are_detected_even_when_record_counts_do_not_increase(
    database: Path, table: str, mutation: str,
) -> None:
    before = _snapshot(database)
    with sqlite3.connect(database) as conn:
        conn.execute(mutation)
    result = compare_persisted_work(before, _snapshot(database))
    assert result == {"classification": "persisted_state_changed", "changed_tables": [table]}


def test_other_stage_tasks_and_other_scan_records_do_not_change_stage_comparison(database: Path) -> None:
    before = _snapshot(database)
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO attack_tasks VALUES ('other_task', ?, 'other_stage', 'completed', '{}')", (SCAN_ID,))
        conn.execute("INSERT INTO attack_attempts VALUES ('other_attempt', 'other_scan', 'observed', NULL)")
    assert compare_persisted_work(before, _snapshot(database))["classification"] == "no_persisted_progress"


@pytest.mark.parametrize("damage", ["missing_database", "corrupt_database", "missing_table", "missing_column"])
def test_unavailable_snapshots_never_claim_no_progress(database: Path, damage: str) -> None:
    before = _snapshot(database)
    if damage == "missing_database":
        database.unlink()
    elif damage == "corrupt_database":
        database.write_bytes(b"partial write")
    else:
        with sqlite3.connect(database) as conn:
            conn.execute("DROP TABLE findings" if damage == "missing_table"
                         else "ALTER TABLE attack_tasks DROP COLUMN stage_run_id")
    after = _snapshot(database)
    assert after["available"] is False
    assert compare_persisted_work(before, after)["classification"] == "unknown"
    assert compare_persisted_work(after, before)["classification"] == "unknown"
    if damage == "missing_database":
        assert not database.exists()


def test_private_artifacts_preserve_full_outputs_and_hashes(database: Path) -> None:
    before = _snapshot(database)
    original = database.read_bytes()
    events = json.dumps({"type": "turn.failed", "error": "private-session-token"}) + "\n" + "x" * 5000
    stderr = "private-stderr-token\n" + "diagnostic detail\n" * 500
    saved = preserve_native_failure(database, scan_id=SCAN_ID, stage_run_id=STAGE_ID,
        event_text=events, stderr=stderr, failure_code="nonzero_exit", exit_code=1, before=before)
    directory = saved["directory"]
    assert saved["summary"] == {"failure_code": "nonzero_exit", "exit_code": 1,
                                "classification": "no_persisted_progress", "changed_tables": []}
    assert directory.is_relative_to(database.parent)
    assert (directory / "events.jsonl").read_text() == events
    assert (directory / "stderr.txt").read_text() == stderr
    manifest = json.loads((directory / "failure.json").read_text())
    assert manifest["artifacts"]["stderr.txt"]["sha256"] == hashlib.sha256(stderr.encode()).hexdigest()
    assert "private-session-token" not in json.dumps(manifest)
    assert "private-stderr-token" not in json.dumps(manifest)
    assert database.read_bytes() == original
    if os.name != "nt":
        assert directory.stat().st_mode & 0o777 == 0o700
        assert directory.parent.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())


def test_separate_failures_preserve_previous_diagnostics(database: Path) -> None:
    before = _snapshot(database)
    first = preserve_native_failure(database, scan_id=SCAN_ID, stage_run_id=STAGE_ID,
        event_text="first event\n", stderr="first failure", failure_code="nonzero_exit", before=before)
    originals = {path.name: path.read_bytes() for path in first["directory"].iterdir()}
    second = preserve_native_failure(database, scan_id=SCAN_ID, stage_run_id=STAGE_ID,
        event_text="second event\n", stderr="second failure", failure_code="nonzero_exit", before=before)
    assert first["directory"] != second["directory"]
    assert {path.name: path.read_bytes() for path in first["directory"].iterdir()} == originals


def test_artifact_write_failure_does_not_mask_original_failure_classification(database: Path) -> None:
    root = database.parent / ".private-diagnostics"
    root.write_text("not a directory")
    saved = preserve_native_failure(database, scan_id=SCAN_ID, stage_run_id=STAGE_ID,
        event_text="error event\n", stderr="error output", failure_code="nonzero_exit", before=_snapshot(database))
    assert saved["summary"]["classification"] == "no_persisted_progress"
    assert saved["directory"] is None
    assert saved["storage_error"] == "FileExistsError"


def test_private_diagnostics_reject_a_symlink_directory(database: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (database.parent / ".private-diagnostics").symlink_to(outside, target_is_directory=True)
    saved = preserve_native_failure(database, scan_id=SCAN_ID, stage_run_id=STAGE_ID,
        event_text="private event\n", stderr="private output", failure_code="nonzero_exit", before=_snapshot(database))
    assert saved["directory"] is None
    assert saved["storage_error"] == "OSError"
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("failure_kind,progress", [
    ("nonzero", False), ("nonzero", True), ("jsonl_only", False), ("timeout", False),
    ("policy", False), ("policy_event", False), ("capacity", False),
])
def test_native_failure_captures_outputs_once_and_never_retries(
    database: Path, tmp_path: Path, failure_kind: str, progress: bool,
) -> None:
    scope = tmp_path / "Scope.md"
    policy = tmp_path / "TargetPolicy.json"
    scope.write_text("# Offline diagnostic fixture")
    policy.write_text("{}")
    event_text = (
        '{"type":"turn.failed","error":{"message":"This content was flagged '
        'for possible cybersecurity risk."}}\n'
        if failure_kind == "policy_event" else
        '{"type":"turn.failed","error":"private-jsonl-token"}\n'
    )
    stderr = "tool editor diagnostic" if failure_kind == "policy_event" else (
        "Selected model is at capacity. Please try a different model."
        if failure_kind == "capacity" else
        "" if failure_kind == "jsonl_only" else (
        "This content was flagged for possible cybersecurity risk."
        if failure_kind == "policy" else "detail\n" * 1000 + "private-stderr-token\n"
        )
    )

    def failed_run(command, **kwargs):
        kwargs["stdout"].write(event_text)
        if progress:
            with sqlite3.connect(database) as conn:
                conn.execute("UPDATE attack_tasks SET status='running' WHERE task_id='task'")
        if failure_kind == "timeout":
            raise CodexProcessTimeout(command, 10, reason="idle", stderr=stderr)
        return SimpleNamespace(returncode=1, stderr=stderr)

    agent = CodexMainAgent(attack_model="gpt-6.1-sol")
    with patch("aidast.agents.native_pipeline.shutil.which", return_value="codex"), \
         patch.object(agent, "_require_login"), \
         patch.object(agent, "_attack_authorization_broker"), \
         patch("aidast.agents.native_pipeline.HelperCommandBroker"), \
         patch("aidast.agents.native_pipeline.stage_helper_client"), \
         patch("aidast.agents.native_pipeline.codex_process.run_codex", side_effect=failed_run) as run, \
         patch("aidast.agents.native_pipeline.record_jsonl_usage") as record_usage:
        with pytest.raises(MainAgentError) as caught:
            agent.run_attack_orchestrator(scan_id=SCAN_ID, db_path=database, scope_path=scope,
                policy_path=policy, stage_run_id=STAGE_ID, attack_tasks=[],
                selected_skill_names=(), selection_reasons={})
    assert run.call_count == 1
    record_usage.assert_called_once_with(event_text.splitlines())
    error = caught.value
    assert getattr(error, "failure_code", None) == (
        "model_policy_refusal" if failure_kind in {"policy", "policy_event"}
        else "model_capacity" if failure_kind == "capacity"
        else "timeout" if failure_kind == "timeout" else "nonzero_exit"
    )
    assert error.failure_diagnostics["classification"] == (
        "persisted_state_changed" if progress else "no_persisted_progress")
    assert (error.diagnostic_directory / "events.jsonl").read_text() == event_text
    assert (error.diagnostic_directory / "stderr.txt").read_text() == stderr
    assert str(error.diagnostic_directory) not in str(error)
    assert ".private-diagnostics" not in str(error)

    # Public snapshots/audits must not serialize private exception attributes,
    # local artifact paths, or the raw outputs saved for local investigation.
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='failed',error_message=?", (str(error),))
        conn.execute("INSERT INTO audit_events VALUES ('failed', ?, ?, 'stage.failed')", (SCAN_ID, STAGE_ID))

    async def public_views() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(result_root=tmp_path)),
                                     base_url="http://test") as client:
            for endpoint in (f"/api/v1/scans/{SCAN_ID}", f"/api/v1/scans/{SCAN_ID}/audit"):
                response = await client.get(endpoint)
                assert response.status_code == 200
                assert ".private-diagnostics" not in response.text
                assert str(error.diagnostic_directory) not in response.text
                assert "private-jsonl-token" not in response.text
                assert "private-stderr-token" not in response.text

    asyncio.run(public_views())
