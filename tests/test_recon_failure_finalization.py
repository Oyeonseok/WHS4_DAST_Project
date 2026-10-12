"""Offline terminal-state and cleanup boundaries after a Recon failure."""

import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aidast.cli import _finalize_recon_failure
from aidast.pipeline.lifecycle import start_stage_run
from aidast.recon import db


@pytest.fixture
def run(tmp_path):
    database = tmp_path / "Recon.db"
    conn = db.init_db(database)
    db.insert_scan(conn, scan_id="scan", scope_type="fixture", scope_value="offline")
    stage = start_stage_run(conn, scan_id="scan", stage="recon")
    executor = SimpleNamespace(conn=conn, close=Mock(wraps=conn.close))
    fixture = SimpleNamespace(
        executor=executor, database=database, stage=stage,
        reports=tmp_path / "reports",
    )
    try:
        yield fixture
    finally:
        conn.close()


def finalize(run, error):
    _finalize_recon_failure(
        run.executor, stage_run_id=run.stage, scan_id="scan",
        database=run.database, report_root=run.reports, error=error,
    )


def statuses(run):
    with sqlite3.connect(run.database) as conn:
        return (
            conn.execute("SELECT status,finished_at FROM scans").fetchone(),
            conn.execute("SELECT status,finished_at FROM stage_runs").fetchone(),
        )


@pytest.mark.parametrize("error,status", [
    (TimeoutError("private model context"), "failed"),
    (KeyboardInterrupt(), "cancelled"),
    (SystemExit(130), "cancelled"),
])
def test_failure_or_interruption_records_terminal_state_and_summary(run, error, status):
    finalize(run, error)

    for actual, finished_at in statuses(run):
        assert actual == status
        assert finished_at is not None
    summary_text = (run.reports / "ScanSummary.json").read_text()
    summary = json.loads(summary_text)
    assert summary["execution_status"] == "partial"
    assert summary["errors"] == [{"stage": "recon", "error_type": type(error).__name__}]
    assert "private model context" not in summary_text
    run.executor.close.assert_called_once_with()


@pytest.mark.parametrize("table,expected_statuses,note", [
    ("scans", ("running", "failed"), "Recon scan finalization failed: IntegrityError"),
    ("stage_runs", ("failed", "running"), "Recon stage finalization failed: IntegrityError"),
])
def test_database_write_failure_does_not_skip_other_cleanup(run, table, expected_statuses, note):
    # An actual SQLite failure verifies rollback and independent terminal writes.
    run.executor.conn.execute(
        f"CREATE TRIGGER reject_cleanup BEFORE UPDATE ON {table} "
        "BEGIN SELECT RAISE(ABORT, 'private storage diagnostic'); END"
    )
    run.executor.conn.commit()
    original = TimeoutError("original model deadline")

    finalize(run, original)

    assert tuple(row[0] for row in statuses(run)) == expected_statuses
    assert original.__notes__ == [note]
    summary = json.loads((run.reports / "ScanSummary.json").read_text())
    assert summary["execution_status"] == "partial"
    assert summary["errors"] == [{"stage": "recon", "error_type": "TimeoutError"}]
    run.executor.close.assert_called_once_with()


def test_summary_and_close_failures_preserve_original_error(run, monkeypatch):
    summary = Mock(side_effect=OSError("private disk diagnostic"))
    monkeypatch.setattr("aidast.cli.write_scan_summary", summary)
    run.executor.close.side_effect = OSError("private cleanup diagnostic")
    original = KeyboardInterrupt()

    finalize(run, original)

    assert tuple(row[0] for row in statuses(run)) == ("cancelled", "cancelled")
    assert original.__notes__ == [
        "Recon summary write failed: OSError",
        "Recon cleanup failed: OSError",
    ]
    summary.assert_called_once()
    run.executor.close.assert_called_once_with()


def test_persistent_database_failure_still_attempts_summary_and_close(run):
    for table in ("scans", "stage_runs"):
        run.executor.conn.execute(
            f"CREATE TRIGGER reject_{table} BEFORE UPDATE ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END"
        )
    run.executor.conn.commit()
    original = TimeoutError("original model deadline")

    finalize(run, original)

    assert tuple(row[0] for row in statuses(run)) == ("running", "running")
    assert len(original.__notes__) == 2
    summary = json.loads((run.reports / "ScanSummary.json").read_text())
    assert summary["execution_status"] == "partial"
    assert summary["errors"] == [{"stage": "recon", "error_type": "TimeoutError"}]
    run.executor.close.assert_called_once_with()
