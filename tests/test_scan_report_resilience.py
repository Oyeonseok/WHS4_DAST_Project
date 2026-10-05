"""Offline failure boundaries and truthful reports for partial scan results."""

import json
import sqlite3
import threading
import time
from contextvars import ContextVar
from pathlib import Path

import pytest

import test_shared_validation_reporting as shared
from aidast.pipeline.lifecycle import finish_stage_run
from aidast.recon import db
from aidast.reporting.auto import generate_scan_reports
from aidast.reporting.runtime import ReportError
from aidast.reporting.scan_summary import write_scan_summary


@pytest.fixture
def case():
    fixture = shared.SharedValidationReportingTests(methodName="runTest")
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


def output_for(case):
    return case.path.parent.parent / "ReportRun" / "scan"


def complete_validation(case):
    finish_stage_run(case.conn, case.run)
    case.conn.execute("UPDATE scans SET status='completed' WHERE scan_id='scan'")
    case.conn.commit()


def test_writer_failure_preserves_other_cases_and_safe_retry(case):
    case.complete(case_id="a_failed", finding="finding")
    case.complete(case_id="b_good", finding="known_finding")
    complete_validation(case)
    calls = []

    class Writer:
        def write(self, context):
            identifier = context["source"]["case_id"]
            calls.append(identifier)
            if identifier == "a_failed":
                raise TimeoutError("secret-token=must-not-be-in-summary")
            return case.draft(context, "evidence_" + identifier)

    results = generate_scan_reports(case.path, output_for(case), scan_id="scan",
                                    platform="hackerone", writer=Writer())
    assert sorted(calls) == ["a_failed", "b_good"]
    assert [item["case_id"] for item in results] == ["b_good"]
    assert results.errors == [{"stage": "report", "case_id": "a_failed",
                               "language": None, "error_type": "TimeoutError"}]
    assert (output_for(case) / "a_failed" / "Report.db").is_file()
    assert not (output_for(case) / "a_failed" / "Report.md").exists()
    assert (output_for(case) / "b_good" / "Report.md").is_file()
    summary = json.loads(Path(results.summary["summary_path"]).read_text())
    assert summary["execution_status"] == "partial"
    assert summary["reports"][0]["case_id"] == "b_good"
    assert "must-not-be-in-summary" not in json.dumps(summary)
    assert case.conn.execute("SELECT status FROM stage_runs WHERE stage='report'").fetchone()[0] == "failed"
    audit = case.conn.execute("SELECT details_json FROM audit_events WHERE event_type='report.draft_failed'").fetchone()[0]
    assert json.loads(audit)["error_type"] == "TimeoutError"
    assert "secret-token" not in audit

    before = (output_for(case) / "b_good" / "Report.md").read_bytes()

    class RetryWriter:
        def write(self, context):
            return case.draft(context, "evidence_" + context["source"]["case_id"])

    retried = generate_scan_reports(case.path, output_for(case), scan_id="scan",
                                   platform="hackerone", writer=RetryWriter())
    assert [item["case_id"] for item in retried] == ["a_failed", "b_good"]
    assert retried.errors == []
    assert (output_for(case) / "b_good" / "Report.md").read_bytes() == before
    # Current completion and historical errors are represented independently.
    assert retried.summary["execution_status"] == "completed"
    assert any(item["stage"] == "report" and item["status"] == "failed"
               for item in retried.summary["stages"])
    assert retried.summary["latest_stages"][-1]["status"] == "completed"


def test_completed_scan_replaces_stale_same_case_report_and_archives_revision(case):
    evidence = case.complete()

    class Writer:
        def write(self, context):
            return case.draft(context, evidence)

    output = output_for(case)
    first, = generate_scan_reports(
        case.path, output, scan_id="scan", platform="hackerone", writer=Writer(),
    )
    first_db = Path(first["report_db"])
    with sqlite3.connect(first_db) as conn:
        first_context = json.loads(conn.execute(
            "SELECT context_json FROM report_runs"
        ).fetchone()[0])

    # A new current eligibility record changes the source binding while the
    # scan, case, platform, and validated decision remain the same.
    case.eligibility()
    complete_validation(case)
    retried, = generate_scan_reports(
        case.path, output, scan_id="scan", platform="hackerone", writer=Writer(),
    )

    assert retried["report_id"] != first["report_id"]
    assert retried["stale"] is False
    archive = (
        first_db.parent / "History" / first_context["context_sha256"]
        / "Snapshot.db"
    )
    assert archive.is_file()
    assert first_db.is_file()
    assert Path(retried["report_path"]).is_file()


def test_locale_writer_failure_does_not_discard_other_locale(case):
    evidence = case.complete()
    complete_validation(case)

    class Writer:
        def write(self, context):
            if context["language"] == "ko":
                raise RuntimeError("writer unavailable")
            return case.draft(context, evidence)

    results = generate_scan_reports(case.path, output_for(case), scan_id="scan", writer=Writer())
    assert len(results) == 1
    assert Path(results[0]["report_path"]) == (output_for(case) / "en" / "case" / "Report.md").resolve()
    assert results.errors[0]["language"] == "ko"
    assert (output_for(case) / "ScanSummary.md").is_file()


def test_model_generation_is_bounded_parallel_and_persisted_in_stable_order(case):
    for case_id, finding in (
        ("a_case", "finding"),
        ("b_case", "known_finding"),
        ("c_case", "contested_finding"),
    ):
        case.complete(case_id=case_id, finding=finding)
    complete_validation(case)
    active = 0
    peak = 0
    completed = []
    lock = threading.Lock()
    inherited = ContextVar("report_parallel_test", default="missing")
    inherited.set("present")

    class Writer:
        def write(self, context):
            nonlocal active, peak
            assert inherited.get() == "present"
            key = (context["source"]["case_id"], context["language"])
            with lock:
                active += 1
                peak = max(peak, active)
            # Earlier ordered items finish later, proving completion order does
            # not control the returned or persisted order.
            time.sleep(.04 if key[0] == "a_case" else .01)
            with lock:
                completed.append(key)
                active -= 1
            return case.draft(context, "evidence_" + key[0])

    results = generate_scan_reports(
        case.path, output_for(case), scan_id="scan", writer=Writer(),
    )

    assert 2 <= peak <= 3
    assert completed[:2] != [("a_case", "ko"), ("a_case", "en")]
    assert [
        (item["case_id"], "en" if "/en/" in item["report_path"] else "ko")
        for item in results
    ] == [
        ("a_case", "ko"), ("a_case", "en"),
        ("b_case", "ko"), ("b_case", "en"),
        ("c_case", "ko"), ("c_case", "en"),
    ]
    assert results.errors == []
    assert results.summary["report_counts"] == {
        "finding_cases": 3,
        "localized_drafts": 6,
    }
    summary_markdown = (output_for(case) / "ScanSummary.md").read_text()
    assert "생성된 취약점 보고서: 3" in summary_markdown
    assert "생성된 언어별 보고서 초안: 6" in summary_markdown


def test_invalid_draft_is_diagnostic_without_publishing_a_finding(case):
    case.complete()
    complete_validation(case)

    class Writer:
        def write(self, context):
            draft = case.draft(context, "foreign-evidence")
            return draft

    results = generate_scan_reports(case.path, output_for(case), scan_id="scan",
                                    platform="hackerone", writer=Writer())
    assert results == []
    assert results.errors[0]["error_type"] == "InvalidReportDraft"
    assert not (output_for(case) / "case" / "Report.md").exists()
    with sqlite3.connect(output_for(case) / "case" / "Report.db") as conn:
        assert conn.execute("SELECT count(*) FROM report_drafts").fetchone()[0] == 0


def test_corrupted_case_stops_batch_and_retains_existing_success(case):
    case.complete(case_id="a_good", finding="finding")
    case.complete(case_id="z_bad", finding="known_finding")
    complete_validation(case)
    case.conn.execute("UPDATE validation_cases SET decision_sha256=? WHERE case_id='z_bad'", ("0" * 64,))
    case.conn.commit()
    calls = []

    class Writer:
        def write(self, context):
            identifier = context["source"]["case_id"]
            calls.append(identifier)
            return case.draft(context, "evidence_" + identifier)

    with pytest.raises(ReportError, match="digest mismatch"):
        generate_scan_reports(case.path, output_for(case), scan_id="scan",
                              platform="hackerone", writer=Writer())
    assert calls == ["a_good"]
    assert (output_for(case) / "a_good" / "Report.md").is_file()
    assert not (output_for(case) / "z_bad").exists()
    summary = json.loads((output_for(case) / "ScanSummary.json").read_text())
    assert summary["execution_status"] == "partial"
    assert [item["case_id"] for item in summary["reports"]] == ["a_good"]
    assert summary["errors"] == [{"stage": "report", "error_type": "ReportError"}]


def test_interrupt_records_cancelled_report_without_converting_to_writer_failure(case):
    case.complete()
    complete_validation(case)

    class Writer:
        def write(self, context):
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        generate_scan_reports(case.path, output_for(case), scan_id="scan",
                              platform="hackerone", writer=Writer())
    assert case.conn.execute("SELECT status FROM stage_runs WHERE stage='report'").fetchone()[0] == "cancelled"
    summary = json.loads((output_for(case) / "ScanSummary.json").read_text())
    assert summary["errors"][0]["error_type"] == "KeyboardInterrupt"
    assert summary["execution_status"] == "partial"


def test_report_storage_failure_stops_batch_and_preserves_prepared_source(case, monkeypatch):
    case.complete(case_id="a_failed", finding="finding")
    case.complete(case_id="b_pending", finding="known_finding")
    complete_validation(case)
    calls = []

    class Writer:
        def write(self, context):
            identifier = context["source"]["case_id"]
            calls.append(identifier)
            return case.draft(context, "evidence_" + identifier)

    def disk_failure(*args, **kwargs):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr("aidast.reporting.case_runtime.record_case_report", disk_failure)
    with pytest.raises(sqlite3.OperationalError, match="disk full"):
        generate_scan_reports(case.path, output_for(case), scan_id="scan",
                              platform="hackerone", writer=Writer())
    # Independent model calls can finish before the first ordered persistence
    # failure is observed.  The later draft must still remain uncommitted.
    assert sorted(calls) == ["a_failed", "b_pending"]
    assert (output_for(case) / "a_failed" / "Report.db").is_file()
    assert not (output_for(case) / "a_failed" / "Report.md").exists()
    assert (output_for(case) / "b_pending" / "Report.db").is_file()
    assert not (output_for(case) / "b_pending" / "Report.md").exists()
    summary = json.loads((output_for(case) / "ScanSummary.json").read_text())
    assert summary["errors"][0]["error_type"] == "OperationalError"
    assert summary["execution_status"] == "partial"


def test_corrupted_published_artifact_remains_fatal_and_is_not_overwritten(case):
    evidence = case.complete()
    complete_validation(case)

    class Writer:
        def write(self, context):
            return case.draft(context, evidence)

    generate_scan_reports(case.path, output_for(case), scan_id="scan",
                          platform="hackerone", writer=Writer())
    report_dir = output_for(case) / "case"
    (report_dir / "Report.context.json").write_text("{}\n")
    before = {path.name: path.read_bytes() for path in report_dir.iterdir() if path.is_file()}
    with pytest.raises(ReportError, match="Report.context.json has different contents"):
        generate_scan_reports(case.path, output_for(case), scan_id="scan",
                              platform="hackerone", writer=Writer())
    assert {path.name: path.read_bytes() for path in report_dir.iterdir() if path.is_file()} == before
    summary = json.loads((output_for(case) / "ScanSummary.json").read_text())
    assert summary["execution_status"] == "partial"
    assert summary["reports"] == []


def test_empty_scan_summary_is_written_without_calling_a_writer(case):
    complete_validation(case)

    class Writer:
        def write(self, context):
            pytest.fail("no writer call for an empty scan")

    results = generate_scan_reports(case.path, output_for(case), scan_id="scan",
                                    platform="hackerone", writer=Writer())
    assert results == []
    assert results.summary["execution_status"] == "completed"
    assert results.summary["validation"]["current_confirmed"] == 0
    assert results.summary["inventory"]["candidate_findings"] == 3
    assert results.summary["reports"] == []
    assert (output_for(case) / "ScanSummary.md").is_file()


def test_recon_summary_is_read_only_scan_bound_and_reports_tool_errors(tmp_path):
    source = tmp_path / "Recon.db"
    with db.connect(source) as conn:
        for identifier in ("scan", "foreign"):
            db.insert_scan(conn, scan_id=identifier, scope_type="test", scope_value="fixture")
            db.insert_asset(conn, scan_id=identifier, identifier="example.test", asset_type="DOMAIN")
        conn.execute("UPDATE scans SET status='completed_with_errors' WHERE scan_id='scan'")
        conn.execute("""INSERT INTO pipeline_runs
            (pipeline_run_id,scan_id,stage,status,error_type,message,recoverable)
            VALUES ('tool','scan','HTTP_PROBE','failed','TimeoutError','sensitive prompt',1)""")
        conn.commit()
    original = source.read_bytes()
    result = write_scan_summary(source, tmp_path / "reports", scan_id="scan")
    assert result["inventory"]["assets"] == 1
    assert result["validation"]["available"] is False
    assert result["tools"]["errors"] == [{"stage": "HTTP_PROBE", "error_type": "TimeoutError",
                                          "recoverable": 1, "count": 1}]
    assert result["execution_status"] == "partial"
    assert "sensitive prompt" not in json.dumps(result)
    assert source.read_bytes() == original
    bytes_before = {p.name: p.read_bytes() for p in (tmp_path / "reports").iterdir()}
    write_scan_summary(source, tmp_path / "reports", scan_id="scan")
    assert {p.name: p.read_bytes() for p in (tmp_path / "reports").iterdir()} == bytes_before


def test_missing_source_is_not_created_and_scan_summary_cannot_overwrite_other_scan(case, tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        write_scan_summary(missing, tmp_path / "reports", scan_id="scan")
    assert not missing.exists()
    write_scan_summary(case.path, output_for(case), scan_id="scan")
    before = (output_for(case) / "ScanSummary.json").read_bytes()
    db.insert_scan(case.conn, scan_id="foreign", scope_type="test", scope_value="fixture")
    case.conn.commit()
    with pytest.raises(ReportError, match="different scan"):
        write_scan_summary(case.path, output_for(case), scan_id="foreign")
    assert (output_for(case) / "ScanSummary.json").read_bytes() == before


def test_symlink_output_does_not_receive_summary(case, tmp_path):
    destination = tmp_path / "outside"
    destination.mkdir()
    output = tmp_path / "linked-output"
    output.symlink_to(destination, target_is_directory=True)
    with pytest.raises(ReportError, match="symlinks"):
        write_scan_summary(case.path, output, scan_id="scan")
    assert list(destination.iterdir()) == []
