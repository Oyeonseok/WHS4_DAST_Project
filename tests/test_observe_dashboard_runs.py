from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from aidast.pipeline.model_settings import ScanModelChoices
from scripts.observe_dashboard_runs import (
    DashboardClient, ObservationError, STAGES, assess, collect_full_ledger,
    evidence, finalize, load_ids, main, observe, remember_events,
)

BASELINE = "a" * 24
MODELS = ScanModelChoices(**{key: "fixture-model" for key in (
    "main_model", "recon_model", "attack_model", "chaining_model",
    "validation_model", "report_model",
)})


def passing_row(scan_id="scan_one"):
    return {"scan_id": scan_id, "terminal_status": "completed",
            "stage_statuses": dict.fromkeys(STAGES, "completed"),
            "error_events": {}, "observation_errors": [], "event_coverage_complete": True,
            "persisted_models": MODELS.model_dump(), "expected_models_match": True,
            "summary_present": True,
            "recon_wiki": {"configured": True, "lint_ok": True,
                           "baseline_id": BASELINE, "baseline_count": 81,
                           "exact_recall": 75 / 81}}


class FixtureDashboard:
    def __init__(self, statuses=("completed",), *, errors=False, summary=True):
        self.statuses = statuses
        self.calls = []
        self.polls = {}
        self.errors = errors
        self.summary = summary

    def request(self, path, payload=None, *, markdown=False):
        self.calls.append((path, payload))
        scan_id = path.split("/")[4] if path.startswith("/api/v1/scans/") else None
        if path.endswith("/audit"):
            return {"events": ([{"id": "older", "level": "error", "event_type": "stage.failed",
                                 "message": "sensitive free-form data"}] if self.errors else [])}
        if path.endswith("/recon-wiki"):
            if payload is not None:
                assert self.statuses[min(self.polls[scan_id] - 1, len(self.statuses) - 1)] == "completed"
            return {"configured": True, "lint": {"ok": True},
                    "comparison": {"baseline_id": BASELINE, "baseline_kind": "source",
                                   "baseline_count": 81, "observed_count": 86,
                                   "matched_count": 75, "exact_recall": 75 / 81,
                                   "path_recall": .97, "confirmed_matched_count": 40,
                                   "declared_candidate_matched_count": 35,
                                   "missing": 6, "report_markdown": "sensitive body"}}
        if path.endswith("/summary"):
            if not self.summary:
                raise ObservationError("HTTP 404", status_code=404)
            return {"scan_id": scan_id, "markdown": "# Summary\nsensitive summary body"}
        if path.startswith("/api/v1/reports?"):
            return {"reports": []}
        count = self.polls.get(scan_id, 0)
        self.polls[scan_id] = count + 1
        return {"scan_id": scan_id, "status": self.statuses[min(count, len(self.statuses) - 1)],
                "stage_statuses": dict.fromkeys(STAGES, "completed"), "logs": [],
                "last_event_id": 12}


@pytest.mark.parametrize("count", [10, 20])
def test_observes_existing_batch_without_launching_or_saving_sensitive_content(tmp_path, count):
    client = FixtureDashboard(statuses=("running", "completed"))
    with patch("scripts.observe_dashboard_runs.load_scan_model_choices", return_value=MODELS):
        result = observe(client, [f"scan_{index}" for index in range(count)],
                         result_root=tmp_path, destination=tmp_path / "evidence",
                         baseline_id=BASELINE, baseline_kind="source", compare_wiki=True,
                         baseline_count=81, min_recall=.90, timeout=10,
                         poll_seconds=.001, settle_seconds=0,
                         expected_models=MODELS.model_dump())
    assert result["passed"] and result["passed_runs"] == count
    writes = [(path, payload) for path, payload in client.calls if payload is not None]
    assert len(writes) == count
    assert all(path.endswith("/recon-wiki") for path, _payload in writes)
    raw = (tmp_path / "evidence/dashboard-observation.json").read_text()
    assert "sensitive" not in raw
    assert (tmp_path / "evidence/dashboard-observation.md").is_file()


@pytest.mark.parametrize("change,failed_check", [
    ({"terminal_status": "failed"}, "completed"),
    ({"stage_statuses": {"Recon": "completed"}}, "stages_completed"),
    ({"error_events": {"1": {"event_type": "stage.failed"}}}, "error_free"),
    ({"event_coverage_complete": False}, "event_coverage_complete"),
    ({"observation_errors": ["outage"]}, "observation_complete"),
    ({"summary_present": False}, "report_present"),
    ({"persisted_models": None}, "models_persisted"),
    ({"expected_models_match": False}, "model_selection"),
])
def test_strict_checks_expose_failure(change, failed_check):
    row = passing_row() | change
    assert assess(row, baseline_id=BASELINE, baseline_count=81, min_recall=.90)[failed_check] is False


@pytest.mark.parametrize("recall", [.89, float("nan"), float("inf"), True, None])
def test_recall_threshold_is_numeric_bounded_and_finite(recall):
    row = passing_row()
    row["recon_wiki"]["exact_recall"] = recall
    assert not assess(row, baseline_id=BASELINE, baseline_count=81, min_recall=.90)["exact_recall"]


def test_baseline_identity_and_count_are_required():
    row = passing_row()
    row["recon_wiki"] |= {"baseline_id": "b" * 24, "baseline_count": 80}
    checks = assess(row, baseline_id=BASELINE, baseline_count=81, min_recall=.90)
    assert not checks["baseline_selection"] and not checks["baseline_count"]
    assert not evidence([passing_row()])["passed"]
    assert not evidence([passing_row()] * 10)["run_count_valid"]


def test_final_collection_cannot_post_before_terminal(tmp_path):
    client = FixtureDashboard()
    row = passing_row() | {"terminal_status": "running"}
    with pytest.raises(ValueError, match="terminal"):
        finalize(client, row, result_root=tmp_path, baseline_id=BASELINE,
                 baseline_kind="source", compare_wiki=True, expected_models=None)
    assert not client.calls


def test_finding_report_is_valid_when_legacy_scan_has_no_summary(tmp_path):
    class LegacyDashboard(FixtureDashboard):
        def request(self, path, payload=None, *, markdown=False):
            if path.startswith("/api/v1/reports?"):
                return {"reports": [{"report_id": "report_one", "scan_id": "scan_one"}]}
            if path == "/api/v1/reports/report_one":
                return "# Existing finding report"
            return super().request(path, payload, markdown=markdown)

    row = passing_row()
    with patch("scripts.observe_dashboard_runs.load_scan_model_choices", return_value=MODELS):
        finalize(LegacyDashboard(summary=False), row, result_root=tmp_path,
                 baseline_id=BASELINE, baseline_kind="source", compare_wiki=False,
                 expected_models=None)
    assert not row["summary_present"] and row["reports"]
    assert not row["observation_errors"]
    assert all(assess(row, baseline_id=BASELINE, baseline_count=81, min_recall=.90).values())


def test_error_event_metadata_is_sanitized_and_not_forgotten():
    row = passing_row()
    remember_events(row, [{"id": 1, "level": "error", "message": "secret-body",
                           "event_type": "stage.failed"}], "audit")
    remember_events(row, [{"id": 2, "level": "info"}], "audit")
    assert len(row["error_events"]) == 1
    assert "secret-body" not in json.dumps(row)


def test_truncated_api_requires_full_ledger_and_reads_old_errors_read_only(tmp_path):
    row = passing_row() | {"last_event_id": 501}
    remember_events(row, [{"id": index, "level": "info"} for index in range(500)], "logs")
    assert not row["event_coverage_complete"]
    ledger = tmp_path / ".webui/events.db"
    ledger.parent.mkdir()
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE web_events(scan_id TEXT,event_id INTEGER,event_type TEXT,payload_json TEXT)")
        connection.executemany("INSERT INTO web_events VALUES(?,?,?,?)", [
            ("scan_one", 1, "log.appended", json.dumps({"level": "error", "message": "secret"})),
            ("scan_one", 501, "log.appended", json.dumps({"level": "info"})),
            ("scan_other", 502, "log.appended", json.dumps({"level": "error"})),
        ])
    before = ledger.read_bytes()
    collect_full_ledger(row, tmp_path)
    assert row["event_coverage_complete"] and len(row["error_events"]) == 1
    assert ledger.read_bytes() == before
    assert "secret" not in json.dumps(row)
    row["last_event_id"] = 999
    with pytest.raises(ObservationError, match="cursor"):
        collect_full_ledger(row, tmp_path)


def test_deadline_preserves_partial_evidence_and_never_compares_running_scan(tmp_path):
    client = FixtureDashboard(statuses=("running",))
    result = observe(client, ["scan_running"], result_root=tmp_path,
                     destination=tmp_path / "evidence", baseline_id=BASELINE,
                     baseline_kind="source", compare_wiki=True, baseline_count=81,
                     min_recall=.90, timeout=.002, poll_seconds=.001, settle_seconds=0)
    assert not result["passed"]
    assert "observation deadline reached" in result["scans"][0]["observation_errors"]
    assert all(payload is None for _path, payload in client.calls)


@pytest.mark.parametrize("url", ["https://example.com", "http://127.0.0.1.evil.test",
                                  "http://user:pass@localhost", "http://localhost/path",
                                  "http://localhost?token=secret", "file:///tmp/api"])
def test_client_rejects_nonlocal_or_credential_urls(url):
    with pytest.raises(ValueError):
        DashboardClient(url)


def test_client_rejects_launch_and_control_posts_before_transport():
    client = DashboardClient("http://127.0.0.1:8000")
    for path in ("/api/v1/scans", "/api/v1/scans/scan_one/resume", "/api/v1/scans/scan_one/stop"):
        with pytest.raises(ValueError, match="only terminal"):
            client.request(path, {})


def test_id_lists_reject_duplicates_traversal_and_accept_both_formats(tmp_path):
    source = tmp_path / "ids.txt"
    source.write_text("# existing dashboard scans\nscan_one\nscan_two\n")
    assert load_ids(source) == ["scan_one", "scan_two"]
    source.write_text('["scan_one", "scan_two"]')
    assert load_ids(source) == ["scan_one", "scan_two"]
    for raw in ('["scan_one", "scan_one"]', '["../scan"]', '[1]', '[]'):
        source.write_text(raw)
        with pytest.raises(ValueError):
            load_ids(source)


def test_cli_requires_baseline_for_comparison_and_rejects_invalid_limits(tmp_path):
    source = tmp_path / "ids.txt"
    source.write_text("scan_one\n")
    args = ["--scan-ids", str(source), "--output", str(tmp_path / "output")]
    assert main(args + ["--compare-wiki"]) == 2
    assert main(args + ["--min-recall", "nan"]) == 2
    assert main(args + ["--poll-seconds", "0"]) == 2
