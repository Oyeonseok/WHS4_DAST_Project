from __future__ import annotations

import json
from pathlib import Path

from scripts.run_dashboard_soak import SoakConfig, SoakSupervisor, evaluate_run


CONFIG = SoakConfig("http://dashboard.test", "baseline", "target", 10)


def good_inputs(scan_id: str = "scan_one"):
    snapshot = {
        "scan_id": scan_id,
        "status": "completed",
        "stage_statuses": {stage: "completed" for stage in (
            "Scope", "Recon", "Attack", "Chaining", "Validation", "Report"
        )},
        "logs": [],
    }
    audit = {"events": []}
    wiki = {
        "configured": True,
        "lint": {"ok": True},
        "comparison": {"baseline_id": "baseline", "baseline_count": 81,
                       "matched_count": 73, "exact_recall": 73 / 81},
    }
    validations = {"cases": [
        {"case_id": "confirmed", "processing_phase": "completed", "current_status": "CONFIRMED"},
        {"case_id": "inconclusive", "processing_phase": "completed", "current_status": "INCONCLUSIVE"},
    ]}
    reports = {"reports": [
        {"report_id": "report_ko", "case_id": "confirmed", "language": "ko", "title": "제목"},
        {"report_id": "report_en", "case_id": "confirmed", "language": "en", "title": "Title"},
    ]}
    return snapshot, audit, wiki, validations, reports


def test_evaluation_requires_completed_stages_clean_logs_recall_and_bilingual_reports():
    result = evaluate_run("scan_one", *good_inputs(), CONFIG)
    assert result["passed"] is True
    assert result["validation"] == {
        "case_count": 2,
        "completed_count": 2,
        "confirmed_count": 1,
        "confirmed_case_ids": ["confirmed"],
    }


def test_evaluation_rejects_skipped_stage_incomplete_case_and_token_title():
    snapshot, audit, wiki, validations, reports = good_inputs()
    snapshot["stage_statuses"]["Attack"] = "skipped"
    validations["cases"][1]["processing_phase"] = "queued"
    reports["reports"][1]["title"] = "[TOKEN_EMAIL] exposure"
    result = evaluate_run("scan_one", snapshot, audit, wiki, validations, reports, CONFIG)
    assert result["passed"] is False
    assert result["checks"]["stages_completed"] is False
    assert result["checks"]["validations_completed"] is False
    assert result["checks"]["clean_report_titles"] is False


def test_evaluation_requires_ko_and_en_for_every_confirmed_case():
    inputs = list(good_inputs())
    inputs[-1]["reports"].pop()
    result = evaluate_run("scan_one", *inputs, CONFIG)
    assert result["checks"]["bilingual_reports"] is False
    assert result["report_coverage"]["missing_languages"] == {"confirmed": ["en"]}


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def call(self, path, payload=None):
        self.calls.append((path, payload))
        response = self.responses[path]
        return response() if callable(response) else response


def test_supervisor_preserves_existing_success_and_evaluates_unrecorded_id(tmp_path: Path):
    ids = tmp_path / "ids.txt"
    ids.write_text("scan_one\nscan_two\n")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"schema_version": "1.0", "status": "running", "runs": [
        {"scan_id": "scan_one", "passed": True, "legacy": "retained"}
    ]}))
    snapshot, audit, wiki, validations, reports = good_inputs("scan_two")
    client = FakeClient({
        "/api/v1/scans/scan_two": snapshot,
        "/api/v1/scans/scan_two/audit": audit,
        "/api/v1/scans/scan_two/recon-wiki": wiki,
        "/api/v1/scans/scan_two/validations": validations,
        "/api/v1/reports?scan_id=scan_two": reports,
    })
    supervisor = SoakSupervisor(
        client=client, config=SoakConfig(CONFIG.base_url, "baseline", "target", 2),
        ids_path=ids, state_path=state, launch_payload={}, poll_seconds=0, sleep=lambda _: None,
    )
    assert supervisor.run() == 0
    saved = json.loads(state.read_text())
    assert saved["status"] == "completed"
    assert [row["scan_id"] for row in saved["runs"]] == ["scan_one", "scan_two"]
    assert saved["runs"][0]["legacy"] == "retained"


def test_supervisor_records_failure_and_does_not_launch_next_scan(tmp_path: Path):
    ids = tmp_path / "ids.txt"
    ids.write_text("scan_bad\n")
    state = tmp_path / "state.json"
    snapshot, audit, wiki, validations, reports = good_inputs("scan_bad")
    snapshot["logs"] = [{"id": 1, "level": "error", "message_code": "boom"}]
    client = FakeClient({
        "/api/v1/scans/scan_bad": snapshot,
        "/api/v1/scans/scan_bad/audit": audit,
        "/api/v1/scans/scan_bad/recon-wiki": wiki,
        "/api/v1/scans/scan_bad/validations": validations,
        "/api/v1/reports?scan_id=scan_bad": reports,
    })
    supervisor = SoakSupervisor(
        client=client, config=CONFIG, ids_path=ids, state_path=state,
        launch_payload={"target": "never launched"}, poll_seconds=0, sleep=lambda _: None,
    )
    assert supervisor.run() == 2
    saved = json.loads(state.read_text())
    assert saved["status"] == "stopped_on_failure"
    assert saved["failed_scan_id"] == "scan_bad"
    assert saved["runs"][0]["passed"] is False
    assert all(path != "/api/v1/scans" for path, _ in client.calls)
