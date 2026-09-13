"""Reporting invariants for shared Pipeline.db Validation cases."""

import copy
import json
import sqlite3
from pathlib import Path

import pytest

from aidast.pipeline.lifecycle import start_stage_run
from aidast.recon import db
from aidast.reporting import ReportAgent, ReportError, prepare_report, record_report, report_status
from aidast.validation import ValidationRepository, canonical_sha256


@pytest.fixture
def validation(tmp_path):
    pipeline_dir = tmp_path / "pipeline"
    pipeline_dir.mkdir()
    path = pipeline_dir / "Pipeline.db"
    conn = db.init_db(path)
    db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
    asset = db.insert_asset(conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="test", port=443,
        base_url="https://test",
    )
    conn.execute(
        "INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('endpoint',?,'/')",
        (origin,),
    )
    conn.execute(
        """INSERT INTO findings
           (finding_id,scan_id,endpoint_id,vuln_type,severity,title)
           VALUES ('finding','scan','endpoint','idor','LOW','fixture')"""
    )
    stage = start_stage_run(conn, scan_id="scan", stage="validation", stage_run_id="stage")
    repo = ValidationRepository(conn)
    repo.create_case(
        scan_id="scan", stage_run_id=stage, target_kind="finding",
        target_id="finding", case_id="case",
    )
    attempt = repo.add_attempt(
        case_id="case", stage_run_id=stage, batch_no=1, attempt_kind="target",
        ordinal=1, signal_type="authorization_boundary", outcome="observed",
    )
    evidence = repo.add_evidence(
        case_id="case", stage_run_id=stage, attempt_id=attempt,
        evidence_kind="observation", details={"summary": "bounded fixture"},
        content_sha256="a" * 64, content_length=1, evidence_id="evidence",
    )
    repo.finalize(
        "case", stage_run_id=stage, expected_version=0, status="CONFIRMED",
        decision={"summary": "confirmed fixture", "evidence_ids": [evidence]},
        evidence_ids=[evidence], impact=(1, 1, 1),
    )
    conn.close()
    return path, evidence


def draft_for(context, evidence="evidence"):
    def cited(text):
        return {"text": text, "evidence_ids": [evidence]}

    return {
        "platform": context["platform"], "case_id": context["source"]["case_id"],
        "source_context_sha256": context["context_sha256"],
        "title": cited("Validated fixture result"), "asset": cited("Local fixture"),
        "weakness": cited("IDOR"), "summary": cited("Fresh replay confirmed the behavior."),
        "steps_to_reproduce": [cited("Review the persisted replay evidence.")],
        "expected_behavior": cited("Cross-user access is denied."),
        "actual_behavior": cited("Cross-user access was observed."),
        "impact": cited("An identity boundary was crossed."),
        "attachment_evidence_ids": [evidence],
    }


def context_for(result):
    return json.loads(Path(result["context_path"]).read_text(encoding="utf-8"))


@pytest.mark.parametrize("platform", ["hackerone", "bugcrowd", "intigriti"])
def test_report_agent_drafts_one_idempotent_shared_case_report(validation, tmp_path, platform):
    path, evidence = validation
    calls = []

    class Writer:
        def write(self, context):
            calls.append(context)
            return draft_for(context, evidence)

    output = tmp_path / "reports" / platform
    result = ReportAgent(Writer()).run(path, output, platform=platform, case_id="case")
    assert result["status"] == "drafted"
    assert result["source"]["decision_sha256"]
    assert ReportAgent(Writer()).run(path, output, platform=platform, case_id="case") == result
    assert len(calls) == 1


@pytest.mark.parametrize(
    "status", ["DISPROVEN", "OUT_OF_SCOPE", "UNDERPOWERED", "BLOCKED", "INCONCLUSIVE"],
)
def test_nonconfirmed_case_is_rejected(validation, tmp_path, status):
    path, _ = validation
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE validation_cases SET current_status=? WHERE case_id='case'", (status,))
    with pytest.raises(ReportError, match="CONFIRMED"):
        prepare_report(path, tmp_path / "report", platform="hackerone", case_id="case")


@pytest.mark.parametrize("platform", ["immunefi", "unknown", "HackerOne", "", "../hackerone"])
def test_unsupported_platform_is_rejected(validation, tmp_path, platform):
    with pytest.raises(ReportError, match="platform"):
        prepare_report(validation[0], tmp_path / "report", platform=platform, case_id="case")


@pytest.mark.parametrize("field,value", [
    ("case_id", "other"),
    ("source_context_sha256", "0" * 64),
    ("attachment_evidence_ids", ["invented"]),
    ("steps_to_reproduce", []),
    ("execute", "shell command"),
    ("vrt_category", {"text": "Unspecified", "evidence_ids": ["evidence"]}),
])
def test_invalid_model_output_never_persists(validation, tmp_path, field, value):
    result = prepare_report(
        validation[0], tmp_path / "report", platform="hackerone", case_id="case",
    )
    draft = draft_for(context_for(result))
    draft[field] = value
    with pytest.raises(ValueError):
        record_report(Path(result["report_db"]), draft)
    assert report_status(Path(result["report_db"]))["status"] == "prepared"


def test_immutable_draft_and_stale_decision(validation, tmp_path):
    path, _ = validation
    result = prepare_report(path, tmp_path / "report", platform="hackerone", case_id="case")
    report_db = Path(result["report_db"])
    draft = draft_for(context_for(result))
    record_report(report_db, draft)
    changed = copy.deepcopy(draft)
    changed["impact"]["text"] = "Different prose"
    with pytest.raises(ReportError, match="different immutable"):
        record_report(report_db, changed)
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE validation_cases SET decision_json='{}',decision_sha256=? WHERE case_id='case'",
            (canonical_sha256({}),),
        )
    assert report_status(report_db)["stale"] is True
    with pytest.raises(ReportError, match="differs"):
        record_report(report_db, draft)


def test_rehashed_forged_context_cannot_expand_evidence(validation, tmp_path):
    result = prepare_report(
        validation[0], tmp_path / "report", platform="hackerone", case_id="case",
    )
    report_db = Path(result["report_db"])
    context = context_for(result)
    context["allowed_evidence_ids"].append("invented")
    context["context_sha256"] = canonical_sha256({
        key: value for key, value in context.items() if key != "context_sha256"
    })
    with sqlite3.connect(report_db) as conn:
        conn.execute(
            "UPDATE report_runs SET context_json=?,context_sha256=?",
            (json.dumps(context, sort_keys=True, separators=(",", ":")),
             context["context_sha256"]),
        )
    with pytest.raises(ReportError, match="source changed"):
        report_status(report_db)


def test_render_escapes_active_markup_and_missing_exports_are_recovered(validation, tmp_path):
    path, _ = validation
    output = tmp_path / "report"
    result = prepare_report(path, output, platform="intigriti", case_id="case")
    draft = draft_for(context_for(result))
    draft["summary"]["text"] = '<script>alert(1)</script> ![beacon](https://invalid/image)'
    record_report(Path(result["report_db"]), draft)
    markdown = output.joinpath("Report.md").read_text(encoding="utf-8")
    assert "<script>" not in markdown and "![beacon](" not in markdown
    output.joinpath("Report.md").unlink()
    output.joinpath("Report.json").unlink()
    prepare_report(path, output, platform="intigriti", case_id="case")
    assert output.joinpath("Report.md").is_file() and output.joinpath("Report.json").is_file()
