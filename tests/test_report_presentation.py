"""Readable reports keep the immutable source and machine evidence intact."""
import io
import json
import zipfile
import pytest

from aidast.reporting.submission import export_report, inspect_report
from test_report_submission import case, prepare, verified


def test_generic_export_keeps_sentence_punctuation_and_endpoint_readable(case):
    db = prepare(case, platform="generic", details={"endpoint": "http://127.0.0.1:3001/api/records"},
                 changes={"summary": {"text": "A recorded result. <script>alert(1)</script>", "evidence_ids": ["evidence_case"]}})
    view = inspect_report(db)
    with zipfile.ZipFile(io.BytesIO(export_report(db))) as archive:
        md = archive.read("Report.md").decode()
    assert "A recorded result." in md
    assert "http://127.0.0.1:3001/api/records" in md
    assert r"\." not in md
    assert "<script>" not in md
    assert view["fields"]["summary"].startswith("A recorded result.")


def test_english_report_preserves_language_from_writer_to_export_and_retry(case):
    from aidast.reporting.runtime import ReportAgent
    evidence = case.complete()

    class Writer:
        def write(self, context):
            assert context["language"] == "en"
            return case.draft(context, evidence)

    agent = ReportAgent(Writer())
    result = agent.run(case.path, case.output, platform="generic", case_id="case", language="en")
    db = case.output / "Report.db"
    originals = {p.name: p.read_bytes() for p in case.output.iterdir() if p.is_file()}
    view = inspect_report(db)
    assert view["language"] == "en" and view["ready"]
    assert "## Summary" in view["markdown"] and "## 핵심 요약" not in view["markdown"]
    assert view["evidence"][0]["display"]["label"] == "Reproduction request"
    with zipfile.ZipFile(io.BytesIO(export_report(db))) as archive:
        assert json.loads(archive.read("Submission.json"))["language"] == "en"
        assert json.loads(archive.read("Manifest.json"))["language"] == "en"
        assert "## Validation evidence" in archive.read("Report.md").decode()
    assert agent.run(case.path, case.output, platform="generic", case_id="case") == result
    assert {p.name: p.read_bytes() for p in case.output.iterdir() if p.is_file()} == originals


def test_invalid_report_language_blocks_export(case):
    db = prepare(case, platform="generic")
    (db.parent / "Report.language.json").write_text('{"language":"unknown"}')
    assert not inspect_report(db)["ready"]
    with pytest.raises(ValueError):
        export_report(db)


def test_case_report_cli_can_request_english_content(case, capsys):
    from aidast.cli import main
    evidence = case.complete()

    class Writer:
        def write(self, context):
            assert context["language"] == "en"
            return case.draft(context, evidence)

    assert main(["report", "run", str(case.path), "--case-id", "case", "--platform", "generic",
                 "--language", "en", "--output-dir", str(case.output)], report_writer=Writer()) == 0
    result = json.loads(capsys.readouterr().out)
    assert inspect_report(case.output / "Report.db")["language"] == "en"
    assert result["status"] == "drafted"


def test_existing_korean_draft_cannot_be_relabelled_as_an_english_translation(case):
    from aidast.reporting.runtime import ReportAgent
    db = prepare(case, platform="generic")
    # Reports written before locale support have no sidecar and default to Korean.
    (db.parent / "Report.language.json").unlink()
    originals = {p.name: p.read_bytes() for p in db.parent.iterdir() if p.is_file()}
    with pytest.raises(ValueError, match="separate output directory"):
        ReportAgent().run(case.path, case.output, platform="generic", case_id="case", language="en")
    assert inspect_report(db)["language"] == "ko"
    assert {p.name: p.read_bytes() for p in db.parent.iterdir() if p.is_file()} == originals


def test_generic_report_explains_evidence_without_internal_identifiers(case):
    db = prepare(case, platform="generic", kind="observation", details={
        "response_status": 200, "response_bytes": 184,
        "request_ids": ["request_internal_only"],
        "evaluation": {"assertions": [{"assertion_id": "assertion_internal_only", "passed": True}]},
    }, changes={"attachment_evidence_ids": ["evidence_case"], "steps_to_reproduce": [
        {"text": "1. Send the recorded request.", "evidence_ids": ["evidence_case"]},
        {"text": "2. Compare the recorded result.", "evidence_ids": ["evidence_case"]},
    ]})
    originals = {p.name: p.read_bytes() for p in db.parent.iterdir() if p.is_file()}
    view = inspect_report(db)
    md = view["markdown"]
    assert md.startswith("# Fixture report\n")
    assert md.index("## 핵심 요약") < md.index("## 영향과 범위") < md.index("## 재현 절차")
    assert "1. Send the recorded request" in md
    assert "1. 1." not in md
    assert "HTTP 200" in md and "184 bytes" in md and "판별 조건 충족" in md
    for internal in ("evidence_case", "request_internal_only", "assertion_internal_only", "Evidence/evidence-"):
        assert internal not in md
    with zipfile.ZipFile(io.BytesIO(export_report(db, expected_revision=view["revision_sha256"]))) as archive:
        evidence = json.loads(archive.read("Evidence/evidence-001.json"))
        assert evidence["evidence_id"] == "evidence_case"
        assert evidence["details"]["request_ids"] == ["request_internal_only"]
        assert archive.read("Report.md").decode() == md
    assert {p.name: p.read_bytes() for p in db.parent.iterdir() if p.is_file()} == originals


def test_generic_custom_template_is_preserved_with_readable_evidence(case):
    db = prepare(case, platform="generic", details={"summary": "Bounded recorded observation."})
    view = verified(db, report_template="Operator format\n{summary}")
    assert "Operator format\nA bounded fixture was validated." in view["markdown"]
    assert "## 검증 근거" in view["markdown"]
    assert "evidence_case" not in view["markdown"]


@pytest.mark.parametrize("url_key", ["endpoint", "response_url"])
def test_recorded_endpoint_and_custom_impact_remain_in_reader_presentation(case, url_key):
    db = prepare(case, platform="generic", details={url_key: "https://example.test/records"})
    view = verified(db, impact_template="Operator impact: {impact}")
    assert "https://example" in view["markdown"] and "/records" in view["markdown"]
    assert view["rendered_impact"] == "Operator impact: Boundary crossed"
    assert view["rendered_impact"] in view["markdown"]


@pytest.mark.parametrize("alignment", [[], {}])
def test_untyped_evidence_metadata_does_not_break_reader_summary(case, alignment):
    db = prepare(case, platform="generic", details={"alignment": alignment})
    view = inspect_report(db)
    assert view["ready"]
    assert view["evidence"][0]["display"]["result"] == "상세 검증 기록에 포함"
    assert export_report(db).startswith(b"PK")
