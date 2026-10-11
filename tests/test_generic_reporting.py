"""Default reports use validated cases without a bug-bounty platform."""
import asyncio
import io
import json
import sqlite3
import zipfile
from pathlib import Path

import httpx
import pytest

from aidast.cli import main
from aidast.agents.main import CodexReportWriter, CodexMainAgent
from aidast.agents.native_pipeline import CodexReportWriter as NativeReportWriter
from aidast.reporting.auto import generate_scan_reports, report_platform_for_program_url
from aidast.reporting.runtime import ReportAgent, ReportError
from aidast.reporting.models import ReportDraft
from aidast.reporting.submission import ProgramRequirements, inspect_report, save_requirements
from aidast.web.reports import ReportCatalog
from aidast.validation.models import canonical_json
from aidast.web.server import create_app
import test_shared_validation_reporting as shared


@pytest.fixture
def case():
    fixture = shared.SharedValidationReportingTests(methodName="runTest")
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


@pytest.mark.parametrize("url", ["", "http://localhost:3001/", "https://example.test/program",
    "https://yeswehack.com/programs/example", "https://fakehackerone.com/example"])
def test_unidentified_platform_uses_generic_report(url):
    assert report_platform_for_program_url(url) == "generic"


def generate(case, **kwargs):
    evidence = case.complete()

    class Writer:
        def write(self, context):
            assert context["platform"] == "generic"
            return case.draft(context, evidence)

    root = case.path.parent.parent
    result, = generate_scan_reports(case.path, root / "ReportRun" / "scan",
        scan_id="scan", writer=Writer(), language="ko", **kwargs)
    return root, result


def test_generic_auto_generates_korean_and_english_reports(case):
    evidence = case.complete()
    languages = []

    class Writer:
        def write(self, context):
            language = context["language"]
            languages.append(language)
            draft = case.draft(context, evidence)
            draft["title"]["text"] = "상품 검색 취약점" if language == "ko" else "Product search vulnerability"
            return draft

    root = case.path.parent.parent
    output = root / "ReportRun" / "scan"
    reports = generate_scan_reports(case.path, output, scan_id="scan", writer=Writer())

    assert languages == ["ko", "en"]
    assert len(reports) == 2
    assert Path(reports[0]["report_path"]) == (output / "case" / "Report.md").resolve()
    assert Path(reports[1]["report_path"]) == (output / "en" / "case" / "Report.md").resolve()
    assert [inspect_report(Path(item["report_db"]))["language"] for item in reports] == ["ko", "en"]
    assert {item["title"] for item in ReportCatalog(root).list(scan_id="scan")} == {
        "상품 검색 취약점", "Product search vulnerability"}
    assert {item["language"] for item in ReportCatalog(root).list(scan_id="scan")} == {"ko", "en"}
    assert [item["report_id"] for item in generate_scan_reports(
        case.path, output, scan_id="scan", writer=Writer())] == [item["report_id"] for item in reports]
    assert languages == ["ko", "en"]


def test_default_report_is_listed_and_exported_by_dashboard_without_program_rules(case):
    root, result = generate(case)
    assert result["status"] == "drafted"
    markdown = Path(result["report_path"]).read_text()
    for heading in ["#### Asset", "#### Weakness", "## Executive Summary", "#### Steps to Reproduce", "#### Impact"]:
        assert heading in markdown
    assert "Platform: generic" in markdown
    assert "Format: PTES-style technical finding" in markdown
    assert "## Technical Report" in markdown

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(result_root=root)),
                                    base_url="http://test") as client:
            listing = await client.get("/api/v1/reports?scan_id=scan")
            assert listing.status_code == 200
            assert listing.json()["reports"][0]["platform"] == "generic"
            endpoint = "/api/v1/reports/" + result["report_id"]
            response = await client.get(endpoint + "/submission")
            assert response.status_code == 200
            view = response.json()
            assert view["ready"] is True
            assert view["requirements"]["verified"] is False
            assert view["requirements"]["severity_required"] is False
            exported = await client.get(endpoint + "/export", params={"revision": view["revision_sha256"]})
            assert exported.status_code == 200
            with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
                assert json.loads(archive.read("Submission.json"))["platform"] == "generic"
                assert "Boundary crossed" in archive.read("Report.md").decode()

    asyncio.run(scenario())


def test_generic_report_still_blocks_stale_validation(case):
    _, result = generate(case, platform="generic")
    case.conn.execute("UPDATE validation_cases SET current_status='DISPROVEN' WHERE case_id='case'")
    case.conn.commit()
    view = inspect_report(Path(result["report_db"]))
    assert not view["ready"]
    assert any(c["code"] == "source_integrity" for c in view["checks"])


@pytest.mark.parametrize("enriched", [False, True])
def test_pre_ptes_generic_draft_remains_readable(case, enriched):
    from aidast.reporting.case_runtime import _case_markdown, case_report_status
    from aidast.reporting._render import render_markdown
    from aidast.reporting.runtime import _sha

    _, result = generate(case, platform="generic")
    report_db = Path(result["report_db"])
    with sqlite3.connect(report_db) as conn:
        draft_json, context_json = conn.execute(
            "SELECT d.draft_json, r.context_json FROM report_drafts d JOIN report_runs r ON d.report_id=r.report_id"
        ).fetchone()
        draft = ReportDraft.model_validate_json(draft_json)
        old_markdown = (_case_markdown(draft, json.loads(context_json), legacy_generic=True)
                        if enriched else render_markdown(
                            draft, source=f"Validation case: `{draft.case_id}`", legacy_generic=True))
        conn.execute("UPDATE report_drafts SET markdown=?, markdown_sha256=?",
                     (old_markdown, _sha(old_markdown)))
    assert case_report_status(report_db)["status"] == "drafted"


def test_generic_report_honors_explicit_required_fields(case):
    _, result = generate(case, platform="generic")
    view = save_requirements(Path(result["report_db"]), ProgramRequirements(
        severity_required=True, required_fields=["test_environment"]))
    assert not view["ready"]
    assert {c["field"] for c in view["checks"] if c["code"] == "required_field"} >= {
        "severity", "test_environment"}


def test_generic_report_does_not_invent_a_draft_without_confirmed_cases(case):
    case.complete(status="DISPROVEN")
    output = case.path.parent.parent / "ReportRun" / "scan"
    assert generate_scan_reports(case.path, output, scan_id="scan", platform="generic") == []
    assert (output / "ScanSummary.json").is_file()
    assert (output / "ScanSummary.md").is_file()
    assert not (output / "Report.md").exists()


def test_case_report_cli_accepts_generic_format(case, capsys):
    evidence = case.complete()

    class Writer:
        def write(self, context):
            return case.draft(context, evidence)

    assert main(["report", "run", str(case.path), "--case-id", "case",
        "--platform", "generic", "--output-dir", str(case.output)], report_writer=Writer()) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["platform"] == "generic"
    assert Path(result["report_path"]).is_file()


def test_unknown_explicit_report_format_is_rejected(case):
    with pytest.raises(ReportError, match="platform"):
        generate_scan_reports(case.path, case.output, scan_id="scan", platform="unknown")


@pytest.mark.parametrize("platform", ["hackerone", "bugcrowd", "intigriti"])
def test_existing_platform_report_can_retry_with_pre_generic_schema(case, platform):
    evidence = case.complete()

    class Writer:
        def write(self, context):
            return case.draft(context, evidence)

    agent = ReportAgent(writer=Writer())
    original = agent.run(case.path, case.output, platform=platform, case_id="case")
    schema_path = Path(original["schema_path"])
    old_schema = ReportDraft.model_json_schema()
    old_schema["properties"]["platform"]["enum"] = ["hackerone", "bugcrowd", "intigriti"]
    schema_path.write_text(canonical_json(old_schema) + "\n")
    before = {path.name: path.read_bytes() for path in case.output.iterdir() if path.is_file()}

    assert agent.run(case.path, case.output, platform=platform, case_id="case") == original
    assert {path.name: path.read_bytes() for path in case.output.iterdir() if path.is_file()} == before


def test_existing_platform_schema_tampering_is_still_rejected(case):
    case.complete()
    prepared = ReportAgent().run(case.path, case.output, platform="hackerone", case_id="case")
    schema_path = Path(prepared["schema_path"])
    schema = json.loads(schema_path.read_text())
    schema["properties"]["platform"]["enum"] = ["hackerone", "bugcrowd", "intigriti"]
    schema["properties"]["title"]["type"] = "integer"
    schema_path.write_text(canonical_json(schema) + "\n")
    with pytest.raises(ReportError, match="Report.schema.json has different contents"):
        ReportAgent().run(case.path, case.output, platform="hackerone", case_id="case")


@pytest.mark.parametrize("writer_class", [CodexReportWriter, NativeReportWriter])
def test_generic_writer_routes_and_stages_general_report_skill(case, writer_class, tmp_path):
    evidence = case.complete()
    prepared = ReportAgent().run(case.path, case.output, platform="generic", case_id="case")
    context = json.loads(Path(prepared["context_path"]).read_text())

    class Agent:
        def _run_structured(self, **options):
            package, name = options["native_skill"]
            assert package == "aidast.skills.reporting.generic"
            CodexMainAgent._stage_native_skill(work_dir=tmp_path, package=package, skill_name=name)
            assert (tmp_path / '.agents/skills/aidast-reporting/references/generic.md').is_file()
            return ReportDraft.model_validate(case.draft(context, evidence))

    result = writer_class(Agent()).write(context)
    assert result["platform"] == "generic"
    assert result["source_context_sha256"] == context["context_sha256"]


@pytest.mark.parametrize("writer_class", [CodexReportWriter, NativeReportWriter])
@pytest.mark.parametrize("platform", ["generic", "hackerone"])
def test_writer_requests_evidence_bound_feature_cause_weakness_title(case, writer_class, platform):
    evidence = case.complete()
    prepared = ReportAgent().run(case.path, case.output, platform=platform, case_id="case")
    context = json.loads(Path(prepared["context_path"]).read_text())

    class Agent:
        def _run_structured(self, **options):
            prompt = options["prompt"]
            assert "affected feature" in prompt
            assert "verified cause" in prompt
            assert "weakness type" in prompt
            assert "Do not invent a cause" in prompt
            return ReportDraft.model_validate(case.draft(context, evidence))

    assert writer_class(Agent()).write(context)["platform"] == platform
