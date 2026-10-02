"""Offline dashboard reads isolate damaged artifacts across program schemas."""

import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from aidast.web.projection import DashboardProjector
from aidast.web.reports import ReportCatalog, ReportNotFoundError
from aidast.web.server import create_app


def _report(root: Path, scan_id: str, digit: str, *, legacy: bool = False) -> Path:
    directory = root / "ReportRun" / scan_id / digit
    directory.mkdir(parents=True)
    database = directory / "Report.db"
    report_id = "report_" + digit * 32
    markdown = f"# Offline report for {scan_id}\n\nExisting masked fixture observations.\n"
    context = json.dumps({"platform": "hackerone" if legacy else "generic", "source": {"scan_id": scan_id}})
    with sqlite3.connect(database) as conn:
        if legacy:
            conn.execute("CREATE TABLE report_runs (report_id TEXT, validation_id TEXT, "
                         "context_json TEXT, created_at TEXT, source_path TEXT)")
            conn.execute("INSERT INTO report_runs VALUES (?,?,?,?,?)", (
                report_id, "validation-fixture", context, "2026-10-01T00:00:00Z", "source.db"))
        else:
            conn.execute("CREATE TABLE report_runs (report_id TEXT, scan_id TEXT, case_id TEXT, "
                         "context_json TEXT, created_at TEXT, source_path TEXT)")
            conn.execute("INSERT INTO report_runs VALUES (?,?,?,?,?,?)", (
                report_id, scan_id, "case-fixture", context, "2026-10-01T00:00:00Z", "source.db"))
        conn.execute("CREATE TABLE report_drafts (report_id TEXT, markdown TEXT, "
                     "markdown_sha256 TEXT, created_at TEXT)")
        conn.execute("INSERT INTO report_drafts VALUES (?,?,?,?)", (
            report_id, markdown, hashlib.sha256(markdown.encode()).hexdigest(), "2026-10-01T00:01:00Z"))
    return database


@pytest.mark.parametrize("damage", [
    "context_list", "context_scalar", "language_scalar", "language_invalid", "language_oversized",
    "language_non_utf8", "invalid_report_id", "hash_mismatch", "duplicate_draft", "partial_schema",
    "db_garbage", "symlinked_directory",
])
def test_one_invalid_report_does_not_interrupt_other_previews(tmp_path: Path, damage: str) -> None:
    good = _report(tmp_path, "scan_healthy", "a")
    broken = _report(tmp_path, "scan_broken", "b")
    original = good.read_bytes()
    if damage.startswith("context_"):
        with sqlite3.connect(broken) as conn:
            conn.execute("UPDATE report_runs SET context_json=?", (
                '[]' if damage == "context_list" else '"private-session-token"',))
    elif damage.startswith("language_"):
        sidecar = broken.with_name("Report.language.json")
        payload = {"language_scalar": b'"private-session-token"', "language_invalid": b'{"language":"zz"}',
                   "language_oversized": b' ' * 129, "language_non_utf8": b'\xff'}[damage]
        sidecar.write_bytes(payload)
    elif damage == "invalid_report_id":
        with sqlite3.connect(broken) as conn:
            conn.execute("UPDATE report_runs SET report_id='invalid\nidentifier'")
            conn.execute("UPDATE report_drafts SET report_id='invalid\nidentifier'")
    elif damage == "hash_mismatch":
        with sqlite3.connect(broken) as conn:
            conn.execute("UPDATE report_drafts SET markdown='# altered draft'")
    elif damage == "duplicate_draft":
        with sqlite3.connect(broken) as conn:
            conn.execute("INSERT INTO report_drafts SELECT * FROM report_drafts")
    elif damage == "partial_schema":
        with sqlite3.connect(broken) as conn:
            conn.execute("ALTER TABLE report_runs DROP COLUMN context_json")
    elif damage == "db_garbage":
        broken.write_bytes(b"not a database")
    elif damage == "symlinked_directory":
        destination = tmp_path / "private-report"
        broken.parent.rename(destination)
        broken.parent.symlink_to(destination, target_is_directory=True)

    catalog = ReportCatalog(tmp_path)
    assert catalog._read(broken) is None
    assert [item["report_id"] for item in catalog.list()] == ["report_" + "a" * 32]
    assert catalog.get("report_" + "a" * 32)["title"] == "Offline report for scan_healthy"
    with pytest.raises(ReportNotFoundError):
        catalog.get("report_" + "b" * 32)
    assert good.read_bytes() == original


def test_legacy_report_schema_remains_available_as_a_preview(tmp_path: Path) -> None:
    database = _report(tmp_path, "scan_legacy", "c", legacy=True)
    original = database.read_bytes()
    item, = ReportCatalog(tmp_path).list(scan_id="scan_legacy")
    assert item["scan_id"] == "scan_legacy"
    assert item["case_id"] == ""
    assert item["title"] == "Offline report for scan_legacy"
    assert database.read_bytes() == original


def _scope(root: Path, scope_id: str, program: str, *, policy: object = None) -> Path:
    directory = root / "Scope" / "generic" / program
    directory.mkdir(parents=True)
    raw = json.dumps({"scope_id": scope_id, "analysis": {"program_name": program}}).encode()
    (directory / "Scope.json").write_bytes(raw)
    (directory / "Approval.json").write_text(json.dumps({
        "scope_id": scope_id, "scope_json_sha256": hashlib.sha256(raw).hexdigest(),
    }))
    if policy is not None:
        (directory / "TargetPolicy.json").write_text(json.dumps(policy))
    return directory


@pytest.mark.parametrize("policy", [None, [], {"policies": None}, {"policies": "invalid"},
    {"policies": [{"limits": None}, {"limits": []}, {"limits": {"max_requests": "invalid"}}]},
    {"policies": [{"limits": {"max_requests": True}}]},
])
def test_scope_projection_handles_missing_or_partial_policy_metadata(tmp_path: Path, policy: object) -> None:
    _scope(tmp_path, "scope_fixture", "Accounting", policy=policy)
    scope = DashboardProjector(tmp_path)._scope_info("scope_fixture")
    assert scope.approved is True
    assert scope.program_name == "Accounting"
    assert scope.budget == 0
    assert scope.per_target_budget is None


def test_numeric_string_policy_budget_metadata_remains_readable(tmp_path: Path) -> None:
    _scope(tmp_path, "scope_fixture", "Accounting", policy={"policies": [
        {"limits": {"max_requests": "100"}}, {"limits": {"max_requests": 100}},
    ]})
    scope = DashboardProjector(tmp_path)._scope_info("scope_fixture")
    assert scope.budget == 200
    assert scope.per_target_budget == 100


@pytest.mark.parametrize("artifact", ["Scope.json", "Approval.json", "TargetPolicy.json"])
@pytest.mark.parametrize("document", [[], None, "private-session-token"])
def test_non_object_scope_metadata_does_not_crash_or_approve_invalid_scope(
    tmp_path: Path, artifact: str, document: object,
) -> None:
    directory = _scope(tmp_path, "scope_fixture", "Documents")
    (directory / artifact).write_text(json.dumps(document))
    scope = DashboardProjector(tmp_path)._scope_info("scope_fixture")
    assert scope.approved is (artifact == "TargetPolicy.json")
    assert "private-session-token" not in repr(scope)


def _scan(root: Path, scan_id: str, *, minimal: bool) -> Path:
    directory = root / "Runs" / scan_id
    directory.mkdir(parents=True)
    database = directory / "Recon.db"
    with sqlite3.connect(database) as conn:
        if minimal:
            conn.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO scans VALUES (?)", (scan_id,))
            conn.execute("CREATE TABLE stage_runs (unfinished_column TEXT)")
        else:
            conn.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, status TEXT, scope_value TEXT)")
            conn.execute("INSERT INTO scans VALUES (?, 'completed', ?)", (scan_id, "scope_" + scan_id))
            conn.execute("CREATE TABLE stage_runs (stage_run_id TEXT, scan_id TEXT, stage TEXT, status TEXT)")
            conn.execute("INSERT INTO stage_runs VALUES ('stage', ?, 'report', 'completed')", (scan_id,))
        conn.execute("CREATE TABLE pipeline_runs (unfinished_column TEXT)")
        conn.execute("CREATE TABLE validation_cases (unfinished_column TEXT)")
        conn.execute("CREATE TABLE assets (unfinished_column TEXT)")
        conn.execute("CREATE TABLE origins (unfinished_column TEXT)")
        conn.execute("CREATE TABLE endpoints (endpoint_id TEXT, path TEXT)")
        conn.execute("INSERT INTO endpoints VALUES ('fixture', '/health')")
        conn.execute("CREATE TABLE findings (finding_id TEXT, scan_id TEXT, title TEXT, severity TEXT)")
        conn.execute("INSERT INTO findings VALUES ('finding', ?, 'Offline observation', 'INFO')", (scan_id,))
        conn.execute("CREATE TABLE audit_events (audit_event_id TEXT, scan_id TEXT, event_type TEXT)")
        conn.execute("INSERT INTO audit_events VALUES ('audit', ?, 'report.completed')", (scan_id,))
    return database


def test_multi_program_dashboard_serves_older_partial_and_current_artifacts_without_transports(tmp_path: Path) -> None:
    """Exercise list → snapshot → audit → report preview through the real ASGI API."""
    databases = [_scan(tmp_path, "scan_accounting", minimal=False),
                 _scan(tmp_path, "scan_documents", minimal=True)]
    _scope(tmp_path, "scope_scan_accounting", "Accounting")
    databases += [_report(tmp_path, "scan_accounting", "a"),
                  _report(tmp_path, "scan_documents", "b", legacy=True)]
    broken = tmp_path / "ReportRun" / "scan_broken" / "Report.db"
    broken.parent.mkdir(parents=True)
    broken.write_bytes(b"partial write")
    originals = {path: path.read_bytes() for path in databases}

    async def scenario() -> None:
        app = create_app(result_root=tmp_path)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            listing = await client.get("/api/v1/scans")
            assert listing.status_code == 200
            assert {item["scan_id"] for item in listing.json()["scans"]} == {
                "scan_accounting", "scan_documents"}
            for scan_id, status in (("scan_accounting", "completed"), ("scan_documents", "pending")):
                response = await client.get("/api/v1/scans/" + scan_id)
                assert response.status_code == 200
                snapshot = response.json()
                assert snapshot["status"] == status
                assert snapshot["requests"] == 0
                assert snapshot["endpoints"] == 1
                assert len(snapshot["findings"]) == 1
                assert len(snapshot["logs"]) == 1
                report_response = await client.get("/api/v1/reports", params={"scan_id": scan_id})
                assert report_response.status_code == 200
                report, = report_response.json()["reports"]
                preview = await client.get("/api/v1/reports/" + report["report_id"])
                assert preview.status_code == 200
                assert scan_id in preview.text
            # Preview availability never authorizes export of an unbound fixture.
            blocked = await client.get("/api/v1/reports/" + "report_" + "a" * 32 + "/export")
            assert blocked.status_code == 409
            assert str(tmp_path) not in blocked.text

    with patch("socket.create_connection", side_effect=AssertionError("no network")), patch(
        "subprocess.run", side_effect=AssertionError("no shell"),
    ):
        asyncio.run(scenario())
    assert all(path.read_bytes() == before for path, before in originals.items())


def test_unscoped_endpoint_rows_are_not_attributed_to_every_scan(tmp_path: Path) -> None:
    database = _scan(tmp_path, "scan_fixture", minimal=True)
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO scans VALUES ('scan_other')")
    snapshot = DashboardProjector(tmp_path).snapshot("scan_fixture")
    assert snapshot["endpoints"] == 0
    assert snapshot["service_endpoints"] == 0


def test_scan_execution_summary_is_available_without_a_confirmed_case_report(
    tmp_path: Path,
) -> None:
    scan_id = "scan_summary_fixture"
    _scan(tmp_path, scan_id, minimal=False)
    directory = tmp_path / "ReportRun" / scan_id
    directory.mkdir(parents=True)
    (directory / "ScanSummary.json").write_text(json.dumps({
        "schema_version": "1.0",
        "scan_id": scan_id,
        "execution_status": "partial",
        "inventory": {"endpoints": 7, "candidate_findings": 1},
        "validation": {"current_confirmed": 0, "statuses": {}, "phases": {}},
        "reports": [],
        "errors": [{"stage": "validation", "error_type": "TimeoutError"}],
    }))
    (directory / "ScanSummary.md").write_text(
        "# 스캔 실행 보고서\n\n확정된 취약점 보고서는 없습니다.\n",
    )

    async def scenario() -> None:
        app = create_app(result_root=tmp_path)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            response = await client.get(f"/api/v1/scans/{scan_id}/summary")
            assert response.status_code == 200
            assert response.json()["execution_status"] == "partial"
            assert response.json()["inventory"]["endpoints"] == 7
            assert "확정된 취약점" in response.json()["markdown"]
            assert (await client.get("/api/v1/scans/scan_missing/summary")).status_code == 404

    asyncio.run(scenario())
