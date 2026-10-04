from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from aidast.agents.main import MainAgentError
from aidast.core.model_calls import ModelCallEvent, SQLiteModelCallSink
from aidast.cli import EXECUTION_PROFILES as CLI_EXECUTION_PROFILES
from aidast.cli import _parser, _run_dashboard
from aidast.recon.profiles import EXECUTION_PROFILES
from aidast.web.projection import DashboardProjector, ScanNotFoundError
from aidast.web.launch import (
    ApprovedScope,
    LaunchJob,
    ProgramResolveRequest,
    ScanLaunchManager,
    ScanLaunchRequest,
)
from aidast.web.server import create_app
from aidast.web.programs import ProgramRegistrationRequest, ProgramRegistry
from aidast.web.requirements import (
    IdentityHeader,
    build_scope_execution_requirements,
)
from aidast.web.scope_workflow import ScopeWorkflowManager
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    SourceEvidence,
    RequiredRequestHeader, HeaderInput, ScopeExecutionRules,
)


SCAN_ID = "scan_web_test"
SCOPE_ID = "scope_web_test"


def _execution_requirements(
    identity_header: IdentityHeader | None, *, rate_quote: str | None = None
):
    return build_scope_execution_requirements(
        ScopeAnalysis(
            required_request_headers=[],
            execution_rules={"exclusions": [], "request_limits": [dict(
                maximum=10, period_seconds=1, scope="program", source_quote=rate_quote
            )] if rate_quote else []},
            program_name="Fixture",
            program_description="Fixture",
            in_scope_assets=[],
            out_of_scope_assets=[],
            allowed_activities=[],
            prohibited_activities=[],
            submission_requirements=[],
            operational_constraints=[],
            safe_harbor="",
            ambiguities=["Focused launcher fixture."],
            source_evidence=[SourceEvidence(section="Scope", quote="Fixture scope")]
            + ([SourceEvidence(section="Rules of engagement", quote=rate_quote)]
               if rate_quote else []),
        ),
        identity_header=identity_header,
    )


def _fixture(root: Path) -> Path:
    run = root / "Runs" / SCAN_ID
    run.mkdir(parents=True)
    database = run / "Recon.db"
    conn = sqlite3.connect(database)
    conn.executescript(
        """
        CREATE TABLE scans (
          scan_id TEXT PRIMARY KEY, scope_type TEXT, scope_value TEXT,
          status TEXT, started_at TEXT, finished_at TEXT
        );
        CREATE TABLE assets (asset_id TEXT PRIMARY KEY,scan_id TEXT,identifier TEXT);
        CREATE TABLE origins (origin_id TEXT PRIMARY KEY,asset_id TEXT);
        CREATE TABLE endpoints (
          endpoint_id TEXT PRIMARY KEY,origin_id TEXT,method TEXT,normalized_path TEXT
        );
        CREATE TABLE http_transactions (
          http_transaction_id TEXT PRIMARY KEY,endpoint_id TEXT
        );
        CREATE TABLE stage_runs (
          stage_run_id TEXT PRIMARY KEY,scan_id TEXT,stage TEXT,status TEXT,
          error_message TEXT,started_at TEXT,finished_at TEXT,created_at TEXT
        );
        CREATE TABLE attack_tasks (
          task_id TEXT PRIMARY KEY,stage_run_id TEXT,scan_id TEXT,status TEXT
        );
        CREATE TABLE findings (
          finding_id TEXT PRIMARY KEY,scan_id TEXT,endpoint_id TEXT,vuln_type TEXT,
          severity TEXT,title TEXT,description TEXT,cvss_score REAL,cvss_vector TEXT,
          cwe_id TEXT,status TEXT,created_at TEXT
        );
        CREATE TABLE audit_events (
          audit_event_id TEXT PRIMARY KEY,scan_id TEXT,stage_run_id TEXT,task_id TEXT,
          event_type TEXT,details_json TEXT,created_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?,?)",
        (SCAN_ID, "approved_scope", SCOPE_ID, "failed", "2026-09-20 01:00:00", "2026-09-20 01:05:00"),
    )
    conn.execute("INSERT INTO assets VALUES ('asset',?,'app.example.com')", (SCAN_ID,))
    conn.execute("INSERT INTO origins VALUES ('origin','asset')")
    conn.execute("INSERT INTO endpoints VALUES ('endpoint','origin','GET','/health')")
    conn.execute("INSERT INTO http_transactions VALUES ('http','endpoint')")
    conn.execute(
        "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
        ("stage", SCAN_ID, "recon", "failed", None, "2026-09-20T01:00:00Z", "2026-09-20T01:05:00Z", "2026-09-20 01:00:00"),
    )
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("finding", SCAN_ID, "endpoint", "header", "LOW", "Version header", None, None, None, "CWE-200", "unreviewed", "2026-09-20 01:04:00"),
    )
    conn.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        ("audit-1", SCAN_ID, "stage", None, "stage.started", json.dumps({"token": "must-not-leak"}), "2026-09-20 01:00:00"),
    )
    conn.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        ("audit-2", SCAN_ID, "stage", None, "stage.failed", json.dumps({"body": "secret"}), "2026-09-20 01:05:00"),
    )
    conn.commit()
    conn.close()

    scope_dir = root / "Scope" / "hackerone" / "prism_vdp"
    scope_dir.mkdir(parents=True)
    scope = {
        "scope_id": SCOPE_ID,
        "analysis": {"program_name": "PRISM"},
    }
    raw = json.dumps(scope, separators=(",", ":")).encode()
    (scope_dir / "Scope.json").write_bytes(raw)
    (scope_dir / "Approval.json").write_text(
        json.dumps(
            {
                "scope_id": SCOPE_ID,
                "scope_json_sha256": hashlib.sha256(raw).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    (scope_dir / "TargetPolicy.json").write_text(
        json.dumps({"policies": [{"limits": {"max_requests": 2000}}]}),
        encoding="utf-8",
    )

    report_dir = root / "ReportRun" / SCAN_ID / "case_web_test"
    report_dir.mkdir(parents=True)
    markdown = "# Local verified draft\n\nRedacted evidence summary.\n"
    with sqlite3.connect(report_dir / "Report.db") as report_conn:
        report_conn.executescript(
            """
            CREATE TABLE report_runs (
              report_id TEXT PRIMARY KEY, source_path TEXT, scan_id TEXT,
              case_id TEXT, decision_sha256 TEXT, context_sha256 TEXT,
              context_json TEXT, created_at TEXT
            );
            CREATE TABLE report_drafts (
              report_id TEXT PRIMARY KEY, draft_sha256 TEXT, draft_json TEXT,
              markdown_sha256 TEXT, markdown TEXT, created_at TEXT
            );
            """
        )
        report_conn.execute(
            "INSERT INTO report_runs VALUES (?,?,?,?,?,?,?,?)",
            (
                "report_" + "a" * 32,
                "source.db",
                SCAN_ID,
                "case_web_test",
                "d" * 64,
                "c" * 64,
                json.dumps({"platform": "hackerone"}),
                "2026-09-20T01:06:00Z",
            ),
        )
        report_conn.execute(
            "INSERT INTO report_drafts VALUES (?,?,?,?,?,?)",
            (
                "report_" + "a" * 32,
                hashlib.sha256(b"{}").hexdigest(),
                "{}",
                hashlib.sha256(markdown.encode()).hexdigest(),
                markdown,
                "2026-09-20T01:07:00Z",
            ),
        )
    return database


def _wiki_baseline(root: Path) -> Path:
    database = root / "References" / "vulnbank" / "Recon.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as conn:
        conn.executescript("""
            CREATE TABLE scans (
              scan_id TEXT PRIMARY KEY, scope_type TEXT, scope_value TEXT,
              status TEXT, started_at TEXT, finished_at TEXT
            );
            CREATE TABLE assets (
              asset_id TEXT PRIMARY KEY, scan_id TEXT, identifier TEXT, asset_type TEXT
            );
            CREATE TABLE origins (
              origin_id TEXT PRIMARY KEY, asset_id TEXT, base_url TEXT
            );
            CREATE TABLE endpoints (
              endpoint_id TEXT PRIMARY KEY, origin_id TEXT, method TEXT, path TEXT,
              normalized_path TEXT, verification_status TEXT, is_excluded INTEGER,
              exclude_reason TEXT, auth_required INTEGER, source_tools TEXT
            );
            CREATE TABLE endpoint_observations (
              observation_id TEXT PRIMARY KEY, endpoint_id TEXT, discovery_kind TEXT
            );
        """)
        conn.execute(
            "INSERT INTO scans VALUES (?,?,?,?,?,?)",
            ("scan_source", "URL", "https://bank.test", "completed", "2026-09-01", "2026-09-01"),
        )
        conn.execute("INSERT INTO assets VALUES ('asset','scan_source','bank.test','URL')")
        conn.execute("INSERT INTO origins VALUES ('origin','asset','https://bank.test')")
        conn.executemany(
            "INSERT INTO endpoints VALUES (?,?,?,?,?,'verified',0,NULL,NULL,'flask_source_import')",
            [
                ("source-get", "origin", "GET", "/health", "/health"),
                ("source-post", "origin", "POST", "/transfer", "/transfer"),
            ],
        )
        conn.executemany(
            "INSERT INTO endpoint_observations VALUES (?,?, 'source_route')",
            [("observation-get", "source-get"), ("observation-post", "source-post")],
        )
    return database


def _make_runtime_wiki_compatible(database: Path) -> None:
    with sqlite3.connect(database) as conn:
        conn.execute("ALTER TABLE origins ADD COLUMN base_url TEXT")
        conn.execute("UPDATE origins SET base_url='http://127.0.0.1:5001'")
        conn.execute("ALTER TABLE endpoints ADD COLUMN path TEXT")
        conn.execute("ALTER TABLE endpoints ADD COLUMN verification_status TEXT DEFAULT 'observed'")
        conn.execute("ALTER TABLE endpoints ADD COLUMN is_excluded INTEGER DEFAULT 0")
        conn.execute("ALTER TABLE endpoints ADD COLUMN exclude_reason TEXT")
        conn.execute("ALTER TABLE endpoints ADD COLUMN auth_required INTEGER")
        conn.execute("ALTER TABLE endpoints ADD COLUMN source_tools TEXT")
        conn.execute("UPDATE endpoints SET path=normalized_path,source_tools='katana'")


def test_projection_reads_sources_without_leaking_audit_details(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    projector = DashboardProjector(tmp_path)

    snapshot = projector.snapshot(SCAN_ID)

    assert snapshot["status"] == "failed"
    assert snapshot["stage"] == "Recon"
    assert snapshot["endpoints"] == 1
    assert snapshot["requests"] == 1
    assert snapshot["budget"] == 2000
    assert snapshot["per_target_budget"] == 2000
    assert snapshot["scope_approved"] is True
    assert snapshot["program_id"] == "h1-prism-vdp"
    assert snapshot["findings"][0]["endpoint"] == "GET /health"
    assert snapshot["last_event_id"] == 2
    assert [item["id"] for item in snapshot["logs"]] == [1, 2]
    assert "must-not-leak" not in json.dumps(snapshot)
    assert "secret" not in json.dumps(snapshot)

    conn = sqlite3.connect(database)
    conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    conn.execute(
        "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
        ("attack", SCAN_ID, "attack", "running", None, "2026-09-20T01:06:00Z", None, "2026-09-20 01:06:00"),
    )
    conn.execute(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        ("audit-3", SCAN_ID, "attack", None, "stage.started", "{}", "2026-09-20 01:06:00"),
    )
    conn.commit()
    conn.close()

    events = projector.events_after(SCAN_ID, 2)
    assert [item["event_id"] for item in events] == list(
        range(3, events[-1]["event_id"] + 1)
    )
    assert {item["type"] for item in events} >= {
        "log.appended",
        "stage.status.changed",
        "scan.status.changed",
    }
    assert projector.snapshot(SCAN_ID)["stage"] == "Attack"


def test_same_stage_completion_emits_authoritative_status_event(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running' WHERE stage_run_id='stage'")
    projector = DashboardProjector(tmp_path)
    before = projector.snapshot(SCAN_ID)
    assert before["status"] == "running"
    assert before["stage_statuses"]["Recon"] == "running"
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id='stage'")
    events = projector.events_after(SCAN_ID, before["last_event_id"])
    assert not any(item["type"] == "scan.status.changed" for item in events)
    assert [item["payload"] for item in events if item["type"] == "stage.status.changed"] == [
        {"stage": "Recon", "stage_statuses": {"Scope": "completed", "Recon": "completed"}},
    ]


def test_projection_exposes_only_allowlisted_recon_activity(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
            ("recon-tool-1", SCAN_ID, "stage", None, "recon.activity",
             json.dumps({"phase": "playwright_bootstrap", "state": "started",
                         "url": "https://example.com/?token=secret", "headers": {"Cookie": "secret"}}),
             "2026-09-20 01:00:01"),
        )
    snapshot = DashboardProjector(tmp_path).snapshot(SCAN_ID)
    activity = [log for log in snapshot["logs"] if log.get("message_code") == "recon.activity"]
    assert len(activity) == 1
    assert activity[0]["message_params"] == {"phase": "playwright_bootstrap", "state": "started"}
    assert activity[0]["audit_id"] == "recon-tool-1"
    replay = DashboardProjector(tmp_path).events_after(SCAN_ID, 0)
    assert any(event["type"] == "log.appended" and event["payload"].get("audit_id") == "recon-tool-1" for event in replay)
    audit = DashboardProjector(tmp_path).audit_log(SCAN_ID)
    assert audit[0]["message_code"] == "recon.activity"
    assert audit[0]["message_params"] == {"phase": "playwright_bootstrap", "state": "started"}
    assert audit[0]["level"] == "info"
    assert "secret" not in json.dumps(audit)
    assert "secret" not in json.dumps(snapshot)


def test_tagging_batches_reach_snapshot_replay_and_history_without_secrets(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        for index, state in enumerate(("started", "finished"), 1):
            conn.execute(
                "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
                (f"tag-batch-{index}", SCAN_ID, "stage", None, "recon.activity",
                 json.dumps({"phase": "observation_tagging", "state": state,
                             "index": 1, "total": 2, "count": 200,
                             "processed_count": 200 if state == "finished" else 0,
                             "failed_count": 0, "url": "https://example.com/?token=secret"}),
                 f"2026-09-20 01:00:0{index}"),
            )
    projector = DashboardProjector(tmp_path)
    snapshot = projector.snapshot(SCAN_ID)
    batches = [log for log in snapshot["logs"] if log.get("message_code") == "recon.activity"]
    assert [item["message_params"]["state"] for item in batches] == ["started", "finished"]
    assert batches[-1]["message_params"]["processed_count"] == 200
    assert [item["payload"]["message_params"]["state"] for item in projector.events_after(SCAN_ID, 0)
            if item["type"] == "log.appended" and item["payload"].get("message_code") == "recon.activity"
            ] == ["started", "finished"]
    assert [item["payload"]["message_params"]["state"] for item in projector.recon_activity(SCAN_ID)["events"]
            ] == ["finished", "started"]
    assert "secret" not in json.dumps(snapshot)


def test_projection_shows_discovered_url_with_response_evidence(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
            ("recon-url-1", SCAN_ID, "stage", None, "recon.activity",
             json.dumps({"phase": "endpoint_discovery", "state": "found", "method": "GET",
                         "url": "https://example.com/missing?token=secret", "source": "ffuf",
                         "response_status": 404, "headers": {"Cookie": "secret"}}),
             "2026-09-20 01:00:02"),
        )
    projector = DashboardProjector(tmp_path)
    expected = {"phase": "endpoint_discovery", "state": "found", "method": "GET",
                "url": "https://example.com/missing", "source": "ffuf", "response_status": 404}
    assert any(log.get("message_params") == expected for log in projector.snapshot(SCAN_ID)["logs"])
    assert any(event["type"] == "log.appended" and event["payload"].get("message_params") == expected
               for event in projector.events_after(SCAN_ID, 0))
    assert projector.audit_log(SCAN_ID)[0]["message_params"] == expected


def test_audit_log_categorizes_failures_without_exposing_error_text(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE stage_runs SET error_message=? WHERE stage_run_id='stage'",
            ("Connection timed out for https://private.example/?token=secret",),
        )
    audit = DashboardProjector(tmp_path).audit_log(SCAN_ID)
    assert audit[0]["event_type"] == "stage.failed"
    assert audit[0]["failure_code"] == "timeout"
    assert audit[0]["level"] == "error"
    assert "private.example" not in json.dumps(audit)
    assert "secret" not in json.dumps(audit)


def test_policy_denied_legacy_task_failure_is_a_warning(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
            ("policy-skip", SCAN_ID, "stage", None, "task.failed",
             json.dumps({"previous_status": "running", "reason":
                         "[policy] exact request envelope denied before dispatch"}),
             "2026-09-20 01:00:03"),
        )
    projector = DashboardProjector(tmp_path)
    entry = next(item for item in projector.audit_log(SCAN_ID)
                 if item["event_type"] == "task.failed")
    assert entry["level"] == "warning"
    replay = projector.snapshot(SCAN_ID)["logs"]
    assert next(item for item in replay if item.get("audit_id") == "policy-skip")["level"] == "warning"


def test_projection_separates_candidate_urls_from_live_responses(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("ALTER TABLE endpoints ADD COLUMN is_excluded INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE TABLE endpoint_observations (endpoint_id TEXT, discovery_kind TEXT)")
        conn.execute("INSERT INTO endpoint_observations VALUES ('endpoint','http_response')")
        conn.execute("INSERT INTO endpoints VALUES ('static','origin','GET','/assets/app.js',1)")
    snapshot = DashboardProjector(tmp_path).snapshot(SCAN_ID)
    assert snapshot["endpoints"] == 2
    assert snapshot["service_endpoints"] == 1
    assert snapshot["live_endpoints"] == 1


def test_projection_reads_live_recon_request_budget_counter(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    database.with_name(f"mitm_capture_{SCAN_ID}.progress.json").write_text(
        json.dumps({"version": 1, "allowed_requests": 14, "used_before": 3,
                    "blocked_requests": 2, "updated_at": "2026-09-20T01:00:00Z"}),
        encoding="utf-8",
    )
    snapshot = DashboardProjector(tmp_path).snapshot(SCAN_ID)
    assert snapshot["requests"] == 17
    assert snapshot["progress"] == 0
    assert type(snapshot["progress"]) is int
    assert 0 <= snapshot["progress"] <= 100


def test_failed_stage_overrides_completed_scan_in_snapshot_and_list(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "UPDATE stage_runs SET finished_at='2026-09-20T01:07:00Z' WHERE scan_id=?",
            (SCAN_ID,),
        )

    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["status"] == "failed"
    assert projector.list_scans()[0]["status"] == "failed"
    assert projector.list_scans()[0]["finished_at"] == "2026-09-20T01:07:00Z"
    assert projector.list_scans()[0]["targets"] == ["app.example.com"]


def test_partial_recon_failure_is_not_projected_as_success(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed_with_errors' WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='completed' WHERE scan_id=?", (SCAN_ID,))
    projector = DashboardProjector(tmp_path)
    snapshot = projector.snapshot(SCAN_ID)
    assert snapshot["status"] == "failed"
    assert snapshot["stage_statuses"]["Recon"] == "failed"
    assert projector.list_scans()[0]["status"] == "failed"
    # The dashboard projection must not rewrite the source execution record.
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT status FROM stage_runs").fetchone()[0] == "completed"


@pytest.mark.parametrize("resume", [False, True])
def test_process_diagnostics_survive_failure_without_exposing_output(tmp_path: Path, resume: bool) -> None:
    from types import SimpleNamespace
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    scope = SimpleNamespace(scope_id=SCOPE_ID, program_id="fixture", program_name="Fixture")
    job = LaunchJob(SCAN_ID, scope, "running", "2026-10-01T00:00:00Z", 0, ())
    manager._jobs[SCAN_ID] = job
    job.process = SimpleNamespace(wait=lambda: 7)
    with manager._process_output(job) as output:
        output.write(b"ValueError: offline policy review required\nprivate-session-token\n")
    first_log = job.process_log
    assert output.closed
    if resume:
        manager._monitor_resume(job, "attempt", "recon")
    else:
        manager._monitor(job)
    assert job.status == "failed"
    snapshot = manager.snapshot(SCAN_ID)
    params = snapshot["logs"][-1]["message_params"]
    assert params["exit_code"] == 7
    saved_log = tmp_path / params["diagnostic_log"]
    assert saved_log == first_log
    assert manager._process_result(job) == {"diagnostic_log": params["diagnostic_log"]}
    assert "ValueError: offline policy review required" in saved_log.read_text()
    assert "private-session-token" not in json.dumps(snapshot)
    if os.name != "nt":
        assert saved_log.stat().st_mode & 0o777 == 0o600
    with manager._process_output(job) as output:
        output.write(b"second attempt\n")
    assert job.process_log != first_log
    assert "offline policy review" in first_log.read_text()


def test_retry_stage_replaces_old_failure_in_scan_status(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET stage='attack' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("retry", SCAN_ID, "attack", "running", None,
             "2026-09-20T01:10:00Z", None, "2026-09-20T01:10:00Z"),
        )
    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["status"] == "running"
    assert projector.list_scans()[0]["status"] == "running"
    assert projector.list_scans()[0]["finished_at"] is None
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE stage_runs SET status='completed',finished_at='2026-09-20T01:11:00Z' WHERE stage_run_id='retry'"
        )
    assert projector.snapshot(SCAN_ID)["status"] == "completed"
    assert projector.list_scans()[0]["status"] == "completed"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("chain", SCAN_ID, "chaining", "skipped", None,
             "2026-09-20T01:12:00Z", "2026-09-20T01:12:01Z", "2026-09-20T01:12:00Z"),
        )
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("validate", SCAN_ID, "validation", "completed", None,
             "2026-09-20T01:13:00Z", "2026-09-20T01:13:01Z", "2026-09-20T01:13:00Z"),
        )
    stages = projector.snapshot(SCAN_ID)["stage_statuses"]
    assert stages["Chaining"] == "skipped"
    assert stages["Validation"] == "completed"


def test_projection_rejects_unknown_and_unsafe_scan_ids(tmp_path: Path) -> None:
    _fixture(tmp_path)
    projector = DashboardProjector(tmp_path)
    for scan_id in ("../Scope", "scan/other", "", "x" * 129):
        try:
            projector.snapshot(scan_id)
        except ScanNotFoundError:
            pass
        else:
            raise AssertionError(f"unsafe scan id accepted: {scan_id}")


def test_report_stage_status_overrides_completed_recon_scan(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("report-stage", SCAN_ID, "report", "running", None, "2026-09-20T01:06:00Z", None, "2026-09-20 01:06:00"),
        )
    projector = DashboardProjector(tmp_path)
    assert (projector.snapshot(SCAN_ID)["stage"], projector.snapshot(SCAN_ID)["status"]) == ("Report", "running")
    assert projector.list_scans()[0]["status"] == "running"
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='failed' WHERE stage_run_id='report-stage'")
    assert (projector.snapshot(SCAN_ID)["stage"], projector.snapshot(SCAN_ID)["status"]) == ("Report", "failed")
    assert projector.list_scans()[0]["status"] == "failed"


def test_report_progress_tracks_prepared_and_drafted_cases(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET stage='report',status='running' WHERE stage_run_id='stage'")
        conn.execute(
            "CREATE TABLE validation_cases (case_id TEXT, scan_id TEXT, "
            "current_status TEXT, processing_phase TEXT, latest_stage_run_id TEXT, "
            "decision_stage_run_id TEXT)"
        )
        conn.executemany("INSERT INTO validation_cases VALUES (?,?,?,?,?,?)", [
            (case_id, SCAN_ID, "CONFIRMED", "completed", "stage", "stage")
            for case_id in ("case_web_test", "case_pending")
        ])
    projector = DashboardProjector(tmp_path)
    first = projector.snapshot(SCAN_ID)
    assert first["progress"] == 50
    output = tmp_path / "ReportRun" / SCAN_ID / "case_pending"
    output.mkdir(parents=True)
    with sqlite3.connect(output / "Report.db") as conn:
        conn.executescript(
            "CREATE TABLE report_runs (report_id TEXT, scan_id TEXT, case_id TEXT);"
            "CREATE TABLE report_drafts (report_id TEXT);"
            "INSERT INTO report_runs VALUES ('report-pending','scan_web_test','case_pending');"
        )
    prepared = projector.snapshot(SCAN_ID)
    assert prepared["progress"] == 75
    assert any(
        event["type"] == "task.progress.updated" and event["payload"]["progress"] == 75
        for event in projector.events_after(SCAN_ID, first["last_event_id"])
    )
    with sqlite3.connect(output / "Report.db") as conn:
        conn.execute("INSERT INTO report_drafts VALUES ('report-pending')")
    assert projector.snapshot(SCAN_ID)["progress"] == 95
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id='stage'")
    assert projector.snapshot(SCAN_ID)["progress"] == 100


def test_recon_activity_tracks_started_task_and_clears_on_completion(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running' WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running' WHERE stage_run_id='stage'")
        conn.execute(
            """CREATE TABLE pipeline_runs (
            pipeline_run_id TEXT PRIMARY KEY, scan_id TEXT, task_id TEXT,
            stage TEXT, status TEXT, started_at TEXT, ended_at TEXT)"""
        )
    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["activity"] == "Preparing Recon"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pipeline_runs VALUES (?,?,?,?,?,?,?)",
            ("started", SCAN_ID, "task-1", "dns_resolution", "running", "2026-09-20T01:01:00Z", None),
        )
    assert projector.snapshot(SCAN_ID)["activity"] == "DNS resolution"
    events = projector.stored_events_after(SCAN_ID, 0)
    assert any(
        event["type"] == "task.progress.updated" and event["payload"].get("activity") == "DNS resolution"
        for event in events
    )
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pipeline_runs VALUES (?,?,?,?,?,?,?)",
            ("completed", SCAN_ID, "task-1", "dns_resolution", "success", "2026-09-20T01:02:00Z", "2026-09-20T01:02:00Z"),
        )
    assert projector.snapshot(SCAN_ID)["activity"] == "Processing Recon results"


def test_recon_progress_advances_when_planned_tasks_finish(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running' WHERE stage_run_id='stage'")
        conn.execute(
            "CREATE TABLE pipeline_runs (pipeline_run_id TEXT, scan_id TEXT, task_id TEXT, "
            "stage TEXT, status TEXT)"
        )
        conn.executemany("INSERT INTO pipeline_runs VALUES (?,?,?,?,?)", [
            ("planned-1", SCAN_ID, "task-1", "DNS_RESOLUTION", "pending"),
            ("planned-2", SCAN_ID, "task-2", "HTTP_PROBE", "pending"),
        ])
    projector = DashboardProjector(tmp_path)
    before = projector.snapshot(SCAN_ID)
    assert before["progress"] == 0
    assert before["activity"] == "Preparing Recon"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO pipeline_runs VALUES (?,?,?,?,?)",
            ("finished-1", SCAN_ID, "task-1", "DNS_RESOLUTION", "success"),
        )
    after = projector.snapshot(SCAN_ID)
    assert after["progress"] == 38
    assert any(
        event["type"] == "task.progress.updated" and event["payload"]["progress"] == 38
        for event in projector.events_after(SCAN_ID, before["last_event_id"])
    )

    projector.record_event(
        SCAN_ID, source_key="work:review", event_type="log.appended",
        payload={"stage": "Recon", "level": "info", "message": "Agent work",
                 "message_code": "agent.work",
                 "message_params": {"agent": "main", "step": "review",
                                    "state": "started", "progress": 89}},
    )
    underway = projector.snapshot(SCAN_ID)
    assert underway["progress"] == 89
    assert underway["logs"][-1]["message_params"]["step"] == "review"

def test_tagging_progress_recovers_running_worker_counts_without_duplicate_logs(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL")
        conn.execute("UPDATE stage_runs SET status='running'")
        conn.executescript("""
            CREATE TABLE endpoint_observations (observation_id TEXT, endpoint_id TEXT);
            CREATE TABLE endpoint_annotations (annotation_id TEXT, observation_id TEXT);
            INSERT INTO assets VALUES ('other-asset','other-scan','other.example.com');
            INSERT INTO origins VALUES ('other-origin','other-asset');
            INSERT INTO endpoints VALUES ('other-endpoint','other-origin','GET','/other');
            INSERT INTO endpoint_observations VALUES ('other-observation','other-endpoint');
            INSERT INTO endpoint_annotations VALUES ('other-tag','other-observation');
        """)
        conn.executemany("INSERT INTO endpoint_observations VALUES (?, 'endpoint')",
                         [(f"obs-{index}",) for index in range(50)])
        conn.executemany("INSERT INTO endpoint_annotations VALUES (?,?)",
                         [(f"tag-{index}", f"obs-{index}") for index in range(25)])
        conn.execute("INSERT INTO endpoint_annotations VALUES ('second-category','obs-0')")
    projector = DashboardProjector(tmp_path)
    projector.record_event(SCAN_ID, source_key="tagging-start", event_type="log.appended",
        payload={"stage": "Recon", "message": "Agent work", "message_code": "agent.work",
                 "message_params": {"agent": "recon", "step": "tagging", "state": "started", "progress": 76}})
    first = projector.snapshot(SCAN_ID)
    assert first["progress"] == 82
    assert first["logs"][-1]["message_params"]["processed"] == 25
    assert first["logs"][-1]["message_params"]["observation_total"] == 50
    assert projector.snapshot(SCAN_ID)["last_event_id"] == first["last_event_id"]
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO endpoint_annotations VALUES ('next','obs-25')")
    next_state = projector.snapshot(SCAN_ID)
    assert next_state["logs"][-1]["message_params"]["processed"] == 26
    assert next_state["last_event_id"] > first["last_event_id"]
    projector.record_event(SCAN_ID, source_key="tagging-failed", event_type="log.appended",
        payload={"stage": "Recon", "message": "Agent work", "message_code": "agent.work",
                 "message_params": {"agent": "recon", "step": "tagging", "state": "failed", "progress": 82}})
    failed = projector.snapshot(SCAN_ID)
    assert failed["logs"][-1]["message_params"]["state"] == "failed"
    projector.record_event(SCAN_ID, source_key="review-start", event_type="log.appended",
        payload={"stage": "Recon", "message": "Agent work", "message_code": "agent.work",
                 "message_params": {"agent": "main", "step": "review", "state": "started", "progress": 89}})
    review = projector.snapshot(SCAN_ID)
    assert review["progress"] == 89
    assert review["logs"][-1]["message_params"]["step"] == "review"

def test_validation_progress_advances_with_case_phases_and_decisions(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET stage='validation',status='running' WHERE stage_run_id='stage'")
        conn.execute(
            "CREATE TABLE validation_cases (case_id TEXT, scan_id TEXT, "
            "latest_stage_run_id TEXT, processing_phase TEXT, decision_stage_run_id TEXT)"
        )
        conn.executemany("INSERT INTO validation_cases VALUES (?,?,?,?,?)", [
            ("case-1", SCAN_ID, "stage", "queued", None),
            ("case-2", SCAN_ID, "stage", "queued", None),
        ])
    projector = DashboardProjector(tmp_path)
    before = projector.snapshot(SCAN_ID)
    assert before["progress"] == 0
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE validation_cases SET processing_phase='blind_replay' WHERE case_id='case-1'")
    underway = projector.snapshot(SCAN_ID)
    assert 0 < underway["progress"] < 50
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE validation_cases SET processing_phase='completed',decision_stage_run_id='stage' "
            "WHERE case_id='case-1'"
        )
    halfway = projector.snapshot(SCAN_ID)
    assert halfway["progress"] == 50
    assert any(
        event["type"] == "task.progress.updated" and event["payload"]["progress"] == 50
        for event in projector.events_after(SCAN_ID, underway["last_event_id"])
    )
    with sqlite3.connect(database) as conn:
        conn.execute(
            "UPDATE validation_cases SET processing_phase='completed',decision_stage_run_id='stage' "
            "WHERE case_id='case-2'"
        )
    assert projector.snapshot(SCAN_ID)["progress"] == 95
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id='stage'")
    assert projector.snapshot(SCAN_ID)["progress"] == 100


@pytest.mark.parametrize("stage", ["attack", "chaining"])
def test_task_stages_show_partial_progress_before_completion(tmp_path: Path, stage: str) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET stage=?,status='running' WHERE stage_run_id='stage'", (stage,))
        conn.executemany("INSERT INTO attack_tasks VALUES (?,?,?,?)", [
            (task_id, "stage", SCAN_ID, "pending") for task_id in ("task-one", "task-two")
        ])
    projector = DashboardProjector(tmp_path)
    assert projector.snapshot(SCAN_ID)["progress"] == 0
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE attack_tasks SET status='completed' WHERE task_id='task-one'")
    assert projector.snapshot(SCAN_ID)["progress"] == 50
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE attack_tasks SET status='skipped' WHERE task_id='task-two'")
    assert projector.snapshot(SCAN_ID)["progress"] == 95
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id='stage'")
    assert projector.snapshot(SCAN_ID)["progress"] == 100


def test_attack_planning_events_advance_progress_before_tasks_exist(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET stage='attack',status='running' WHERE stage_run_id='stage'")
    projector = DashboardProjector(tmp_path)
    before = projector.snapshot(SCAN_ID)
    assert before["progress"] == 0
    projector.record_event(
        SCAN_ID,
        source_key="attack-planning:54",
        event_type="log.appended",
        payload={
            "stage": "Attack",
            "level": "info",
            "message": "Agent work",
            "message_code": "agent.work",
            "message_params": {
                "agent": "attack",
                "step": "planning",
                "state": "progress",
                "processed": 54,
                "endpoint_total": 108,
            },
        },
    )
    snapshot = projector.snapshot(SCAN_ID)
    assert snapshot["progress"] == 10
    assert any(
        event["type"] == "task.progress.updated"
        and event["payload"]["progress"] == 10
        for event in projector.events_after(SCAN_ID, before["last_event_id"])
    )


def test_projection_reads_program_grouped_scan(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    grouped = tmp_path / "Runs" / "yeswehack" / "example-program" / SCAN_ID
    grouped.parent.mkdir(parents=True)
    database.parent.rename(grouped)
    projector = DashboardProjector(tmp_path)
    assert projector.locate_database(SCAN_ID) == grouped / "Recon.db"
    assert [item["scan_id"] for item in projector.list_scans()] == [SCAN_ID]
    assert projector.snapshot(SCAN_ID)["scope_id"] == SCOPE_ID


def test_api_snapshot_listing_and_websocket_replay(tmp_path: Path) -> None:
    _fixture(tmp_path)
    app = create_app(result_root=tmp_path, poll_interval=0.01)

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/api/v1/health")).json() == {
                "status": "ok",
                "mode": "local-operator",
                "protocol": 1,
                "result_root": str(tmp_path.resolve()),
            }
            listing = await client.get("/api/v1/scans")
            assert listing.status_code == 200
            assert [item["scan_id"] for item in listing.json()["scans"]] == [SCAN_ID]
            assert listing.json()["scans"][0]["targets"] == ["app.example.com"]

            response = await client.get(f"/api/v1/scans/{SCAN_ID}")
            assert response.status_code == 200, response.text
            assert response.json()["scope_approved"] is True
            audit = await client.get(f"/api/v1/scans/{SCAN_ID}/audit")
            assert audit.status_code == 200
            assert [item["event_type"] for item in audit.json()["events"]] == [
                "stage.failed",
                "stage.started",
            ]
            assert "must-not-leak" not in audit.text
            assert "secret" not in audit.text
            reports = await client.get(f"/api/v1/reports?scan_id={SCAN_ID}")
            assert reports.status_code == 200
            assert reports.json()["reports"][0]["title"] == "Local verified draft"
            assert "markdown" not in reports.json()["reports"][0]
            report = await client.get("/api/v1/reports/report_" + "a" * 32)
            assert report.status_code == 200
            assert report.text.startswith("# Local verified draft")
            assert (await client.get("/api/v1/reports/..%2Fsecret")).status_code == 404
            assert (await client.get("/api/v1/scans/..%2Fsecret")).status_code == 404

            registered = await client.post(
                "/api/v1/programs",
                headers={"Origin": "http://test"},
                json={
                    "program_url": "https://hackerone.com/new-public-program",
                    "visibility": "public",
                },
            )
            assert registered.status_code == 201
            assert registered.json()["program"]["scope_status"] == "scope_required"
            assert (await client.get("/api/v1/programs")).json()["programs"][0]["program"] == "New Public Program"
            denied = await client.post(
                "/api/v1/programs",
                headers={"Origin": "https://foreign.example"},
                json={
                    "program_url": "https://hackerone.com/rejected",
                    "visibility": "public",
                },
            )
            assert denied.status_code == 403

        incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        await incoming.put({"type": "websocket.connect"})
        await incoming.put({"type": "websocket.disconnect", "code": 1000})
        outgoing: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            return await incoming.get()

        async def send(message: dict[str, Any]) -> None:
            outgoing.append(message)

        await app(
            {
                "type": "websocket",
                "asgi": {"version": "3.0", "spec_version": "2.4"},
                "http_version": "1.1",
                "scheme": "ws",
                "server": ("test", 80),
                "client": ("testclient", 50000),
                "root_path": "",
                "path": f"/ws/scans/{SCAN_ID}",
                "raw_path": f"/ws/scans/{SCAN_ID}".encode(),
                "query_string": b"after=0",
                "headers": [],
                "subprotocols": [],
                "state": {},
            },
            receive,
            send,
        )
        payloads = [
            json.loads(message["text"])
            for message in outgoing
            if message["type"] == "websocket.send"
        ]
        first, second = payloads
        assert [first["event_id"], second["event_id"]] == [1, 2]
        assert first["scan_id"] == SCAN_ID

    asyncio.run(exercise_api())


def test_dashboard_accumulates_recon_wiki_and_compares_selected_baseline(
    tmp_path: Path,
) -> None:
    runtime = _fixture(tmp_path)
    _make_runtime_wiki_compatible(runtime)
    _wiki_baseline(tmp_path)
    app = create_app(result_root=tmp_path)

    async def exercise_api() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            catalog = await client.get("/api/v1/recon-wiki/databases")
            assert catalog.status_code == 200
            baseline = next(
                item for item in catalog.json()["databases"] if item["kind"] == "source"
            )
            response = await client.post(
                f"/api/v1/scans/{SCAN_ID}/recon-wiki",
                headers={"Origin": "http://test"},
                json={
                    "baseline_id": baseline["database_id"],
                    "baseline_kind": "source",
                    "target_id": "vulnbank@test-version",
                },
            )
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["endpoint_count"] == 1
            assert result["comparison"]["baseline_count"] == 2
            assert result["comparison"]["matched_count"] == 1
            assert result["comparison"]["exact_recall"] == 0.5
            assert result["comparison"]["missing"] == 1
            assert result["lint"] == {"ok": True, "issues": []}
            status = await client.get(f"/api/v1/scans/{SCAN_ID}/recon-wiki")
            assert status.status_code == 200
            assert status.json()["comparison"]["exact_recall"] == 0.5
            assert (tmp_path / result["wiki_index"]).is_file()

    asyncio.run(exercise_api())


def test_scope_dashboard_requires_explicit_yes_or_no(tmp_path: Path) -> None:
    text = (
        "Example policy: *.example.test is in scope. Denial of service is prohibited. "
        "Automated tooling\nmax. 10 requests /sec\n"
        "Request header\nX-Intigriti-Username:{Username}"
    )
    page = ProgramPage(
        requested_url="https://bugcrowd.com/engagements/example",
        final_url="https://bugcrowd.com/engagements/example",
        title="Example",
        captured_at=datetime(2026, 9, 20, tzinfo=timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode()).hexdigest(),
        text=text,
    )
    analysis = ScopeAnalysis(
        execution_rules=ScopeExecutionRules(exclusions=[], request_limits=[dict(maximum=10, period_seconds=1, scope="program", source_quote="Automated tooling\nmax. 10 requests /sec")]),
        required_request_headers=[RequiredRequestHeader(
            name="X-Intigriti-Username", value_template="{intigriti_username}",
            inputs=[HeaderInput(key="intigriti_username", label="Username", kind="username")],
            source_quote="Request header\nX-Intigriti-Username:{Username}")],
        program_name="Example Program",
        program_description="Authorized public bug bounty program.",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.WILDCARD,
                asset="*.example.test",
                description="Public applications",
                eligibility="Bounty eligible",
                maximum_severity="Critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["Non-destructive testing"],
        prohibited_activities=["Denial of service"],
        submission_requirements=["Reproducible steps"],
        operational_constraints=[
            "Maximum automated-tooling rate: 10 requests per second.",
            "Use request header X-Intigriti-Username:{Username}.",
        ],
        safe_harbor="Policy-compliant research is authorized.",
        ambiguities=[],
        source_evidence=[
            SourceEvidence(section="Scope", quote="*.example.test is in scope"),
            SourceEvidence(
                section="Rules of engagement",
                quote=(
                    "Automated tooling\nmax. 10 requests /sec\n"
                    "Request header\nX-Intigriti-Username:{Username}"
                ),
            ),
        ],
    )

    class Reader:
        def read(self, _url: str) -> ProgramPage:
            return page

    class Agent:
        def collect_scope(self, _url: str):
            raise AssertionError("the injected deterministic reader must be used")

        def interpret_captured_scope(self, _page: ProgramPage) -> ScopeAnalysis:
            return analysis

    registry = ProgramRegistry(tmp_path)
    workflow = ScopeWorkflowManager(
        tmp_path,
        registry,
        agent_factory=Agent,
        public_reader_factory=Reader,
    )
    app = create_app(result_root=tmp_path, scope_workflow=workflow)
    launched_process = threading.Event()
    release_process = threading.Event()
    captured_launch: dict[str, Any] = {}

    class Process:
        def wait(self) -> int:
            launched_process.set()
            release_process.wait(2)
            return 0

    def process_factory(argv: list[str], **kwargs: Any) -> Process:
        captured_launch.update(argv=argv, kwargs=kwargs)
        return Process()

    app.state.launch_manager.process_factory = process_factory

    async def wait_for_status(client: httpx.AsyncClient, program_id: str, expected: str):
        for _ in range(100):
            response = await client.get(f"/api/v1/programs/{program_id}/scope-job")
            if response.status_code == 200 and response.json()["job"]["scope_status"] == expected:
                return response.json()
            await asyncio.sleep(0.01)
        raise AssertionError(f"Scope job never reached {expected}")

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=app)
        headers = {"Origin": "http://test"}
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            registered = await client.post(
                "/api/v1/programs",
                headers=headers,
                json={
                    "program_url": "https://bugcrowd.com/engagements/example",
                    "visibility": "public",
                },
            )
            program_id = registered.json()["program"]["id"]
            started = await client.post(
                f"/api/v1/programs/{program_id}/scope-collection",
                headers=headers,
                json={"login_mode": "headless"},
            )
            assert started.status_code == 202
            await wait_for_status(client, program_id, "review_required")
            activity = (await client.get(f"/api/v1/programs/{program_id}/scope-job")).json()["events"]
            assert activity[0]["message_code"] == "scope.started"
            assert activity[-1]["message_code"] == "scope.review_required"
            assert activity[-1]["message_params"] == {"in_scope": 1, "out_of_scope": 0}
            draft = await client.get(f"/api/v1/programs/{program_id}/scope-draft")
            assert draft.status_code == 200
            assert draft.json()["draft"]["in_scope_assets"][0]["asset"] == "*.example.test"
            unavailable = await client.get(f"/api/v1/programs/{program_id}/approved-scope")
            assert unavailable.status_code == 400
            assert not (tmp_path / "Scope" / "bugcrowd" / "example").exists()

            rejected = await client.post(
                f"/api/v1/programs/{program_id}/scope-decision",
                headers=headers,
                json={"decision": "no"},
            )
            assert rejected.json()["job"]["scope_status"] == "rejected"
            assert not (tmp_path / "Scope" / "bugcrowd" / "example").exists()

            await client.post(
                f"/api/v1/programs/{program_id}/scope-collection",
                headers=headers,
                json={"login_mode": "headless"},
            )
            await wait_for_status(client, program_id, "review_required")
            unconfirmed = await client.post(
                f"/api/v1/programs/{program_id}/scope-decision",
                headers=headers,
                json={"decision": "yes", "approved_by": "reviewer"},
            )
            assert unconfirmed.status_code == 422
            approved = await client.post(
                f"/api/v1/programs/{program_id}/scope-decision",
                headers=headers,
                json={
                    "decision": "yes",
                    "approved_by": "reviewer",
                    "confirmation": True,
                },
            )
            assert approved.status_code == 200
            assert approved.json()["job"]["scope_status"] == "approved"
            output = tmp_path / "Scope" / "bugcrowd" / "example"
            assert (output / "Scope.json").is_file()
            assert (output / "Scope.md").is_file()
            assert (output / "Manifest.json").is_file()
            assert (output / "Approval.json").is_file()
            detail = await client.get(f"/api/v1/programs/{program_id}/approved-scope")
            assert detail.status_code == 200
            scope = detail.json()["scope"]
            assert detail.json()["approval"]["approved_by"] == "reviewer"
            assert scope["program_name"] == "Example Program"
            assert scope["in_scope_assets"][0]["asset"] == "*.example.test"
            assert scope["allowed_activities"] == ["Non-destructive testing"]
            assert scope["prohibited_activities"] == ["Denial of service"]
            assert scope["submission_requirements"] == ["Reproducible steps"]
            assert scope["source_evidence"][0]["quote"] == "*.example.test is in scope"
            assert "text" not in scope
            assert "content_sha256" not in scope
            approved_scope = (await client.get("/api/v1/scopes")).json()["scopes"][0]
            assert approved_scope["program_name"] == "Example Program"
            catalog_detail = await client.get(
                f"/api/v1/scopes/{approved_scope['scope_id']}"
            )
            assert catalog_detail.status_code == 200
            assert catalog_detail.json()["scope"]["in_scope_assets"][0]["asset"] == "*.example.test"
            assert catalog_detail.json()["scope"]["allowed_activities"] == [
                "Non-destructive testing"
            ]
            assert catalog_detail.json()["approval"]["approved_by"] == "reviewer"
            missing_detail = await client.get("/api/v1/scopes/missing")
            assert missing_detail.status_code == 404
            requirements = approved_scope["execution_requirements"]
            assert requirements["scope_max_requests_per_second"] == 10
            assert requirements["required_header"] == {
                "name": "X-Intigriti-Username",
                "input_field": "intigriti_username",
            }
            assert requirements["profiles"][0]["limits"]["max_requests"] == 500
            assert requirements["profiles"][0]["limits"]["requests_per_second"] == 10

            launched = await client.post(
                "/api/v1/scans",
                headers=headers,
                json={
                    "scope_id": approved_scope["scope_id"],
                    "targets": ["*.example.test"],
                    "profile": "safe-recon",
                    "max_requests": 500,
                    "max_rps": 10,
                    "max_concurrency": 2,
                    "timeout_seconds": 15,
                    "max_depth": 2,
                    "ffuf_max_time_seconds": 60,
                    "tag_batch_size": 25,
                    "login_mode": "none",
                    "authorization_confirmed": True,
                    "identity_values": {"intigriti_username": "dashboard-reviewer"},
                },
            )
            assert launched.status_code == 202, launched.text
            launch = launched.json()
            assert launch["status"] == "running"
            assert launch["targets"] == ["*.example.test"]
            assert launched_process.wait(1)
            argv = captured_launch["argv"]
            assert argv[1:4] == ["-m", "aidast", "run"]
            assert argv[argv.index("--target") + 1] == "*.example.test"
            assert argv[argv.index("--header-input") + 1] == (
                "intigriti_username=dashboard-reviewer"
            )
            assert captured_launch["kwargs"]["shell"] is False

            outside = await client.post(
                "/api/v1/scans",
                headers=headers,
                json={
                    "scope_id": approved_scope["scope_id"],
                    "targets": ["outside.example.test"],
                    "authorization_confirmed": True,
                    "identity_values": {"intigriti_username": "dashboard-reviewer"},
                },
            )
            assert outside.status_code == 400
            assert "not in the approved Scope" in outside.json()["detail"]
            release_process.set()
            with sqlite3.connect(tmp_path / ".webui" / "programs.db") as connection:
                connection.execute("DELETE FROM registered_programs")
            assert (await client.get("/api/v1/programs")).json()["programs"] == []
            assert (await client.get(f"/api/v1/scopes/{approved_scope['scope_id']}")).status_code == 200
            restored = await client.post(
                "/api/v1/programs",
                headers=headers,
                json={"program_url": "https://bugcrowd.com/engagements/example", "visibility": "public"},
            )
            assert restored.status_code == 201
            (output / "Scope.json").write_text("{}", encoding="utf-8")
            compromised = await client.get(f"/api/v1/programs/{program_id}/approved-scope")
            assert compromised.status_code == 400
            assert (await client.get(f"/api/v1/scopes/{approved_scope['scope_id']}")).status_code == 404

    asyncio.run(exercise())


def test_recon_activity_api_pages_every_safe_event_beyond_snapshot_window(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    expected_urls: list[str] = []
    rows = []
    for index in range(720):
        stamp = f"2026-09-20 02:{index // 60:02d}:{index % 60:02d}"
        kind = index % 4
        if kind == 0:
            url = f"https://example.com/p{index}"
            expected_urls.append(url)
            details = {"phase": "endpoint_discovery", "state": "found", "method": "GET",
                       "url": f"{url}?token=secret-{index}", "source": "ffuf", "response_status": 200,
                       "headers": {"Cookie": "secret"}, "body": "secret"}
            event_type = "recon.activity"
        elif kind == 1:
            details = {"phase": "ffuf", "state": "started", "headers": {"Cookie": "secret"}}
            event_type = "recon.activity"
        elif kind == 2:
            details = {"secret": "must-not-leak"}
            event_type = "stage.started"
        else:
            details = {"phase": "endpoint_discovery", "state": "found", "method": "GET",
                       "url": "https://user:secret@example.com/creds"}
            event_type = "recon.activity"
        rows.append((f"bulk-{index}", SCAN_ID, "stage", None, event_type, json.dumps(details), stamp))
    with sqlite3.connect(database) as conn:
        conn.executemany("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)", rows)
    app = create_app(result_root=tmp_path, poll_interval=0.01)

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            snapshot = (await client.get(f"/api/v1/scans/{SCAN_ID}")).json()
            snapshot_urls = {log["message_params"].get("url") for log in snapshot["logs"]}
            assert len(snapshot["logs"]) == 500
            assert not set(expected_urls) <= snapshot_urls

            pages: list[dict[str, Any]] = []
            url = f"/api/v1/scans/{SCAN_ID}/recon-activity"
            while True:
                response = await client.get(url)
                assert response.status_code == 200
                body = response.json()
                assert 0 < len(body["events"]) <= 200
                pages.append(body)
                if body["next_before"] is None:
                    break
                assert body["next_before"] == body["events"][-1]["event_id"]
                url = f"/api/v1/scans/{SCAN_ID}/recon-activity?before={body['next_before']}"
            assert len(pages) >= 2
            events = [event for page in pages for event in page["events"]]
            ids = [event["event_id"] for event in events]
            assert ids == sorted(set(ids), reverse=True)
            assert all(event["version"] == 1 and event["type"] == "log.appended"
                       and event["scan_id"] == SCAN_ID and event["occurred_at"]
                       and event["payload"]["message_code"] == "recon.activity" for event in events)
            found = [event["payload"]["message_params"]["url"] for event in events
                     if event["payload"]["message_params"]["state"] == "found"]
            assert sorted(found) == sorted(expected_urls)
            assert any(event["payload"]["message_params"]["phase"] == "ffuf" for event in events)
            assert "secret" not in json.dumps(pages)
            assert "must-not-leak" not in json.dumps(pages)
            assert "example.com/creds" not in json.dumps(pages)

            assert (await client.get(f"/api/v1/scans/{SCAN_ID}/recon-activity?before=0")).status_code == 422
            assert (await client.get(f"/api/v1/scans/{SCAN_ID}/recon-activity?before=abc")).status_code == 422
            assert (await client.get("/api/v1/scans/scan_missing/recon-activity")).status_code == 404

    asyncio.run(exercise())


def test_scope_activity_schema_upgrades_existing_event_database(tmp_path: Path) -> None:
    database = tmp_path / ".webui" / "scope_jobs.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE scope_job_events (job_id TEXT, event_id INTEGER, occurred_at TEXT, level TEXT, message TEXT, PRIMARY KEY(job_id,event_id))"
        )
        conn.execute(
            "INSERT INTO scope_job_events VALUES ('scopejob_old',1,'2026-09-20T00:00:00Z','info','legacy')"
        )
    ScopeWorkflowManager(tmp_path, ProgramRegistry(tmp_path))
    with sqlite3.connect(database) as conn:
        row = conn.execute(
            "SELECT message,message_code,message_params FROM scope_job_events WHERE job_id='scopejob_old'"
        ).fetchone()
    assert row == ("legacy", None, "{}")


def test_dashboard_cli_defaults_and_rejects_remote_bind(tmp_path: Path) -> None:
    defaults = _parser().parse_args(["dashboard"])
    assert defaults.host == "127.0.0.1"
    assert defaults.port == 8000

    remote = _parser().parse_args(
        ["dashboard", "--host", "0.0.0.0", "--result-root", str(tmp_path)]
    )
    with pytest.raises(MainAgentError, match="bind only to localhost"):
        _run_dashboard(remote)


def test_scan_launcher_builds_fixed_argv_and_streams_pre_database_logs(tmp_path: Path) -> None:
    wordlist = tmp_path / "resources" / "wordlists" / "common.txt"
    wordlist.parent.mkdir(parents=True)
    wordlist.write_text("api\napp\n", encoding="utf-8")
    projector = DashboardProjector(tmp_path)
    captured: dict[str, Any] = {}
    waiting = threading.Event()

    class Process:
        def wait(self) -> int:
            waiting.wait(2)
            return 0

    def process_factory(argv: list[str], **kwargs: Any) -> Process:
        captured.update(argv=argv, kwargs=kwargs)
        return Process()

    from aidast.scope.identity_headers import ScopeHeaderResolver
    from aidast.orchestration.scope import ScopeCoordinator
    from test_scope_workflow import sample_analysis, sample_page
    header_quote = "Include X-HackerOne:{Username} in every request."
    scope_analysis = sample_analysis().model_copy(update={
        "in_scope_assets": [ScopeAsset(asset_type=AssetType.DOMAIN, asset="prismlife.com", description="", eligibility="", maximum_severity="HIGH")],
        "source_evidence": [SourceEvidence(section="Scope", quote="prismlife.com"), SourceEvidence(section="Headers", quote=header_quote)],
        "required_request_headers": [RequiredRequestHeader(name="X-HackerOne", value_template="{hackerone_username}",
            inputs=[HeaderInput(key="hackerone_username", label="Username", kind="username")], source_quote=header_quote)],
    })
    source_page = sample_page()
    source_text = "prismlife.com is in scope. " + header_quote + " Automated tooling max. 10 requests /sec"
    source_page = source_page.model_copy(update={"text": source_text, "content_sha256": hashlib.sha256(source_text.encode()).hexdigest()})
    class ScopeAgent:
        def collect_scope(self, _url):
            return source_page, scope_analysis
    launch_scope_dir = tmp_path / "Scope" / "hackerone" / "prism_vdp"
    ScopeCoordinator(launch_scope_dir).collect("https://hackerone.com/prism_vdp", main_agent=ScopeAgent(),
                                            approved_by="operator", review=lambda _: True)

    approved = ApprovedScope(
        scope_id="scope_verified",
        program_id="h1-prism-vdp",
        program_name="PRISM VDP",
        platform="hackerone",
        program_url="https://hackerone.com/prism_vdp",
        targets=({"asset_type": "DOMAIN", "asset": "prismlife.com", "description": "", "maximum_severity": "HIGH"},),
        identity_header="hackerone",
        approved_by="operator",
        execution_requirements=build_scope_execution_requirements(scope_analysis),
        directory=launch_scope_dir,
    )

    class Catalog:
        header_resolver = ScopeHeaderResolver(tmp_path / ".header-requirements")
        def list(self) -> list[ApprovedScope]:
            return [approved]

        def get(self, scope_id: str) -> ApprovedScope:
            if scope_id != approved.scope_id:
                raise ValueError("approved scope not found")
            return approved

    manager = ScanLaunchManager(
        tmp_path, projector, process_factory=process_factory, project_root=tmp_path
    )
    manager.catalog = Catalog()  # type: ignore[assignment]
    request = ScanLaunchRequest(
        scope_id=approved.scope_id,
        targets=["prismlife.com"],
        profile="safe-recon",
        max_requests=120,
        max_rps=0.4,
        max_depth=1,
        max_concurrency=1,
        timeout_seconds=10,
        ffuf_max_time_seconds=0,
        tag_batch_size=17,
        recon_model="gpt-6-sol",
        attack_model="gpt-6-luna",
        validation_model="gpt-5.6-terra",
        report_model="gpt-6-astra",
        login_mode="none",
        start_url="https://prismlife.com/app",
        hackerone_username="web_operator",
        authorization_confirmed=True,
    )
    launched = manager.launch(request)
    from aidast.pipeline.model_settings import load_scan_model_choices, scan_model_settings_path
    saved_models = load_scan_model_choices(tmp_path, launched["scan_id"])
    assert saved_models is not None
    assert (saved_models.main_model, saved_models.recon_model, saved_models.attack_model,
            saved_models.chaining_model, saved_models.validation_model, saved_models.report_model) == (
        "gpt-6-sol", "gpt-6-sol", "gpt-6-luna", "gpt-6-luna", "gpt-5.6-terra", "gpt-6-astra")
    assert "web_operator" not in scan_model_settings_path(tmp_path, launched["scan_id"]).read_text()
    assert launched["targets"] == ["prismlife.com"]
    assert manager.list_jobs()[0]["targets"] == ["prismlife.com"]
    argv = captured["argv"]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["env"]["PYTHONUNBUFFERED"] == "1"
    assert captured["kwargs"]["stderr"] == subprocess.STDOUT
    assert argv[1:4] == ["-m", "aidast", "run"]
    assert argv[argv.index("--target") + 1] == "prismlife.com"
    assert argv[argv.index("--max-requests") + 1] == "120"
    assert "--ffuf-wordlist" in argv
    assert argv[argv.index("--ffuf-wordlist") + 1] == str(wordlist)
    assert argv[argv.index("--ffuf-max-time-seconds") + 1] == "0"
    assert argv[argv.index("--max-rps") + 1] == "0.4"
    assert argv[argv.index("--max-depth") + 1] == "1"
    assert argv[argv.index("--max-concurrency") + 1] == "1"
    assert argv[argv.index("--timeout-seconds") + 1] == "10"
    assert argv[argv.index("--tag-batch-size") + 1] == "17"
    assert argv[argv.index("--recon-model") + 1] == "gpt-6-sol"
    assert argv[argv.index("--attack-model") + 1] == "gpt-6-luna"
    assert argv[argv.index("--validation-model") + 1] == "gpt-5.6-terra"
    assert argv[argv.index("--report-model") + 1] == "gpt-6-astra"
    assert argv[argv.index("--scan-id") + 1] == launched["scan_id"]
    assert argv[argv.index("--start-url") + 1] == "https://prismlife.com/app"
    assert manager.snapshot(launched["scan_id"])["logs"][-1]["message"] == "AI DAST pipeline process started."
    assert manager.snapshot(launched["scan_id"])["logs"][-1]["message_code"] == "pipeline.started"
    params = manager.snapshot(launched["scan_id"])["logs"][-1]["message_params"]
    assert (tmp_path / params["diagnostic_log"]).is_file()
    assert projector.stored_events_after(launched["scan_id"], 0)[0]["event_id"] == 1
    app = create_app(result_root=tmp_path, launch_manager=manager)

    async def before_recon_database() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(f"/api/v1/scans/{launched['scan_id']}/recon-activity")
            assert response.status_code == 200
            assert response.json() == {"events": [], "next_before": None}
            unknown = await client.get("/api/v1/scans/scan_missing/recon-activity")
            assert unknown.status_code == 404

    asyncio.run(before_recon_database())

    with pytest.raises(ValueError, match="not in the approved Scope"):
        manager.launch(request.model_copy(update={"targets": ["outside.example"]}))
    with pytest.raises(ValueError, match="outside the selected approved target"):
        manager.launch(request.model_copy(update={"start_url": "https://outside.example/"}))
    with pytest.raises(ValueError, match="request rate exceeds"):
        manager.launch(request.model_copy(update={"max_rps": 0.6}))

    from dataclasses import replace

    # A stale catalog projection cannot loosen the freshly verified document.
    approved = replace(approved, execution_requirements=_execution_requirements(
        "hackerone", rate_quote="Automated tooling max. 10 requests /sec"))
    with pytest.raises(ValueError, match="request rate exceeds"):
        manager.launch(request.model_copy(update={"max_rps": 10}))
    from aidast.scope.execution_rules import ScopeExecutionResolver, EXECUTION_INTERPRETATION_VERSION
    document, _ = ScopeCoordinator(launch_scope_dir).load_approved_scope()
    resolver = ScopeExecutionResolver(tmp_path / '.execution-requirements')
    rate_quote = "Automated tooling max. 10 requests /sec"
    resolver.cache_dir.mkdir()
    resolver.cache_path(document).write_text(json.dumps(dict(
        interpretation_version=EXECUTION_INTERPRETATION_VERSION, approved_digest=resolver.digest(document),
        requirements=dict(required_request_headers=[item.model_dump() for item in scope_analysis.required_request_headers],
            execution_rules=dict(policy_review_version=2, exclusions=[], request_limits=[dict(maximum=10,period_seconds=1,scope="program",source_quote=rate_quote)])))))
    manager.catalog.header_resolver = resolver
    manager.launch(request.model_copy(update={"max_rps": 10}))
    argv = captured["argv"]
    assert float(argv[argv.index("--max-rps") + 1]) == 10.0
    with pytest.raises(ValueError, match="request rate exceeds"):
        manager.launch(request.model_copy(update={"max_rps": 11}))
    waiting.set()


def test_scan_completion_log_does_not_claim_report_generation(tmp_path: Path) -> None:
    from types import SimpleNamespace

    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    job = SimpleNamespace(
        scan_id=SCAN_ID,
        process=SimpleNamespace(wait=lambda: 0),
        status="running",
        finished_at=None,
    )
    manager._monitor(job)
    events = projector.stored_events_after(SCAN_ID, 0)
    assert job.status == "completed"
    assert events[-1]["payload"]["stage"] == "Validation"


def test_scan_completion_log_reports_persisted_report_stage(tmp_path: Path) -> None:
    from types import SimpleNamespace

    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='completed' WHERE scan_id=?", (SCAN_ID,))
        conn.execute(
            "INSERT INTO stage_runs VALUES (?,?,?,?,?,?,?,?)",
            ("report-stage", SCAN_ID, "report", "completed", None, "2026-09-20T01:06:00Z", "2026-09-20T01:07:00Z", "2026-09-20 01:06:00"),
        )
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    job = SimpleNamespace(
        scan_id=SCAN_ID,
        process=SimpleNamespace(wait=lambda: 0),
        status="running",
        finished_at=None,
    )
    manager._monitor(job)
    events = projector.stored_events_after(SCAN_ID, 0)
    assert events[-1]["payload"]["stage"] == "Report"
    assert "through Report" in events[-1]["payload"]["message"]
def test_scan_cancel_terminates_managed_process_and_persists_cancelled_state(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    finished = threading.Event()

    class Process:
        def poll(self) -> int | None:
            return -15 if finished.is_set() else None

        def terminate(self) -> None:
            finished.set()

        def wait(self) -> int:
            assert finished.wait(2)
            return -15

    job = LaunchJob(SCAN_ID, None, "running", "2026-09-20T01:00:00Z", 10, ("example.com",), Process())  # type: ignore[arg-type]
    manager._jobs[SCAN_ID] = job
    monitor = threading.Thread(target=manager._monitor, args=(job,), daemon=True)
    monitor.start()
    app = create_app(result_root=tmp_path, launch_manager=manager)

    async def cancel_via_api() -> None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            rejected = await client.post(f"/api/v1/scans/{SCAN_ID}/cancel", headers={"Origin": "http://elsewhere"})
            assert rejected.status_code == 403
            response = await client.post(f"/api/v1/scans/{SCAN_ID}/cancel", headers={"Origin": "http://test"})
            assert response.status_code == 202
            assert response.json() == {"scan_id": SCAN_ID, "status": "cancelling"}

    asyncio.run(cancel_via_api())
    monitor.join(timeout=3)
    assert not monitor.is_alive()
    assert job.status == "cancelled"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT status FROM scans WHERE scan_id=?", (SCAN_ID,)).fetchone()[0] == "cancelled"
        assert conn.execute("SELECT status FROM stage_runs WHERE scan_id=?", (SCAN_ID,)).fetchone()[0] == "cancelled"
    assert [log["payload"]["message_code"] for log in projector.stored_events_after(SCAN_ID, 0)
            if log["type"] == "log.appended"][-2:] == ["pipeline.cancel_requested", "pipeline.cancelled"]
    with pytest.raises(ValueError, match="no active process"):
        manager.cancel(SCAN_ID)


@pytest.mark.skipif(os.name != "posix", reason="pause uses POSIX process groups")
def test_scan_pause_continue_and_cancel_preserve_one_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    projector = DashboardProjector(tmp_path)
    manager = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                               cwd=tmp_path, start_new_session=True)
    monkeypatch.setattr(manager, "_isolated_scan_pid", lambda _scan_id: process.pid)
    job = LaunchJob(SCAN_ID, None, "running", "2026-09-20T01:00:00Z", 10,
                    ("example.com",), process)  # type: ignore[arg-type]
    manager._jobs[SCAN_ID] = job
    monitor = threading.Thread(target=manager._monitor, args=(job,), daemon=True)
    monitor.start()
    app = create_app(result_root=tmp_path, launch_manager=manager)
    try:
        async def control() -> None:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
                origin = {"Origin": "http://test"}
                paused = await client.post(f"/api/v1/scans/{SCAN_ID}/pause", headers=origin)
                assert paused.status_code == 202
                assert paused.json()["status"] == "paused"
                assert (await client.get(f"/api/v1/scans/{SCAN_ID}")).json()["status"] == "paused"
                assert process.poll() is None
                continued = await client.post(f"/api/v1/scans/{SCAN_ID}/continue", headers=origin)
                assert continued.status_code == 202
                assert continued.json()["status"] == "running"
                assert (await client.get(f"/api/v1/scans/{SCAN_ID}")).json()["status"] == "running"
                await client.post(f"/api/v1/scans/{SCAN_ID}/pause", headers=origin)
                cancelled = await client.post(f"/api/v1/scans/{SCAN_ID}/cancel", headers=origin)
                assert cancelled.status_code == 202, cancelled.text
                assert cancelled.json()["status"] == "cancelling"
        asyncio.run(control())
        monitor.join(timeout=5)
        assert not monitor.is_alive()
        assert projector.snapshot(SCAN_ID)["status"] == "cancelled"
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="uses POSIX process termination")
def test_scan_termination_falls_back_to_owned_process_when_group_signal_is_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=tmp_path, start_new_session=True,
    )
    monkeypatch.setattr(
        "aidast.web.launch.signal_session",
        lambda *_args: (_ for _ in ()).throw(PermissionError("protected helper")),
    )
    try:
        ScanLaunchManager._terminate_process(process)
        assert process.wait(timeout=5) == -signal.SIGTERM
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_paused_scan_can_continue_after_dashboard_restart(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
    (tmp_path / "aidast.py").write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, "-m", "aidast", "run", "https://example.com", "--scan-id", SCAN_ID],
        cwd=tmp_path, start_new_session=True,
    )
    try:
        projector = DashboardProjector(tmp_path)
        first = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
        first._record_process(SCAN_ID, process)
        restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
        assert restarted._isolated_scan_pid(SCAN_ID) == process.pid
        assert restarted.pause(SCAN_ID)["status"] == "paused"
        assert projector.snapshot(SCAN_ID)["status"] == "paused"
        another_restart = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
        assert another_restart.continue_scan(SCAN_ID)["status"] == "running"
        assert process.poll() is None
        assert another_restart.cancel(SCAN_ID)["status"] == "cancelling"
        for _ in range(50):
            if projector.snapshot(SCAN_ID)["status"] == "cancelled":
                break
            threading.Event().wait(0.1)
        assert projector.snapshot(SCAN_ID)["status"] == "cancelled"
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def test_windows_scan_pause_continue_and_cancel_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import aidast.web.launch as launch_module

    database = _fixture(tmp_path)
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))
        conn.execute("UPDATE stage_runs SET status='running',finished_at=NULL WHERE scan_id=?", (SCAN_ID,))

    class Worker:
        pid = 42

    alive = True
    actions: list[str] = []

    def control(_pid: int, _started: str, action: str) -> None:
        nonlocal alive
        actions.append(action)
        if action == "terminate":
            alive = False

    monkeypatch.setattr(launch_module, "_windows_host", lambda: True)
    monkeypatch.setattr(launch_module.subprocess, "Popen", Worker)
    monkeypatch.setattr(launch_module, "process_cwd", lambda _pid: tmp_path)
    monkeypatch.setattr(launch_module, "process_args", lambda _pid: [
        "python.exe", "-m", "aidast", "run", "https://example.com", "--scan-id", SCAN_ID,
    ])
    monkeypatch.setattr(launch_module, "control_process", control)
    monkeypatch.setattr(
        ScanLaunchManager, "_process_stat",
        staticmethod(lambda _pid: ("R" if alive else "Z", "1234.5")),
    )

    projector = DashboardProjector(tmp_path)
    first = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    first._record_process(SCAN_ID, Worker())
    restarted = ScanLaunchManager(tmp_path, projector, project_root=tmp_path)
    assert restarted.pause(SCAN_ID)["status"] == "paused"
    assert restarted.continue_scan(SCAN_ID)["status"] == "running"
    assert restarted.cancel(SCAN_ID)["status"] == "cancelling"
    for _ in range(50):
        if projector.snapshot(SCAN_ID)["status"] == "cancelled":
            break
        threading.Event().wait(0.02)
    assert projector.snapshot(SCAN_ID)["status"] == "cancelled"
    assert actions == ["pause", "resume", "terminate"]


def test_scan_request_rejects_unconfirmed_or_excessive_budget() -> None:
    base = {
        "scope_id": "scope_verified",
        "targets": ["prismlife.com"],
        "profile": "safe-recon",
    }
    with pytest.raises(ValueError, match="authorization confirmation"):
        ScanLaunchRequest(**base)
    with pytest.raises(ValueError, match="request budget exceeds"):
        ScanLaunchRequest(**base, max_requests=501, authorization_confirmed=True)
    for invalid_batch in (0, 201, 1.5):
        with pytest.raises(ValueError):
            ScanLaunchRequest(**base, tag_batch_size=invalid_batch, authorization_confirmed=True)
    for invalid_model in ("", "https://example.test/model", "model with spaces", "x" * 129):
        with pytest.raises(ValueError):
            ScanLaunchRequest(**base, recon_model=invalid_model, authorization_confirmed=True)
        with pytest.raises(ValueError):
            ScanLaunchRequest(**base, attack_model=invalid_model, authorization_confirmed=True)
        with pytest.raises(ValueError):
            ScanLaunchRequest(**base, validation_model=invalid_model, authorization_confirmed=True)
        with pytest.raises(ValueError):
            ScanLaunchRequest(**base, report_model=invalid_model, authorization_confirmed=True)
    with pytest.raises(ValueError, match="concurrency exceeds"):
        ScanLaunchRequest(
            **base,
            max_concurrency=3,
            authorization_confirmed=True,
        )
    with pytest.raises(ValueError, match="exactly one target"):
        ScanLaunchRequest(**{
            **base,
            "targets": ["one.example", "two.example"],
            "start_url": "https://one.example/",
            "authorization_confirmed": True,
        })
    with pytest.raises(ValueError, match="absolute HTTPS"):
        ProgramResolveRequest(program_url="http://hackerone.com/program")


def test_scan_api_receives_distinct_recon_and_attack_models(tmp_path: Path) -> None:
    captured: list[ScanLaunchRequest] = []

    class Launcher:
        def launch(self, request: ScanLaunchRequest) -> dict[str, str]:
            captured.append(request)
            return {"scan_id": "scan_" + "a" * 32, "status": "running"}

    app = create_app(result_root=tmp_path, launch_manager=Launcher())
    async def exercise_api() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            return await client.post(
                "/api/v1/scans",
                headers={"Origin": "http://test"},
                json={
                    "scope_id": "scope_verified",
                    "targets": ["prismlife.com"],
                    "authorization_confirmed": True,
                    "recon_model": "gpt-6-sol",
                    "attack_model": "gpt-6-luna",
                    "validation_model": "gpt-5.6-terra",
                    "report_model": "gpt-6-astra",
                },
            )

    response = asyncio.run(exercise_api())
    assert response.status_code == 202
    assert (captured[0].recon_model, captured[0].attack_model) == (
        "gpt-6-sol", "gpt-6-luna",
    )
    assert (captured[0].validation_model, captured[0].report_model) == (
        "gpt-5.6-terra", "gpt-6-astra",
    )


def test_scan_token_usage_api_returns_scan_total_and_rejects_unknown_scan(tmp_path: Path) -> None:
    _fixture(tmp_path)
    SQLiteModelCallSink(tmp_path).append(ModelCallEvent(
        call_id="a" * 32, state="success", occurred_at="2026-09-27T00:00:00Z",
        scan_id=SCAN_ID, stage="Recon", stage_run_id=None, task_id=None,
        case_id=None, scope_job_id=None, operation_code="recon_plan",
        invocation_kind="structured", requested_model="gpt-6-sol",
        elapsed_ms=120, error_code=None,
        input_tokens=8, cached_input_tokens=3, output_tokens=2,
        usage_status="reported",
    ))
    app = create_app(result_root=tmp_path)

    async def request_usage() -> tuple[httpx.Response, httpx.Response]:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test",
        ) as client:
            return (
                await client.get(f"/api/v1/scans/{SCAN_ID}/token-usage"),
                await client.get("/api/v1/scans/scan_" + "b" * 32 + "/token-usage"),
            )

    usage, unknown = asyncio.run(request_usage())
    assert usage.status_code == 200
    assert usage.json()["total"] == {
        "input_tokens": 8, "output_tokens": 2, "total_tokens": 10,
        "measured_calls": 1, "unreported_calls": 0,
    }
    assert usage.json()["stages"]["Recon"]["total_tokens"] == 10
    assert usage.json()["stages"]["Validation"]["measured_calls"] == 0
    assert unknown.status_code == 404


def test_run_parser_accepts_only_generated_scan_identifiers() -> None:
    assert CLI_EXECUTION_PROFILES is EXECUTION_PROFILES
    valid = "scan_" + "a" * 32
    parsed = _parser().parse_args(
        ["run", "https://example.test/program", "--target", "example.test", "--scan-id", valid]
    )
    assert parsed.scan_id == valid
    with pytest.raises(SystemExit):
        _parser().parse_args(
            ["run", "https://example.test/program", "--target", "example.test", "--scan-id", "../escape"]
        )


def test_program_registry_persists_and_masks_private_programs(tmp_path: Path) -> None:
    registry = ProgramRegistry(tmp_path)
    public = registry.register(ProgramRegistrationRequest(
        program_url="https://hackerone.com/public-program",
        visibility="public",
    ))
    private = registry.register(ProgramRegistrationRequest(
        program_url="https://hackerone.com/private-program",
        visibility="private",
    ))
    assert public["program"] == "Public Program"
    assert private["program"] == "Private program"
    assert private["id"].startswith("registered-")
    serialized = json.dumps(ProgramRegistry(tmp_path).list())
    assert "private-program" not in serialized
    with pytest.raises(ValueError, match="absolute HTTPS"):
        ProgramRegistrationRequest(
            program_url="http://hackerone.com/not-https",
            visibility="public",
        )


def test_validations_api_reports_case_verdicts_and_safe_evidence(tmp_path: Path) -> None:
    database = _fixture(tmp_path)
    decision = {"blind_assessment": {
        "reproduced": True, "conclusion": "Bearer abcdef1234567890 leaked",
        "impact_boundary": {"score": 2, "reason": "Login response observed"},
        "impact_sensitivity": {"score": 0, "reason": "Protected account access not established"},
        "impact_actor_requirements": {"score": 2, "reason": "No existing credential required"},
    }, "evidence_ids": ["e1"], "body": "secret-body"}
    with sqlite3.connect(database) as conn:
        conn.executescript(
            """
            CREATE TABLE validation_cases (
              case_id TEXT, scan_id TEXT, target_kind TEXT, finding_id TEXT, chain_id TEXT,
              latest_stage_run_id TEXT, decision_stage_run_id TEXT, processing_phase TEXT,
              current_status TEXT, decision_json TEXT, known_source_case_id TEXT,
              severity TEXT, impact_score INTEGER, created_at TEXT, updated_at TEXT
            );
            CREATE TABLE validation_attempts (
              attempt_id TEXT, case_id TEXT, stage_run_id TEXT, attempt_kind TEXT,
              outcome TEXT, observation_json TEXT
            );
            CREATE TABLE validation_evidence (
              evidence_id TEXT, case_id TEXT, stage_run_id TEXT, details_json TEXT
            );
            """
        )
        rows = [
            ("c-confirmed", SCAN_ID, "finding", "f1", None, "stage", "stage", "completed", "CONFIRMED",
             json.dumps(decision), None, "HIGH", 7),
            ("c-disproven", SCAN_ID, "finding", "f2", None, "stage", "stage", "completed", "DISPROVEN",
             json.dumps({"reason": "control matched target"}), None, None, None),
            ("c-pending", SCAN_ID, "chain", None, "ch1", "stage", None, "queued", None, None, None, None, None),
            ("c-known", SCAN_ID, "finding", "f3", None, "stage", "stage", "completed", "KNOWN",
             json.dumps({"reason": "exact metadata match"}), "c-confirmed", None, None),
            ("c-other", "other-scan", "finding", "f9", None, "stage", "stage", "completed", "CONFIRMED",
             json.dumps({"reason": "other"}), None, None, None),
        ]
        for i, row in enumerate(rows):
            conn.execute(
                "INSERT INTO validation_cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (*row, f"2026-09-20 01:0{i}:00", f"2026-09-20 01:0{i}:00"),
            )
        conn.execute("INSERT INTO validation_attempts VALUES ('a1','c-confirmed','stage','target','observed','{\"headers\":\"Cookie: sid=1\"}')")
        conn.execute("INSERT INTO validation_attempts VALUES ('a2','c-confirmed','stage','negative_control','not_observed','{}')")
        conn.execute("INSERT INTO validation_evidence VALUES ('e1','c-confirmed','stage','{\"body\":\"secret-body\"}')")
    app = create_app(result_root=tmp_path)

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/v1/scans/{SCAN_ID}/validations")
            assert response.status_code == 200
            body = response.json()
            assert body["scan_id"] == SCAN_ID
            by_id = {case["case_id"]: case for case in body["cases"]}
            assert set(by_id) == {"c-confirmed", "c-disproven", "c-pending", "c-known"}
            assert by_id["c-confirmed"]["current_status"] == "CONFIRMED"
            assert by_id["c-confirmed"]["target_id"] == "f1"
            assert by_id["c-confirmed"]["decision"]["severity"] == "HIGH"
            assert "[REDACTED]" in by_id["c-confirmed"]["decision"]["reason"]
            assert by_id["c-confirmed"]["decision"]["reproduced"] is True
            assert by_id["c-confirmed"]["decision"]["impact_axes"]["sensitivity"] == {
                "score": 0, "reason": "Protected account access not established",
            }
            assert by_id["c-confirmed"]["evidence"] == {
                "attempts": {"target": {"observed": 1}, "negative_control": {"not_observed": 1}},
                "evidence_count": 1,
            }
            assert by_id["c-disproven"]["current_status"] == "DISPROVEN"
            assert by_id["c-disproven"]["decision"]["reason"] == "control matched target"
            assert by_id["c-known"]["current_status"] == "KNOWN"
            assert by_id["c-known"]["decision"]["known_source_case_id"] == "c-confirmed"
            pending = by_id["c-pending"]
            assert pending["current_status"] is None and pending["processing_phase"] == "queued"
            assert pending["target_kind"] == "chain" and pending["target_id"] == "ch1"
            assert "decision" not in pending and "evidence" not in pending
            for leaked in ("abcdef1234567890", "secret-body", "Cookie", "sid=1"):
                assert leaked not in response.text
            assert (await client.get("/api/v1/scans/unknown-scan/validations")).status_code == 404

    asyncio.run(exercise())


def test_resume_uses_saved_policy_without_new_launch_inputs(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    projector = DashboardProjector(tmp_path)
    process = Mock()
    factory = Mock(return_value=process)
    manager = ScanLaunchManager(tmp_path, projector, process_factory=factory, project_root=tmp_path)
    plan = SimpleNamespace(scope_id='approved', targets=('https://example.test/',), stage='recon')
    monkeypatch.setattr('aidast.web.launch.inspect_resume', lambda root, scan_id: plan)
    manager.catalog = SimpleNamespace(get=lambda scope_id: SimpleNamespace(scope_id=scope_id))
    monkeypatch.setattr('aidast.web.launch.threading.Thread.start', lambda self: None)
    result = manager.resume('scan_resume_fixture')
    assert result['status'] == 'running'
    argv = factory.call_args.args[0]
    assert argv[1:5] == ['-m', 'aidast', 'resume', 'scan_resume_fixture']
    assert '--policy-input' not in argv and '--confirm-policy' not in argv
