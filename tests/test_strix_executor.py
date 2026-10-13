from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from aidast.recon.strix_bridge import build_strix_proxy_rules
from aidast.recon.strix_executor import StrixReconExecutor, strix_model_name
from aidast.scope.models import AssetType, ScopeAsset, ScopeDocument
from test_scope_workflow import sample_analysis, sample_page


def _scope(target: ScopeAsset) -> ScopeDocument:
    analysis = sample_analysis().model_copy(update={"in_scope_assets": [target]})
    return ScopeDocument(
        scope_id="scope_strix_test",
        created_at=datetime.now(timezone.utc),
        source=sample_page(),
        analysis=analysis,
    )


def test_strix_model_name_routes_dashboard_codex_models() -> None:
    assert strix_model_name("gpt-6.1-sol") == "chatgpt/gpt-6.1-sol"
    assert strix_model_name("openrouter/example/model") == "openrouter/example/model"


def test_strix_capture_is_canonicalized_and_persisted_for_attack(tmp_path: Path) -> None:
    target = ScopeAsset(
        asset_type=AssetType.URL,
        asset="http://127.0.0.1:5001/",
        description="local authorized target",
        eligibility="test",
        maximum_severity="Critical",
    )
    scope = _scope(target)
    capture_dir = tmp_path / "capture"

    async def fake_run(*_args, **kwargs):
        capture_dir.mkdir(parents=True, exist_ok=True)
        capture = capture_dir / "mitm_capture.jsonl"
        capture.write_text(json.dumps({
            "source": "mitmproxy",
            "method": "GET",
            "url": "http://host.docker.internal:5001/rest/products?id=1",
            "request_headers": {},
            "request_body": None,
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"data":[]}',
            "content_type": "application/json",
            "capture_bodies": True,
            "policy_blocked": False,
        }) + "\n", encoding="utf-8")
        rules = build_strix_proxy_rules(
            scope,
            [target],
            execution_limits={"max_requests": 25, "budget_total": 25},
        )
        assert kwargs["model"] == "chatgpt/gpt-6.1-sol"
        assert kwargs["execution_limits"]["max_requests"] == 3000
        return object(), capture, rules

    executor = StrixReconExecutor(
        scan_id="scan_strix_test",
        scope_document=scope,
        targets=[target],
        db_path=tmp_path / "Recon.db",
        capture_directory=capture_dir,
        recon_model="gpt-6.1-sol",
    )
    try:
        with patch("aidast.recon.strix_executor.run_strix_recon", side_effect=fake_run):
            assert executor.run([]) == 0
        endpoint = executor.conn.execute(
            """SELECT o.host,o.port,e.method,e.normalized_path,e.verification_status
               FROM endpoints e JOIN origins o USING(origin_id)"""
        ).fetchone()
        assert endpoint == ("127.0.0.1", 5001, "GET", "/rest/products", "verified")
        transaction = executor.conn.execute(
            "SELECT url,response_status FROM http_transactions WHERE origin_id IS NOT NULL"
        ).fetchone()
        assert transaction == ("http://127.0.0.1:5001/rest/products?id=1", 200)
    finally:
        executor.close()


def test_strix_capture_reconciles_value_free_form_declarations(tmp_path: Path) -> None:
    target = ScopeAsset(
        asset_type=AssetType.URL,
        asset="https://example.test/",
        description="authorized form target",
        eligibility="test",
        maximum_severity="Critical",
    )
    scope = _scope(target)
    capture_dir = tmp_path / "capture"

    async def fake_run(*_args, **_kwargs):
        capture_dir.mkdir(parents=True, exist_ok=True)
        capture = capture_dir / "mitm_capture.jsonl"
        capture.write_text(json.dumps({
            "source": "mitmproxy",
            "method": "GET",
            "url": "https://example.test/",
            "request_headers": {},
            "request_body": None,
            "response_status": 200,
            "response_headers": {"Content-Type": "text/html"},
            "response_body": (
                '<form action="/session" method="post">'
                '<input name="username" value="private-user">'
                '<input name="password" type="password" value="private-password">'
                '</form>'
            ),
            "content_type": "text/html",
            "capture_bodies": True,
            "policy_blocked": False,
        }) + "\n", encoding="utf-8")
        return object(), capture, build_strix_proxy_rules(
            scope, [target],
            execution_limits={"max_requests": 25, "budget_total": 25},
        )

    executor = StrixReconExecutor(
        scan_id="scan_strix_form",
        scope_document=scope,
        targets=[target],
        db_path=tmp_path / "Recon.db",
        capture_directory=capture_dir,
    )
    try:
        with patch("aidast.recon.strix_executor.run_strix_recon", side_effect=fake_run):
            assert executor.run([]) == 0
        endpoint = executor.conn.execute(
            """SELECT endpoint_id,method,normalized_path,is_excluded,exclude_reason
               FROM endpoints WHERE normalized_path='/session'"""
        ).fetchone()
        assert endpoint[1:] == (
            "POST", "/session", 1, "unverified_candidate",
        )
        assert executor.conn.execute(
            "SELECT name,location FROM parameters WHERE endpoint_id=? ORDER BY name",
            (endpoint[0],),
        ).fetchall() == [("password", "form"), ("username", "form")]
        observation = executor.conn.execute(
            """SELECT discovery_kind,evidence_json FROM endpoint_observations
               WHERE endpoint_id=?""", (endpoint[0],),
        ).fetchone()
        assert observation[0] == "form_action"
        assert "private-user" not in (observation[1] or "")
        assert "private-password" not in (observation[1] or "")
    finally:
        executor.close()


def test_integrated_executor_falls_back_when_strix_runtime_is_blocked(
    tmp_path: Path, capsys,
) -> None:
    target = ScopeAsset(
        asset_type=AssetType.DOMAIN,
        asset="example.com",
        description="authorized target",
        eligibility="test",
        maximum_severity="Critical",
    )
    fallback = MagicMock()
    fallback.auth_session_files = []
    fallback.run.return_value = 0
    executor = StrixReconExecutor(
        scan_id="scan_strix_fallback",
        scope_document=_scope(target),
        targets=[target],
        db_path=tmp_path / "Recon.db",
        capture_directory=tmp_path / "capture",
        fallback_factory=lambda: fallback,
    )
    with patch(
        "aidast.recon.strix_executor.run_strix_recon",
        side_effect=RuntimeError("docker unavailable"),
    ):
        assert executor.run([]) == 0
    fallback.run.assert_called_once_with([])
    assert "RuntimeError: docker unavailable" in capsys.readouterr().out
    executor.close()
    fallback.close.assert_called_once()


def test_integrated_executor_preserves_partial_capture_before_fallback(
    tmp_path: Path, capsys,
) -> None:
    target = ScopeAsset(
        asset_type=AssetType.URL,
        asset="https://example.com/",
        description="authorized target",
        eligibility="test",
        maximum_severity="Critical",
    )
    scope = _scope(target)
    capture_dir = tmp_path / "capture"
    fallback = MagicMock()
    fallback.auth_session_files = []
    fallback.run.return_value = 0

    async def interrupted_run(*_args, **_kwargs):
        capture_dir.mkdir(parents=True, exist_ok=True)
        (capture_dir / "mitm_capture.jsonl").write_text(json.dumps({
            "source": "mitmproxy",
            "method": "GET",
            "url": "https://example.com/api/status",
            "request_headers": {},
            "request_body": None,
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": '{"ok":true}',
            "content_type": "application/json",
            "capture_bodies": True,
            "policy_blocked": False,
        }) + "\n", encoding="utf-8")
        raise RuntimeError("provider stream interrupted")

    executor = StrixReconExecutor(
        scan_id="scan_partial_strix",
        scope_document=scope,
        targets=[target],
        db_path=tmp_path / "Recon.db",
        capture_directory=capture_dir,
        fallback_factory=lambda: fallback,
    )
    try:
        with patch(
            "aidast.recon.strix_executor.run_strix_recon",
            side_effect=interrupted_run,
        ):
            assert executor.run([]) == 0
        assert executor.conn.execute(
            "SELECT normalized_path FROM endpoints"
        ).fetchone() == ("/api/status",)
        fallback.run.assert_called_once_with([])
        assert "중단 전 Strix 정찰 결과를 보존했습니다" in capsys.readouterr().out
    finally:
        executor.close()


def test_strix_request_ledger_is_merged_into_shared_host_budget(tmp_path: Path) -> None:
    target = ScopeAsset(
        asset_type=AssetType.DOMAIN,
        asset="example.com",
        description="authorized target",
        eligibility="test",
        maximum_severity="Critical",
    )
    capture_dir = tmp_path / "capture"
    capture_dir.mkdir()
    capture = capture_dir / "mitm_capture.jsonl"
    capture.write_text('{"policy_blocked":false}\n', encoding="utf-8")
    local_ledger = capture_dir / "request_governor.db"
    configuration = json.dumps({
        "scan_id": "scan_ledger",
        "program_id": "program",
        "scan_max_requests": 10,
        "scan_max_seconds": None,
        "requests_per_second": 1.0,
        "concurrency": 1,
        "request_limits": [],
    }, sort_keys=True)
    with sqlite3.connect(local_ledger) as connection:
        connection.executescript("""
            CREATE TABLE governor_scans (
                program TEXT, scan TEXT, started REAL NOT NULL, configuration TEXT NOT NULL,
                last_dispatch REAL, PRIMARY KEY(program,scan));
            CREATE TABLE governor_requests (
                id TEXT PRIMARY KEY, program TEXT NOT NULL, scan TEXT NOT NULL,
                origin TEXT NOT NULL, units INTEGER NOT NULL, capacity INTEGER NOT NULL,
                charged REAL NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL);
        """)
        connection.execute(
            "INSERT INTO governor_scans VALUES (?,?,?,?,?)",
            ("program", "scan_ledger", 1.0, configuration, 2.0),
        )
        connection.execute(
            "INSERT INTO governor_requests VALUES (?,?,?,?,?,?,?,?,?)",
            ("request", "program", "scan_ledger", '[\"https\",\"example.com\",443]',
             1, 1, 2.0, 32.0, "completed"),
        )
    host_ledger = tmp_path / "shared" / "budget.db"
    executor = StrixReconExecutor(
        scan_id="scan_ledger",
        scope_document=_scope(target),
        targets=[target],
        db_path=tmp_path / "Recon.db",
        capture_directory=capture_dir,
    )
    executor._host_governor_binding = {"ledger_path": str(host_ledger)}
    try:
        executor._merge_request_governor_ledger(capture)
        with sqlite3.connect(host_ledger) as connection:
            assert connection.execute(
                "SELECT units,state FROM governor_requests WHERE id='request'"
            ).fetchone() == (1, "completed")
    finally:
        executor.close()
