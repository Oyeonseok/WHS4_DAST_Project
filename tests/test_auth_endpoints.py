from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from aidast.auth.endpoints import (
    AuthenticationEndpoint,
    AuthenticationEndpointError,
    parse_authentication_endpoints,
    serialize_authentication_endpoints,
)
from aidast.auth.browser import _capture_native, collect_target_sessions, load_session
from aidast.recon import db as recon_db
from aidast.recon.executor import ReconExecutor
from aidast.scope.models import AssetType, ScopeAsset


def test_request_metadata_discards_secrets_and_deduplicates() -> None:
    first = AuthenticationEndpoint.from_request(
        "post",
        "https://example.test/rest/user/login?token=secret#fragment",
        target_origin="https://example.test",
        observed_at="2026-09-17T01:02:03Z",
    )
    second = AuthenticationEndpoint.from_request(
        "POST",
        "https://example.test/rest/user/login?password=other",
        target_origin="https://example.test",
    )

    assert first is not None
    assert second is not None
    parsed = parse_authentication_endpoints(
        [first.to_bundle_dict(), second.to_bundle_dict()],
        target_origin="https://example.test",
    )

    assert [(item.method, item.origin, item.path) for item in parsed] == [
        ("POST", "https://example.test", "/rest/user/login")
    ]
    serialized = json.dumps(serialize_authentication_endpoints(parsed))
    assert "secret" not in serialized
    assert "password" not in serialized


def test_request_metadata_ignores_unapproved_origin() -> None:
    assert AuthenticationEndpoint.from_request(
        "POST",
        "https://identity.example/login",
        target_origin="https://example.test",
    ) is None

    endpoint = AuthenticationEndpoint.from_request(
        "POST",
        "https://identity.example/login",
        target_origin="https://example.test",
        allowed_bootstrap_origins=frozenset({"https://identity.example"}),
    )
    assert endpoint is not None
    assert endpoint.origin == "https://identity.example"


@pytest.mark.parametrize(
    "raw",
    [
        [{"method": "POST", "origin": "https://example.test", "path": "/login?x=1", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://user@example.test", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "file://example.test", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://evil.test", "path": "/login", "source": "auth_bootstrap"}],
        [{"method": "POST", "origin": "https://example.test", "path": "/login", "source": "auth_bootstrap", "body": "secret"}],
    ],
)
def test_bundle_parser_rejects_unsafe_or_unknown_fields(raw: object) -> None:
    with pytest.raises(AuthenticationEndpointError):
        parse_authentication_endpoints(raw, target_origin="https://example.test")


def test_empty_bundle_metadata_is_valid() -> None:
    assert parse_authentication_endpoints(
        [], target_origin="https://example.test"
    ) == ()


def _target() -> ScopeAsset:
    return ScopeAsset(
        asset_type=AssetType.URL,
        asset="https://example.test",
        description="test target",
        eligibility="eligible",
        maximum_severity="high",
    )


def _storage_state() -> dict:
    return {
        "cookies": [{"name": "session", "value": "private", "domain": "example.test"}],
        "origins": [{"origin": "https://example.test", "localStorage": []}],
        "session_storage": {"https://example.test": {}},
    }


def _write_bundle(root: Path, *, endpoints: object = None, include_field: bool = True) -> Path:
    state = root / "storage.json"
    storage = root / "storage.json.sessionstorage.json"
    state.write_text(json.dumps({"cookies": [], "origins": []}))
    storage.write_text("{}")
    document = {
        "schema_version": "1.0",
        "scope_id": "scope",
        "run_id": "run",
        "asset_type": "URL",
        "asset": "https://example.test",
        "start_url": "https://example.test",
        "identity": "primary",
        "authentication": "operator_confirmed",
        "sha256": {
            state.name: hashlib.sha256(state.read_bytes()).hexdigest(),
            storage.name: hashlib.sha256(storage.read_bytes()).hexdigest(),
        },
    }
    if include_field:
        document["authentication_endpoints"] = endpoints if endpoints is not None else []
    bundle = root / "Session.json"
    bundle.write_text(json.dumps(document))
    return bundle


def test_collect_session_persists_sanitized_authentication_endpoints(tmp_path: Path) -> None:
    raw = _storage_state()
    raw["authentication_endpoints"] = [{
        "method": "POST",
        "url": "https://example.test/rest/user/login?token=secret",
        "observed_at": "2026-09-17T01:02:03Z",
    }]
    sessions = collect_target_sessions(
        [_target()],
        scope_id="scope",
        run_id="run",
        identity="primary",
        start_urls={("URL", "https://example.test"): "https://example.test"},
        root=tmp_path,
        capture=lambda *_: raw,
    )

    session = sessions[("URL", "https://example.test")]
    assert session.has_authentication_endpoint_provenance is True
    assert session.authentication_endpoints[0].path == "/rest/user/login"
    bundle_text = session.bundle_path.read_text()
    assert "secret" not in bundle_text
    assert "?" not in json.loads(bundle_text)["authentication_endpoints"][0]["path"]


def test_legacy_bundle_loads_without_endpoint_provenance(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, include_field=False)

    session = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )

    assert session.has_authentication_endpoint_provenance is False
    assert session.authentication_endpoints == ()


def test_empty_endpoint_array_has_known_provenance(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, endpoints=[])
    session = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )
    assert session.has_authentication_endpoint_provenance is True
    assert session.authentication_endpoints == ()


def test_reauthentication_replaces_bundle_endpoint_set(tmp_path: Path) -> None:
    bundle = _write_bundle(tmp_path, endpoints=[{
        "method": "POST", "origin": "https://example.test",
        "path": "/old-login", "source": "auth_bootstrap",
    }])
    session = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )

    session.replace_authentication_endpoints([
        AuthenticationEndpoint("POST", "https://example.test", "/rest/user/login")
    ])
    reloaded = load_session(
        bundle,
        scope_id="scope",
        asset_type="URL",
        asset="https://example.test",
        identity="primary",
    )

    assert [item.path for item in reloaded.authentication_endpoints] == [
        "/rest/user/login"
    ]


def test_native_capture_observes_and_sanitizes_login_request_before_confirmation(
    tmp_path: Path,
) -> None:
    callback = None
    context = MagicMock()
    context.storage_state.return_value = {
        "cookies": [],
        "origins": [{"origin": "https://example.test", "localStorage": []}],
    }
    page = MagicMock(url="https://example.test/dashboard")
    page.evaluate.return_value = {}
    context.pages = [page]

    def register(_event: str, handler) -> None:
        nonlocal callback
        callback = handler

    context.on.side_effect = register
    browser = MagicMock(contexts=[context])
    playwright = MagicMock()
    playwright.chromium.connect_over_cdp.return_value = browser
    manager = MagicMock()
    manager.__enter__.return_value = playwright
    listener = MagicMock()
    listener.__enter__.return_value = listener
    listener.getsockname.return_value = ("127.0.0.1", 43123)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    process = MagicMock()
    process.poll.return_value = None

    def confirm(_prompt: str) -> str:
        assert callback is not None
        callback(SimpleNamespace(
            method="POST",
            url="https://example.test/rest/user/login?password=private#ignored",
        ))
        return ""

    with (
        patch("aidast.auth.browser.shutil.which", return_value="/test/chrome"),
        patch("aidast.auth.browser.socket.socket", return_value=listener),
        patch("aidast.auth.browser.socket.create_connection", return_value=connection),
        patch("aidast.auth.browser.subprocess.Popen", return_value=process),
        patch("playwright.sync_api.sync_playwright", return_value=manager),
        patch("builtins.input", side_effect=confirm),
    ):
        raw = _capture_native(
            "https://example.test", tmp_path / "login-export.json"
        )

    assert raw["authentication_endpoints"] == [{
        "method": "POST",
        "origin": "https://example.test",
        "path": "/rest/user/login",
        "source": "auth_bootstrap",
    }]
    assert "private" not in json.dumps(raw["authentication_endpoints"])


def _executor_with_origin(tmp_path: Path) -> tuple[ReconExecutor, str]:
    executor = ReconExecutor(
        scan_id="scan",
        scope_type="test",
        scope_value="scope",
        db_path=tmp_path / "Recon.db",
        diagnostic_path=tmp_path / "recon.jsonl",
    )
    asset_id = recon_db.insert_asset(
        executor.conn,
        scan_id="scan",
        identifier="https://example.test",
        asset_type="URL",
    )
    origin_id = recon_db.upsert_origin(
        executor.conn,
        asset_id=asset_id,
        scheme="https",
        host="example.test",
        port=443,
        base_url="https://example.test",
    )
    return executor, origin_id


def test_recon_imports_restored_login_endpoint_as_passive_evidence(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "session"
    bundle_root.mkdir()
    bundle = _write_bundle(bundle_root, endpoints=[{
        "method": "POST",
        "origin": "https://example.test",
        "path": "/rest/user/login",
        "source": "auth_bootstrap",
    }])
    session = load_session(
        bundle, scope_id="scope", asset_type="URL",
        asset="https://example.test", identity="primary",
    )
    executor, origin_id = _executor_with_origin(tmp_path)
    task = SimpleNamespace(
        task_id="origin-task",
        target=SimpleNamespace(asset="https://example.test"),
    )
    try:
        imported = executor._import_authentication_endpoints(task, origin_id, session)
        endpoint = executor.conn.execute(
            "SELECT method,normalized_path,source_tools FROM endpoints"
        ).fetchone()
        observation = executor.conn.execute(
            "SELECT discovery_kind,source_tool FROM endpoint_observations"
        ).fetchone()
    finally:
        executor.close()

    assert imported == 1
    assert endpoint == ("POST", "/rest/user/login", "auth_bootstrap")
    assert observation == ("passive_login_observation", "auth_bootstrap")


def test_recon_reports_legacy_bundle_without_inventing_endpoint(tmp_path: Path) -> None:
    bundle_root = tmp_path / "session"
    bundle_root.mkdir()
    bundle = _write_bundle(bundle_root, include_field=False)
    session = load_session(
        bundle, scope_id="scope", asset_type="URL",
        asset="https://example.test", identity="primary",
    )
    executor, origin_id = _executor_with_origin(tmp_path)
    task = SimpleNamespace(
        task_id="origin-task",
        target=SimpleNamespace(asset="https://example.test"),
    )
    try:
        imported = executor._import_authentication_endpoints(task, origin_id, session)
        endpoint_count = executor.conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
    finally:
        executor.close()

    events = [json.loads(line) for line in (tmp_path / "recon.jsonl").read_text().splitlines()]
    assert imported == 0
    assert endpoint_count == 0
    assert any(event["event"] == "auth_endpoint_provenance_missing" for event in events)
