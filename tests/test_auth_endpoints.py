from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from aidast.auth.endpoints import (
    AuthenticationEndpoint,
    AuthenticationEndpointError,
    parse_authentication_endpoints,
    serialize_authentication_endpoints,
)
from aidast.auth.browser import collect_target_sessions, load_session
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
