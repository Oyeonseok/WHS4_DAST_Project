from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aidast.pipeline.browser_credentials import register_browser_session_credentials
from aidast.attack.coverage import _credential_references
from aidast.recon import db
from aidast.validation.execution.credentials import PipelineCredentialResolver


def _database(root: Path) -> Path:
    path = root / "Recon.db"
    conn = db.init_db(path)
    db.insert_scan(conn, scan_id="scan_auth", scope_type="approved", scope_value="scope")
    asset = db.insert_asset(conn, scan_id="scan_auth", identifier="https://example.test/", asset_type="URL")
    db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.test", port=443,
                     base_url="https://example.test/")
    conn.close()
    return path


def test_authenticated_browser_snapshot_becomes_resolvable_opaque_reference(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    token = "header.payload.signature"
    source.write_text(json.dumps({"cookies": [], "origins": [{
        "origin": "https://example.test", "localStorage": [
            {"name": "token", "value": token},
        ],
    }]}), encoding="utf-8")
    result_root = tmp_path / "result"
    with sqlite3.connect(database) as conn:
        refs = register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=result_root,
            sessions=[("https://example.test/", source, True)],
        )
        assert len(refs) == 1
        assert conn.execute("SELECT auth_state FROM sessions").fetchone()[0] == "authenticated"
        assert token not in " ".join(str(row) for row in conn.execute(
            "SELECT * FROM credential_references"
        ))
    assert PipelineCredentialResolver(database).unsupported_reason(
        refs[0]["credential_reference_id"]
    ) == "credential_reference_unavailable"
    resolver = PipelineCredentialResolver(
        database, result_root=result_root, browser_sessions=True,
    )
    with pytest.raises(ValueError):
        resolver(refs[0]["credential_reference_id"])
    with pytest.raises(ValueError):
        resolver(refs[0]["credential_reference_id"], destination_url="https://other.example.test/")
    assert resolver(refs[0]["credential_reference_id"], destination_url="https://example.test/profile") == {
        "Authorization": f"Bearer {token}",
    }


def test_unauthenticated_browser_snapshot_does_not_create_reference(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [
        {"name": "language", "value": "en", "domain": "example.test"},
    ], "origins": []}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        assert register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, False)],
        ) == []
        assert conn.execute("SELECT COUNT(*) FROM credential_references").fetchone()[0] == 0


def test_multiple_assets_on_one_origin_share_one_credential_reference(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [], "origins": [{
        "origin": "https://example.test", "localStorage": [
            {"name": "token", "value": "header.payload.signature"},
        ],
    }]}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        asset = db.insert_asset(conn, scan_id="scan_auth", identifier="https://example.test/app", asset_type="URL")
        db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.test", port=443,
                         base_url="https://example.test/app")
        refs = register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True),
                      ("https://example.test/app", source, True)],
        )
        assert len(refs) == 1
        assert conn.execute("SELECT COUNT(*) FROM credential_references").fetchone()[0] == 1


def test_unconfirmed_cookie_does_not_become_authenticated_reference(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [
        {"name": "analytics_id", "value": "visitor", "domain": "example.test"},
    ], "origins": []}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        assert register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True)],
        ) == []
        assert conn.execute("SELECT COUNT(*) FROM credential_references").fetchone()[0] == 0


def test_session_named_cookie_needs_confirmed_login(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [
        {"name": "sessionid", "value": "public-visitor", "domain": "example.test"},
    ], "origins": []}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        assert register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True)],
        ) == []
        assert conn.execute("SELECT COUNT(*) FROM credential_references").fetchone()[0] == 0


def test_confirmed_cookie_session_can_be_handed_to_attack(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [
        {"name": "sessionid", "value": "approved-session", "domain": "example.test"},
    ], "origins": []}), encoding="utf-8")
    Path(str(source) + ".authenticated").write_text("authenticated\n", encoding="utf-8")
    with sqlite3.connect(database) as conn:
        refs = register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True)],
        )
        assert len(refs) == 1


def test_duplicate_asset_origins_do_not_abort_browser_handoff(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [], "origins": [{
        "origin": "https://example.test", "localStorage": [
            {"name": "token", "value": "header.payload.signature"},
        ],
    }]}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        asset = db.insert_asset(conn, scan_id="scan_auth", identifier="example.test", asset_type="DOMAIN")
        db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.test", port=443,
                         base_url="https://example.test/")
        assert conn.execute("SELECT count(*) FROM origins").fetchone()[0] == 2
        refs = register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True),
                      ("https://example.test/", source, True)],
        )
        assert len(refs) == 1
    assert PipelineCredentialResolver(database, result_root=tmp_path / "result", browser_sessions=True)(
        refs[0]["credential_reference_id"], destination_url="https://example.test/"
    )["Authorization"] == "Bearer header.payload.signature"


def test_available_browser_reference_is_scoped_to_coverage_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = _database(tmp_path)
    monkeypatch.setattr("aidast.validation.execution.credentials.RESULT_ROOT", tmp_path / "result")
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [], "origins": [{
        "origin": "https://example.test", "localStorage": [
            {"name": "token", "value": "header.payload.signature"},
        ],
    }]}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        refs = register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True)],
        )
        assert len(refs) == 1
        assert _credential_references(
            conn, "scan_auth", "authenticated", available_only=True,
            origin_url="https://example.test/profile",
        ) == refs
        assert _credential_references(
            conn, "scan_auth", "authenticated", available_only=True,
            origin_url="https://other.example.test/profile",
        ) == []


def test_repeated_handoff_keeps_same_origin_reference_resolvable(tmp_path: Path) -> None:
    database = _database(tmp_path)
    source = tmp_path / "browser.json"
    source.write_text(json.dumps({"cookies": [], "origins": [{
        "origin": "https://example.test", "localStorage": [
            {"name": "token", "value": "header.payload.signature"},
        ],
    }]}), encoding="utf-8")
    with sqlite3.connect(database) as conn:
        first = register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True)],
        )
        register_browser_session_credentials(
            conn, scan_id="scan_auth", result_root=tmp_path / "result",
            sessions=[("https://example.test/", source, True)],
        )
    resolver = PipelineCredentialResolver(
        database, result_root=tmp_path / "result", browser_sessions=True,
    )
    assert resolver(first[0]["credential_reference_id"], destination_url="https://example.test/") == {
        "Authorization": "Bearer header.payload.signature",
    }
