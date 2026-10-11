from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch
from urllib.request import __version__ as URLLIB_VERSION

import pytest

from aidast.attack.request_cli import guarded_request
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.pipeline.lifecycle import register_credential_reference
from aidast.recon import db
from test_attack_request_guard import FakeOpener, fixture


BROWSER_UA = "Mozilla/5.0 TestBrowser/151.0"
DEFAULT_UA = f"Python-urllib/{URLLIB_VERSION}"


def record_request(
    database: Path, *, headers: dict, status: int = 200,
    url: str = "https://example.test/", linked: bool = True,
    scan_id: str = "scan",
    origin_scan_id: str | None = None,
) -> None:
    with sqlite3.connect(database) as conn:
        endpoint = conn.execute(
            """SELECT e.endpoint_id FROM endpoints e
               JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=?""",
            (scan_id,),
        ).fetchone()[0] if linked else None
        transaction = db.insert_http_transaction(
            conn, endpoint_id=endpoint, source="mitmproxy", method="GET",
            url=url, request_headers=headers, response_status=status,
        )
        if origin_scan_id:
            origin = conn.execute(
                """SELECT o.origin_id FROM origins o JOIN assets a ON a.asset_id=o.asset_id
                   WHERE a.scan_id=?""", (origin_scan_id,),
            ).fetchone()[0]
            conn.execute("UPDATE http_transactions SET origin_id=? WHERE http_transaction_id=?",
                         (origin, transaction))


def send_request(paths, *, headers: dict | None = None):
    database, policy, payload, stage, task = paths
    payload.write_text(json.dumps({
        "method": "GET", "url": "https://example.test/api/profile",
        "headers": headers or {},
    }), encoding="utf-8")
    opener = FakeOpener()
    with patch("aidast.attack.request_cli.build_opener", return_value=opener):
        guarded_request(
            database, scan_id="scan", stage_run_id=stage, task_id=task,
            policy_path=policy, payload_path=payload,
        )
    return opener.calls[0][0]


def test_recon_user_agent_survives_materialization_and_reaches_unauthenticated_attack(
    tmp_path: Path,
) -> None:
    paths = fixture(tmp_path)
    source = paths[0]
    record_request(source, headers={
        "user-agent": BROWSER_UA, "sec-fetch-mode": "navigate",
        "Cookie": "recon-cookie-must-not-be-replayed",
        "Authorization": "Bearer recon-token-must-not-be-replayed",
    })
    before = source.read_bytes()
    handoff = tmp_path / "Handoff.json"
    handoff.write_text(HandoffManifest(
        scan_id="scan", db_path=source.name,
        artifacts=[hash_artifact(source, root=tmp_path, role="database")],
    ).model_dump_json(), encoding="utf-8")
    pipeline = tmp_path / "attack" / "Pipeline.db"
    materialize_pipeline(handoff, pipeline)

    request = send_request((pipeline, *paths[1:]))

    assert request.get_header("User-agent") == BROWSER_UA
    assert request.get_header("Cookie") is None
    assert request.get_header("Authorization") is None
    assert source.read_bytes() == before


def test_successful_browser_user_agent_wins_over_other_clients_and_blocked_browser(
    tmp_path: Path,
) -> None:
    paths = fixture(tmp_path)
    record_request(paths[0], headers={"User-Agent": BROWSER_UA, "Sec-Fetch-Mode": "navigate"})
    record_request(paths[0], headers={"User-Agent": "crawler/1.0"})
    record_request(paths[0], headers={
        "User-Agent": "blocked-browser/2.0", "Sec-Fetch-Mode": "navigate",
    }, status=403)

    assert send_request(paths).get_header("User-agent") == BROWSER_UA


@pytest.mark.parametrize("name", ["User-Agent", "user-agent", "USER-AGENT"])
def test_explicit_attack_user_agent_takes_precedence(tmp_path: Path, name: str) -> None:
    paths = fixture(tmp_path)
    record_request(paths[0], headers={"User-Agent": BROWSER_UA})

    request = send_request(paths, headers={name: "intentional-probe/2.0"})

    assert request.get_header("User-agent") == "intentional-probe/2.0"


@pytest.mark.parametrize("url", [
    "https://other.example.test/", "http://example.test/", "https://example.test:444/",
])
def test_recon_user_agent_is_not_inherited_across_origins(tmp_path: Path, url: str) -> None:
    paths = fixture(tmp_path)
    record_request(paths[0], headers={"User-Agent": BROWSER_UA}, url=url)

    assert send_request(paths).get_header("User-agent") == DEFAULT_UA


def test_unlinked_browser_transaction_in_single_scan_can_supply_user_agent(tmp_path: Path) -> None:
    paths = fixture(tmp_path)
    record_request(paths[0], headers={"User-Agent": BROWSER_UA}, linked=False)

    assert send_request(paths).get_header("User-agent") == BROWSER_UA


def test_other_scan_and_unlinked_shared_database_transactions_are_not_inherited(
    tmp_path: Path,
) -> None:
    paths = fixture(tmp_path)
    with sqlite3.connect(paths[0]) as conn:
        db.insert_scan(conn, scan_id="other_scan", scope_type="approved", scope_value="scope")
        asset = db.insert_asset(conn, scan_id="other_scan", identifier="example.test", asset_type="DOMAIN")
        origin = db.upsert_origin(
            conn, asset_id=asset, scheme="https", host="example.test", port=443,
            base_url="https://example.test/",
        )
        db.upsert_endpoint(conn, origin_id=origin, method="GET", path="/",
                           normalized_path="/", source_tool="fixture")
    record_request(paths[0], headers={"User-Agent": BROWSER_UA}, scan_id="other_scan")
    record_request(paths[0], headers={"User-Agent": "unattributed/1.0"}, linked=False)

    assert send_request(paths).get_header("User-agent") == DEFAULT_UA


def test_origin_linked_passive_browser_transaction_survives_shared_database(tmp_path: Path) -> None:
    paths = fixture(tmp_path)
    with sqlite3.connect(paths[0]) as conn:
        db.insert_scan(conn, scan_id="other_scan", scope_type="approved", scope_value="scope")
    record_request(paths[0], headers={"User-Agent": BROWSER_UA}, linked=False,
                   origin_scan_id="scan")

    assert send_request(paths).get_header("User-agent") == BROWSER_UA


def test_origin_and_endpoint_scan_attribution_cannot_conflict(tmp_path: Path) -> None:
    paths = fixture(tmp_path)
    with sqlite3.connect(paths[0]) as conn:
        db.insert_scan(conn, scan_id="other_scan", scope_type="approved", scope_value="scope")
        asset = db.insert_asset(conn, scan_id="other_scan", identifier="example.test", asset_type="DOMAIN")
        db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.test", port=443,
                         base_url="https://example.test/")
    record_request(paths[0], headers={"User-Agent": BROWSER_UA}, origin_scan_id="other_scan")

    assert send_request(paths).get_header("User-agent") == DEFAULT_UA


@pytest.mark.parametrize("value", ["", "[REDACTED]", "browser\r\nX-Injected: yes", 123])
def test_unusable_recorded_user_agent_does_not_break_attack(tmp_path: Path, value) -> None:
    paths = fixture(tmp_path)
    record_request(paths[0], headers={"User-Agent": value})

    request = send_request(paths)
    assert request.get_header("User-agent") == DEFAULT_UA
    assert request.get_header("X-injected") is None


def test_missing_recon_user_agent_keeps_existing_request_behavior(tmp_path: Path) -> None:
    assert send_request(fixture(tmp_path)).get_header("User-agent") == DEFAULT_UA


def test_authenticated_attack_inherits_user_agent_without_replacing_resolved_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = fixture(tmp_path)
    database, policy, payload, stage, task = paths
    record_request(database, headers={"User-Agent": BROWSER_UA, "Cookie": "other-recon-session"})
    with sqlite3.connect(database) as conn:
        reference = register_credential_reference(
            conn, scan_id="scan", label="authenticated-user",
            reference_uri="env://AIDAST_UA_TEST_HEADERS", identity_role="authenticated",
        )
        conn.execute("UPDATE attack_tasks SET payload_json=? WHERE task_id=?", (
            json.dumps({"credential_references": [{"credential_reference_id": reference}]}), task,
        ))
    monkeypatch.setenv("AIDAST_UA_TEST_HEADERS", json.dumps({"Cookie": "session=resolved-credential"}))
    payload.write_text(json.dumps({
        "method": "GET", "url": "https://example.test/api/profile",
        "credential_reference_id": reference,
    }), encoding="utf-8")
    opener = FakeOpener()
    with patch("aidast.attack.request_cli.build_opener", return_value=opener):
        result = guarded_request(database, scan_id="scan", stage_run_id=stage, task_id=task,
                                 policy_path=policy, payload_path=payload)

    request = opener.calls[0][0]
    assert request.get_header("User-agent") == BROWSER_UA
    assert request.get_header("Cookie") == "session=resolved-credential"
    assert "session=resolved-credential" not in json.dumps(result)
