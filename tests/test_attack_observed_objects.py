"""Black-box browser paths provide bounded Attack object prerequisites."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from aidast.attack.observed_objects import seed_observed_object_facts


def _database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE assets (asset_id TEXT, scan_id TEXT);
        CREATE TABLE origins (origin_id TEXT, asset_id TEXT);
        CREATE TABLE endpoints (
            endpoint_id TEXT, origin_id TEXT, method TEXT,
            normalized_path TEXT
        );
        CREATE TABLE sessions (
            session_id TEXT, auth_state TEXT
        );
        CREATE TABLE discovery_contexts (
            context_id TEXT, session_id TEXT
        );
        CREATE TABLE endpoint_observations (
            endpoint_id TEXT, context_id TEXT, observed_url TEXT,
            source_tool TEXT
        );
        CREATE TABLE credential_references (
            scan_id TEXT, session_id TEXT, label TEXT
        );
        CREATE TABLE http_transactions (
            endpoint_id TEXT, url TEXT, response_status INTEGER,
            response_body BLOB
        );
        CREATE TABLE attack_facts (
            fact_id TEXT PRIMARY KEY, scan_id TEXT, fact_type TEXT,
            fact_key TEXT, fact_value TEXT, confidence REAL,
            source_endpoint_id TEXT,
            UNIQUE(scan_id,fact_type,fact_key)
        );
        INSERT INTO assets VALUES ('asset','scan');
        INSERT INTO origins VALUES ('origin','asset');
        INSERT INTO sessions VALUES ('session','authenticated');
        INSERT INTO discovery_contexts VALUES ('context','session');
        INSERT INTO credential_references VALUES ('scan','session','opaque-browser-session');
    """)
    return conn


def test_authenticated_browser_path_becomes_owned_numeric_fixture() -> None:
    with closing(_database()) as conn:
        conn.execute("INSERT INTO endpoints VALUES ('basket','origin','GET','/rest/basket/:id')")
        conn.execute("""INSERT INTO endpoint_observations VALUES
            ('basket','context','https://target.test/rest/basket/6',
             'playwright_interaction')""")

        assert seed_observed_object_facts(conn, "scan") == 1
        row = conn.execute(
            "SELECT fact_type,fact_key,fact_value FROM attack_facts"
        ).fetchone()

    assert row["fact_type"] == "owned_test_object"
    assert row["fact_key"] == "observed.basket.id"
    assert json.loads(row["fact_value"]) == {
        "credential_label": "opaque-browser-session",
        "evidence": "authenticated_browser_path",
        "parameter_name": "id",
        "resource": "basket",
        "value": "6",
    }


def test_public_success_is_reference_not_owned_fixture() -> None:
    with closing(_database()) as conn:
        conn.execute("INSERT INTO endpoints VALUES ('product','origin','GET','/api/Products/:id')")
        conn.execute("""INSERT INTO http_transactions VALUES
            ('product','https://target.test/api/Products/1',200,NULL)""")

        assert seed_observed_object_facts(conn, "scan") == 1
        row = conn.execute(
            "SELECT fact_type,fact_value FROM attack_facts"
        ).fetchone()

    assert row["fact_type"] == "observed_reference_object"
    assert json.loads(row["fact_value"])["value"] == "1"
    assert "credential" not in row["fact_value"]


def test_catalog_visit_does_not_claim_ownership_and_secret_slots_are_ignored() -> None:
    with closing(_database()) as conn:
        conn.executemany("INSERT INTO endpoints VALUES (?,?,?,?)", [
            ("product", "origin", "GET", "/api/Products/:id"),
            ("account", "origin", "GET", "/account/{token}"),
        ])
        conn.executemany("INSERT INTO endpoint_observations VALUES (?,?,?,?)", [
            ("product", "context", "https://target.test/api/Products/1", "playwright_interaction"),
            ("account", "context", "https://target.test/account/private-token", "playwright_interaction"),
        ])

        assert seed_observed_object_facts(conn, "scan") == 0
        assert conn.execute("SELECT count(*) FROM attack_facts").fetchone()[0] == 0


def test_authenticated_numeric_record_visit_does_not_claim_object_ownership() -> None:
    with closing(_database()) as conn:
        conn.execute("INSERT INTO endpoints VALUES ('address','origin','GET','/api/Addresss/:id')")
        conn.execute("""INSERT INTO endpoint_observations VALUES
            ('address','context','https://target.test/api/Addresss/7',
             'playwright_interaction')""")

        assert seed_observed_object_facts(conn, "scan") == 0
        assert conn.execute("SELECT count(*) FROM attack_facts").fetchone()[0] == 0


def test_collection_exposes_only_numeric_reference_identifiers() -> None:
    with closing(_database()) as conn:
        conn.execute("INSERT INTO endpoints VALUES ('items','origin','GET','/api/BasketItems')")
        conn.execute("INSERT INTO http_transactions VALUES (?,?,?,?)", (
            "items", "https://target.test/api/BasketItems", 200,
            json.dumps({"data": [{
                "id": 9, "BasketId": 6, "ProductId": 1,
                "email": "private@example.test", "token": "private-token",
            }]}),
        ))

        assert seed_observed_object_facts(conn, "scan") == 3
        payload = "\n".join(
            row[0] for row in conn.execute(
                "SELECT fact_value FROM attack_facts ORDER BY fact_key"
            )
        )

    assert '"value": "1"' in payload
    assert '"value": "6"' in payload
    assert '"value": "9"' in payload
    assert "private" not in payload


def test_collection_record_bound_to_owned_parent_becomes_owned_child() -> None:
    with closing(_database()) as conn:
        conn.executemany("INSERT INTO endpoints VALUES (?,?,?,?)", [
            ("basket", "origin", "GET", "/rest/basket/:id"),
            ("items", "origin", "GET", "/api/BasketItems"),
        ])
        conn.execute("""INSERT INTO endpoint_observations VALUES
            ('basket','context','https://target.test/rest/basket/6',
             'playwright_interaction')""")
        conn.execute("INSERT INTO http_transactions VALUES (?,?,?,?)", (
            "items", "https://target.test/api/BasketItems", 200,
            json.dumps({"data": [{"id": 9, "BasketId": 6, "ProductId": 1}]}),
        ))

        seed_observed_object_facts(conn, "scan")
        row = conn.execute(
            """SELECT fact_value FROM attack_facts
               WHERE fact_type='owned_test_object'
                 AND fact_key='observed.basketitems.id.9'"""
        ).fetchone()

    value = json.loads(row[0])
    assert value["value"] == "9"
    assert value["identifiers"] == {"BasketId": "6", "ProductId": "1", "id": "9"}
    assert value["credential_label"] == "opaque-browser-session"


def test_fact_seeding_is_idempotent() -> None:
    with closing(_database()) as conn:
        conn.execute("INSERT INTO endpoints VALUES ('basket','origin','GET','/rest/basket/:id')")
        conn.execute("""INSERT INTO endpoint_observations VALUES
            ('basket','context','https://target.test/rest/basket/6',
             'playwright_interaction')""")
        assert seed_observed_object_facts(conn, "scan") == 1
        assert seed_observed_object_facts(conn, "scan") == 0
