"""Keep distinct API resource routes in the final Recon surface."""

import json

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder
from aidast.recon.judgment import merge_and_normalize
from aidast.recon.surface import export_surface


def test_many_api_and_rest_resource_names_stay_distinct() -> None:
    paths = [
        "/api/Addresss", "/api/BasketItems", "/api/Challenges",
        "/api/Complaints", "/api/Feedbacks", "/api/Recycles",
        "/rest/captcha", "/rest/continue-code", "/rest/languages",
        "/rest/repeat-notification", "/rest/saveLoginIp", "/rest/user/whoami",
    ]
    rows = [{"method": "GET", "path": path, "source": "adaptive_js"}
            for path in paths]

    surface = merge_and_normalize(rows)

    assert {row["normalized_path"] for row in surface} == set(paths)
    assert len(surface) == len(paths)


def test_nested_api_routes_stay_distinct_while_explicit_ids_normalize() -> None:
    static_paths = [
        "/api/v1/Addresss", "/api/v1/BasketItems", "/api/v1/Challenges",
        "/api/v1/Complaints", "/api/v1/Feedbacks", "/api/v1/Recycles",
        "/rest/user/whoami", "/rest/user/profile", "/rest/user/settings",
        "/rest/user/preferences", "/rest/user/notifications",
    ]
    rows = [{"method": "GET", "path": path, "source": "crawler"}
            for path in static_paths + [
                "/api/Users/123", "/api/Users/456",
                "/rest/items/550e8400-e29b-41d4-a716-446655440000",
                "/rest/items/550e8400-e29b-41d4-a716-446655440001",
            ]]

    surface = merge_and_normalize(rows)

    assert {row["normalized_path"] for row in surface} == (
        set(static_paths) | {"/api/Users/:id", "/rest/items/:id"}
    )


def test_reconciliation_keeps_static_api_routes_and_their_http_evidence(tmp_path) -> None:
    paths = [
        "/api/Addresss", "/api/BasketItems", "/api/Challenges",
        "/api/Complaints", "/api/Feedbacks", "/api/Recycles",
    ]
    rows = [{
        "method": "GET", "path": path,
        "url": "https://example.test" + path, "source": "adaptive_js",
    } for path in paths]
    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url",
                       scope_value="https://example.test")
        asset = db.insert_asset(connection, scan_id="scan",
                                identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https",
                                  host="example.test", port=443,
                                  base_url="https://example.test")
        ObservationRecorder(connection, origin_id=origin, scan_id="scan").record(
            "adaptive_js", rows,
        )
        for path in paths:
            endpoint_id = connection.execute(
                "SELECT endpoint_id FROM endpoints WHERE origin_id=? AND path=?",
                (origin, path),
            ).fetchone()[0]
            db.insert_http_transaction(
                connection, endpoint_id=endpoint_id, source="mitmproxy",
                method="GET", url="https://example.test" + path,
                response_status=200,
            )
        for item in merge_and_normalize(rows):
            db.upsert_endpoint(
                connection, origin_id=origin, method=item["method"],
                path=item["path"], normalized_path=item["normalized_path"],
                source_tool="adaptive_js",
            )

        db.reconcile_observed_endpoints(connection, origin_id=origin,
                                        raw_endpoints=rows)
        surface = json.loads(export_surface(
            connection, scan_id="scan", output_path=tmp_path / "Surface.json",
        ).read_text())
        linked = connection.execute("""
            SELECT e.path, t.url FROM http_transactions AS t
            JOIN endpoints AS e ON e.endpoint_id = t.endpoint_id
            ORDER BY t.url
        """).fetchall()

    assert {e["path"] for e in surface["origins"][0]["endpoints"]} == set(paths)
    assert linked == [(path, "https://example.test" + path) for path in paths]
