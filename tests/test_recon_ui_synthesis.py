from __future__ import annotations

import sqlite3

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder
from aidast.recon.ui_synthesis import (
    reconcile_synthetic_ui_candidates,
    synthesize_client_ui_routes,
)


def _database(tmp_path):
    conn = db.init_db(tmp_path / "Recon.db")
    db.insert_scan(conn, scan_id="scan-ui", scope_type="test", scope_value="example")
    asset = db.insert_asset(
        conn, scan_id="scan-ui", identifier="example.test", asset_type="DOMAIN",
    )
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    return conn, origin


def test_synthesis_is_bounded_same_origin_and_keeps_role_provenance() -> None:
    html = """
      <a href="/account/orders?token=discard">Orders</a>
      <a href="https://outside.test/admin">Outside</a>
      <nav data-route="/admin/users" data-role="admin">Users</nav>
      <script src="/assets/main.js"></script>
    """
    rows = synthesize_client_ui_routes(
        html, media_type="text/html", document_url="https://example.test/app",
        base_url="https://example.test", limit=2,
    )

    assert [row["path"] for row in rows] == ["/account/orders", "/admin/users"]
    assert all(row["verification_status"] == "candidate" for row in rows)
    assert rows[0]["url"] == "https://example.test/account/orders"
    assert rows[1]["evidence"]["required_role_hint"] == "administrator"
    assert all(row["discovery_kind"] == "synthetic_ui_candidate" for row in rows)


def test_route_stays_synthetic_until_captured_http_response_exists(tmp_path) -> None:
    conn, origin = _database(tmp_path)
    try:
        row = synthesize_client_ui_routes(
            '<a href="/private/orders">Orders</a>', media_type="text/html",
            document_url="https://example.test/app", base_url="https://example.test",
        )[0]
        recorder = ObservationRecorder(
            conn, origin_id=origin, scan_id="scan-ui", agent=None,
        )
        recorder.record("passive_reconciliation", [row])
        endpoint_id = conn.execute(
            "SELECT endpoint_id FROM endpoints WHERE normalized_path='/private/orders'"
        ).fetchone()[0]

        # A later declaration or model statement cannot promote the route.
        recorder.record("browser", [{
            "method": "GET", "path": "/private/orders",
            "url": "https://example.test/private/orders",
            "source": "playwright_http", "evidence": {"response_status": 200},
        }])
        assert conn.execute(
            "SELECT state FROM synthetic_ui_candidates"
        ).fetchone()[0] == "synthetic"

        db.insert_http_transaction(
            conn, endpoint_id=endpoint_id, source="browser", method="GET",
            url="https://example.test/private/orders", response_status=200,
        )
        assert reconcile_synthetic_ui_candidates(conn, origin_id=origin) == 1
        state, promoted = conn.execute(
            "SELECT state,promoted_endpoint_id FROM synthetic_ui_candidates"
        ).fetchone()
        assert (state, promoted) == ("verified", endpoint_id)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        conn.close()


def test_javascript_route_config_is_not_evaluated() -> None:
    script = """
      const routes = [
        {path: '/billing', canActivate: [AuthGuard]},
        {path: '/admin/audit', roles: ['admin']},
        {path: computeRoute()},
      ];
      router.navigate(['/settings/profile']);
    """
    rows = synthesize_client_ui_routes(
        script, media_type="application/javascript",
        document_url="https://example.test/main.js", base_url="https://example.test",
    )
    by_path = {row["path"]: row for row in rows}
    assert set(by_path) == {"/billing", "/admin/audit", "/settings/profile"}
    assert by_path["/billing"]["evidence"]["required_role_hint"] == "authenticated"
    assert by_path["/admin/audit"]["evidence"]["required_role_hint"] == "administrator"
