import json
import sqlite3

from aidast.cli import main
from aidast.recon.wiki import compare_databases, ingest_database, lint_wiki


def _database(path, routes):
    with sqlite3.connect(path) as connection:
        connection.executescript("""
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
        """)
        connection.execute(
            "INSERT INTO scans VALUES ('scan','URL','https://bank.test','completed','now','now')"
        )
        connection.execute("INSERT INTO assets VALUES ('asset','scan','bank.test','URL')")
        connection.execute("INSERT INTO origins VALUES ('origin','asset','https://bank.test')")
        connection.executemany(
            "INSERT INTO endpoints VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    f"endpoint-{index}", "origin", method, route, route, status,
                    int(excluded), reason, None, tool,
                )
                for index, (method, route, status, excluded, reason, tool) in enumerate(routes)
            ],
        )


def test_compare_is_method_aware_and_excludes_static_routes(tmp_path):
    observed = tmp_path / "observed.db"
    baseline = tmp_path / "baseline.db"
    _database(observed, [
        ("GET", "/login", "verified", False, None, "katana"),
        ("GET", "/transfer", "observed", False, None, "katana"),
        ("GET", "/app.js", "observed", True, "static_asset", "katana"),
    ])
    _database(baseline, [
        ("GET", "/login", "verified", False, None, "source_import"),
        ("POST", "/transfer", "verified", False, None, "source_import"),
        ("POST", "/reset", "verified", False, None, "source_import"),
    ])

    result = compare_databases(
        tmp_path / "knowledge", observed_database=observed, baseline_database=baseline,
    )

    assert result.matched_count == 1
    assert result.baseline_count == 3
    assert result.observed_count == 2
    assert result.exact_recall == 1 / 3
    assert result.path_recall == 2 / 3
    assert result.missing == (("POST", "/reset"), ("POST", "/transfer"))
    report = result.report_path.read_text()
    assert "POST | 0 | 2 | 0.00%" in report


def test_compare_normalizes_named_route_parameters(tmp_path):
    observed = tmp_path / "observed.db"
    baseline = tmp_path / "baseline.db"
    _database(observed, [
        ("PUT", "/basket/:id/coupon/:id", "observed", False, None, "katana"),
    ])
    _database(baseline, [
        ("PUT", "/basket/:basket_id/coupon/:coupon", "observed", False, None,
         "official_source_manifest"),
    ])

    result = compare_databases(
        tmp_path / "knowledge", observed_database=observed, baseline_database=baseline,
    )

    assert result.matched_count == 1
    assert result.exact_recall == 1.0


def test_compare_counts_passive_route_candidates_but_not_static_assets(tmp_path):
    observed = tmp_path / "observed.db"
    baseline = tmp_path / "baseline.db"
    _database(observed, [
        ("POST", "/transfer", "candidate", True, "unverified_candidate", "passive_declaration"),
        ("GET", "/app.js", "observed", True, "static_asset", "katana"),
    ])
    _database(baseline, [
        ("POST", "/transfer", "verified", False, None, "source_import"),
        ("GET", "/app.js", "verified", False, None, "source_import"),
    ])

    result = compare_databases(
        tmp_path / "knowledge", observed_database=observed, baseline_database=baseline,
    )

    assert result.observed_count == 1
    assert result.matched_count == 1
    assert result.confirmed_count == 0
    assert result.declared_candidate_count == 1
    assert result.inferred_candidate_count == 0
    assert result.declared_candidate_matched_count == 1
    assert result.missing == (("GET", "/app.js"),)
    assert "Passive declared candidates included: **yes**" in result.report_path.read_text()


def test_ingest_is_idempotent_and_lint_detects_raw_mutation(tmp_path):
    database = tmp_path / "Recon.db"
    _database(database, [("GET", "/", "verified", False, None, "katana")])
    root = tmp_path / "knowledge"

    first = ingest_database(root, database, kind="runtime", label="scan one")
    second = ingest_database(root, database, kind="runtime", label="scan one")

    assert first.source_id == second.source_id
    assert first.created is True
    assert second.created is False
    assert (root / "wiki/log.md").read_text().count("ingested") == 1
    assert lint_wiki(root) == ()

    payload = json.loads(first.raw_path.read_text())
    payload["endpoints"][0]["normalized_path"] = "/tampered"
    first.raw_path.write_text(json.dumps(payload))
    assert any("inventory was modified" in issue for issue in lint_wiki(root))


def test_cli_builds_and_lints_wiki(tmp_path, capsys):
    database = tmp_path / "Recon.db"
    _database(database, [("GET", "/health", "observed", False, None, "httpx")])
    root = tmp_path / "wiki-root"

    assert main(["recon-wiki", "init", "--root", str(root)]) == 0
    assert main([
        "recon-wiki", "ingest", str(database), "--root", str(root),
        "--kind", "runtime", "--label", "health scan",
    ]) == 0
    assert main(["recon-wiki", "lint", "--root", str(root)]) == 0
    output = capsys.readouterr().out
    assert '"ok": true' in output
    assert (root / "wiki/index.md").is_file()
