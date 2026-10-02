import json
import sqlite3
from pathlib import Path

import pytest

from aidast.recon.reference import ReferenceDatabaseError, build_reference_database
from aidast.recon.wiki import ingest_database, lint_wiki
from aidast.web.recon_wiki import ReconWikiCatalog


def _manifest(path: Path) -> Path:
    payload = {
        "schema_version": "1.0",
        "reference_id": "test-source-routes",
        "target": "Test App",
        "version": "1.0.0",
        "source_commit": "a" * 40,
        "route_count": 3,
        "method_counts": {"GET": 2, "POST": 1},
        "routes": ["GET /", "GET /items/:item_id", "POST /items"],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_builds_idempotent_source_reference_for_dashboard_and_wiki(tmp_path: Path) -> None:
    database = tmp_path / "References/Test/Recon.db"
    first = build_reference_database(
        _manifest(tmp_path / "routes.json"), database,
        target_url="http://127.0.0.1:5001/",
    )
    second = build_reference_database(
        tmp_path / "routes.json", database, target_url="http://127.0.0.1:5001/",
    )

    assert first.created is True and second.created is False
    assert first.route_count == 3 and first.method_counts == {"GET": 2, "POST": 1}
    with sqlite3.connect(database) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT COUNT(*) FROM endpoints").fetchone() == (3,)
        assert conn.execute("SELECT COUNT(*) FROM endpoint_observations").fetchone() == (3,)
        assert conn.execute("SELECT COUNT(*) FROM parameters").fetchone() == (1,)

    entry = ReconWikiCatalog(tmp_path).entries()[0]
    assert entry["kind"] == "source" and entry["endpoint_count"] == 3
    assert entry["label"] == "Test App v1.0.0 source routes · http://127.0.0.1:5001"
    source = ingest_database(
        tmp_path / "ReconWiki/test", database, kind="source", label="Test source",
        target_id="test-app@1.0.0",
    )
    assert source.endpoint_count == 3
    assert lint_wiki(tmp_path / "ReconWiki/test") == ()


def test_rejects_manifest_count_drift(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "routes.json")
    payload = json.loads(manifest.read_text())
    payload["route_count"] = 2
    manifest.write_text(json.dumps(payload))

    with pytest.raises(ReferenceDatabaseError, match="counts"):
        build_reference_database(
            manifest, tmp_path / "Recon.db", target_url="http://127.0.0.1:5001/",
        )
