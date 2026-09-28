import json
import sqlite3
from pathlib import Path

import pytest

from evaluate_recon_get_routes import main


def test_report_matches_only_observed_get_routes_on_target_origin(tmp_path: Path) -> None:
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({
        "origin": "http://127.0.0.1:3001/",
        "routes": ["GET /", "GET /rest/basket/:id", "GET /profile", "GET /secret"],
    }))
    db = tmp_path / "Recon.db"
    connection = sqlite3.connect(db)
    connection.executescript("""
        CREATE TABLE origins (origin_id TEXT, base_url TEXT);
        CREATE TABLE scans (status TEXT);
        CREATE TABLE endpoints (
          endpoint_id TEXT, origin_id TEXT, method TEXT, path TEXT,
          normalized_path TEXT, is_excluded INTEGER, source_tools TEXT
        );
        CREATE TABLE http_transactions (
          endpoint_id TEXT, origin_id TEXT, method TEXT, response_status INTEGER,
          url TEXT
        );
        INSERT INTO origins VALUES ('target', 'http://127.0.0.1:3001/');
        INSERT INTO scans VALUES ('completed');
        INSERT INTO origins VALUES ('other', 'http://127.0.0.1:3002/');
        INSERT INTO endpoints VALUES ('root', 'target', 'GET', '/', '/', 0, 'katana');
        INSERT INTO endpoints VALUES ('basket', 'target', 'GET', '/rest/basket/8', '/rest/basket/:id', 0, 'playwright');
        INSERT INTO endpoints VALUES ('profile', 'target', 'GET', '/profile', '/profile', 0, 'ffuf');
        INSERT INTO endpoints VALUES ('secret', 'other', 'GET', '/secret', '/secret', 0, 'ffuf');
        INSERT INTO endpoints VALUES ('post', 'target', 'POST', '/secret', '/secret', 0, 'browser');
        INSERT INTO endpoints VALUES ('excluded', 'target', 'GET', '/secret', '/secret', 1, 'katana');
        INSERT INTO endpoints VALUES ('cross', 'target', 'GET', '/secret', '/secret', 0, 'katana');
        INSERT INTO http_transactions VALUES ('root', 'target', 'GET', 200, 'http://127.0.0.1:3001/');
        INSERT INTO http_transactions VALUES ('basket', 'target', 'GET', 200, 'http://127.0.0.1:3001/rest/basket/8');
        INSERT INTO http_transactions VALUES ('profile', 'target', 'GET', 500, 'http://127.0.0.1:3001/profile');
        INSERT INTO http_transactions VALUES ('secret', 'other', 'GET', 200, 'http://127.0.0.1:3002/secret');
        INSERT INTO http_transactions VALUES ('post', 'target', 'POST', 200, 'http://127.0.0.1:3001/secret');
        INSERT INTO http_transactions VALUES ('excluded', 'target', 'GET', 200, 'http://127.0.0.1:3001/secret');
        INSERT INTO http_transactions VALUES ('cross', 'other', 'GET', 200, 'http://127.0.0.1:3002/secret');
    """)
    connection.close()
    output = tmp_path / "report.md"

    assert main(["--ground-truth", str(truth), "--run", f"trial={db}", "--output", str(output)]) == 0

    report = output.read_text()
    assert "3/4" in report
    assert "| GET /rest/basket/:id | O | 200 |" in report
    assert "| GET /profile | O | 500 |" in report
    assert "| GET /secret | X | — |" in report
    assert "### trial 누락 경로" in report
    assert "- `GET /secret`" in report


def test_report_matches_express_route_case_insensitively(tmp_path: Path) -> None:
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({
        "origin": "http://127.0.0.1:3001/", "routes": ["GET /api/Users"],
    }))
    db = tmp_path / "Recon.db"
    connection = sqlite3.connect(db)
    connection.executescript("""
        CREATE TABLE origins (origin_id TEXT, base_url TEXT);
        CREATE TABLE scans (status TEXT);
        CREATE TABLE endpoints (
          endpoint_id TEXT, origin_id TEXT, method TEXT, path TEXT, normalized_path TEXT,
          is_excluded INTEGER
        );
        CREATE TABLE http_transactions (
          endpoint_id TEXT, origin_id TEXT, method TEXT, response_status INTEGER,
          url TEXT
        );
        INSERT INTO origins VALUES ('target', 'http://127.0.0.1:3001/');
        INSERT INTO scans VALUES ('completed');
        INSERT INTO endpoints VALUES ('users', 'target', 'GET', '/api/users', '/api/users', 0);
        INSERT INTO http_transactions VALUES ('users', 'target', 'GET', 200, 'http://127.0.0.1:3001/api/users');
    """)
    connection.close()
    output = tmp_path / "report.md"

    assert main(["--ground-truth", str(truth), "--run", f"trial={db}", "--output", str(output)]) == 0

    assert "| GET /api/Users | O | 200 |" in output.read_text()


def test_report_uses_observed_path_when_recon_normalization_is_too_broad(tmp_path: Path) -> None:
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({
        "origin": "http://127.0.0.1:3001/",
        "routes": ["GET /rest/languages", "GET /rest/wallet"],
    }))
    db = tmp_path / "Recon.db"
    connection = sqlite3.connect(db)
    connection.executescript("""
        CREATE TABLE scans (status TEXT);
        CREATE TABLE origins (origin_id TEXT, base_url TEXT);
        CREATE TABLE endpoints (
          endpoint_id TEXT, origin_id TEXT, method TEXT, path TEXT,
          normalized_path TEXT, is_excluded INTEGER
        );
        CREATE TABLE http_transactions (
          endpoint_id TEXT, origin_id TEXT, method TEXT, response_status INTEGER,
          url TEXT
        );
        INSERT INTO scans VALUES ('completed');
        INSERT INTO origins VALUES ('target', 'http://127.0.0.1:3001/');
        INSERT INTO endpoints VALUES ('languages', 'target', 'GET',
                                      '/rest/languages', '/rest/:param', 0);
        INSERT INTO http_transactions VALUES ('languages', 'target', 'GET', 200, 'http://127.0.0.1:3001/rest/languages');
    """)
    connection.close()
    output = tmp_path / "report.md"

    assert main(["--ground-truth", str(truth), "--run", f"trial={db}", "--output", str(output)]) == 0

    report = output.read_text()
    assert "| GET /rest/languages | O | 200 |" in report
    assert "| GET /rest/wallet | X | — |" in report


def test_report_uses_each_requested_url_after_endpoint_paths_merge(tmp_path: Path) -> None:
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({
        "origin": "http://127.0.0.1:3001/",
        "routes": ["GET /api/Challenges", "GET /api/Addresss", "GET /api/BasketItems"],
    }))
    db = tmp_path / "Recon.db"
    connection = sqlite3.connect(db)
    connection.executescript("""
        CREATE TABLE scans (status TEXT);
        CREATE TABLE origins (origin_id TEXT, base_url TEXT);
        CREATE TABLE endpoints (
          endpoint_id TEXT, origin_id TEXT, method TEXT, path TEXT,
          normalized_path TEXT, is_excluded INTEGER
        );
        CREATE TABLE http_transactions (
          endpoint_id TEXT, origin_id TEXT, method TEXT, response_status INTEGER,
          url TEXT
        );
        INSERT INTO scans VALUES ('completed');
        INSERT INTO origins VALUES ('target', 'http://127.0.0.1:3001/');
        INSERT INTO endpoints VALUES ('merged', 'target', 'GET',
                                     '/api/Challenges/', '/api/:param', 0);
        INSERT INTO http_transactions VALUES ('merged', 'target', 'GET', 200,
                                              'http://127.0.0.1:3001/api/Challenges/');
        INSERT INTO http_transactions VALUES ('merged', 'target', 'GET', 200,
                                              'http://127.0.0.1:3001/api/Addresss');
        INSERT INTO http_transactions VALUES ('merged', 'target', 'GET', 200,
                                              'http://127.0.0.1:3001/api/BasketItems');
    """)
    connection.close()
    output = tmp_path / "report.md"

    assert main(["--ground-truth", str(truth), "--run", f"trial={db}",
                 "--output", str(output)]) == 0

    report = output.read_text()
    assert "3/3" in report
    assert "| GET /api/Addresss | O | 200 |" in report
    assert "| GET /api/BasketItems | O | 200 |" in report


def test_surface_report_does_not_count_merged_static_paths(tmp_path: Path) -> None:
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({
        "origin": "http://127.0.0.1:3001/",
        "routes": ["GET /api/Challenges", "GET /api/Addresss", "GET /rest/basket/:id"],
    }))
    surface = tmp_path / "Surface.json"
    surface.write_text(json.dumps({"origins": [{
        "base_url": "http://127.0.0.1:3001/",
        "endpoints": [
            {"method": "GET", "path": "/api/:param"},
            {"method": "GET", "path": "/rest/basket/:id"},
        ],
    }]}))
    db = tmp_path / "Recon.db"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE scans (status TEXT)")
    connection.execute("INSERT INTO scans VALUES ('completed')")
    connection.execute("CREATE TABLE origins (origin_id TEXT, base_url TEXT)")
    connection.execute("CREATE TABLE endpoints (endpoint_id TEXT, origin_id TEXT, method TEXT, is_excluded INTEGER)")
    connection.execute("CREATE TABLE http_transactions (endpoint_id TEXT, origin_id TEXT, method TEXT, response_status INTEGER, url TEXT)")
    connection.commit()
    connection.close()
    output = tmp_path / "report.md"
    surface_output = tmp_path / "surface-report.md"

    assert main([
        "--ground-truth", str(truth), "--run", f"trial={db}",
        "--surface-run", f"trial={surface}",
        "--output", str(output), "--surface-output", str(surface_output),
    ]) == 0

    report = surface_output.read_text()
    assert "1/3" in report
    assert "| GET /api/Challenges | X |" in report
    assert "| GET /api/Addresss | X |" in report
    assert "| GET /rest/basket/:id | O |" in report


def test_report_rejects_incomplete_scan(tmp_path: Path) -> None:
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({
        "origin": "http://127.0.0.1:3001/", "routes": ["GET /"],
    }))
    db = tmp_path / "Recon.db"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE scans (status TEXT)")
    connection.execute("INSERT INTO scans VALUES ('running')")
    connection.execute("CREATE TABLE origins (origin_id TEXT, base_url TEXT)")
    connection.execute("CREATE TABLE endpoints (endpoint_id TEXT, origin_id TEXT, method TEXT, normalized_path TEXT, is_excluded INTEGER)")
    connection.execute("CREATE TABLE http_transactions (endpoint_id TEXT, origin_id TEXT, method TEXT, response_status INTEGER)")
    connection.commit()
    connection.close()

    with pytest.raises(ValueError, match="not completed"):
        main(["--ground-truth", str(truth), "--run", f"trial={db}",
              "--output", str(tmp_path / "report.md")])
