from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aidast.pipeline.resume import inspect_resume
from aidast.attack.skill_selector import (
    available_attack_skill_names,
    select_relevant_attack_skills,
)
from aidast.recon.source_import import extract_flask_endpoints, import_flask_source


SOURCE = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/users/<int:user_id>", methods=["GET", "POST"])
def user(user_id):
    # Vulnerability: SQL injection and IDOR
    data = request.get_json() or {}
    query = request.args.get("q")
    return data.get("display_name", query)
'''


def test_extracts_methods_path_and_parameters(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    endpoints = extract_flask_endpoints(tmp_path)
    assert {(item.method, item.path) for item in endpoints} == {
        ("GET", "/api/users/{user_id}"),
        ("POST", "/api/users/{user_id}"),
    }
    assert {tag for item in endpoints for tag in item.vulnerability_tags} == {"sqli", "idor"}
    assert {(item.name, item.location) for item in endpoints[0].parameters} == {
        ("user_id", "path"), ("q", "query"), ("display_name", "json"),
    }


def test_auth_detection_ignores_no_authentication_prose(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('''
from flask import Flask
app = Flask(__name__)

@app.route("/anonymous")
@rate_limit
def anonymous():
    """No authentication required; broken authorization is intentional."""
    return {"ok": True}

@app.route("/private")
@token_required
def private():
    return {"ok": True}
''', encoding="utf-8")
    endpoints = {item.path: item for item in extract_flask_endpoints(tmp_path)}
    assert endpoints["/anonymous"].auth_required is False
    assert endpoints["/private"].auth_required is True


def test_source_rationale_preserves_bounded_vulnerability_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    endpoint = extract_flask_endpoints(tmp_path)[0]
    evidence = dict(endpoint.vulnerability_evidence)
    assert "SQL injection" in evidence["sqli"]
    assert "IDOR" in evidence["idor"]


def test_mixed_route_does_not_copy_post_markers_to_get(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text('''
from flask import Flask, request
app = Flask(__name__)

@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        # Vulnerability: No rate limiting on PIN attempts
        data = request.get_json()
        return data.get("reset_pin")
    return "form"
''', encoding="utf-8")

    endpoints = {
        item.method: item for item in extract_flask_endpoints(tmp_path)
    }

    assert endpoints["GET"].vulnerability_tags == ()
    assert endpoints["POST"].vulnerability_tags == ("brute_force",)


def test_import_creates_resumable_verified_handoff(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(SOURCE, encoding="utf-8")
    result_root = tmp_path / "result"
    result = import_flask_source(
        source, target_url="https://lab.example/", result_root=result_root,
        approved_by="fixture-operator", source_ref="fixture-commit",
    )

    assert result.endpoint_count == 2
    assert result.parameter_count == 6
    assert result.vulnerability_signal_count == 4
    plan = inspect_resume(result_root, result.scan_id)
    assert plan.stage == "attack"
    assert plan.database == result.pipeline_database

    with sqlite3.connect(result.recon_database) as conn:
        assert conn.execute(
            "SELECT status FROM scans WHERE scan_id=?", (result.scan_id,)
        ).fetchone() == ("completed",)
        assert conn.execute("SELECT COUNT(*) FROM endpoints").fetchone() == (2,)
        assert conn.execute("SELECT COUNT(*) FROM parameters").fetchone() == (6,)
        assert conn.execute(
            "SELECT COUNT(*) FROM endpoint_annotations WHERE category='source_vulnerability'"
        ).fetchone() == (4,)
    inventory = json.loads(result.inventory.read_text(encoding="utf-8"))
    assert inventory["vulnerability_counts"] == {"idor": 2, "sqli": 2}
    skills, reasons = select_relevant_attack_skills(
        result.pipeline_database, result.scan_id, available_attack_skill_names()
    )
    assert "hunt-sqli" in skills
    assert "hunt-idor" in skills
    assert "operator-provided source marker" in reasons["hunt-sqli"]


def test_lab_benchmark_expands_only_loopback_attack_policy(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(SOURCE, encoding="utf-8")
    result = import_flask_source(
        source, target_url="http://127.0.0.1:5001/",
        result_root=tmp_path / "result", approved_by="fixture-operator",
        source_ref="fixture-commit", lab_benchmark=True,
    )
    policy = json.loads(
        (result.recon_database.parent / "TargetPolicy.json").read_text(encoding="utf-8")
    )["policies"][0]
    assert policy["attack_allowed_methods"] == [
        "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE",
    ]
    assert policy["limits"]["concurrency"] == 8
    scope = (result.recon_database.parent / "Scope.md").read_text(encoding="utf-8")
    assert "disposable local lab fixtures" in scope
    assert "- http://127.0.0.1:5001/" in scope
