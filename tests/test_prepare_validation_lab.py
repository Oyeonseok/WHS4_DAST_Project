"""A synthetic Attack claim fixture must preserve real GET observations and provenance."""

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.prepare_validation_lab import _contract, prepare_validation_lab
from aidast.validation.core.integrity import CandidateIntegrityGate
from aidast.validation.core.policy import TargetPolicyProvider


def _recorded_probe(source: Path):
    observations = json.loads((source / "LocalControlObservations.json").read_text())["observations"]
    by_url = {item["url"]: item for item in observations}
    def probe(url: str):
        item = by_url[url]
        return (item["observed_http_status"], item["response_body_sha256"],
                item["response_bytes"])
    return probe


def _recorded_identity(source: Path):
    value = json.loads((source / "LocalControlObservations.json").read_text())["runtime_identity"]
    return lambda: value


@pytest.mark.parametrize("endpoint", [
    "/api/Complaints", "/api/Feedbacks/:id", "/api/PrivacyRequests", "/api/Users",
])
def test_unauthenticated_disclosure_uses_auth_bypass_profile(endpoint: str) -> None:
    _, _, _, _, skill = _contract({
        "candidate_id": f"juice-shop:case:GET:{endpoint}:unauthenticated_disclosure",
        "project": "juice-shop", "endpoint_template": endpoint,
        "vuln_class": "unauthenticated_disclosure",
    })
    assert skill == "hunt-auth-bypass"


def test_prepare_seven_isolated_cases_without_leaking_answers(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not all((source / name).exists() for name in (
        "CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json"
    )):
        pytest.skip("local pinned lab observations are not available")

    output = tmp_path / "fixture"
    mapping = prepare_validation_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "LocalControlObservations.json", output,
        live_probe=_recorded_probe(source),
        identity_probe=_recorded_identity(source),
    )

    assert len(mapping["cases"]) == 7
    assert {item["scan_id"] for item in mapping["cases"]} == {
        "validation-lab-juice-shop", "validation-lab-vuln-bank"
    }
    assert all("expected_verdict" not in json.dumps(item) for item in mapping["cases"])
    policy = TargetPolicyProvider(output / "TargetPolicy.json")
    assert policy("http://127.0.0.1:3001/api/Users", "GET")
    for item in policy._policies:
        assert item.limits.requests_per_second <= 0.5
        assert item.limits.concurrency <= 2
        assert item.limits.timeout_seconds <= 15
        assert item.limits.max_depth <= 2
        assert item.limits.max_requests <= 500
    with pytest.raises(ValueError, match="exactly one"):
        policy("http://127.0.0.1:3001/api/Products", "GET")
    with pytest.raises(ValueError, match="exactly one"):
        policy("http://127.0.0.1:5001/api/v3/user/1", "GET")
    with sqlite3.connect(output / "Pipeline.db") as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 7
        assert conn.execute("SELECT COUNT(*) FROM attack_requests").fetchone()[0] == 7
        assert conn.execute("SELECT COUNT(*) FROM attack_attempts WHERE outcome='confirmed'").fetchone()[0] == 7
        assert conn.execute(
            "SELECT COUNT(*) FROM attack_attempts WHERE length(response_signature)=64"
        ).fetchone()[0] == 7
        assert conn.execute("SELECT COUNT(*) FROM attack_requests WHERE response_body IS NOT NULL").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM validation_scope_bindings WHERE approval_digest IS NOT NULL"
        ).fetchone()[0] == 2
        for case in mapping["cases"]:
            candidate = CandidateIntegrityGate(conn).validate_finding(
                case_id="preflight-" + case["finding_id"],
                scan_id=case["scan_id"], finding_id=case["finding_id"]
            )
            assert candidate.staged.blind_view()["method"] == "GET"
            if case["candidate_id"].startswith("juice-shop:"):
                assert candidate.staged.blind_view()["attack_skill_name"] == "hunt-auth-bypass"


def test_prepare_impact_probe_stages_weak_marker_and_bounded_action(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not all((source / name).exists() for name in (
        "CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json"
    )):
        pytest.skip("local pinned lab observations are not available")

    output = tmp_path / "impact"
    mapping = prepare_validation_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "LocalControlObservations.json", output,
        live_probe=_recorded_probe(source), identity_probe=_recorded_identity(source),
        impact_probe=True, impact_marker_probe=lambda url: (
            {"users", "password", "seeded_admin"}, _recorded_probe(source)(url)[1],
        ),
    )
    selected = mapping["impact_lab"]
    assert selected["candidate_id"] == "vuln-bank:curated:GET:/debug/users:excessive_data_exposure"
    with sqlite3.connect(output / "Pipeline.db") as conn:
        conn.row_factory = sqlite3.Row
        spec = conn.execute(
            "SELECT * FROM finding_reproduction_specs WHERE finding_id=?",
            (selected["finding_id"],),
        ).fetchone()
        runtime = json.loads(spec["runtime_contract_json"])
        impact = json.loads(spec["impact_development_contract_json"])
        assert runtime["target"]["assertions"][0]["expected"] == "users"
        assert impact["actions"][0]["path_id"] == "bounded-impact-confirmation"
        assert impact["actions"][0]["method"] == "GET"
        assert impact["actions"][0]["assertions"][0]["expected"] == '"password":'
        assert impact["actions"][0]["assertions"][1]["expected"] == '"username":"admin"'
        receipt = impact["actions"][0]["precondition_observation"]
        assert receipt == {
            "source_request_id": json.loads(spec["source_request_ids_json"])[0],
            "response_sha256": next(item["response_body_sha256"] for item in
                                    json.loads((source / "LocalControlObservations.json").read_text())["observations"]
                                    if item["url"] == "http://127.0.0.1:5001/debug/users"),
            "response_status": 200,
            "marker_json_path": ["users", "*", "username"],
            "marker_assertion_id": "seeded-admin-username",
        }
        candidate = CandidateIntegrityGate(conn).validate_finding(
            case_id="preflight-impact", scan_id=selected["scan_id"],
            finding_id=selected["finding_id"],
        )
        assert len(candidate.impact_development_actions) == 1
        assert candidate.source_requests == ({
            "request_id": receipt["source_request_id"],
            "method": "GET", "url": "http://127.0.0.1:5001/debug/users",
            "response_status": 200,
            "authorization_source": "scope_safe_method",
        },)
        from aidast.validation.orchestration.coordinator import _impact_planning_context
        planning = _impact_planning_context(candidate, ())
        assert planning[0] == {
            "context_kind": "verified_attack_source_requests",
            "requests": [candidate.source_requests[0]],
        }
        assert planning[1]["capabilities"][0]["precondition_observation"] == receipt


def test_prepare_impact_probe_rejects_missing_live_marker(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not all((source / name).exists() for name in (
        "CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json"
    )):
        pytest.skip("local pinned lab observations are not available")

    with pytest.raises(ValueError, match="impact marker"):
        prepare_validation_lab(
            source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
            source / "LocalControlObservations.json", tmp_path / "impact",
            live_probe=_recorded_probe(source), identity_probe=_recorded_identity(source),
            impact_probe=True, impact_marker_probe=lambda url: (
                {"users"}, _recorded_probe(source)(url)[1],
            ),
        )


def test_prepare_impact_probe_rejects_marker_from_different_response(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not all((source / name).exists() for name in (
        "CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json"
    )):
        pytest.skip("local pinned lab observations are not available")
    with pytest.raises(ValueError, match="impact marker"):
        prepare_validation_lab(
            source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
            source / "LocalControlObservations.json", tmp_path / "impact",
            live_probe=_recorded_probe(source), identity_probe=_recorded_identity(source),
            impact_probe=True,
            impact_marker_probe=lambda url: ({"users", "password", "seeded_admin"}, "f" * 64),
        )


def test_impact_marker_probe_counts_json_keys_only() -> None:
    from scripts.prepare_validation_lab import impact_marker_names

    assert impact_marker_names(b'{"users":[{"note":"password","password":"redacted"}]}') == {
        "users", "password"
    }
    assert impact_marker_names(b'{"users":[{"note":"password"}]}') == {"users"}
    assert impact_marker_names(b'{"users":[],"password":"redacted"}') == {"users"}
    assert impact_marker_names(
        b'{"users":[{"username":"admin","password":"redacted"}]}'
    ) == {"users", "password", "seeded_admin"}
    assert impact_marker_names(
        b'{"users": [{"username": "admin", "password": "redacted"}]}'
    ) == {"users", "password"}


def test_preparation_rejects_changed_observation(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not all((source / name).exists() for name in (
        "CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json"
    )):
        pytest.skip("local pinned lab observations are not available")
    report = json.loads((source / "LocalControlObservations.json").read_text())
    report["observations"][0]["observed_http_status"] = 200
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(report))

    with pytest.raises(ValueError, match="observation"):
        prepare_validation_lab(source / "CandidateInventory.db",
                               source / "CandidateAnswerKey.db", changed, tmp_path / "fixture",
                               live_probe=_recorded_probe(source),
                               identity_probe=_recorded_identity(source))

    report["observations"][0]["observed_http_status"] = report["observations"][0]["answer_key_http_status"]
    report["observations"][0]["url"] = "http://127.0.0.1:3001/api/OtherResource"
    changed.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="observation"):
        prepare_validation_lab(source / "CandidateInventory.db",
                               source / "CandidateAnswerKey.db", changed, tmp_path / "fixture",
                               live_probe=_recorded_probe(source),
                               identity_probe=_recorded_identity(source))

    report["observations"][0]["url"] = json.loads(
        (source / "LocalControlObservations.json").read_text()
    )["observations"][0]["url"]
    report["observations"][0]["response_body_sha256"] = "a" * 64
    changed.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="observation"):
        prepare_validation_lab(source / "CandidateInventory.db",
                               source / "CandidateAnswerKey.db", changed, tmp_path / "fixture",
                               live_probe=_recorded_probe(source),
                               identity_probe=_recorded_identity(source))

    report["observations"][0]["response_body_sha256"] = json.loads(
        (source / "LocalControlObservations.json").read_text()
    )["observations"][0]["response_body_sha256"]
    report["runtime_identity"]["services"]["juice-shop"]["image_id"] = "sha256:" + "0" * 64
    changed.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="identity"):
        prepare_validation_lab(source / "CandidateInventory.db",
                               source / "CandidateAnswerKey.db", changed, tmp_path / "fixture",
                               live_probe=_recorded_probe(source),
                               identity_probe=_recorded_identity(source))
