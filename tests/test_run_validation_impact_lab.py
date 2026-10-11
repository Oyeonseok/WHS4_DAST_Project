"""The impact lab must use the native brokered Development port."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aidast.validation.execution.native_impact import NativeImpactDevelopmentPort
from scripts.prepare_validation_lab import prepare_validation_lab


def test_impact_runner_selects_bounded_case_and_native_port(tmp_path: Path) -> None:
    from scripts.run_validation_impact_lab import build_impact_lab_coordinator
    root = Path(__file__).resolve().parents[1]
    source = root / "result/test-runs/validation-candidates"
    if not all((source / name).exists() for name in (
        "CandidateInventory.db", "CandidateAnswerKey.db", "LocalControlObservations.json"
    )):
        pytest.skip("local pinned lab observations are not available")
    report = json.loads((source / "LocalControlObservations.json").read_text())
    by_url = {item["url"]: item for item in report["observations"]}
    bundle = tmp_path / "impact"
    prepare_validation_lab(
        source / "CandidateInventory.db", source / "CandidateAnswerKey.db",
        source / "LocalControlObservations.json", bundle,
        live_probe=lambda url: (
            by_url[url]["observed_http_status"], by_url[url]["response_body_sha256"],
            by_url[url]["response_bytes"],
        ),
        identity_probe=lambda: report["runtime_identity"],
        impact_probe=True, impact_marker_probe=lambda url: (
            {"users", "password", "seeded_admin", "seeded_admin_account"},
            by_url[url]["response_body_sha256"],
        ),
    )

    coordinator, selected = build_impact_lab_coordinator(bundle)
    assert selected["candidate_id"] == "vuln-bank:curated:GET:/debug/users:excessive_data_exposure"
    assert isinstance(coordinator.impact_development_port, NativeImpactDevelopmentPort)
    assert coordinator.impact_development_port.policy_provider is not None
    assert coordinator.impact_development_port.policy_provider(
        "http://127.0.0.1:5001/debug/users", "GET"
    )
    assert coordinator.impact_precondition_verifier is not None
    from aidast.validation.core.integrity import CandidateIntegrityGate
    import sqlite3
    from scripts.run_validation_impact_lab import verify_impact_lab_preconditions
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        candidate = CandidateIntegrityGate(conn).validate_finding(
            case_id="preflight-impact", scan_id=selected["scan_id"],
            finding_id=selected["finding_id"],
        )
    digest = by_url["http://127.0.0.1:5001/debug/users"]["response_body_sha256"]
    request = SimpleNamespace(
        path_id="bounded-impact-confirmation",
        required_preconditions=(
            "An exact same-origin safe-method request already captured by Attack",
            "A unique non-secret configuration or data marker for the stronger impact",
        ),
    )
    receipt = verify_impact_lab_preconditions(candidate, request, probe=lambda url: (
        {"users", "password", "seeded_admin", "seeded_admin_account"}, digest,
    ))
    assert receipt["details"]["marker_assertion_expected"] == "ADMIN001"
    assert receipt["details"]["marker_json_path"] == ["users", 0, "account_number"]
    assert receipt["source_request_ids"] == [candidate.impact_development_actions[0].precondition_observation.source_request_id]
    with pytest.raises(ValueError, match="precondition"):
        verify_impact_lab_preconditions(candidate, request, probe=lambda url: (
            {"users", "password", "seeded_admin", "seeded_admin_account"}, "f" * 64,
        ))


def test_impact_runner_rejects_standard_bundle(tmp_path: Path) -> None:
    from scripts.run_validation_impact_lab import build_impact_lab_coordinator
    bundle = tmp_path / "standard"
    bundle.mkdir()
    (bundle / "CandidateFindingMap.json").write_text(json.dumps({"cases": []}))
    with pytest.raises(ValueError, match="impact lab"):
        build_impact_lab_coordinator(bundle)
