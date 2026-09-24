"""The impact lab must use the native brokered Development port."""

import json
from pathlib import Path

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
            {"users", "password", "seeded_admin"}, by_url[url]["response_body_sha256"],
        ),
    )

    coordinator, selected = build_impact_lab_coordinator(bundle)
    assert selected["candidate_id"] == "vuln-bank:curated:GET:/debug/users:excessive_data_exposure"
    assert isinstance(coordinator.impact_development_port, NativeImpactDevelopmentPort)
    assert coordinator.impact_development_port.policy_provider is not None
    assert coordinator.impact_development_port.policy_provider(
        "http://127.0.0.1:5001/debug/users", "GET"
    )


def test_impact_runner_rejects_standard_bundle(tmp_path: Path) -> None:
    from scripts.run_validation_impact_lab import build_impact_lab_coordinator
    bundle = tmp_path / "standard"
    bundle.mkdir()
    (bundle / "CandidateFindingMap.json").write_text(json.dumps({"cases": []}))
    with pytest.raises(ValueError, match="impact lab"):
        build_impact_lab_coordinator(bundle)
