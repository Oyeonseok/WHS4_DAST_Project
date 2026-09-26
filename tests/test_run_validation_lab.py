"""The ordinary lab runner must execute verified Impact paths in the same bundle."""

import json
from pathlib import Path
from types import SimpleNamespace

from aidast.validation.execution.native_impact import NativeImpactDevelopmentPort


def test_standard_lab_runner_wires_declared_impact_fixture(tmp_path: Path, monkeypatch) -> None:
    from scripts import run_validation_lab
    from scripts.run_validation_impact_lab import verify_impact_lab_preconditions

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    candidate = {
        "candidate_id": "vuln-bank:curated:GET:/debug/users:excessive_data_exposure",
        "scan_id": "scan", "finding_id": "finding",
    }
    (bundle / "CandidateFindingMap.json").write_text(json.dumps({
        "fixture_kind": "synthetic_attack_claims_for_validation_only",
        "cases": [candidate], "impact_lab": candidate,
    }))
    captured = {}

    class FakeCoordinator:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self, scan_id, *, finding_id):
            return SimpleNamespace(stage_run_id="stage", summary={"statuses": {"CONFIRMED": 1}})

    monkeypatch.setattr(run_validation_lab, "load_lab_negative_proofs", lambda **kwargs: {})
    monkeypatch.setattr(run_validation_lab, "TargetPolicyProvider", lambda path: object())
    monkeypatch.setattr(run_validation_lab, "ValidationCoordinator", FakeCoordinator)
    results = run_validation_lab.run_lab(bundle=bundle, candidate_root=tmp_path)

    assert results[0]["statuses"] == {"CONFIRMED": 1}
    assert isinstance(captured["impact_development_port"], NativeImpactDevelopmentPort)
    assert captured["impact_precondition_verifier"] is verify_impact_lab_preconditions
    assert captured["reproduction"].__class__.__name__ == "LabNegativeProofHttpPort"
