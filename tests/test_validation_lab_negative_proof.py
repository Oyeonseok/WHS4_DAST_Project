"""Independent source and response gates for bounded lab negative evidence."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from aidast.validation import BlindCase, ReproductionObservation, canonical_sha256

from scripts.validation_lab_negative_proof import (
    LabNegativeProof, LabNegativeProofHttpPort, is_bounded_negative_response,
    load_lab_negative_proofs,
    verify_route_source,
)


def _blind(*, kind: str = "auth_denial") -> BlindCase:
    runtime = {
        "schema_version": 1,
        "target": {"request": (
            {} if kind == "auth_denial" else
            {"path_parameters": {"category_id": "1' OR 1=1"}}
        ), "assertions": [{"assertion_id": "effect", "kind": "body_contains", "expected": "secret"}]},
        "positive_control": {"request": {}, "assertions": []},
        "negative_control": {"request": {}, "assertions": []},
    }
    return BlindCase(
        case_id="case", target_kind="finding",
        endpoint="http://127.0.0.1:5001/api/billers/by-category/{category_id}"
        if kind == "integer_route" else "http://127.0.0.1:3001/api/Users",
        method="GET", injection_location="path" if kind == "integer_route" else "query",
        parameter_name="category_id" if kind == "integer_route" else "probe",
        payload_template={}, required_identity_roles=(), credential_references=(),
        signal_types=("error_signature",) if kind == "integer_route" else ("authorization_boundary",),
        controls={}, runtime_contract=runtime,
        attack_skill_name="hunt-sqli" if kind == "integer_route" else "hunt-auth-bypass",
        attack_skill_sha256="a" * 64, validation_skill_sha256="b" * 64,
        validation_profile_sha256="c" * 64,
    )


def _proof(blind: BlindCase, *, kind: str = "auth_denial") -> LabNegativeProof:
    return LabNegativeProof(
        candidate_id="case", scan_id="scan", endpoint=blind.endpoint,
        attack_skill_name=blind.attack_skill_name,
        runtime_sha256=canonical_sha256(blind.runtime_contract),
        target_url=("http://127.0.0.1:3001/api/Users" if kind == "auth_denial" else
                    "http://127.0.0.1:5001/api/billers/by-category/1%27%20OR%201%3D1"),
        expected_status=401 if kind == "auth_denial" else 404,
        proof_kind=kind, source_sha256="d" * 64,
        source_line=12, source_anchor="pinned route guard",
    )


def _observation(proof: LabNegativeProof) -> ReproductionObservation:
    return ReproductionObservation(
        outcome="not_observed", signal_type="authorization_boundary"
        if proof.proof_kind == "auth_denial" else "error_signature",
        signal_observed=False,
        details={"response_status": proof.expected_status,
                 "response_url": proof.target_url,
                 "response_body_sha256": "e" * 64},
        content_sha256="e" * 64, content_length=12,
    )


def test_source_rule_requires_the_exact_guard_or_integer_route() -> None:
    assert verify_route_source(
        "app.get('/api/Users', security.isAuthorized())\n", 1,
        "app.get('/api/Users', security.isAuthorized())", "auth_denial", "/api/Users",
    )
    assert not verify_route_source(
        "app.get('/api/Users', security.allowAll())\n", 1,
        "app.get('/api/Users', security.isAuthorized())", "auth_denial", "/api/Users",
    )
    source = "@app.route('/api/billers/by-category/<int:category_id>', methods=['GET'])\n" \
             "def billers(category_id):\n    query = f'WHERE category_id = {category_id}'\n"
    assert verify_route_source(
        source, 1, "WHERE category_id = {category_id}", "integer_route",
        "/api/billers/by-category/<int:category_id>",
    )
    assert not verify_route_source(
        source.replace("<int:category_id>", "<category_id>"), 1,
        "WHERE category_id = {category_id}", "integer_route",
        "/api/billers/by-category/<int:category_id>",
    )


def test_negative_response_requires_exact_case_control_hash_and_absent_signal() -> None:
    blind = _blind()
    proof = _proof(blind)
    observed = _observation(proof)
    assert is_bounded_negative_response(proof, blind, observed, "e" * 64, "scan")
    assert not is_bounded_negative_response(proof, blind, observed, "f" * 64, "scan")
    assert not is_bounded_negative_response(proof, blind, observed, "e" * 64, "other")
    assert not is_bounded_negative_response(
        proof, blind, observed.model_copy(update={"signal_observed": True}), "e" * 64, "scan"
    )
    assert not is_bounded_negative_response(
        proof, blind.model_copy(update={"runtime_contract": {
            **blind.runtime_contract,
            "target": {**blind.runtime_contract["target"],
                       "request": {"headers": {"Authorization": "Bearer token"}}},
        }}), observed, "e" * 64, "scan"
    )


def test_integer_route_proof_requires_noninteger_payload() -> None:
    blind = _blind(kind="integer_route")
    proof = _proof(blind, kind="integer_route")
    observed = _observation(proof)
    assert is_bounded_negative_response(proof, blind, observed, "e" * 64, "scan")
    numeric = blind.model_copy(update={"runtime_contract": {
        **blind.runtime_contract,
        "target": {**blind.runtime_contract["target"],
                   "request": {"path_parameters": {"category_id": "1"}}},
    }})
    assert not is_bounded_negative_response(proof, numeric, observed, "e" * 64, "scan")


def test_port_marks_targets_only_after_matching_inert_control() -> None:
    blind = _blind()
    proof = _proof(blind)
    observation = _observation(proof)
    port = LabNegativeProofHttpPort({("scan", blind.endpoint): proof})
    context = {"batch_no": 1, "ordinal": 1, "attempt_id": "attempt", "db_path": Path("unused"),
               "scan_id": "scan", "stage_run_id": "stage", "case_id": "case", "policy": None}
    with patch("scripts.validation_lab_negative_proof.HttpReproductionPort.execute",
               return_value=observation):
        early = port.execute(blind, attempt_kind="target", **context)
        control = port.execute(blind, attempt_kind="negative_control", **context)
        target = port.execute(blind, attempt_kind="target", **context)
    assert not early.explicit_non_exploit
    assert not control.explicit_non_exploit
    assert target.explicit_non_exploit
    assert target.details["bounded_negative_proof"]["source_sha256"] == proof.source_sha256
    assert target.details["bounded_negative_proof"]["source_line"] == 12
    assert target.details["bounded_negative_proof"]["source_anchor"] == "pinned route guard"
    assert target.details["bounded_negative_proof"]["negative_control_digest"] == "e" * 64


def test_lab_loader_verifies_pinned_sources_and_runtime_identity(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    candidates = root / "result/test-runs/validation-candidates"
    bundle = candidates / "validation-lab-classification-v2"
    required = [candidates / "CandidateInventory.db",
                candidates / "LocalControlObservations.json",
                bundle / "CandidateFindingMap.json", bundle / "Pipeline.db"]
    if not all(path.exists() for path in required):
        pytest.skip("isolated local Validation lab fixture is not installed")
    identity = json.loads(required[1].read_text())["runtime_identity"]
    paths = {
        "juice-shop": root / "resources/lab/juice-shop-v20.2.0-server.ts",
        "vuln-bank": root / "result/lab/vuln-bank/app.py",
    }
    def load(**kwargs):
        return load_lab_negative_proofs(
            inventory_path=required[0], observations_path=required[1],
            mapping_path=required[2], pipeline_path=required[3],
            source_files=paths, **kwargs,
        )

    assert len(load(identity_probe=lambda: identity)) == 6
    with pytest.raises(ValueError, match="runtime identity"):
        load(identity_probe=lambda: {})
    altered = tmp_path / "app.py"
    altered.write_bytes(paths["vuln-bank"].read_bytes() + b"\n# changed\n")
    paths["vuln-bank"] = altered
    with pytest.raises(ValueError, match="source digest mismatch"):
        load(identity_probe=lambda: identity)
