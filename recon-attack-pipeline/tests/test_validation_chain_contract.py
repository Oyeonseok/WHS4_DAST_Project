"""Demonstrated-chain runtime contract and fresh value-transfer tests."""

import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import start_stage_run
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (BlindCase, ChainReproductionPort,
                               ChainRuntimeContract, ValidationRepository,
                               validate_runtime_contract)


def http_attempt(path_parameters, *, expected):
    return {
        "request": {"path_parameters": path_parameters},
        "assertions": [{
            "assertion_id": "body", "kind": "body_contains", "expected": expected,
        }],
    }


class Response:
    status = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, body):
        self.body = body

    def read(self, maximum):
        return self.body

    def close(self):
        pass


class ValidationChainContractTests(unittest.TestCase):
    def contract(self):
        source = http_attempt({}, expected="fresh-7")
        target = http_attempt({"id": "placeholder"}, expected="private")
        return ChainRuntimeContract(
            runtime_kind="chain", schema_version=1,
            steps=[
                {"position": 0, "endpoint": "https://test/token", "method": "GET",
                 "runtime_contract": {"schema_version": 1, "target": source,
                                      "positive_control": source, "negative_control": source}},
                {"position": 1, "endpoint": "https://test/items/{id}", "method": "GET",
                 "runtime_contract": {"schema_version": 1, "target": target,
                                      "positive_control": target, "negative_control": target}},
            ],
            bindings=[{
                "binding_name": "object_id", "from_position": 0, "to_position": 1,
                "source_kind": "json_path", "source_path": ["id"],
                "target_kind": "path_parameter", "target_path": ["id"],
            }],
        )

    def test_contract_is_dispatched_and_requires_explicit_adjacent_binding(self):
        contract = self.contract()
        self.assertIsInstance(
            validate_runtime_contract(contract.model_dump(mode="json")), ChainRuntimeContract,
        )
        invalid = contract.model_dump(mode="json")
        invalid["bindings"] = []
        with self.assertRaises(ValueError):
            ChainRuntimeContract.model_validate(invalid)

    def test_adapter_extracts_fresh_response_value_and_injects_next_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Pipeline.db"
            conn = db.init_db(path)
            self.addCleanup(conn.close)
            db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
            asset = db.insert_asset(conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
            origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="test", port=443,
                                      base_url="https://test")
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES ('endpoint',?,'GET','/items/{id}')", (origin,))
            conn.execute("INSERT INTO finding_chains(chain_id,scan_id,title,combined_severity,status) VALUES ('chain','scan','fixture','HIGH','demonstrated')")
            stage = start_stage_run(conn, scan_id="scan", stage="validation", stage_run_id="stage")
            repo = ValidationRepository(conn)
            repo.create_case(scan_id="scan", stage_run_id=stage, target_kind="chain",
                             target_id="chain", case_id="case")
            repo.add_attempt(case_id="case", stage_run_id=stage, batch_no=1,
                             attempt_kind="target", ordinal=1, signal_type="response_diff",
                             outcome="error", finished=False, attempt_id="attempt")
            policy = TargetPolicy(
                asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
                allowed_hosts=["test"], allowed_ports=[443], allowed_path_prefixes=["/"],
                allowed_methods=["GET"], limits=PolicyLimits(requests_per_second=50),
                tools=ToolPolicy(), scope_id="scope", policy_id="policy",
            )
            blind = BlindCase(
                case_id="case", target_kind="chain", endpoint="https://test/items/{id}",
                method="GET", injection_location="path", parameter_name="id",
                payload_template={}, required_identity_roles=(), credential_references=(),
                signal_types=("response_diff",), controls={}, attack_skill_name="chain",
                attack_skill_sha256="a" * 64, validation_skill_sha256="b" * 64,
                validation_profile_sha256="c" * 64,
                runtime_contract=self.contract().model_dump(mode="json"),
            )
            requested = []

            def transport(request, timeout):
                requested.append(request.full_url)
                return Response(b'{"id":"fresh-7"}' if request.full_url.endswith("/token")
                                else b'{"result":"private"}')

            result = ChainReproductionPort(transport=transport).execute(
                blind, attempt_kind="target", batch_no=1, ordinal=1,
                attempt_id="attempt", db_path=path, scan_id="scan",
                stage_run_id="stage", case_id="case", policy=policy,
            )
            self.assertTrue(result.signal_observed)
            self.assertEqual(requested, ["https://test/token", "https://test/items/fresh-7"])
            self.assertNotIn("fresh-7", str(result.details))
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM validation_http_requests WHERE status='completed'"
            ).fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
