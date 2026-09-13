"""Validation request safety and per-hop ledger tests."""

import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import start_stage_run
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (BlindCase, ValidationRepository, ValidationRequestBroker,
                               ValidationRequestError, HttpReproductionPort)


class Response:
    status = 200
    headers = {"Content-Type": "text/plain", "Set-Cookie": "secret"}

    def read(self, maximum):
        return b"ok"

    def close(self):
        pass


class ValidationRequestBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "Pipeline.db"
        self.conn = db.init_db(self.path)
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES ('endpoint',?,'GET','/items/{id}')", (origin,))
        self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES ('finding','scan','endpoint','idor','LOW','fixture')")
        self.stage = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="stage")
        repo = ValidationRepository(self.conn)
        repo.create_case(scan_id="scan", stage_run_id=self.stage, target_kind="finding",
                         target_id="finding", case_id="case")
        self.attempt = repo.add_attempt(
            case_id="case", stage_run_id=self.stage, batch_no=1, attempt_kind="target",
            ordinal=1, signal_type="response_diff", outcome="error", finished=False,
            attempt_id="attempt",
        )
        self.policy = TargetPolicy(
            asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
            allowed_hosts=["test"], allowed_ports=[443], allowed_path_prefixes=["/items"],
            allowed_methods=["GET"], limits=PolicyLimits(requests_per_second=50),
            tools=ToolPolicy(), scope_id="scope", policy_id="policy",
        )
        self.blind = BlindCase(
            case_id="case", target_kind="finding", endpoint="https://test/items/{id}",
            method="GET", injection_location="path", parameter_name="id",
            payload_template={"id": "<slot:int>"}, required_identity_roles=("user",),
            credential_references=("credential",), signal_types=("response_diff",), controls={},
            attack_skill_name="hunt-idor", attack_skill_sha256="a" * 64,
            validation_skill_sha256="b" * 64, validation_profile_sha256="c" * 64,
        )

    def broker(self):
        return ValidationRequestBroker(
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=self.blind, policy=self.policy,
            transport=lambda request, timeout: Response(),
            credential_resolver=lambda reference: {"Authorization": "Bearer private"},
            sleeper=lambda delay: None, clock=lambda: 100.0,
        )

    def test_request_is_policy_checked_and_persists_redacted_ledger(self):
        result = self.broker().request("https://test/items/7?token=private", method="GET")
        self.assertEqual(result.body, b"ok")
        row = self.conn.execute(
            "SELECT status,url,result_json,policy_sha256 FROM validation_http_requests"
        ).fetchone()
        self.assertEqual(row[0], "completed")
        self.assertEqual(row[1], "https://test/items/7?token=%5BREDACTED%5D")
        self.assertNotIn("private", row[2])
        self.assertEqual(len(row[3]), 64)

    def test_staged_method_and_path_cannot_be_broadened(self):
        broker = self.broker()
        with self.assertRaises(ValidationRequestError):
            broker.request("https://test/admin", method="GET")
        with self.assertRaises(ValidationRequestError):
            broker.request("https://test/items/7", method="POST")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM validation_http_requests").fetchone()[0], 0)

    def test_http_reproduction_adapter_receives_runtime_context_and_writes_ledger(self):
        port = HttpReproductionPort(
            request_builder=lambda blind, kind, batch, ordinal: (
                "https://test/items/7", {}, None
            ),
            evaluator=lambda kind, response: {
                "signal_observed": True, "comparison": "different"
            },
            transport=lambda request, timeout: Response(),
            credential_resolver=lambda reference: {"Authorization": "Bearer private"},
        )
        result = port.execute(
            self.blind, attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id="attempt", db_path=self.path, scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(result.details["request_ids"].__len__(), 1)
        self.assertEqual(self.conn.execute(
            "SELECT status FROM validation_http_requests"
        ).fetchone()[0], "completed")


if __name__ == "__main__":
    unittest.main()
