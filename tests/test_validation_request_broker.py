"""Validation request safety and per-hop ledger tests."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aidast.pipeline.browser_credentials import register_browser_session_credentials
from aidast.pipeline.lifecycle import start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (BlindCase, HttpReproductionPort, HttpRuntimeContract,
                               OobReproductionPort, OobRuntimeContract,
                               ScopePolicySource,
                               ValidationRepository, ValidationRequestBroker,
                               ValidationRequestError)


class Response:
    status = 200
    headers = {"Content-Type": "text/plain", "Set-Cookie": "secret"}

    def read(self, maximum):
        return b"ok"

    def close(self):
        pass


class OobObserverFixture:
    def __init__(self):
        self.armed = []

    def arm(self, token):
        self.armed.append(token)

    def poll(self, token, *, wait_seconds):
        return {"events": [
            {"token": "stale.cb.invalid", "protocol": "dns"},
            {"token": token, "protocol": "dns"},
        ]}


class ValidationRequestBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "Pipeline.db"
        self.conn = db.init_db(self.path)
        migrate_live_pipeline_schema(self.conn)
        migrate_live_pipeline_schema(self.conn)
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES ('endpoint',?,'GET','/items/{id}')", (origin,))
        self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES ('finding','scan','endpoint','idor','LOW','fixture')")
        self.stage = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="stage")
        repo = ValidationRepository(self.conn)
        scope_sha256 = repo.bind_scope(
            "scan", ScopePolicySource.from_text("# Policy\nRule", source_path="fixture")
        )
        repo.create_case(scan_id="scan", stage_run_id=self.stage, target_kind="finding",
                         target_id="finding", scope_sha256=scope_sha256, case_id="case")
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
            credential_references=("credential",), signal_types=("response_diff",),
            attack_skill_name="hunt-idor", attack_skill_sha256="a" * 64,
            validation_skill_sha256="b" * 64, validation_profile_sha256="c" * 64,
        )

    def test_native_http_preflight_accepts_registered_browser_session(self):
        from aidast.validation import build_native_validation_coordinator

        snapshot = Path(self.temp.name) / "browser.json"
        snapshot.write_text(json.dumps({"cookies": [], "origins": [{
            "origin": "https://test", "localStorage": [
                {"name": "token", "value": "header.payload.signature"},
            ],
        }]}), encoding="utf-8")
        result_root = Path(self.temp.name) / "result"
        reference = register_browser_session_credentials(
            self.conn, scan_id="scan", result_root=result_root,
            sessions=[("https://test/", snapshot, True)],
        )[0]["credential_reference_id"]
        policy_path = Path(self.temp.name) / "TargetPolicy.json"
        policy_path.write_text(json.dumps({
            "policies": [self.policy.model_dump(mode="json")],
        }), encoding="utf-8")
        with patch("aidast.validation.execution.credentials.RESULT_ROOT", result_root):
            coordinator = build_native_validation_coordinator(
                db_path=self.path, policy_path=policy_path,
            )
            case = self.blind.model_copy(update={
                "endpoint": "https://test/items/7",
                "credential_references": (reference,), "runtime_contract": {},
            })
            self.assertIsNone(coordinator.reproduction.http.unsupported_reason(case))

    def test_browser_session_headers_resolve_for_dispatched_url(self):
        from aidast.validation.execution.credentials import PipelineCredentialResolver

        snapshot = Path(self.temp.name) / "browser.json"
        snapshot.write_text(json.dumps({"cookies": [], "origins": [{
            "origin": "https://test", "localStorage": [
                {"name": "token", "value": "header.payload.signature"},
            ],
        }]}), encoding="utf-8")
        result_root = Path(self.temp.name) / "result"
        reference = register_browser_session_credentials(
            self.conn, scan_id="scan", result_root=result_root,
            sessions=[("https://test/", snapshot, True)],
        )[0]["credential_reference_id"]
        seen = []
        broker = ValidationRequestBroker(
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=self.blind.model_copy(update={
                "credential_references": (reference,),
            }), policy=self.policy,
            transport=lambda request, timeout: seen.append(request) or Response(),
            credential_resolver=PipelineCredentialResolver(
                self.path, result_root=result_root, browser_sessions=True,
            ),
        )
        self.assertEqual(broker.request("https://test/items/7", method="GET").body, b"ok")
        self.assertEqual(seen[0].get_header("Authorization"),
                         "Bearer header.payload.signature")

    def test_browser_replay_uses_registered_session_for_navigation(self):
        from aidast.validation import BrowserReproductionPort, BrowserRuntimeContract
        from aidast.validation.execution.credentials import PipelineCredentialResolver

        snapshot = Path(self.temp.name) / "browser.json"
        snapshot.write_text(json.dumps({"cookies": [], "origins": [{
            "origin": "https://test", "localStorage": [
                {"name": "token", "value": "header.payload.signature"},
            ],
        }]}), encoding="utf-8")
        result_root = Path(self.temp.name) / "result"
        reference = register_browser_session_credentials(
            self.conn, scan_id="scan", result_root=result_root,
            sessions=[("https://test/", snapshot, True)],
        )[0]["credential_reference_id"]
        attempt = {"navigation": {}, "wait_ms": 10, "assertions": [{
            "assertion_id": "marker", "kind": "console_contains", "expected": "marker",
        }]}
        contract = BrowserRuntimeContract.model_validate({
            "runtime_kind": "browser", "schema_version": 1,
            "target": attempt, "positive_control": attempt, "negative_control": attempt,
        })
        case = self.blind.model_copy(update={
            "endpoint": "https://test/items/7", "credential_references": (reference,),
            "runtime_contract": contract.model_dump(mode="json"),
        })
        seen = []
        def executor(**kwargs):
            seen.append(kwargs)
            return {"final_url": kwargs["url"], "elements": {},
                    "console_messages": ["marker"], "request_ids": ["browser-request"]}
        port = BrowserReproductionPort(
            executor=executor,
            credential_resolver=PipelineCredentialResolver(
                self.path, result_root=result_root, browser_sessions=True,
            ),
        )
        self.assertIsNone(port.unsupported_reason(case))
        result = port.execute(
            case, attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id="attempt", db_path=self.path, scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(seen[0]["headers"]["Authorization"],
                         "Bearer header.payload.signature")

    def test_login_session_verification_uses_fresh_token_and_redacts_ledger(self):
        from aidast.validation.execution.http_adapter import HttpReproductionPort
        from aidast.validation.contracts.runtime_contract import HttpRuntimeContract

        for protected_status, token_present in (
                (200, True), (401, True), (200, False)):
            with self.subTest(status=protected_status, token=token_present):
                calls = []

                def transport(request, timeout):
                    calls.append(request)
                    response = Response()
                    response.status = protected_status if len(calls) == 2 else 200
                    body = (b'{"user":{"id":7}}' if len(calls) == 2 else
                            b'{"authentication":{"token":"private-fresh-token"}}' if token_present else
                            b'{"authentication":{}}')
                    response.read = lambda maximum: body
                    return response

                attempt = {"request": {}, "assertions": [{
                    "assertion_id": "login", "kind": "body_contains", "expected": '"authentication"',
                }]}
                runtime = HttpRuntimeContract.model_validate({
                    "schema_version": 1, "target": attempt, "positive_control": attempt,
                    "negative_control": attempt,
                    "session_verification": {
                        "endpoint_template": "/items/session", "token_path": ["authentication", "token"],
                        "request": {}, "assertions": [
                            {"assertion_id": "protected-status", "kind": "status_equals", "expected": 200},
                            {"assertion_id": "account", "kind": "json_equals", "path": ["user", "id"], "expected": 7},
                        ],
                    },
                })
                blind = self.blind.model_copy(update={
                    "endpoint": "https://test/items/login", "credential_references": (),
                    "runtime_contract": runtime.model_dump(mode="json"),
                })
                result = HttpReproductionPort(transport=transport).execute(
                    blind, attempt_kind="target", batch_no=1, ordinal=1,
                    attempt_id=self.attempt, db_path=self.path, scan_id="scan",
                    stage_run_id=self.stage, case_id="case", policy=self.policy,
                )
                proof = result.details["protected_access"]
                from aidast.validation.persistence.evidence_policy import sanitize_metadata
                self.assertIsInstance(sanitize_metadata(result.details)["protected_access"], dict)
                repo = ValidationRepository(self.conn)
                evidence_id = repo.add_evidence(
                    case_id="case", stage_run_id=self.stage, attempt_id=self.attempt,
                    evidence_kind="observation", details=result.details,
                    content_sha256=result.content_sha256, content_length=result.content_length,
                )
                stored = json.loads(self.conn.execute(
                    "SELECT details_json FROM validation_evidence WHERE evidence_id=?", (evidence_id,),
                ).fetchone()[0])
                self.assertEqual(stored["protected_access"]["verified"], proof["verified"])
                self.assertEqual(proof["verified"], token_present and protected_status == 200)
                self.assertEqual(len(calls), 2 if token_present else 1)
                if token_present:
                    self.assertEqual(calls[1].get_header("Authorization"), "Bearer private-fresh-token")
                self.assertTrue(result.signal_observed)
                self.assertNotIn("private-fresh-token", result.model_dump_json())
                rows = self.conn.execute("SELECT result_json FROM validation_http_requests").fetchall()
                self.assertNotIn("private-fresh-token", str(rows))

    def broker(self):
        return ValidationRequestBroker(
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=self.blind, policy=self.policy,
            transport=lambda request, timeout: Response(),
            credential_resolver=lambda reference: {"Authorization": "Bearer private"},
            sleeper=lambda delay: None, clock=lambda: 100.0,
        )

    def test_target_replay_uses_case_credentials_once(self):
        calls, resolutions = [], []
        proof = [{"assertion_id": "effect", "kind": "body_contains", "expected": "ok"}]
        runtime = HttpRuntimeContract.model_validate({
            "schema_version": 1,
            "target": {"request": {"path_parameters": {"id": 1}}, "assertions": proof},
            "positive_control": {"request": {"path_parameters": {"id": 1}}, "assertions": proof},
            "negative_control": {"identity_mode": "anonymous", "request": {"path_parameters": {"id": 1}}, "assertions": proof},
        })
        blind = self.blind.model_copy(update={"runtime_contract": runtime.model_dump(mode="json")})
        def resolve(reference):
            resolutions.append(reference)
            return {"Authorization": "Bearer private", "Cookie": "login=private"}
        def transport(request, timeout):
            calls.append(request)
            return Response()
        port = HttpReproductionPort(transport=transport, credential_resolver=resolve)
        port.execute(blind, attempt_kind="target", batch_no=1, ordinal=1,
                     attempt_id=self.attempt, db_path=self.path, scan_id="scan",
                     stage_run_id=self.stage, case_id="case", policy=self.policy)
        self.assertEqual(resolutions, ["credential"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer private")
        self.assertEqual(calls[0].get_header("Cookie"), "login=private")

    def test_target_can_select_one_identity_without_header_collision(self):
        calls, resolutions = [], []
        proof = [{"assertion_id": "effect", "kind": "body_contains", "expected": "ok"}]
        runtime = HttpRuntimeContract.model_validate({
            "schema_version": 1,
            "target": {"request": {"path_parameters": {"id": 7}}, "assertions": proof,
                       "credential_roles": ["identity_a"]},
            "positive_control": {"request": {"path_parameters": {"id": 7}}, "assertions": proof,
                                 "credential_roles": ["identity_b"]},
            "negative_control": {"request": {"path_parameters": {"id": 7}}, "assertions": proof,
                                 "identity_mode": "anonymous"},
        })
        blind = self.blind.model_copy(update={
            "required_identity_roles": ("identity_a", "identity_b"),
            "credential_references": ("credential-a", "credential-b"),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        def resolve(reference):
            resolutions.append(reference)
            return {"Authorization": "Bearer " + reference}
        def transport(request, timeout):
            calls.append(request.get_header("Authorization"))
            return Response()
        port = HttpReproductionPort(transport=transport, credential_resolver=resolve)
        port.execute(blind, attempt_kind="target", batch_no=1, ordinal=1,
                     attempt_id=self.attempt, db_path=self.path, scan_id="scan",
                     stage_run_id=self.stage, case_id="case", policy=self.policy)
        self.assertEqual(resolutions, ["credential-a"])
        self.assertEqual(calls, ["Bearer credential-a"])

    def test_legacy_negative_control_endpoint_is_never_dispatched(self):
        calls = []
        proof = [{"assertion_id": "effect", "kind": "body_contains", "expected": "secret"}]
        runtime = HttpRuntimeContract.model_validate({
            "schema_version": 1,
            "target": {"request": {"path_parameters": {"id": 1}}, "assertions": proof},
            "positive_control": {"request": {"path_parameters": {"id": 1}}, "assertions": proof},
            "negative_control": {
                "endpoint_template": "/items/__aidast_negative_control_missing__",
                "request": {}, "assertions": proof,
            },
        })
        blind = self.blind.model_copy(update={
            "credential_references": (),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        def transport(request, timeout):
            calls.append(request.full_url)
            response = Response()
            response.status = 404
            response.read = lambda maximum: b"missing"
            return response
        HttpReproductionPort(transport=transport).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id=self.attempt, db_path=self.path, scan_id="scan",
            stage_run_id=self.stage, case_id="case", policy=self.policy,
        )
        self.assertEqual(calls, ["https://test/items/1"])

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

    def test_hackerone_identity_header_is_added_after_runtime_and_credentials(self):
        captured = []

        def transport(request, timeout):
            captured.append(dict(request.header_items()))
            return Response()

        self.policy = self.policy.model_copy(update={
            "hackerone_username": "trusted_hacker",
        })
        broker = ValidationRequestBroker(
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=self.blind, policy=self.policy,
            transport=transport,
            credential_resolver=lambda reference: {"X-HackerOne": "credential-value"},
            sleeper=lambda delay: None, clock=lambda: 100.0,
        )

        broker.request(
            "https://test/items/7", method="GET",
            headers={"x-hackerone": "runtime-value"},
        )

        self.assertEqual(captured[0]["X-hackerone"], "trusted_hacker")

    def test_staged_method_and_path_cannot_be_broadened(self):
        broker = self.broker()
        with self.assertRaises(ValidationRequestError):
            broker.request("https://test/admin", method="GET")
        with self.assertRaises(ValidationRequestError):
            broker.request("https://test/items/7", method="POST")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM validation_http_requests").fetchone()[0], 0)

    def test_transport_reservations_consume_legacy_request_and_concurrency_budgets(self):
        from aidast.validation.execution.transport_broker import (
            TransportOperationSpec, ValidationTransportBroker,
        )
        transport = ValidationTransportBroker(
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            attempt_id="attempt", blind_case=self.blind, policy=self.policy,
        )
        transport.reserve(TransportOperationSpec(
            runtime_kind="multipart", operation_kind="request",
            destination="https://test/items/0", policy_url="https://test/items/0",
            method="GET", request_bytes=1, max_response_bytes=1,
        ))
        for limits, message in ((PolicyLimits(max_requests=1), "budget exhausted"),
                                (PolicyLimits(concurrency=1), "concurrency")):
            self.policy = self.policy.model_copy(update={"limits": limits})
            with self.subTest(message=message), self.assertRaisesRegex(ValidationRequestError, message):
                self.broker().request("https://test/items/0", method="GET")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM validation_http_requests").fetchone()[0], 0)

    def test_scope_authorized_mutation_uses_validation_authority(self):
        self.policy = self.policy.model_copy(update={
            "attack_allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Active security testing is allowed.",
        })
        self.blind = self.blind.model_copy(update={"method": "POST"})

        result = self.broker().request(
            "https://test/items/7", method="POST", data=b"fixture"
        )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(
            tuple(self.conn.execute(
                "SELECT method,status FROM validation_http_requests"
            ).fetchone()),
            ("POST", "completed"),
        )

    def test_browser_transport_can_ledger_policy_allowed_subresources(self):
        broker = self.broker()
        request_id = broker.begin_observed_request(
            "https://test/items/app.js", method="GET",
            headers={"Authorization": "Bearer private"},
        )
        broker.complete_observed_request(
            request_id, response_status=200,
            response_headers={"Set-Cookie": "private"},
        )
        row = self.conn.execute(
            "SELECT status,url,result_json FROM validation_http_requests"
        ).fetchone()
        self.assertEqual(row[:2], ("completed", "https://test/items/app.js"))
        self.assertNotIn("private", row[2])
        with self.assertRaises(ValidationRequestError):
            broker.begin_observed_request("https://other.test/app.js", method="GET")

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

    def test_http_reproduction_adapter_executes_staged_runtime_contract(self):
        attempt = {
            "request": {"path_parameters": {"id": 7}},
            "assertions": [{
                "assertion_id": "body-marker", "kind": "body_contains", "expected": "ok",
            }],
        }
        contract = HttpRuntimeContract(
            schema_version=1, target=attempt,
            positive_control=attempt, negative_control=attempt,
        )
        blind = self.blind.model_copy(update={
            "runtime_contract": contract.model_dump(mode="json"),
        })
        result = HttpReproductionPort(
            transport=lambda request, timeout: Response(),
            credential_resolver=lambda reference: {"Authorization": "Bearer private"},
        ).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id="attempt", db_path=self.path, scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(self.conn.execute(
            "SELECT url FROM validation_http_requests ORDER BY created_at DESC LIMIT 1"
        ).fetchone()[0], "https://test/items/7")

    def test_oob_adapter_arms_unique_token_before_policy_checked_trigger(self):
        attempt = {
            "trigger": {
                "path_parameters": {"id": 7},
                "query_parameters": {
                    "callback": "https://{nonce}.cb.invalid",
                },
            },
            "token_template": "https://{nonce}.cb.invalid",
            "protocols": ["dns"],
            "minimum_callbacks": 1,
            "wait_seconds": 0,
        }
        contract = OobRuntimeContract(
            runtime_kind="oob", schema_version=1, target=attempt,
            positive_control=attempt, negative_control=attempt,
        )
        blind = self.blind.model_copy(update={
            "signal_types": ("oob_callback",),
            "runtime_contract": contract.model_dump(mode="json"),
        })
        observer = OobObserverFixture()
        result = OobReproductionPort(
            observer=observer, transport=lambda request, timeout: Response(),
            credential_resolver=lambda reference: {"Authorization": "Bearer private"},
        ).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1,
            attempt_id="attempt", db_path=self.path, scan_id="scan",
            stage_run_id="stage", case_id="case", policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(len(observer.armed), 1)
        self.assertNotIn(observer.armed[0], str(result.details))
        row = self.conn.execute(
            "SELECT status,url FROM validation_http_requests"
        ).fetchone()
        self.assertEqual(row[0], "completed")
        self.assertIn("callback=%5BREDACTED%5D", row[1])


if __name__ == "__main__":
    unittest.main()
