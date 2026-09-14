"""Socket-level acceptance test for the native HTTP Validation pipeline."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (
    ClaimComparison,
    build_native_validation_coordinator,
    canonical_reproduction_spec,
    canonical_sha256,
    validate_runtime_contract,
)


class _ObjectHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        object_id = self.path.removeprefix("/objects/")
        documents = {
            "owned": {"owner_id": "self"},
            "inert": {"error": "not found"},
            "target": {"owner_id": "other-user"},
        }
        document = documents.get(object_id, {"error": "unknown"})
        encoded = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.send_response(200 if object_id in documents else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


class _AcceptanceAgent:
    agent_id = "validation_acceptance_agent"

    def assess(self, blind_case, observations, correction=None):
        evidence = tuple(item["evidence_id"] for item in observations)
        targets = tuple(
            item["attempt_id"] for item in observations
            if item["attempt_kind"] == "target"
        )
        controls = tuple(
            item["attempt_id"] for item in observations
            if item["attempt_kind"] != "target"
        )
        axis = {
            "score": 1,
            "evidence_ids": (evidence[0],),
            "reason": "The live control and target evidence supports this bounded score.",
        }
        return {
            "case_id": blind_case["case_id"],
            "blind_case_sha256": blind_case["blind_case_sha256"],
            "reproduced": True,
            "signal_types": tuple(blind_case["signal_types"]),
            "target_attempt_ids": targets,
            "control_attempt_ids": controls,
            "evidence_ids": evidence,
            "blocker_axis": None,
            "blocker_reason": None,
            "impact_boundary": axis,
            "impact_sensitivity": axis,
            "impact_actor_requirements": axis,
            "conclusion": "The live target marker repeated while the inert control stayed clear.",
        }

    def compare(self, claim, assessment, correction=None):
        return ClaimComparison(
            case_id=assessment["case_id"],
            blind_assessment_sha256=claim["blind_assessment_sha256"],
            attack_claim_sha256=claim["attack_claim_sha256"],
            alignment="aligned",
            conflict_axes=(),
            validation_evidence_ids=(assessment["evidence_ids"][0],),
            attack_evidence_ids=(claim["attack_evidence_ids"][0],),
            reason="The live reproduction mechanism aligns with the stored Attack claim.",
        )


@unittest.skipUnless(
    os.environ.get("AIDAST_LIVE_ACCEPTANCE") == "1",
    "set AIDAST_LIVE_ACCEPTANCE=1 to bind the local acceptance target",
)
class ValidationLiveAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        _ObjectHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ObjectHandler)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"

    def test_native_http_pipeline_confirms_only_with_clear_live_negative_control(self):
        database = self.root / "Pipeline.db"
        policy_path = self.root / "TargetPolicy.json"
        policy = TargetPolicy(
            asset_type=AssetType.URL,
            asset=f"{self.base_url}/objects",
            allowed_schemes=["http"],
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[self.port],
            allowed_path_prefixes=["/objects"],
            allowed_methods=["GET"],
            limits=PolicyLimits(requests_per_second=50, max_requests=20),
            tools=ToolPolicy(),
            scope_id="acceptance-scope",
            policy_id="acceptance-policy",
        )
        policy_path.write_text(json.dumps({
            "policies": [policy.model_dump(mode="json")],
        }), encoding="utf-8")

        conn = db.init_db(database)
        db.insert_scan(
            conn, scan_id="acceptance-scan", scope_type="test",
            scope_value="local-live-target",
        )
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP "
            "WHERE scan_id='acceptance-scan'"
        )
        asset_id = db.insert_asset(
            conn, scan_id="acceptance-scan", identifier=policy.asset,
            asset_type="URL",
        )
        origin_id = db.upsert_origin(
            conn, asset_id=asset_id, scheme="http", host="127.0.0.1",
            port=self.port, base_url=self.base_url,
        )
        conn.execute(
            "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
            "VALUES ('acceptance-endpoint',?,'GET','/objects/{id}')",
            (origin_id,),
        )
        attack_stage = start_stage_run(
            conn, scan_id="acceptance-scan", stage="attack",
            stage_run_id="acceptance-attack-stage",
        )
        task_id = create_task(
            conn, stage_run_id=attack_stage, skill_name="hunt-idor",
            endpoint_id="acceptance-endpoint", task_id="acceptance-task",
        )
        transition_task(conn, task_id, status="running")
        fingerprint = "f" * 64
        conn.execute(
            """INSERT INTO findings
               (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
               VALUES ('acceptance-finding','acceptance-scan','acceptance-endpoint',
                       'idor','MEDIUM','Live IDOR fixture','Cross-user object read')"""
        )
        conn.execute(
            """INSERT INTO attack_attempts
               (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,
                outcome,finding_id,resolution_reason,resolved_at)
               VALUES ('acceptance-attempt','acceptance-scan','acceptance-task','hunt-idor',
                       'acceptance-endpoint',?,'confirmed','acceptance-finding',
                       'promoted',CURRENT_TIMESTAMP)""",
            (fingerprint,),
        )
        policy_sha = canonical_sha256(policy.model_dump(mode="json"))
        conn.execute(
            """INSERT INTO attack_http_requests
               (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
                request_fingerprint,status,response_status,response_bytes,scheduled_at)
               VALUES ('acceptance-source-http','acceptance-scan','acceptance-attack-stage',
                       'acceptance-task','acceptance-policy',?,'GET',? ,?,'completed',200,25,0)""",
            (policy_sha, f"{self.base_url}/objects/target", fingerprint),
        )
        conn.execute(
            """INSERT INTO attack_requests
               (request_id,finding_id,method,url,response_status,response_body)
               VALUES ('acceptance-evidence','acceptance-finding','GET',?,200,X'7B7D')""",
            (f"{self.base_url}/objects/target",),
        )

        marker = {
            "assertion_id": "foreign-owner", "kind": "json_equals",
            "path": ["owner_id"], "expected": "other-user",
        }
        runtime = validate_runtime_contract({
            "schema_version": 1,
            "target": {
                "request": {"path_parameters": {"id": "target"}},
                "assertions": [marker],
            },
            "positive_control": {
                "request": {"path_parameters": {"id": "owned"}},
                "assertions": [{
                    "assertion_id": "healthy", "kind": "status_equals", "expected": 200,
                }],
            },
            "negative_control": {
                "request": {"path_parameters": {"id": "inert"}},
                "assertions": [marker],
            },
        }).model_dump(mode="json")
        spec = canonical_reproduction_spec(
            finding_id="acceptance-finding", attack_skill_name="hunt-idor",
            endpoint_id="acceptance-endpoint", method="GET",
            endpoint_template="/objects/{id}", injection_location="path",
            parameter_name="id", payload_template={"id": "<slot:string>"},
            required_identity_roles=[], source_attempt_ids=["acceptance-attempt"],
            source_request_ids=["acceptance-source-http"],
            source_policy_sha256=policy_sha, runtime_contract=runtime,
            runtime_contract_sha256=canonical_sha256(runtime),
        )
        conn.execute(
            """INSERT INTO finding_reproduction_specs
               (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,
                injection_location,parameter_name,payload_template_json,
                required_identity_roles_json,source_attempt_ids_json,source_request_ids_json,
                payload_structure_sha256,source_policy_sha256,runtime_contract_json,
                runtime_contract_sha256,spec_sha256)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"],
                spec["method"], spec["endpoint_template"], spec["injection_location"],
                spec["parameter_name"], json.dumps(spec["payload_template"]),
                json.dumps(spec["required_identity_roles"]),
                json.dumps(spec["source_attempt_ids"]),
                json.dumps(spec["source_request_ids"]), spec["payload_structure_sha256"],
                spec["source_policy_sha256"], json.dumps(runtime, sort_keys=True),
                spec["runtime_contract_sha256"], spec["spec_sha256"],
            ),
        )
        transition_task(conn, task_id, status="completed")
        finish_stage_run(conn, attack_stage)
        chain_stage = start_stage_run(
            conn, scan_id="acceptance-scan", stage="chaining",
            stage_run_id="acceptance-chain-stage",
        )
        finish_stage_run(conn, chain_stage, status="skipped")
        conn.close()

        coordinator = build_native_validation_coordinator(
            db_path=database, policy_path=policy_path,
        )
        coordinator.agent = _AcceptanceAgent()
        result = coordinator.run("acceptance-scan")

        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(
            _ObjectHandler.requests,
            ["/objects/owned", "/objects/inert", "/objects/target",
             "/objects/target", "/objects/target"],
        )
        with sqlite3.connect(database) as verified:
            self.assertEqual(verified.execute(
                "SELECT current_status FROM validation_cases"
            ).fetchone()[0], "CONFIRMED")
            self.assertEqual(verified.execute(
                "SELECT count(*) FROM validation_attempts WHERE finished_at IS NOT NULL"
            ).fetchone()[0], 5)
            self.assertEqual(verified.execute(
                "SELECT count(*) FROM validation_http_requests WHERE status='completed'"
            ).fetchone()[0], 5)
            self.assertEqual(verified.execute(
                "SELECT count(*) FROM validation_evidence WHERE evidence_kind='observation'"
            ).fetchone()[0], 5)


if __name__ == "__main__":
    unittest.main()
