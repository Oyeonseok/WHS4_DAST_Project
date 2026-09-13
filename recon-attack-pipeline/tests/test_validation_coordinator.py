"""End-to-end shared DB Validation coordination with deterministic fakes."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aidast.pipeline.lifecycle import create_task, finish_stage_run, start_stage_run, transition_task
from aidast.recon import db
from aidast.recon.policy import PolicyLimits, TargetPolicy, ToolPolicy
from aidast.scope.models import AssetType
from aidast.validation import (ClaimComparison, HttpReproductionPort,
                               ReproductionObservation,
                               ValidationCoordinator, ValidationCoordinatorError,
                               canonical_reproduction_spec)


class FakePort:
    def __init__(self):
        self.calls = []

    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        self.calls.append((attempt_kind, batch_no, ordinal))
        observed = attempt_kind != "negative_control"
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            details={"kind": attempt_kind, "ordinal": ordinal},
            content_sha256=(str(ordinal) * 64)[:64], content_length=1,
        )


class FakeChainPort(FakePort):
    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        if blind_case.target_kind == "chain":
            self.asserted_chain = True
            assert len(blind_case.payload_template["ordered_steps"]) == 2
            assert blind_case.payload_template["bindings"] == [{
                "from_position": 0, "to_position": 1, "binding_name": "object_id",
            }]
        return super().execute(
            blind_case, attempt_kind=attempt_kind, batch_no=batch_no,
            ordinal=ordinal, attempt_id=attempt_id, **context,
        )


class FakeAgent:
    agent_id = "validation_agent_fixture"

    def assess(self, blind_case, observations, correction=None):
        evidence = tuple(item["evidence_id"] for item in observations)
        targets = tuple(item["attempt_id"] for item in observations if item["attempt_kind"] == "target")
        controls = tuple(item["attempt_id"] for item in observations if item["attempt_kind"] != "target")
        axis = {"score": 1, "evidence_ids": (evidence[0],), "reason": "Current evidence supports score one."}
        return {
            "case_id": blind_case["case_id"], "blind_case_sha256": blind_case["blind_case_sha256"],
            "reproduced": True, "signal_types": tuple(blind_case["signal_types"]),
            "target_attempt_ids": targets, "control_attempt_ids": controls,
            "evidence_ids": evidence, "blocker_axis": None, "blocker_reason": None,
            "impact_boundary": axis, "impact_sensitivity": axis,
            "impact_actor_requirements": axis, "conclusion": "Three stable target observations.",
        }

    def compare(self, claim, assessment, correction=None):
        return ClaimComparison(
            case_id=assessment["case_id"],
            blind_assessment_sha256=claim["blind_assessment_sha256"],
            attack_claim_sha256=claim["attack_claim_sha256"], alignment="aligned",
            conflict_axes=(), validation_evidence_ids=(assessment["evidence_ids"][0],),
            attack_evidence_ids=(claim["attack_evidence_ids"][0],),
            reason="The reproduced mechanism aligns with the Attack claim.",
        )


class BlockerAgent(FakeAgent):
    def assess(self, blind_case, observations, correction=None):
        result = super().assess(blind_case, observations, correction)
        targets = [item for item in observations if item["attempt_kind"] == "target"]
        if not all(item["signal_observed"] for item in targets):
            result["reproduced"] = None
            result["blocker_axis"] = "identity_auth"
            result["blocker_reason"] = "The target returned an objective authentication blocker."
        return result


class UnderpoweredAgent(FakeAgent):
    def assess(self, blind_case, observations, correction=None):
        result = super().assess(blind_case, observations, correction)
        result["impact_boundary"] = {
            "score": 0, "evidence_ids": (result["evidence_ids"][0],),
            "reason": "No crossed identity boundary was demonstrated.",
        }
        return result


class BlockThenPassPort(FakePort):
    def execute(self, blind_case, *, attempt_kind, batch_no, ordinal, attempt_id, **context):
        result = super().execute(blind_case, attempt_kind=attempt_kind,
                                 batch_no=batch_no, ordinal=ordinal, attempt_id=attempt_id,
                                 **context)
        if batch_no == 1 and attempt_kind == "target":
            return result.model_copy(update={
                "outcome": "blocked", "signal_observed": False,
                "blocker_axis": "identity_auth",
            })
        return result


class SuccessfulPrerequisite:
    def perform(self, blind_case, *, action_type, blocker_axis):
        return {"succeeded": True, "action_type": action_type}


class CrashedAgent(FakeAgent):
    def assess(self, blind_case, observations, correction=None):
        raise RuntimeError("agent process stopped")


class CompareCrashedAgent(FakeAgent):
    def compare(self, claim, assessment, correction=None):
        raise RuntimeError("agent process stopped after blind freeze")


class CountingAgent(FakeAgent):
    def __init__(self):
        self.assess_calls = 0
        self.compare_calls = 0

    def assess(self, blind_case, observations, correction=None):
        self.assess_calls += 1
        return super().assess(blind_case, observations, correction)

    def compare(self, claim, assessment, correction=None):
        self.compare_calls += 1
        return super().compare(claim, assessment, correction)


class ValidationCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "Pipeline.db"
        conn = db.init_db(self.path)
        db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
        conn.execute("UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'")
        asset = db.insert_asset(conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        conn.execute("""INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path)
                      VALUES ('endpoint',?,'GET','/objects/{id}')""", (origin,))
        attack = start_stage_run(conn, scan_id="scan", stage="attack", stage_run_id="attack_stage")
        task = create_task(conn, stage_run_id=attack, skill_name="hunt-idor",
                           endpoint_id="endpoint", task_id="attack_task")
        transition_task(conn, task, status="running")
        fingerprint = "f" * 64
        conn.execute("""INSERT INTO findings
            (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
            VALUES ('finding','scan','endpoint','idor','LOW','IDOR fixture','Cross-user read')""")
        conn.execute("""INSERT INTO attack_attempts
            (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,outcome,
             finding_id,resolution_reason,resolved_at)
            VALUES ('attempt','scan','attack_task','hunt-idor','endpoint',?,'confirmed',
                    'finding','promoted',CURRENT_TIMESTAMP)""", (fingerprint,))
        self.policy = TargetPolicy(
            asset_type=AssetType.DOMAIN, asset="test", allowed_schemes=["https"],
            allowed_hosts=["test"], allowed_ports=[443], allowed_path_prefixes=["/"],
            allowed_methods=["GET"], limits=PolicyLimits(), tools=ToolPolicy(),
            scope_id="scope", policy_id="policy",
        )
        from aidast.validation import canonical_sha256
        policy_sha = canonical_sha256(self.policy.model_dump(mode="json"))
        conn.execute("""INSERT INTO attack_http_requests
            (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
             request_fingerprint,status,response_status,response_bytes,scheduled_at)
            VALUES ('http','scan','attack_stage','attack_task','policy',?,'GET',
                    'https://test/objects/1',?,'completed',200,1,0)""", (policy_sha, fingerprint))
        conn.execute("""INSERT INTO attack_requests
            (request_id,finding_id,method,url,response_status,response_body)
            VALUES ('attack_evidence','finding','GET','https://test/objects/1',200,X'31')""")
        spec = canonical_reproduction_spec(
            finding_id="finding", attack_skill_name="hunt-idor", endpoint_id="endpoint",
            method="GET", endpoint_template="/objects/{id}", injection_location="path",
            parameter_name="id", payload_template={"id": "<slot:int>"},
            required_identity_roles=[], source_attempt_ids=["attempt"],
            source_request_ids=["http"], source_policy_sha256=policy_sha,
        )
        conn.execute("""INSERT INTO finding_reproduction_specs
            (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,injection_location,
             parameter_name,payload_template_json,required_identity_roles_json,
             source_attempt_ids_json,source_request_ids_json,payload_structure_sha256,
             source_policy_sha256,spec_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"], spec["method"],
            spec["endpoint_template"], spec["injection_location"], spec["parameter_name"],
            json.dumps(spec["payload_template"]), json.dumps(spec["required_identity_roles"]),
            json.dumps(spec["source_attempt_ids"]), json.dumps(spec["source_request_ids"]),
            spec["payload_structure_sha256"], spec["source_policy_sha256"], spec["spec_sha256"],
        ))
        transition_task(conn, task, status="completed")
        finish_stage_run(conn, attack)
        chaining = start_stage_run(conn, scan_id="scan", stage="chaining", stage_run_id="chain_stage")
        finish_stage_run(conn, chaining, status="skipped")
        conn.close()

    def test_run_executes_fresh_three_with_controls_and_commits_confirmed(self):
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.validation_agent_ids, ("validation_agent_fixture",))
        self.assertEqual([kind for kind, _, _ in port.calls],
                         ["positive_control", "negative_control", "target", "target", "target"])
        with db.connect(self.path) as conn:
            row = conn.execute("SELECT current_status,processing_phase FROM validation_cases").fetchone()
            self.assertEqual(row, ("CONFIRMED", "completed"))
            self.assertEqual(conn.execute("SELECT count(*) FROM validation_attempts").fetchone()[0], 5)

    def test_native_http_preflight_isolates_missing_contract(self):
        agent = CountingAgent()
        result = ValidationCoordinator(
            db_path=self.path, agent=agent, reproduction=HttpReproductionPort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.validation_agent_ids, ())
        with db.connect(self.path) as conn:
            case = conn.execute(
                "SELECT current_status,decision_json FROM validation_cases"
            ).fetchone()
            attempts = conn.execute(
                "SELECT count(*) FROM validation_attempts"
            ).fetchone()[0]
        self.assertEqual(case[0], "INCONCLUSIVE")
        self.assertEqual(
            json.loads(case[1])["reason"], "http_runtime_contract_missing"
        )
        self.assertEqual(attempts, 0)
        self.assertEqual(agent.assess_calls, 0)

    def test_replay_lazily_creates_exactly_one_native_agent(self):
        port = FakePort()
        with patch(
            "aidast.validation.codex_runner.CodexBlindValidationRunner",
            return_value=FakeAgent(),
        ) as factory:
            result = ValidationCoordinator(
                db_path=self.path, agent=None, reproduction=port,
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")

        factory.assert_called_once_with()
        self.assertEqual(result.validation_agent_ids, ("validation_agent_fixture",))
        self.assertEqual(len(port.calls), 5)

    def test_integrity_failure_sends_no_requests_and_finishes_inconclusive(self):
        with db.connect(self.path) as conn:
            conn.execute("""INSERT INTO findings
                (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
                VALUES ('legacy_finding','scan','endpoint','idor','LOW','Legacy fixture','No spec')""")
            conn.commit()
        port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan", finding_id="legacy_finding")
        self.assertEqual(port.calls, [])
        self.assertEqual(result.summary["statuses"], {"INCONCLUSIVE": 1})

    def test_resolvable_blocker_uses_one_action_and_fresh_batch(self):
        port = BlockThenPassPort()
        result = ValidationCoordinator(
            db_path=self.path, agent=BlockerAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
            prerequisite_resolver=SuccessfulPrerequisite(),
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 1})
        self.assertEqual(len(port.calls), 10)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT status FROM validation_development_actions"
            ).fetchone(), ("succeeded",))
            self.assertEqual(conn.execute(
                "SELECT count(DISTINCT batch_no) FROM validation_attempts"
            ).fetchone()[0], 2)

    def test_resume_reuses_completed_batch_without_redispatch(self):
        first_port = FakePort()
        coordinator = ValidationCoordinator(
            db_path=self.path, agent=CrashedAgent(), reproduction=first_port,
            policy_provider=lambda endpoint, method: self.policy,
        )
        with self.assertRaises(ValidationCoordinatorError):
            coordinator.run("scan")
        self.assertEqual(len(first_port.calls), 5)
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
        resumed_port = FakePort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=resumed_port,
            policy_provider=lambda endpoint, method: self.policy,
        ).resume(stage_id)
        self.assertEqual(result.status, "completed")
        self.assertEqual(resumed_port.calls, [])
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_attempts"
            ).fetchone()[0], 5)

    def test_resume_reuses_frozen_assessment_and_continues_at_unblinding(self):
        first_port = FakePort()
        with self.assertRaises(ValidationCoordinatorError):
            ValidationCoordinator(
                db_path=self.path, agent=CompareCrashedAgent(), reproduction=first_port,
                policy_provider=lambda endpoint, method: self.policy,
            ).run("scan")
        self.assertEqual(len(first_port.calls), 5)
        with db.connect(self.path) as conn:
            stage_id = conn.execute(
                "SELECT stage_run_id FROM stage_runs WHERE stage='validation'"
            ).fetchone()[0]
            frozen = conn.execute(
                "SELECT blind_assessment_sha256 FROM validation_cases"
            ).fetchone()[0]
            self.assertIsNotNone(frozen)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_evidence WHERE evidence_kind='blind_assessment'"
            ).fetchone()[0], 1)

        resumed_port = FakePort()
        resumed_agent = CountingAgent()
        result = ValidationCoordinator(
            db_path=self.path, agent=resumed_agent, reproduction=resumed_port,
            policy_provider=lambda endpoint, method: self.policy,
        ).resume(stage_id)

        self.assertEqual(result.status, "completed")
        self.assertEqual(resumed_port.calls, [])
        self.assertEqual(resumed_agent.assess_calls, 0)
        self.assertEqual(resumed_agent.compare_calls, 1)
        with db.connect(self.path) as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_attempts"
            ).fetchone()[0], 5)
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM validation_evidence WHERE evidence_kind='blind_assessment'"
            ).fetchone()[0], 1)
            self.assertEqual(conn.execute(
                "SELECT current_status,processing_phase FROM validation_cases"
            ).fetchone(), ("CONFIRMED", "completed"))

    def test_underpowered_finding_persists_profile_bounded_hypothesis(self):
        result = ValidationCoordinator(
            db_path=self.path, agent=UnderpoweredAgent(), reproduction=FakePort(),
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")
        self.assertEqual(result.summary["statuses"], {"UNDERPOWERED": 1})
        with db.connect(self.path) as conn:
            hypothesis = conn.execute(
                """SELECT path_id,gap_axis,execution_owner FROM validation_impact_hypotheses"""
            ).fetchone()
            self.assertEqual(hypothesis, ("cross-role-object-access", "boundary", "validation"))

    def test_demonstrated_chain_replays_end_to_end_after_node_gate(self):
        from aidast.validation import canonical_sha256
        policy_sha = canonical_sha256(self.policy.model_dump(mode="json"))
        with db.connect(self.path) as conn:
            conn.execute("""INSERT INTO findings
                (finding_id,scan_id,endpoint_id,vuln_type,severity,title,description)
                VALUES ('finding2','scan','endpoint','idor','MEDIUM','Second IDOR','Private record')""")
            conn.execute("""INSERT INTO attack_attempts
                (attempt_id,scan_id,task_id,skill_name,endpoint_id,request_fingerprint,outcome,
                 finding_id,resolution_reason,resolved_at)
                VALUES ('attempt2','scan','attack_task','hunt-idor','endpoint',?,'confirmed',
                        'finding2','promoted',CURRENT_TIMESTAMP)""", ("e" * 64,))
            conn.execute("""INSERT INTO attack_http_requests
                (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,method,url,
                 request_fingerprint,status,response_status,response_bytes,scheduled_at)
                VALUES ('http2','scan','attack_stage','attack_task','policy',?,'GET',
                        'https://test/objects/2',?,'completed',200,1,0)""",
                         (policy_sha, "e" * 64))
            conn.execute("""INSERT INTO attack_requests
                (request_id,finding_id,method,url,response_status,response_body)
                VALUES ('attack_evidence2','finding2','GET','https://test/objects/2',200,X'32')""")
            spec = canonical_reproduction_spec(
                finding_id="finding2", attack_skill_name="hunt-idor", endpoint_id="endpoint",
                method="GET", endpoint_template="/objects/{id}", injection_location="path",
                parameter_name="id", payload_template={"id": "<slot:int>"},
                required_identity_roles=[], source_attempt_ids=["attempt2"],
                source_request_ids=["http2"], source_policy_sha256=policy_sha,
            )
            conn.execute("""INSERT INTO finding_reproduction_specs
                (finding_id,attack_skill_name,endpoint_id,method,endpoint_template,injection_location,
                 parameter_name,payload_template_json,required_identity_roles_json,
                 source_attempt_ids_json,source_request_ids_json,payload_structure_sha256,
                 source_policy_sha256,spec_sha256) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                spec["finding_id"], spec["attack_skill_name"], spec["endpoint_id"], spec["method"],
                spec["endpoint_template"], spec["injection_location"], spec["parameter_name"],
                json.dumps(spec["payload_template"]), json.dumps(spec["required_identity_roles"]),
                json.dumps(spec["source_attempt_ids"]), json.dumps(spec["source_request_ids"]),
                spec["payload_structure_sha256"], spec["source_policy_sha256"], spec["spec_sha256"],
            ))
            conn.execute("""INSERT INTO attack_tasks
                (task_id,stage_run_id,scan_id,skill_name,endpoint_id,status,finished_at)
                VALUES ('chain_task','chain_stage','scan','chain','endpoint','completed',CURRENT_TIMESTAMP)""")
            conn.execute("UPDATE stage_runs SET status='completed' WHERE stage_run_id='chain_stage'")
            conn.execute("""INSERT INTO finding_chains
                (chain_id,scan_id,title,combined_severity,description,status)
                VALUES ('chain','scan','Two-step object disclosure','HIGH',
                        'Terminal private record disclosure','demonstrated')""")
            conn.executemany("""INSERT INTO finding_chain_nodes(chain_id,finding_id,position,role)
                VALUES ('chain',?,?,?)""", [
                ("finding", 0, "source"), ("finding2", 1, "terminal"),
            ])
            conn.execute("""INSERT INTO chain_candidates
                (candidate_id,scan_id,stage_run_id,task_id,source_finding_id,chain_id,status,
                 title,hypothesis,terminal_impact,confidence,hypothesis_sha256,resolved_at)
                VALUES ('candidate','scan','chain_stage','chain_task','finding','chain',
                'evidence_collected','Two-step object disclosure','First result feeds second request',
                'Private record disclosure',1.0,?,CURRENT_TIMESTAMP)""", ("c" * 64,))
            conn.executemany("""INSERT INTO chain_candidate_nodes
                (candidate_id,position,finding_id,expected_vuln_type,node_role)
                VALUES ('candidate',?,?,?,?)""", [
                (0, "finding", "idor", "source"),
                (1, "finding2", "idor", "terminal"),
            ])
            conn.execute("""INSERT INTO chain_candidate_edges
                (candidate_id,edge_position,from_position,to_position,relationship)
                VALUES ('candidate',0,0,1,'captured identifier feeds terminal request')""")
            conn.execute("""INSERT INTO chain_executions
                (execution_id,candidate_id,chain_id,scan_id,stage_run_id,task_id,status,
                 terminal_impact,terminal_assertion_json,finished_at)
                VALUES ('execution','candidate','chain','scan','chain_stage','chain_task','succeeded',
                'Private record disclosure',?,CURRENT_TIMESTAMP)""",
                         (json.dumps({"name": "private_record_disclosed"}),))
            conn.executemany("""INSERT INTO chain_execution_steps
                (execution_id,position,candidate_node_position,finding_id,request_id,attempt_id,
                 assertion_results_json,evidence_summary) VALUES ('execution',?,?,?,?,?,?,?)""", [
                (0, 0, "finding", "http", "attempt", "[]", "Captured object identifier"),
                (1, 1, "finding2", "http2", "attempt2", json.dumps([
                    {"terminal": True, "passed": True, "name": "private_record_disclosed"}
                ]), "Reached terminal private record"),
            ])
            conn.execute("""INSERT INTO chain_execution_bindings
                (execution_id,edge_position,from_step_position,to_step_position,binding_name,value_sha256)
                VALUES ('execution',0,0,1,'object_id',?)""", ("b" * 64,))
            conn.commit()
            chaining_tables = (
                "finding_chains", "finding_chain_nodes", "chain_candidates",
                "chain_candidate_nodes", "chain_candidate_edges", "chain_evidence",
                "chain_executions", "chain_execution_steps", "chain_execution_bindings",
            )
            chaining_before = {
                table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                for table in chaining_tables
            }

        port = FakeChainPort()
        result = ValidationCoordinator(
            db_path=self.path, agent=FakeAgent(), reproduction=port,
            policy_provider=lambda endpoint, method: self.policy,
        ).run("scan")

        self.assertEqual(result.summary["statuses"], {"CONFIRMED": 2, "KNOWN": 1})
        self.assertEqual(len(port.calls), 10)
        self.assertTrue(port.asserted_chain)
        with db.connect(self.path) as conn:
            chain_case = conn.execute(
                "SELECT current_status,impact_score FROM validation_cases WHERE chain_id='chain'"
            ).fetchone()
            self.assertEqual(chain_case, ("CONFIRMED", 3))
            self.assertEqual({
                table: tuple(conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                for table in chaining_tables
            }, chaining_before)


if __name__ == "__main__":
    unittest.main()
