"""End-to-end tests for Recon -> Skill Attack -> Finding handoff."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

from aidast.attack.evidence import EndpointEvidence, EvidenceSnapshot, SQLiteEvidenceReader
from aidast.attack.runtime import ReviewPlan, _build_tasks, prepare_review
from aidast.attack.skill_agent import AttackTestResult, AuthorizedTest, SkillAttackAgent
from aidast.attack.skills import AttackSkillLibrary
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.validation.source import read_source


class MemoryStore:
    run_id, scan_id = "run", "scan"

    def __init__(self):
        self.statuses, self.events, self.iterations = [], [], []
        self.attempts, self.evidence, self.findings, self.requests = [], [], [], []

    def set_status(self, value): self.statuses.append(value)
    def append_event(self, event_type, details=None):
        self.events.append((event_type, copy.deepcopy(details)))
    def record_iteration(self, **value):
        self.iterations.append(value); return SimpleNamespace(status="inserted")
    def record_attempt(self, **value):
        self.attempts.append(value); return SimpleNamespace(status="inserted")
    def complete_attempt(self, attempt_id, **value):
        next(item for item in self.attempts if item["attempt_id"] == attempt_id).update(value)
    def record_evidence(self, **value):
        self.evidence.append(value); return SimpleNamespace(status="inserted")
    def record_finding(self, **value):
        self.findings.append(value); return SimpleNamespace(status="inserted")
    def record_request(self, **value):
        self.requests.append(value); return SimpleNamespace(status="inserted")
    def record_finding_bundle(self, **value):
        self.findings.append(value)
        self.requests.extend(value["requests"])
        return SimpleNamespace(status="inserted")


class Planner:
    def propose(self, context, schema):
        endpoint = context["endpoints"][0]
        test = next(item for item in context["authorized_tests"] if "hunt-idor" in item["skill_ids"])
        return {"hypotheses": [{
            "task_id": endpoint["task_id"], "endpoint_id": endpoint["endpoint_id"],
            "skill_id": "hunt-idor", "title": "Object authorization may be missing",
            "rationale": "Recon classified an identifier-bearing authorization endpoint.",
            "expected_result": "A non-owner identity must be denied.", "test_ids": [test["test_id"]],
        }]}

    def assess(self, context, schema):
        result = context["results"][0]
        return {
            "hypothesis_id": context["hypothesis_id"], "disposition": "confirmed",
            "vuln_type": "IDOR", "severity": "HIGH", "title": "Cross-user object access",
            "description": "The approved differential test returned another user's object.",
            "cwe_id": "CWE-639", "supporting_test_ids": [result["test"]["test_id"]],
        }


class Executor:
    def available_tests(self, task, skills):
        identifiers = tuple(skill.skill_id for skill in skills)
        if "hunt-idor" not in identifiers:
            return ()
        return (AuthorizedTest("test-idor", task.task_id, task.endpoint_id,
                               ("hunt-idor",), "Two-identity access check",
                               "Compare an owner-approved object request with a non-owner request"),)

    def execute(self, test, *, hypothesis_id):
        return AttackTestResult(test.test_id, "supports", 200, ("content-type",),
                                b'{"owner":"other-user"}', "GET",
                                "https://example.test/api/account/7",
                                "The non-owner response contained the protected object.")


def snapshot() -> EvidenceSnapshot:
    return EvidenceSnapshot("scan", "completed", "2026-09-09", (
        EndpointEvidence("ep", "GET", "/api/account/7", ("obs",), (
            ("ann1", "obs", "function", "authorization"),
            ("ann2", "obs", "data_role", "identifier"),
        )),
    ))


class SkillAttackTests(unittest.TestCase):
    def test_packaged_library_loads_and_verifies_original_skill(self):
        skill = AttackSkillLibrary().load("hunt-idor")
        self.assertEqual(skill.skill_id, "hunt-idor")
        self.assertIn("Step-by-Step Hunting Methodology", skill.content)
        self.assertEqual(len(skill.source_sha256), 64)

    def test_agent_creates_hypothesis_executes_approved_test_and_finding(self):
        evidence = snapshot()
        plan = ReviewPlan("scan", "handoff", Path("unused"), Path("config"), Path("queue"),
                          _build_tasks(evidence))
        store = MemoryStore()
        result = SkillAttackAgent(plan, evidence, run_id="run", store=store,
                                  planner=Planner(), executor=Executor()).run()
        self.assertEqual(result.status, "completed", result)
        self.assertEqual(result.hypothesis_count, 1)
        self.assertEqual(len(result.finding_ids), 1)
        self.assertEqual(store.findings[0]["assessment"]["vuln_type"], "IDOR")
        self.assertEqual(store.requests[0]["response_body"], b'{"owner":"other-user"}')
        self.assertIn("hypothesis.created", [event[0] for event in store.events])

    def test_model_cannot_select_unapproved_test(self):
        class BadPlanner(Planner):
            def propose(self, context, schema):
                value = super().propose(context, schema)
                value["hypotheses"][0]["test_ids"] = ["invented-test"]
                return value
        evidence = snapshot()
        plan = ReviewPlan("scan", "handoff", Path("unused"), Path("config"), Path("queue"),
                          _build_tasks(evidence))
        store = MemoryStore()
        result = SkillAttackAgent(plan, evidence, run_id="run", store=store,
                                  planner=BadPlanner(), executor=Executor()).run()
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.finding_ids, ())
        self.assertEqual(store.iterations, [])

    def test_unknown_test_outcome_persists_paused_status(self):
        class BrokenExecutor(Executor):
            def execute(self, test, *, hypothesis_id):
                raise TimeoutError("outcome unknown")
        evidence = snapshot()
        plan = ReviewPlan("scan", "handoff", Path("unused"), Path("config"), Path("queue"),
                          _build_tasks(evidence))
        store = MemoryStore()
        result = SkillAttackAgent(plan, evidence, run_id="run", store=store,
                                  planner=Planner(), executor=BrokenExecutor()).run()
        self.assertEqual(result.status, "paused")
        self.assertEqual(store.statuses[-1], "paused")
        self.assertEqual(store.attempts[0]["outcome"], "outcome_unknown")

    def test_refuted_result_cannot_be_assessed_as_confirmed(self):
        class RefutingExecutor(Executor):
            def execute(self, test, *, hypothesis_id):
                return AttackTestResult(test.test_id, "refutes", 403, (), b"denied", "GET",
                                        "https://example.test/api/account/7", "Access was denied")
        evidence = snapshot()
        plan = ReviewPlan("scan", "handoff", Path("unused"), Path("config"), Path("queue"),
                          _build_tasks(evidence))
        store = MemoryStore()
        result = SkillAttackAgent(plan, evidence, run_id="run", store=store,
                                  planner=Planner(), executor=RefutingExecutor()).run()
        self.assertEqual(result.status, "failed")
        self.assertEqual(store.findings, [])

    def test_real_attack_db_is_consumable_by_validation(self):
        from aidast.attack.store import materialize_attack_database
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handoff_dir = root / "recon"
            handoff_dir.mkdir()
            source = handoff_dir / "Recon.db"
            conn = db.init_db(source)
            conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) "
                         "VALUES ('scan','test','local','completed','2026-09-09')")
            conn.execute("INSERT INTO assets(asset_id,scan_id,identifier,asset_type) "
                         "VALUES ('asset','scan','example.test','DOMAIN')")
            conn.execute("INSERT INTO origins(origin_id,asset_id,base_url) "
                         "VALUES ('origin','asset','https://example.test')")
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
                         "VALUES ('ep','origin','GET','/api/account/7')")
            conn.execute("INSERT INTO endpoint_observations(observation_id,endpoint_id,source_tool,"
                         "discovery_kind,association_method,observed_at) "
                         "VALUES ('obs','ep','fixture','tool_report','direct','2026-09-09')")
            conn.execute("INSERT INTO annotation_runs(annotation_run_id,scan_id,model,prompt_version,"
                         "taxonomy_version,status,started_at,finished_at) "
                         "VALUES ('ar','scan','fixture','1','1','completed','2026-09-09','2026-09-09')")
            for aid, category, tag in (("ann1", "function", "authorization"),
                                       ("ann2", "data_role", "identifier")):
                conn.execute("INSERT INTO endpoint_annotations(annotation_id,observation_id,annotation_run_id,"
                             "category,tag,rationale,created_at) VALUES (?,?,?,?,?,'fixture','2026-09-09')",
                             (aid, "obs", "ar", category, tag))
            conn.commit(); conn.close()
            handoff = handoff_dir / "Handoff.json"
            handoff.write_text(HandoffManifest(
                manifest_id="handoff", scan_id="scan", db_path="Recon.db",
                artifacts=[hash_artifact(source, root=handoff_dir, role="database")],
            ).model_dump_json(), encoding="utf-8")
            plan = prepare_review(handoff, root / "review")
            evidence = SQLiteEvidenceReader().read(source, "scan")
            attack_dir = root / "attack"
            with materialize_attack_database(handoff, attack_dir, run_id="run") as store:
                self.assertEqual(store.save_plan(plan.to_dict(), tasks=[asdict(t) for t in plan.tasks]).status,
                                 "inserted")
                result = SkillAttackAgent(plan, evidence, run_id="run", store=store,
                                          planner=Planner(), executor=Executor()).run()
                self.assertEqual(result.status, "completed", result)
                resumed = SkillAttackAgent(plan, evidence, run_id="run", store=store,
                                           planner=Planner(), executor=Executor()).run()
                self.assertEqual(resumed.reason, "terminal_run")
                self.assertEqual(resumed.finding_ids, result.finding_ids)
            source_result = read_source(attack_dir / "Attack.db", run_id="run")
            self.assertEqual(len(source_result["contexts"]), 1)
            context = source_result["contexts"][0]
            self.assertEqual(context["finding"]["vuln_type"], "IDOR")
            self.assertEqual(context["evidence"][0]["body_sha256"],
                             context["requests"][0]["response_body_sha256"])

    def test_validation_keeps_shared_task_evidence_with_its_hypothesis(self):
        """A finding must not inherit evidence from a sibling hypothesis on the same task."""
        from aidast.attack.store import materialize_attack_database
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recon_dir = root / "recon"
            recon_dir.mkdir()
            source = recon_dir / "Recon.db"
            conn = db.init_db(source)
            conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) VALUES ('scan','test','local','completed','2026-09-09')")
            conn.execute("INSERT INTO assets(asset_id,scan_id,identifier,asset_type) VALUES ('asset','scan','example.test','DOMAIN')")
            conn.execute("INSERT INTO origins(origin_id,asset_id,base_url) VALUES ('origin','asset','https://example.test')")
            conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) VALUES ('ep','origin','GET','/item/7')")
            conn.commit(); conn.close()
            handoff = recon_dir / "Handoff.json"
            handoff.write_text(HandoffManifest(
                manifest_id="handoff", scan_id="scan", db_path="Recon.db",
                artifacts=[hash_artifact(source, root=recon_dir, role="database")],
            ).model_dump_json(), encoding="utf-8")
            attack_dir = root / "attack"
            with materialize_attack_database(handoff, attack_dir, run_id="run") as store:
                task = {"task_id": "task", "endpoint_id": "ep", "priority": 1,
                        "observation_ids": [], "annotation_ids": [], "annotation_tags": [],
                        "observation_summaries": []}
                plan = {"scan_id": "scan", "handoff_id": "handoff", "tasks": [task]}
                self.assertEqual(store.save_plan(plan, tasks=[task]).status, "inserted")
                for suffix in ("one", "two"):
                    hypothesis = f"hypothesis_{suffix}"
                    attempt = f"attempt_{suffix}"
                    self.assertEqual(store.record_attempt(
                        attempt_id=attempt, task_id="task", endpoint_id="ep", skill_name="hunt-idor",
                        test_id=f"test_{suffix}", hypothesis_id=hypothesis,
                    ).status, "inserted")
                    store.complete_attempt(attempt, outcome="supports", response_status=200)
                    self.assertEqual(store.record_evidence(
                        evidence_id=f"evidence_{suffix}", task_id="task", attempt_id=attempt,
                        kind="attack_test", body=suffix,
                        metadata={"hypothesis_id": hypothesis},
                    ).status, "inserted")
                    assessment = {"disposition": "confirmed", "vuln_type": "IDOR", "severity": "HIGH",
                                  "title": f"finding {suffix}", "description": suffix}
                    self.assertEqual(store.record_finding(
                        finding_id=f"finding_{suffix}", task_id="task", endpoint_id="ep",
                        skill_name="hunt-idor", hypothesis_id=hypothesis, assessment=assessment,
                    ).status, "inserted")
            result = read_source(attack_dir / "Attack.db", run_id="run")
            by_finding = {item["finding_id"]: item for item in result["contexts"]}
            self.assertEqual([e["evidence_id"] for e in by_finding["finding_one"]["evidence"]],
                             ["evidence_one"])
            self.assertEqual([e["evidence_id"] for e in by_finding["finding_two"]["evidence"]],
                             ["evidence_two"])


if __name__ == "__main__":
    unittest.main()
