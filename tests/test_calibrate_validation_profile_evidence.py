"""Ground-truth coverage stays distinct from synthetic axis fixtures."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aidast.validation.contracts.models import BlindAssessment, canonical_sha256
from scripts.calibrate_validation_profile_evidence import calibrate_profile_evidence


ROOT = Path(__file__).resolve().parents[1]


class ProfileCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.official = self.root / "official.json"
        self.mapping = self.root / "mapping.json"
        self.pipeline = self.root / "Pipeline.db"
        self.candidate_id = "vuln-bank:curated:GET:/debug/users:excessive_data_exposure"
        self.official.write_text(json.dumps([{
            "candidate_id": self.candidate_id,
            "target_validation_status": "CONFIRMED",
            "readiness": "GET_REPLAY_READY",
            "proof_requirement": "Read-only protected user data and controls.",
        }]))
        self.mapping.write_text(json.dumps({
            "fixture_kind": "synthetic_attack_claims_for_validation_only",
            "cases": [{"candidate_id": self.candidate_id,
                       "scan_id": "scan", "finding_id": "finding"}],
        }))
        with sqlite3.connect(self.pipeline) as conn:
            conn.executescript("""
                CREATE TABLE finding_reproduction_specs (
                    finding_id TEXT, attack_skill_name TEXT);
                CREATE TABLE validation_cases (
                    case_id TEXT, scan_id TEXT, finding_id TEXT, current_status TEXT,
                    processing_phase TEXT, latest_stage_run_id TEXT,
                    decision_stage_run_id TEXT, blind_assessment_sha256 TEXT,
                    validation_profile_sha256 TEXT);
                CREATE TABLE validation_evidence (
                    case_id TEXT, stage_run_id TEXT, evidence_kind TEXT,
                    details_json TEXT, content_sha256 TEXT);
                INSERT INTO finding_reproduction_specs VALUES ('finding','hunt-source-leak');
                INSERT INTO validation_cases VALUES (
                    'case','scan','finding','CONFIRMED','completed','stage','stage',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
            """)
            axis = lambda score, refs: {
                "score": score, "evidence_ids": refs, "reason": "Observed replay citation.",
            }
            frozen = BlindAssessment.model_validate_json(json.dumps({
                "case_id": "case", "blind_case_sha256": "f" * 64,
                "reproduced": True, "signal_types": ["error_signature"],
                "target_attempt_ids": ["t1", "t2", "t3"],
                "control_attempt_ids": ["p1", "n1"],
                "evidence_ids": ["e-t1", "e-t2", "e-t3", "e-p1", "e-n1"],
                "impact_boundary": axis(1, ["e-t1", "e-n1"]),
                "impact_sensitivity": axis(0, ["e-t1"]),
                "impact_actor_requirements": axis(2, ["e-t1"]),
                "conclusion": "Controlled replay fixture.",
            })).model_dump(mode="json")
            self.assessment_sha = canonical_sha256(frozen)
            conn.execute("UPDATE validation_cases SET blind_assessment_sha256=?",
                         (self.assessment_sha,))
            conn.execute("INSERT INTO validation_evidence VALUES (?,?,?,?,?)",
                         ("case", "stage", "blind_assessment",
                          json.dumps(frozen), self.assessment_sha))

    def audit(self, **changes):
        document = {
            "rule_version": "profile-evidence-v1", "mode": "audit",
            "case_id": "case", "stage_run_id": "stage",
            "profile_id": "hunt-source-leak",
            "profile_sha256": "b" * 64,
            "assessment_sha256": self.assessment_sha,
            "replay_status": "complete",
            "raw_axes": [1, 0, 2], "effective_axes": [1, 0, 2],
            "runtime_kind": "http",
            "target_attempt_ids": ["t1", "t2", "t3"],
            "control_attempt_ids": ["p1", "n1"],
            "observed_target_evidence_ids": ["e-t1", "e-t2", "e-t3"],
            "inert_negative_evidence_ids": ["e-n1"],
            "facts": [{"kind": "assertion_differential",
                       "profile_id": "hunt-source-leak", "runtime_kind": "http",
                       "assertion_kind": "body_contains",
                       "assertion_id_sha256": "c" * 64,
                       "assertion_predicate_sha256": "d" * 64,
                       "expected_sha256": "e" * 64,
                       "target_attempt_ids": ["t1", "t2", "t3"],
                       "target_evidence_ids": ["e-t1", "e-t2", "e-t3"],
                       "negative_attempt_id": "n1",
                       "negative_evidence_id": "e-n1",
                       "provenance": "contract_bound_adapter_summary"}],
        } | changes
        with sqlite3.connect(self.pipeline) as conn:
            conn.execute(
                "INSERT INTO validation_evidence VALUES (?,?,?,?,?)",
                ("case", "stage", "blind_profile_evidence_audit",
                 json.dumps(document), canonical_sha256(document)),
            )

    def calibrate(self, *, transition=None, axis_labels=None):
        return calibrate_profile_evidence(
            self.official,
            transition or ROOT / "resources/lab/validation-transition-answer-key.json",
            self.mapping, self.pipeline, axis_labels=axis_labels,
        )

    def test_official_status_and_synthetic_axes_remain_separate(self):
        self.audit()
        report = self.calibrate()
        self.assertEqual(report["summary"]["official_status_labels"], 1)
        self.assertEqual(report["summary"]["synthetic_axis_trials"], 6)
        self.assertEqual(report["summary"]["rubric_consistent_trials"], 6)
        self.assertEqual(report["summary"]["current_audits_binding_valid"], 1)
        self.assertEqual(report["cases"][0]["status_comparison"], "STATUS_MATCH")
        self.assertEqual(report["cases"][0]["audit_status"], "VALID_BINDING")
        self.assertEqual(report["profiles"]["hunt-source-leak"]["axis_label_provenance"],
                         "synthetic_transition_fixture")
        self.assertEqual(report["profiles"]["hunt-source-leak"]["enforcement_mode"],
                         "audit")
        self.assertEqual(report["profiles"]["hunt-idor"]["enforcement_mode"], "audit")
        self.assertEqual(len(report["profiles"]), 58)

    def test_stale_or_tampered_audit_cannot_count_as_calibrated(self):
        self.audit(stage_run_id="old-stage")
        report = self.calibrate()
        self.assertEqual(report["cases"][0]["audit_status"], "INVALID_BINDING")
        self.assertEqual(report["summary"]["current_audits_binding_valid"], 0)

    def test_fact_without_replay_citations_is_invalid(self):
        self.audit(facts=[{"kind": "assertion_differential"}])
        report = self.calibrate()
        self.assertEqual(report["cases"][0]["audit_status"], "INVALID_BINDING")

    def test_fact_citations_are_sets_even_when_assessment_order_differs(self):
        self.audit(target_attempt_ids=["t3", "t2", "t1"],
                   observed_target_evidence_ids=["e-t3", "e-t2", "e-t1"])
        report = self.calibrate()
        self.assertEqual(report["cases"][0]["audit_status"], "VALID_BINDING")

    def test_nonempty_value_receipt_requires_a_path_digest_and_shape(self):
        self.audit(facts=[{
            "kind": "json_value_differential",
            "profile_id": "hunt-source-leak", "runtime_kind": "http",
            "assertion_kind": "json_path_nonempty_string",
            "assertion_id_sha256": "c" * 64,
            "assertion_predicate_sha256": "d" * 64,
            "expected_sha256": "e" * 64,
            "json_path_sha256": "f" * 64,
            "value_shape": "nonempty_string",
            "target_attempt_ids": ["t1", "t2", "t3"],
            "target_evidence_ids": ["e-t1", "e-t2", "e-t3"],
            "negative_attempt_id": "n1", "negative_evidence_id": "e-n1",
            "provenance": "contract_bound_adapter_summary",
        }])
        self.assertEqual(self.calibrate()["cases"][0]["audit_status"], "VALID_BINDING")

    def test_blocked_status_is_unresolved_not_a_wrong_verdict(self):
        with sqlite3.connect(self.pipeline) as conn:
            conn.execute("UPDATE validation_cases SET current_status='BLOCKED'")
        report = self.calibrate()
        self.assertEqual(report["cases"][0]["status_comparison"], "UNRESOLVED")

    def test_transition_axes_must_agree_with_decision_rubric(self):
        transition = json.loads((ROOT / "resources/lab/validation-transition-answer-key.json").read_text())
        transition["cases"]["verified_marker"]["fixture_final_axes"] = [0, 0, 0]
        path = self.root / "bad-transition.json"
        path.write_text(json.dumps(transition))
        with self.assertRaisesRegex(ValueError, "contradicts impact rubric"):
            self.calibrate(transition=path)

    def test_provided_axis_label_compares_measured_effective_axes_without_trust_upgrade(self):
        self.audit(effective_axes=[1, 0, 2])
        labels = self.root / "axis-labels.json"
        labels.write_text(json.dumps({
            "oracle_kind": "provided_profile_axis_labels",
            "cases": [{"candidate_id": self.candidate_id,
                       "profile_id": "hunt-source-leak",
                       "expected_axes": [1, 2, 2],
                       "source_refs": ["reviewed-observation-1"]}],
        }))
        report = self.calibrate(axis_labels=labels)
        self.assertEqual(report["cases"][0]["actual_effective_axes"], [1, 0, 2])
        self.assertEqual(report["cases"][0]["axis_comparison"], "PROVIDED_AXIS_MISMATCH")
        self.assertEqual(report["summary"]["provided_axis_labels"], 1)
        self.assertEqual(report["summary"]["independent_axis_labels"], 0)
        self.assertEqual(report["profiles"]["hunt-source-leak"]["enforcement_mode"], "audit")

    def test_synthetic_transition_axes_are_not_independent_labels(self):
        self.audit()
        report = self.calibrate()
        self.assertEqual(report["cases"][0]["axis_comparison"], "NO_AXIS_LABEL")
        self.assertEqual(report["summary"]["independent_axis_labels"], 0)

    def test_tampered_audit_axes_cannot_match_a_provided_label(self):
        self.audit(effective_axes=[1, 2, 2])
        labels = self.root / "axis-labels.json"
        labels.write_text(json.dumps({
            "oracle_kind": "provided_profile_axis_labels",
            "cases": [{"candidate_id": self.candidate_id,
                       "profile_id": "hunt-source-leak",
                       "expected_axes": [1, 2, 2],
                       "source_refs": ["reviewed-observation-1"]}],
        }))
        report = self.calibrate(axis_labels=labels)
        self.assertEqual(report["cases"][0]["audit_status"], "INVALID_BINDING")
        self.assertEqual(report["cases"][0]["axis_comparison"], "PENDING_AUDIT")

    def test_tampered_frozen_assessment_invalidates_audit(self):
        self.audit()
        with sqlite3.connect(self.pipeline) as conn:
            details = json.loads(conn.execute(
                "SELECT details_json FROM validation_evidence WHERE evidence_kind='blind_assessment'"
            ).fetchone()[0])
            details["impact_sensitivity"]["score"] = 1
            conn.execute(
                "UPDATE validation_evidence SET details_json=? WHERE evidence_kind='blind_assessment'",
                (json.dumps(details),),
            )
        report = self.calibrate()
        self.assertEqual(report["cases"][0]["audit_status"], "INVALID_BINDING")

    def test_nonready_candidate_cannot_receive_an_axis_label(self):
        official = json.loads(self.official.read_text())
        official.append({
            "candidate_id": "vuln-bank:case:GET:/api/v1/payments:bola",
            "target_validation_status": "CONFIRMED",
            "readiness": "REQUIRES_AUTH_PREREQUISITES",
        })
        self.official.write_text(json.dumps(official))
        labels = self.root / "axis-labels.json"
        labels.write_text(json.dumps({
            "oracle_kind": "provided_profile_axis_labels",
            "cases": [{"candidate_id": official[-1]["candidate_id"],
                       "profile_id": "hunt-idor", "expected_axes": [1, 1, 1],
                       "source_refs": ["reviewed-observation-1"]}],
        }))
        with self.assertRaisesRegex(ValueError, "provided axis label is invalid"):
            self.calibrate(axis_labels=labels)

    def test_synthetic_transition_key_cannot_be_used_as_axis_labels(self):
        with self.assertRaisesRegex(ValueError, "axis oracle is invalid"):
            self.calibrate(axis_labels=ROOT / "resources/lab/validation-transition-answer-key.json")

    def test_independent_lab_scorer_can_reject_a_matching_unproved_decision(self):
        self.audit()
        score = {"cases": [{
            "candidate_id": self.candidate_id,
            "target_validation_status": "CONFIRMED",
            "actual_validation_status": "CONFIRMED",
            "result": "UNSUPPORTED_DECISION",
        }]}
        with patch("scripts.calibrate_validation_profile_evidence.score_validation_lab",
                   return_value=score):
            report = calibrate_profile_evidence(
                self.official, ROOT / "resources/lab/validation-transition-answer-key.json",
                self.mapping, self.pipeline,
                candidate_inventory=self.root / "inventory.db",
                answer_db=self.root / "answers.db",
            )
        self.assertEqual(report["cases"][0]["status_comparison"], "STATUS_MATCH")
        self.assertEqual(report["cases"][0]["independent_score_result"],
                         "UNSUPPORTED_DECISION")
        self.assertEqual(report["summary"]["evidence_backed_status_matches"], 0)


if __name__ == "__main__":
    unittest.main()
