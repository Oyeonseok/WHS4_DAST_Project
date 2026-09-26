"""Ground-truth coverage stays distinct from synthetic axis fixtures."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.validation.contracts.models import canonical_sha256
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

    def audit(self, **changes):
        document = {
            "rule_version": "profile-evidence-v1", "mode": "audit",
            "case_id": "case", "stage_run_id": "stage",
            "profile_id": "hunt-source-leak",
            "profile_sha256": "b" * 64,
            "assessment_sha256": "a" * 64,
            "replay_status": "complete",
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

    def calibrate(self, *, transition=None):
        return calibrate_profile_evidence(
            self.official,
            transition or ROOT / "resources/lab/validation-transition-answer-key.json",
            self.mapping, self.pipeline,
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


if __name__ == "__main__":
    unittest.main()
