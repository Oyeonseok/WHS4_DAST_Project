"""Transactional invariants for shared Validation storage."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import finish_stage_run, resume_validation_stage_run, start_stage_run
from aidast.recon import db
from aidast.validation import (ConcurrentValidationUpdate, ValidationRepository,
                               ValidationRepositoryError, canonical_sha256)


class ValidationRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.conn = db.init_db(Path(self.temp.name) / "Pipeline.db")
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('endpoint',?,'/')", (origin,))
        for identifier in ("one", "two"):
            self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES (?, 'scan','endpoint','idor','LOW','fixture')", (identifier,))
        db.insert_scan(self.conn, scan_id="other_scan", scope_type="test", scope_value="other")
        other_asset = db.insert_asset(self.conn, scan_id="other_scan", identifier="other", asset_type="DOMAIN")
        other_origin = db.upsert_origin(self.conn, asset_id=other_asset, scheme="https", host="other",
                                        port=443, base_url="https://other")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('other_endpoint',?,'/')", (other_origin,))
        self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES ('foreign','other_scan','other_endpoint','idor','LOW','fixture')")
        self.conn.commit()
        self.run = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="run")
        self.repo = ValidationRepository(self.conn)

    def case_with_evidence(self, identifier="case", finding="one"):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id=finding, case_id=identifier)
        attempt = self.repo.add_attempt(case_id=identifier, stage_run_id=self.run, batch_no=1,
            attempt_kind="target", ordinal=1, signal_type="response_diff", outcome="observed",
            attempt_id=f"attempt_{identifier}")
        evidence = self.repo.add_evidence(case_id=identifier, stage_run_id=self.run,
            attempt_id=attempt, evidence_kind="observation", details={"bounded": True},
            content_sha256="a" * 64, content_length=1, evidence_id=f"evidence_{identifier}")
        return evidence

    def test_finalize_is_digest_bound_and_optimistically_locked(self):
        evidence = self.case_with_evidence()
        decision = {"reason": "fixture", "evidence_ids": [evidence]}
        self.assertEqual(self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
            status="CONFIRMED", decision=decision, evidence_ids=[evidence], impact=(1, 1, 1)), 1)
        stored = self.repo.read_case("case")
        self.assertEqual(stored["decision_sha256"], canonical_sha256(decision))
        with self.assertRaises(ConcurrentValidationUpdate):
            self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
                status="INCONCLUSIVE", decision={"reason": "stale"}, evidence_ids=[])

    def test_foreign_stage_evidence_and_invalid_impact_are_rejected(self):
        evidence = self.case_with_evidence()
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="two", case_id="other")
        with self.assertRaises(ValidationRepositoryError):
            self.repo.finalize("other", stage_run_id=self.run, expected_version=0,
                status="INCONCLUSIVE", decision={"reason": "bad"}, evidence_ids=[evidence])
        with self.assertRaises(ValidationRepositoryError):
            self.repo.finalize("case", stage_run_id=self.run, expected_version=0,
                status="CONFIRMED", decision={"reason": "weak"}, evidence_ids=[evidence], impact=(0, 3, 3))
        with self.assertRaises(ValidationRepositoryError):
            self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                                  target_id="foreign")

    def test_known_source_must_be_current_and_is_invalidated_atomically(self):
        source_evidence = self.case_with_evidence("source", "one")
        self.repo.finalize("source", stage_run_id=self.run, expected_version=0, status="CONFIRMED",
            decision={"result": "confirmed"}, evidence_ids=[source_evidence], impact=(1, 1, 1))
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="two", case_id="duplicate")
        self.repo.finalize("duplicate", stage_run_id=self.run, expected_version=0, status="KNOWN",
            decision={"result": "known"}, evidence_ids=[], known_source_case_id="source", known_similarity=.9)
        finish_stage_run(self.conn, self.run)
        rerun = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="rerun")
        self.repo.begin_revalidation("source", stage_run_id=rerun, expected_version=1)
        self.repo.finalize("source", stage_run_id=rerun, expected_version=2, status="INCONCLUSIVE",
            decision={"result": "changed"}, evidence_ids=[])
        duplicate = self.repo.read_case("duplicate")
        self.assertEqual(duplicate["current_status"], "INCONCLUSIVE")
        self.assertEqual(duplicate["decision"]["reason"], "known_source_no_longer_confirmed")

    def test_failed_stage_cleanup_and_resume(self):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="one", case_id="case")
        self.conn.execute("UPDATE validation_cases SET processing_phase='blind_replay' WHERE case_id='case'")
        self.repo.add_attempt(case_id="case", stage_run_id=self.run, batch_no=1,
            attempt_kind="target", ordinal=1, signal_type="timing", outcome="error", finished=False)
        finish_stage_run(self.conn, self.run, status="failed", error_message="worker stopped")
        self.assertEqual(self.conn.execute("SELECT processing_phase FROM validation_cases").fetchone()[0], "interrupted")
        self.assertEqual(self.conn.execute("SELECT outcome FROM validation_attempts").fetchone()[0], "outcome_unknown")
        resume_validation_stage_run(self.conn, self.run)
        self.assertEqual(self.conn.execute("SELECT status FROM stage_runs").fetchone()[0], "running")
        audit = self.conn.execute("SELECT details_json FROM audit_events WHERE event_type='stage.resumed'").fetchone()[0]
        self.assertIn("worker stopped", audit)

    def test_validation_stage_cannot_complete_with_unfinished_case(self):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="one", case_id="case")
        with self.assertRaisesRegex(ValueError, "terminal current case"):
            finish_stage_run(self.conn, self.run)
