"""Shared Pipeline.db Validation status and report v2 source binding."""

import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.lifecycle import start_stage_run
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db
from aidast.reporting import (
    CaseReportAgent as ReportAgent,
    CaseReportError as ReportError,
    case_report_status as report_status,
    record_case_report as record_report,
)
from aidast.validation import ValidationRepository, shared_validation_status


class SharedValidationReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        pipeline_dir = root / "pipeline"
        pipeline_dir.mkdir()
        self.path = pipeline_dir / "Pipeline.db"
        self.conn = db.init_db(self.path)
        migrate_live_pipeline_schema(self.conn)
        self.addCleanup(self.conn.close)
        db.insert_scan(self.conn, scan_id="scan", scope_type="test", scope_value="local")
        asset = db.insert_asset(self.conn, scan_id="scan", identifier="test", asset_type="DOMAIN")
        origin = db.upsert_origin(self.conn, asset_id=asset, scheme="https", host="test", port=443,
                                  base_url="https://test")
        self.conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,normalized_path) VALUES ('endpoint',?,'/')", (origin,))
        for identifier in ("finding", "known_finding", "contested_finding"):
            self.conn.execute("INSERT INTO findings(finding_id,scan_id,endpoint_id,vuln_type,severity,title) VALUES (?,'scan','endpoint','idor','LOW','fixture')", (identifier,))
        self.conn.commit()
        self.run = start_stage_run(self.conn, scan_id="scan", stage="validation", stage_run_id="run")
        self.repo = ValidationRepository(self.conn)
        self.output = root / "reports" / "case"

    def complete(self, case_id="case", finding="finding", status="CONFIRMED"):
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id=finding, case_id=case_id)
        attempt = self.repo.add_attempt(case_id=case_id, stage_run_id=self.run, batch_no=1,
            attempt_kind="target", ordinal=1, signal_type="response_diff", outcome="observed")
        evidence = self.repo.add_evidence(case_id=case_id, stage_run_id=self.run, attempt_id=attempt,
            evidence_kind="observation", details={"summary": "bounded fixture"},
            content_sha256="a" * 64, content_length=1, evidence_id="evidence_" + case_id)
        self.repo.finalize(case_id, stage_run_id=self.run, expected_version=0, status=status,
            decision={"summary": "confirmed fixture", "evidence_ids": [evidence]},
            evidence_ids=[evidence], impact=(1, 1, 1) if status == "CONFIRMED" else None)
        return evidence

    def draft(self, context, evidence):
        def cited(text):
            return {"text": text, "evidence_ids": [evidence]}
        return {"platform": context["platform"], "case_id": context["source"]["case_id"],
                "source_context_sha256": context["context_sha256"], "title": cited("Fixture report"),
                "asset": cited("Local fixture"), "weakness": cited("IDOR"),
                "summary": cited("A bounded fixture was validated."),
                "steps_to_reproduce": [cited("Review the persisted fixture evidence.")],
                "expected_behavior": cited("Access is denied"),
                "actual_behavior": cited("Access was observed"), "impact": cited("Boundary crossed")}

    def test_status_and_v2_report_use_case_decision_not_database_hash(self):
        evidence = self.complete()
        case_status = shared_validation_status(self.path, case_id="case")
        self.assertEqual(case_status["case"]["current_status"], "CONFIRMED")
        calls = []

        class Writer:
            def write(inner, context):
                calls.append(context)
                return self.draft(context, evidence)

        result = ReportAgent(Writer()).run(self.path, self.output, platform="hackerone", case_id="case")
        self.assertEqual((result["status"], result["stale"]), ("drafted", False))
        self.assertEqual(report_status(Path(result["report_db"]))["case_id"], "case")
        self.assertEqual(len(calls), 1)
        self.conn.execute("CREATE TABLE unrelated_after_report(value TEXT)")
        self.conn.commit()
        self.assertFalse(report_status(Path(result["report_db"]))["stale"])

    def test_changed_decision_marks_existing_report_stale(self):
        evidence = self.complete()
        prepared = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="case")
        self.conn.execute("UPDATE validation_cases SET decision_json='{}',decision_sha256=? WHERE case_id='case'",
                          ("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",))
        self.conn.commit()
        self.assertTrue(report_status(Path(prepared["report_db"]))["stale"])
        with self.assertRaisesRegex(ReportError, "differs"):
            record_report(Path(prepared["report_db"]), self.draft(
                __import__("json").loads(Path(prepared["report_db"]).parent.joinpath("Report.context.json").read_text()), evidence))

    def test_nonconfirmed_known_and_contested_are_not_report_drafts(self):
        self.complete("source", "finding")
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="known_finding", case_id="known")
        self.repo.finalize("known", stage_run_id=self.run, expected_version=0, status="KNOWN",
            decision={"result": "known"}, evidence_ids=[], known_source_case_id="source")
        known = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="known")
        self.assertEqual((known["eligibility"], known["known_source_case_id"]), ("known", "source"))
        self.repo.create_case(scan_id="scan", stage_run_id=self.run, target_kind="finding",
                              target_id="contested_finding", case_id="contested")
        self.repo.finalize("contested", stage_run_id=self.run, expected_version=0, status="CONTESTED",
            decision={"review": "required"}, evidence_ids=[])
        contested = ReportAgent().run(self.path, self.output, platform="hackerone", case_id="contested")
        self.assertEqual(contested["eligibility"], "review_only")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
