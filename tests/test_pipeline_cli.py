from __future__ import annotations

import io
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.cli import _parser, _write_recon_handoff, main
from aidast.paths import RESULT_ROOT
from aidast.pipeline.models import HandoffManifest
from aidast.recon import db
from aidast.recon.models import ReconPlan
from aidast.recon.policy import TargetPolicy
from aidast.web.projection import DashboardProjector


class PipelineCliTests(unittest.TestCase):
    def test_generated_artifact_defaults_stay_under_result(self) -> None:
        parser = _parser()
        cases = (
            (["scope", "https://example.test/program"], ("output_dir",)),
            (["recon", "https://example.test/program"],
             ("output_dir", "db_path", "surface_path")),
            (["run", "https://example.test/program", "--all-targets"],
             ("output_dir", "run_root", "attack_output_root")),
            (["attack", "plan", "handoff.json"], ("output_dir",)),
            (["validate", "run", "Attack.db"], ("output_dir",)),
            (["report", "run", "Validation.db", "--platform", "hackerone"],
             ("output_dir",)),
        )
        for arguments, fields in cases:
            with self.subTest(command=arguments[:2]):
                parsed = parser.parse_args(arguments)
                for field in fields:
                    self.assertTrue(getattr(parsed, field).is_relative_to(RESULT_ROOT))

    def test_run_prepares_thin_database_and_offline_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            program_dir = root / "scope"
            program_dir.mkdir()
            (program_dir / "Scope.md").write_text("# Approved\n", encoding="utf-8")
            (program_dir / "Scope.json").write_text("{}\n", encoding="utf-8")
            (program_dir / "Approval.json").write_text(json.dumps({
                "scope_id": "pipeline-fixture", "approved_by": "fixture-reviewer",
                "approved_at": "2026-09-18T00:00:00Z",
                "scope_json_sha256": hashlib.sha256((program_dir / "Scope.json").read_bytes()).hexdigest(),
                "scope_markdown_sha256": hashlib.sha256((program_dir / "Scope.md").read_bytes()).hexdigest(),
            }), encoding="utf-8")
            from aidast.scope.models import ScopeDocument
            from test_recon_workflow import program_page, scope_analysis
            scope = ScopeDocument(
                scope_id="pipeline-fixture", created_at=datetime.now(timezone.utc),
                source=program_page(), analysis=scope_analysis(),
            )

            def fixture_executor(**kwargs):
                conn = db.init_db(kwargs["db_path"])
                db.insert_scan(
                    conn, scan_id=kwargs["scan_id"], scope_type="approved_scope",
                    scope_value=kwargs["scope_value"],
                )
                from aidast.recon.annotations import ObservationRecorder
                asset = db.insert_asset(conn, scan_id=kwargs["scan_id"], identifier="example.com", asset_type="DOMAIN")
                origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.com", port=443, base_url="https://example.com")
                ObservationRecorder(conn, origin_id=origin, scan_id=kwargs["scan_id"]).record(
                    "fixture", [{"method": "GET", "path": f"/page-{index}"} for index in range(3)],
                )
                # One target-local tool failure is recoverable because another
                # target produced a usable, policy-bound service surface.
                return SimpleNamespace(conn=conn, scan_id=kwargs["scan_id"], run=lambda tasks: 1)

            stdout = io.StringIO()
            observed_during_planning = []

            def plan_recon(*, scope_id, scope_markdown, allowed_targets):
                observed_during_planning.extend(
                    DashboardProjector(root).stored_events_after(scan_id, 0)
                )
                return ReconPlan(
                    plan_id='fixture', scope_id='pipeline-fixture', objective='Offline fixture', mode='safe',
                    targets=[dict(asset_type='WILDCARD', asset='*.example.com', steps=['ASSET_DISCOVERY'], constraints=[])],
                    global_constraints=[], completion_criteria=['Offline fixture complete'])

            scan_id = "scan_" + "a" * 32
            with (
                patch.dict(os.environ, {"AIDAST_RESULT_ROOT": str(root)}),
                patch("aidast.cli.resolve_scope_directory", return_value=program_dir),
                patch("aidast.cli.ScopeCoordinator") as coordinator,
                patch("aidast.cli.CodexMainAgent") as planner,
                patch("aidast.cli.ReconCoordinator") as recon,
                patch("aidast.cli.ReconExecutor", side_effect=fixture_executor),
                patch("aidast.cli.OfflineReconReview") as review,
                patch("aidast.cli.AttackCoordinator") as attack_coordinator,
                patch("aidast.cli.ChainingCoordinator") as chaining_coordinator,
                patch(
                    "aidast.validation.build_native_validation_coordinator"
                ) as validation_coordinator,
                patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
                patch("subprocess.run", side_effect=AssertionError("external process forbidden")),
                redirect_stdout(stdout),
            ):
                coordinator.return_value.load_approved_scope.return_value = (scope, "scope fixture")
                from test_recon_annotations import FakeAgent
                planner.return_value._run_structured.side_effect = FakeAgent()._run_structured
                planner.return_value.create_recon_plan.side_effect = plan_recon
                planner.return_value.create_target_policies.return_value = {
                    ('WILDCARD', '*.example.com'): TargetPolicy(
                        scope_id='pipeline-fixture', policy_id='fixture', asset_type='WILDCARD',
                        asset='*.example.com', allowed_hosts=['example.com'], include_subdomains=True)}
                recon.return_value.create_tasks.return_value = []
                review.return_value.review.return_value.model_dump_json.return_value = "{}"
                attack_coordinator.return_value.run.return_value = SimpleNamespace(
                    status="COMPLETED",
                    finding_ids=[],
                )
                chaining_coordinator.return_value.run.return_value = SimpleNamespace(
                    status="SKIPPED",
                )
                validation_coordinator.return_value.run.return_value = SimpleNamespace(
                    status="completed",
                    case_ids=[],
                )
                result = main([
                    "run", "https://example.test/program", "--all-targets",
                    "--output-dir", str(root / "Scope"),
                    "--scan-id", scan_id,
                    "--recon-model", "gpt-6-sol",
                    "--attack-model", "gpt-6-luna",
                    "--validation-model", "gpt-5.6-terra",
                    "--report-model", "gpt-6-astra",
                    "--run-root", str(root / "Runs"),
                    "--attack-output-root", str(root / "AttackRuns"),
                    "--tag-batch-size", "2",
                ])
            self.assertEqual(result, 0)
            self.assertNotIn("Automatic reports unavailable", stdout.getvalue())
            progress = [
                event for event in DashboardProjector(root).stored_events_after(scan_id, 0)
                if event["payload"].get("message_code") == "agent.work"
            ]
            self.assertIn(("report", "draft", "finished"), [
                (event["payload"]["message_params"]["agent"],
                 event["payload"]["message_params"]["step"],
                 event["payload"]["message_params"]["state"])
                for event in progress
            ])
            self.assertIn(("main", "recon_plan", "started"), [
                (event["payload"]["message_params"]["agent"],
                 event["payload"]["message_params"]["step"],
                 event["payload"]["message_params"]["state"])
                for event in observed_during_planning
                if event["payload"].get("message_code") == "agent.work"
            ])
            self.assertIn(("recon", "execute", "started"), [
                (event["payload"]["message_params"]["agent"],
                 event["payload"]["message_params"]["step"],
                 event["payload"]["message_params"]["state"])
                for event in progress
            ])
            self.assertIn(("attack", "execute", "started"), [
                (event["payload"]["message_params"]["agent"],
                 event["payload"]["message_params"]["step"],
                 event["payload"]["message_params"]["state"])
                for event in progress
            ])
            recon_progress = [event["payload"]["message_params"]["progress"]
                              for event in progress
                              if event["payload"].get("stage") == "Recon"
                              and "progress" in event["payload"]["message_params"]]
            self.assertEqual(recon_progress, sorted(recon_progress))
            tagging_updates = [event["payload"]["message_params"] for event in progress
                               if event["payload"]["message_params"].get("step") == "tagging"
                               and event["payload"]["message_params"].get("state") == "progress"]
            self.assertEqual([(item["processed"], item["observation_total"], item["batch_number"],
                               item["batch_total"], item["progress"]) for item in tagging_updates],
                             [(2, 3, 1, 2, 84), (3, 3, 2, 2, 88)])
            self.assertEqual(
                [item.kwargs["main_model"] for item in planner.call_args_list],
                ["gpt-6-sol", "gpt-6-luna"],
            )
            self.assertEqual(planner.call_args_list[0].kwargs["attack_model"], "gpt-6-luna")
            self.assertEqual(planner.call_args_list[0].kwargs["chaining_model"], "gpt-6-luna")
            self.assertEqual(planner.call_args_list[0].kwargs["validation_model"], "gpt-5.6-terra")
            self.assertEqual(
                validation_coordinator.call_args.kwargs["validation_model"],
                "gpt-5.6-terra",
            )
            self.assertIn("Legacy Attack plan saved:", stdout.getvalue())
            database, = (root / "AttackRuns").glob("*/*/scan_*/legacy/Attack.db")
            self.assertEqual(database.relative_to(root / "AttackRuns").parts[:2], ("example-test", "program"))
            self.assertTrue((root / "Runs" / "example-test" / "program" / database.parent.parent.name / "Recon.db").is_file())
            from aidast.pipeline.model_settings import MODEL_SETTINGS_FILE, load_scan_model_choices, read_scan_model_choices
            model_path = root / "Runs" / "example-test" / "program" / scan_id / MODEL_SETTINGS_FILE
            models = read_scan_model_choices(model_path, scan_id=scan_id)
            self.assertEqual(models, load_scan_model_choices(root, scan_id))
            self.assertEqual(models.report_model, "gpt-6-astra")
            handoff = HandoffManifest.model_validate_json(model_path.with_name("Handoff.json").read_text())
            self.assertIn(MODEL_SETTINGS_FILE, handoff.verify_artifacts(root=model_path.parent))
            self.assertTrue((database.parent / "review/evidence-review-queue.json").is_file())
            self.assertTrue((root / "ReportRun" / scan_id / "ScanSummary.json").is_file())
            recon_database = root / "Runs" / "example-test" / "program" / scan_id / "Recon.db"
            with closing(sqlite3.connect(recon_database)) as conn:
                self.assertEqual(
                    conn.execute("SELECT status FROM scans WHERE scan_id=?", (scan_id,)).fetchone()[0],
                    "completed",
                )
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attack_plans").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attack_attempts").fetchone()[0], 0)
                self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='endpoints'").fetchone())

    def test_recon_handoff_is_consumed_by_attack_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            run_dir = root / "recon-run"
            program_dir = root / "scope"
            run_dir.mkdir()
            program_dir.mkdir()
            (program_dir / "Scope.md").write_text("# Approved\n", encoding="utf-8")
            for name in ("Scope.json", "TargetPolicy.json"):
                (program_dir / name).write_text("{}\n", encoding="utf-8")
            (program_dir / "Approval.json").write_text(json.dumps({
                "scope_id": "scope_cli", "approved_by": "fixture-reviewer",
                "approved_at": "2026-09-18T00:00:00Z",
                "scope_json_sha256": hashlib.sha256((program_dir / "Scope.json").read_bytes()).hexdigest(),
                "scope_markdown_sha256": hashlib.sha256((program_dir / "Scope.md").read_bytes()).hexdigest(),
            }), encoding="utf-8")
            surface_path = run_dir / "Surface.json"
            review_path = run_dir / "ReconReview.json"
            surface_path.write_text("{}\n", encoding="utf-8")
            review_path.write_text("{}\n", encoding="utf-8")

            conn = db.init_db(run_dir / "Recon.db")
            db.insert_scan(
                conn, scan_id="scan_cli", scope_type="approved_scope",
                scope_value="scope_cli",
            )
            asset_id = db.insert_asset(
                conn, scan_id="scan_cli", identifier="example.com",
                asset_type="DOMAIN",
            )
            origin_id = db.upsert_origin(
                conn, asset_id=asset_id, scheme="https", host="example.com",
                port=443, base_url="https://example.com",
            )
            db.upsert_endpoint(
                conn, origin_id=origin_id, method="GET", path="/api/items",
                normalized_path="/api/items", source_tool="fixture",
            )
            conn.execute(
                "UPDATE scans SET status='completed', finished_at=CURRENT_TIMESTAMP "
                "WHERE scan_id='scan_cli'"
            )
            conn.commit()
            executor = SimpleNamespace(conn=conn, scan_id="scan_cli")
            handoff = _write_recon_handoff(
                executor=executor,
                run_dir=run_dir,
                program_dir=program_dir,
                policy_path=program_dir / "TargetPolicy.json",
                surface_path=surface_path,
                review_path=review_path,
                stage_run_id="stage_cli",
            )

            output_dir = root / "attack-review"
            with redirect_stdout(io.StringIO()):
                result = main([
                    "attack", str(handoff), "--output-dir", str(output_dir)
                ])

            self.assertEqual(result, 0)
            queue = json.loads(
                (output_dir / "evidence-review-queue.json").read_text(encoding="utf-8")
            )
            self.assertEqual(queue["scan_id"], "scan_cli")
            self.assertEqual(len(queue["tasks"]), 1)
            self.assertEqual(queue["tasks"][0]["path"], "/api/items")
            conn.close()

    def test_run_requires_explicit_scope_target_selection(self) -> None:
        with self.assertRaises(SystemExit):
            main(["run", "https://bugcrowd.com/engagements/example"])


if __name__ == "__main__":
    unittest.main()
