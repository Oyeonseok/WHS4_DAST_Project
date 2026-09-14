from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aidast.cli import _write_recon_handoff, main
from aidast.attack.models import AttackStageResult
from aidast.chaining.models import ChainingStageResult
from aidast.recon import db
from aidast.recon.annotations import AnnotationBatch, ObservationRecorder


class PipelineCliTests(unittest.TestCase):
    def test_annotation_status_and_resume_only_process_pending_rows(self) -> None:
        class AnnotationAgent:
            def _run_structured(self, **kwargs):
                payload = json.loads(kwargs["prompt"].split("\n", 1)[1])
                return AnnotationBatch(annotations=[{
                    "observation_id": item["observation_id"],
                    "category": "function",
                    "tag": "unknown",
                    "rationale": "근거 부족",
                    "confidence": None,
                } for item in payload["observations"]])

        with tempfile.TemporaryDirectory() as temporary_dir:
            database = Path(temporary_dir) / "Pipeline.db"
            conn = db.init_db(database)
            db.insert_scan(
                conn, scan_id="scan_annotations", scope_type="test",
                scope_value="example.com",
            )
            asset = db.insert_asset(
                conn, scan_id="scan_annotations", identifier="example.com",
                asset_type="DOMAIN",
            )
            origin = db.upsert_origin(
                conn, asset_id=asset, scheme="https", host="example.com",
                port=443, base_url="https://example.com",
            )
            ObservationRecorder(
                conn, origin_id=origin, scan_id="scan_annotations",
            ).record("fixture", [{
                "method": "GET", "path": "/api", "source": "fixture",
                "context": {"context_key": "fixture"},
            }])
            conn.close()

            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=AnnotationAgent()),
                redirect_stdout(output),
            ):
                result = main([
                    "annotations", "resume", str(database),
                    "--scan-id", "scan_annotations",
                ])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue().splitlines()[-1])["tagged"], 1)

            output = io.StringIO()
            with redirect_stdout(output):
                result = main([
                    "annotations", "status", str(database),
                    "--scan-id", "scan_annotations",
                ])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["pending"], 0)

    def test_run_uses_shared_database_and_starts_native_attack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            program_dir = root / "scope"
            program_dir.mkdir()
            for name in ("Scope.md", "Scope.json", "Approval.json"):
                (program_dir / name).write_text("{}\n", encoding="utf-8")
            scope = SimpleNamespace(
                scope_id="pipeline-fixture", analysis=SimpleNamespace(in_scope_assets=[]),
            )

            def fixture_executor(**kwargs):
                conn = db.init_db(kwargs["db_path"])
                db.insert_scan(
                    conn, scan_id=kwargs["scan_id"], scope_type="approved_scope",
                    scope_value=kwargs["scope_value"],
                )
                return SimpleNamespace(conn=conn, scan_id=kwargs["scan_id"], run=lambda tasks: None)

            stdout = io.StringIO()
            validation = Mock()
            validation.run.return_value = SimpleNamespace(
                stage_run_id="fixture-validation-stage", case_ids=(),
            )
            with (
                patch("aidast.cli.resolve_scope_directory", return_value=program_dir),
                patch("aidast.cli.ScopeCoordinator") as coordinator,
                patch("aidast.cli.CodexMainAgent") as planner,
                patch("aidast.cli.ReconCoordinator") as recon,
                patch("aidast.cli.ReconExecutor", side_effect=fixture_executor),
                patch("aidast.cli.OfflineReconReview") as review,
                patch("aidast.cli.AttackCoordinator") as attack,
                patch("aidast.cli.ChainingCoordinator") as chaining,
                patch(
                    "aidast.validation.build_native_validation_coordinator",
                    return_value=validation,
                ) as validation_factory,
                patch("socket.create_connection", side_effect=AssertionError("network forbidden")),
                patch("subprocess.run", side_effect=AssertionError("external process forbidden")),
                redirect_stdout(stdout),
            ):
                coordinator.return_value.load_approved_scope.return_value = (scope, "scope fixture")
                planner.return_value.create_recon_plan.return_value = SimpleNamespace(plan_id="fixture", targets=[])
                planner.return_value.create_target_policies.return_value = {}
                recon.return_value.create_tasks.return_value = []
                review.return_value.review.return_value.model_dump_json.return_value = "{}"
                attack.return_value.run.return_value = AttackStageResult(
                    status="COMPLETED", scan_id="fixture-scan", db_path="Pipeline.db",
                    stage_run_id="fixture-stage", attack_agent_ids=["agent-fixture"],
                )
                chaining.return_value.run.return_value = ChainingStageResult(
                    status="SKIPPED", scan_id="fixture-scan", db_path="Pipeline.db",
                    stage_run_id="fixture-chain-stage",
                )
                result = main([
                    "run", "https://example.test/program", "--all-targets",
                    "--run-root", str(root / "Runs"),
                    "--attack-output-root", str(root / "AttackRuns"),
                ])
            self.assertEqual(result, 0)
            self.assertIn("Native Attack Agent completed: agent-fixture", stdout.getvalue())
            database, = (root / "Runs").glob("*/Pipeline.db")
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM attack_attempts").fetchone()[0], 0)
                self.assertIsNotNone(conn.execute("SELECT name FROM sqlite_master WHERE name='endpoints'").fetchone())
            attack.assert_called_once()
            chaining.assert_called_once()
            validation.run.assert_called_once()
            validation_factory.assert_called_once_with(
                db_path=database,
                policy_path=database.parent / "TargetPolicy.json",
            )
            self.assertIn("Shared Validation completed", stdout.getvalue())

    def test_recon_handoff_is_consumed_by_attack_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            run_dir = root / "recon-run"
            program_dir = root / "scope"
            run_dir.mkdir()
            program_dir.mkdir()
            for name in ("Scope.json", "Approval.json", "TargetPolicy.json"):
                (program_dir / name).write_text("{}\n", encoding="utf-8")
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
