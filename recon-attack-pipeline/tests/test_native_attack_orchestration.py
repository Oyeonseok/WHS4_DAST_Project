from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aidast.agents.main import CodexMainAgent
from aidast.attack.db_cli import (
    commit_attempt, commit_finding, query, resolve_attempt, transition_task,
)
from aidast.attack.models import AttackStageResult
from aidast.orchestration.attack import AttackCoordinator, AttackCoordinatorError
from aidast.pipeline.lifecycle import create_task, start_stage_run
from aidast.recon import db


class FakeNativeMain:
    def __init__(self) -> None:
        self.calls = []

    def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
        self.calls.append(kwargs)
        for task in kwargs["attack_tasks"]:
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "running",
            )
            transition_task(
                kwargs["db_path"], kwargs["scan_id"], kwargs["stage_run_id"],
                task["task_id"], "completed",
            )
        return AttackStageResult(
            status="COMPLETED",
            scan_id=kwargs["scan_id"],
            db_path=str(kwargs["db_path"]),
            stage_run_id=kwargs["stage_run_id"],
            attack_agent_ids=["/root/aidast_attack"],
            summary="no applicable findings",
        )


def completed_pipeline(root: Path) -> Path:
    path = root / "Pipeline.db"
    conn = db.init_db(path)
    db.insert_scan(
        conn, scan_id="scan_native", scope_type="approved_scope", scope_value="scope"
    )
    asset = db.insert_asset(
        conn, scan_id="scan_native", identifier="example.test", asset_type="DOMAIN"
    )
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test",
    )
    endpoint = db.upsert_endpoint(
        conn, origin_id=origin, method="GET", path="/api/items",
        normalized_path="/api/items", source_tool="fixture",
    )
    conn.execute(
        """INSERT INTO parameters
           (parameter_id,endpoint_id,name,location,data_type,is_identifier)
           VALUES ('parameter_item_id',?,'object_id','query','string',1)""",
        (endpoint,),
    )
    conn.execute(
        "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan_native'"
    )
    conn.commit()
    conn.close()
    return path


class NativeAttackCoordinatorTests(unittest.TestCase):
    def test_completed_recon_spawns_one_agent_and_finishes_attack_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FakeNativeMain()

            result = AttackCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy
            ).run("scan_native")

            self.assertEqual(result.attack_agent_ids, ["/root/aidast_attack"])
            self.assertEqual(len(main.calls), 1)
            with closing(sqlite3.connect(database)) as conn:
                row = conn.execute(
                    "SELECT status FROM stage_runs WHERE scan_id='scan_native' AND stage='attack'"
                ).fetchone()
            self.assertEqual(row, ("completed",))
            self.assertGreater(len(main.calls[0]["attack_tasks"]), 0)

    def test_existing_attack_stage_prevents_duplicate_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            coordinator = AttackCoordinator(
                agent=FakeNativeMain(), db_path=database, scope_path=scope,
                policy_path=policy,
            )
            coordinator.run("scan_native")
            with self.assertRaisesRegex(AttackCoordinatorError, "already exists"):
                coordinator.run("scan_native")

    def test_unresolved_lead_prevents_stage_completion(self) -> None:
        class UnresolvedLeadMain(FakeNativeMain):
            def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
                with closing(sqlite3.connect(kwargs["db_path"])) as conn, conn:
                    endpoint_id = conn.execute(
                        "SELECT endpoint_id FROM endpoints LIMIT 1"
                    ).fetchone()[0]
                    conn.execute(
                        """INSERT INTO attack_attempts
                           (attempt_id,scan_id,skill_name,endpoint_id,
                            request_fingerprint,outcome)
                           VALUES ('attempt_open','scan_native','hunt-cors',?,?,'lead')""",
                        (endpoint_id, "d" * 64),
                    )
                return super().run_attack_orchestrator(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            coordinator = AttackCoordinator(
                agent=UnresolvedLeadMain(), db_path=database,
                scope_path=scope, policy_path=policy,
            )
            with self.assertRaisesRegex(AttackCoordinatorError, "unresolved lead"):
                coordinator.run("scan_native")

    def test_failed_stage_can_resume_without_reusing_stage_or_tasks(self) -> None:
        class FailOnceMain(FakeNativeMain):
            def run_attack_orchestrator(self, **kwargs) -> AttackStageResult:
                if not self.calls:
                    self.calls.append(kwargs)
                    raise RuntimeError("interrupted")
                return super().run_attack_orchestrator(**kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")
            main = FailOnceMain()
            coordinator = AttackCoordinator(
                agent=main, db_path=database, scope_path=scope, policy_path=policy,
            )
            with self.assertRaisesRegex(AttackCoordinatorError, "interrupted"):
                coordinator.run("scan_native")
            result = coordinator.run("scan_native")
            self.assertEqual(result.status, "COMPLETED")
            with closing(sqlite3.connect(database)) as conn:
                stages = conn.execute(
                    "SELECT stage_run_id,status FROM stage_runs WHERE stage='attack' ORDER BY created_at"
                ).fetchall()
                tasks = conn.execute(
                    "SELECT stage_run_id,status FROM attack_tasks ORDER BY created_at"
                ).fetchall()
            self.assertEqual([row[1] for row in stages], ["failed", "completed"])
            self.assertEqual({row[1] for row in tasks}, {"cancelled", "completed"})
            self.assertNotEqual(stages[0][0], stages[1][0])


class NativeAttackMainAgentTests(unittest.TestCase):
    def test_main_stages_hunt_skills_and_custom_attack_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            scope = root / "Scope.md"
            policy = root / "TargetPolicy.json"
            scope.write_text("# approved", encoding="utf-8")
            policy.write_text("{}", encoding="utf-8")

            def fake_run(command, **kwargs):
                work = Path(command[command.index("--cd") + 1])
                self.assertNotIn("--ephemeral", command)
                self.assertEqual(
                    command[command.index("--model") + 1], "gpt-5.6-sol"
                )
                self.assertTrue(
                    (work / ".codex/agents/aidast-attack.toml").is_file()
                )
                agent_config = (
                    work / ".codex/agents/aidast-attack.toml"
                ).read_text(encoding="utf-8")
                self.assertIn('model = "gpt-5.6-sol"', agent_config)
                self.assertTrue(
                    (work / ".agents/skills/aidast-live-attack/SKILL.md").is_file()
                )
                self.assertTrue((work / "tools/request_cli.py").is_file())
                self.assertTrue(
                    (work / "hunt-skills/hunt-dispatch/SKILL.md").is_file()
                )
                self.assertTrue((work / "hunt-skills/hunt-idor/SKILL.md").is_file())
                self.assertLessEqual(
                    len(list((work / "hunt-skills").glob("hunt-*/SKILL.md"))), 9
                )
                self.assertFalse((work / "hunt-skills/hunt-xxe").exists())
                self.assertFalse((work / "hunt-skills/chain").exists())
                config = json.loads((work / "config.json").read_text(encoding="utf-8"))
                self.assertEqual(config["pipeline_db_path"], str(database.resolve()))
                self.assertIn("hunt-idor", config["hunt_skill_names"])
                self.assertIn(
                    "identifier parameter",
                    config["hunt_skill_selection_reasons"]["hunt-idor"],
                )
                self.assertEqual(config["hunt_skill_root"], str(work / "hunt-skills"))
                self.assertEqual(config["attack_tasks"][0]["task_id"], "task_one")
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(AttackStageResult(
                    status="COMPLETED", scan_id="scan_native",
                    db_path=str(database.resolve()), stage_run_id="stage_attack",
                    attack_agent_ids=["/root/aidast_attack"],
                ).model_dump_json(), encoding="utf-8")
                return SimpleNamespace(returncode=0, stderr="")

            agent = CodexMainAgent(python_executable=str(Path(__file__).resolve()))
            with (
                patch("aidast.agents.main.shutil.which", return_value="codex.exe"),
                patch.object(CodexMainAgent, "_require_login"),
                patch("aidast.agents.main.subprocess.run", side_effect=fake_run),
            ):
                result = agent.run_attack_orchestrator(
                    scan_id="scan_native", db_path=database, scope_path=scope,
                    policy_path=policy, stage_run_id="stage_attack",
                    attack_tasks=[{
                        "task_id": "task_one", "skill_name": "hunt-idor",
                        "selection_reasons": ["identifier parameter"],
                    }],
                    selected_skill_names=("hunt-idor",),
                    selection_reasons={"hunt-idor": ("identifier parameter",)},
                )
            self.assertEqual(result.attack_agent_ids, ["/root/aidast_attack"])


class NativeAttackDatabaseCliTests(unittest.TestCase):
    def test_agent_helper_queries_recon_and_commits_attack_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = completed_pipeline(root)
            endpoint_id = query(
                database,
                "SELECT endpoint_id FROM endpoints WHERE path='/api/items'",
            )[0]["endpoint_id"]
            with closing(sqlite3.connect(database)) as conn:
                stage_run_id = start_stage_run(conn, scan_id="scan_native", stage="attack")
                task_id = create_task(
                    conn, stage_run_id=stage_run_id, skill_name="hunt-cors",
                )
            transition_task(
                database, "scan_native", stage_run_id, task_id, "running"
            )
            attempt = root / "attempt.json"
            attempt.write_text(json.dumps({
                "task_id": task_id, "skill_name": "hunt-cors", "endpoint_id": endpoint_id,
                "request_fingerprint": "a" * 64, "method": "GET",
                "url": "https://example.test/api/items", "payload_variant": "baseline",
                "response_status": 200, "response_signature": "b" * 64,
                "outcome": "lead",
            }), encoding="utf-8")
            attempt_result = commit_attempt(database, "scan_native", attempt)
            self.assertTrue(attempt_result["committed"])
            duplicate = commit_attempt(database, "scan_native", attempt)
            self.assertFalse(duplicate["committed"])
            self.assertEqual(duplicate["attempt_id"], attempt_result["attempt_id"])

            with closing(sqlite3.connect(database)) as conn, conn:
                conn.execute("""INSERT INTO attack_http_requests
                    (request_id,scan_id,stage_run_id,task_id,policy_id,policy_sha256,
                     method,url,request_fingerprint,status,response_status,response_bytes,scheduled_at)
                    VALUES ('http_fixture','scan_native',?,?,'policy',?,'GET',
                    'https://example.test/api/items',?,'completed',200,5,0)""",
                    (stage_run_id, task_id, "d" * 64, "a" * 64))

            finding = root / "finding.json"
            finding.write_text(json.dumps({
                "scan_id": "scan_native", "endpoint_id": endpoint_id,
                "vuln_type": "CORS", "severity": "MEDIUM",
                "title": "Untrusted origin accepted",
                "description": "The observed response reflected an untrusted origin.",
                "lead_attempt_ids": [attempt_result["attempt_id"]],
                "reproduction": {
                    "method": "GET", "endpoint_template": "/api/items",
                    "injection_location": "query", "parameter_name": "object_id",
                    "payload_template": {"object_id": "<slot:string>"},
                    "required_identity_roles": [],
                    "source_request_ids": ["http_fixture"],
                },
                "evidence": [{
                    "role": "unauthenticated", "method": "GET",
                    "url": "https://example.test/api/items", "response_status": 200,
                    "response_headers": "access-control-allow-origin: https://redacted.invalid",
                    "response_body": "proof", "response_time_ms": 10,
                }],
            }), encoding="utf-8")
            result = commit_finding(database, "scan_native", finding)
            with closing(sqlite3.connect(database)) as conn:
                stored = conn.execute(
                    "SELECT vuln_type,status FROM findings WHERE finding_id=?",
                    (result["finding_id"],),
                ).fetchone()
                requests = conn.execute("SELECT COUNT(*) FROM attack_requests").fetchone()[0]
                promoted = conn.execute(
                    """SELECT outcome,finding_id,resolved_at IS NOT NULL
                       FROM attack_attempts WHERE attempt_id=?""",
                    (attempt_result["attempt_id"],),
                ).fetchone()
            self.assertEqual(stored, ("CORS", "unreviewed"))
            self.assertEqual(requests, 1)
            self.assertEqual(promoted, ("confirmed", result["finding_id"], 1))
            self.assertEqual(result["promoted_attempt_count"], 1)

            second_attempt = root / "second-attempt.json"
            second_attempt.write_text(json.dumps({
                "task_id": task_id, "skill_name": "hunt-cors", "endpoint_id": endpoint_id,
                "request_fingerprint": "c" * 64, "method": "GET",
                "url": "https://example.test/api/items", "payload_variant": "control",
                "response_status": 200, "response_signature": "e" * 64,
                "outcome": "lead",
            }), encoding="utf-8")
            second = commit_attempt(database, "scan_native", second_attempt)
            resolution = root / "resolution.json"
            resolution.write_text(json.dumps({
                "attempt_id": second["attempt_id"], "resolution": "rejected",
                "reason": "matched the negative control",
            }), encoding="utf-8")
            self.assertTrue(
                resolve_attempt(database, "scan_native", resolution)["resolved"]
            )
            with closing(sqlite3.connect(database)) as conn:
                closed = conn.execute(
                    "SELECT outcome,resolution_reason,resolved_at IS NOT NULL "
                    "FROM attack_attempts WHERE attempt_id=?", (second["attempt_id"],),
                ).fetchone()
            self.assertEqual(closed, ("rejected", "matched the negative control", 1))
            transition_task(
                database, "scan_native", stage_run_id, task_id, "completed"
            )


if __name__ == "__main__":
    unittest.main()
