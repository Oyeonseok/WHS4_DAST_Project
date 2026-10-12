from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from pydantic import BaseModel

from aidast.core.model_calls import (
    ModelCallEvent,
    SQLiteModelCallSink,
    close_abandoned_model_calls,
    logged_model_call,
    model_call_context,
    read_model_call_events,
    read_scan_token_usage,
    record_jsonl_usage,
    record_session_usage,
    using_model_call_sink,
)
from aidast.web.programs import ProgramRegistry
from aidast.web.scope_workflow import ScopeCollectionRequest, ScopeWorkflowManager
from aidast.web.server import create_app


class ModelCallLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "logs" / "CodexCalls.db"

    def test_resume_closes_abandoned_started_calls_append_only(self) -> None:
        sink = SQLiteModelCallSink(self.root)
        sink.append(ModelCallEvent(
            call_id='a' * 32, state='started',
            occurred_at='2026-01-01T00:00:00+00:00',
            scan_id='scan-1', stage='Attack', stage_run_id='stage-1',
            task_id=None, case_id=None, scope_job_id=None,
            operation_code='attack_orchestrator',
            invocation_kind='attack_orchestrator', requested_model='gpt-6-sol',
            elapsed_ms=None, error_code=None, input_tokens=None,
            cached_input_tokens=None, output_tokens=None,
            usage_status='not_captured', input_summary={'task_count': 8},
            result_summary={},
        ))

        self.assertEqual(close_abandoned_model_calls(self.root, 'scan-1'), 1)
        self.assertEqual(close_abandoned_model_calls(self.root, 'scan-1'), 0)
        events, _ = read_model_call_events(self.root)
        self.assertEqual([event['state'] for event in events], ['error', 'started'])
        self.assertEqual(events[0]['error_code'], 'agent_error')
        self.assertEqual(events[0]['usage_status'], 'absent')
        self.assertEqual(events[0]['input_summary'], {'task_count': 8})

    def test_scope_policy_call_records_safe_work_summary_and_clears_scan_linkage(self) -> None:
        class Result(BaseModel):
            required_request_headers: list[str]
            execution_rules: dict[str, list[str]]

        class Agent:
            _main_model = "gpt-5.6-sol"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str, prompt: str) -> Result:
                return Result(required_request_headers=["private-header"],
                              execution_rules={"required_inputs": ["private-input"]})

        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            model_call_context(scan_id="other-scan", stage="Recon", task_id="old-task"),
        ):
            Agent().run(operation="approved Scope execution interpretation", prompt="private-prompt")
        events, _ = read_model_call_events(self.root)
        completed = events[0]
        self.assertEqual(completed["operation_code"], "scope_execution_interpretation")
        self.assertEqual(completed["stage"], "Scope")
        self.assertIsNone(completed["scan_id"])
        self.assertIsNone(completed["task_id"])
        self.assertEqual(completed["input_summary"], {"prompt_characters": 14})
        self.assertEqual(completed["result_summary"]["header_count"], 1)
        self.assertEqual(completed["result_summary"]["rule_count"], 1)
        stored = self.database.read_bytes().decode("utf-8", errors="ignore")
        for secret in ["private-header", "private-input", "private-prompt"]:
            self.assertNotIn(secret, stored)

    def test_old_metadata_database_reads_without_migration_and_new_calls_add_details(self) -> None:
        class Agent:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str, prompt: str) -> None:
                return None

        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            Agent().run(operation="Scope collection", prompt="old")
        with sqlite3.connect(self.database) as conn:
            conn.execute("ALTER TABLE codex_call_events DROP COLUMN input_summary")
            conn.execute("ALTER TABLE codex_call_events DROP COLUMN result_summary")
        original = self.database.read_bytes()
        events, _ = read_model_call_events(self.root)
        self.assertEqual(events[0]["input_summary"], {})
        self.assertEqual(events[0]["result_summary"], {})
        self.assertEqual(self.database.read_bytes(), original)
        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            Agent().run(operation="Scope collection", prompt="new prompt")
        events, _ = read_model_call_events(self.root)
        self.assertEqual(events[0]["input_summary"], {"prompt_characters": 10})
        self.assertEqual(events[-1]["input_summary"], {})

    def test_corrupt_summary_is_rejected_without_exposing_contents(self) -> None:
        class Agent:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                return None

        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            Agent().run(operation="Scope collection")
        with sqlite3.connect(self.database) as conn:
            conn.execute("DROP TRIGGER codex_call_no_update")
            conn.execute("UPDATE codex_call_events SET result_summary=?",
                         (json.dumps({"private-output": "secret-response"}),))
        with TestClient(create_app(result_root=self.root)) as client:
            response = client.get("/api/v1/model-calls")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret-response", response.text)

    def test_scope_navigation_records_only_the_chosen_safe_action(self) -> None:
        class Result(BaseModel):
            action: str
            candidate_id: int | None = None

        class Agent:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str, action: str) -> Result:
                return Result(action=action, candidate_id=37)

        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            Agent().run(operation="Scope page navigation", action="open")
            Agent().run(operation="Scope page navigation", action="capture")
        events, _ = read_model_call_events(self.root)
        completed = [event["result_summary"] for event in events if event["state"] == "success"]
        self.assertEqual(completed, [{"field_count": 2, "capture_selected": 1},
                                    {"field_count": 2, "navigation_selected": 1}])
        self.assertNotIn("candidate_id", self.database.read_bytes().decode("utf-8", errors="ignore"))

    def test_disabled_calls_create_no_files_and_enabled_calls_record_metadata_only(self) -> None:
        class Agent:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str, prompt: str) -> str:
                return "private result"

        agent = Agent()
        self.assertEqual(agent.run(operation="Scope collection", prompt="private prompt"), "private result")
        self.assertFalse(self.database.exists())
        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            model_call_context(stage="scope", scope_job_id="job-1"),
        ):
            self.assertEqual(agent.run(operation="Scope collection", prompt="private prompt"), "private result")
        events, cursor = read_model_call_events(self.root, limit=10)
        self.assertEqual([event["state"] for event in events], ["success", "started"])
        self.assertIsNone(cursor)
        self.assertEqual([event["scope_job_id"] for event in events], ["job-1", "job-1"])
        self.assertEqual(events[0]["operation_code"], "scope_collection")
        self.assertEqual(events[0]["requested_model"], "gpt-test")
        self.assertIsNone(events[0]["scan_id"])
        self.assertNotIn("private prompt", self.database.read_bytes().decode("utf-8", errors="ignore"))
        self.assertNotIn("private result", self.database.read_bytes().decode("utf-8", errors="ignore"))

    def test_failure_preserves_original_error_without_storing_its_message(self) -> None:
        class Agent:
            _main_model = None

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                raise RuntimeError("private exception text")

        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            model_call_context(scan_id="scan-1", stage="validation", case_id="case-1"),
            self.assertRaisesRegex(RuntimeError, "private exception text"),
        ):
            Agent().run(operation="blind Validation assessment")
        events, _ = read_model_call_events(self.root)
        self.assertEqual([event["state"] for event in events], ["error", "started"])
        self.assertEqual(events[0]["scan_id"], "scan-1")
        self.assertEqual(events[0]["case_id"], "case-1")
        self.assertEqual(events[0]["operation_code"], "validation_assessment")
        self.assertEqual(events[0]["error_code"], "agent_error")
        self.assertIsNone(events[0]["requested_model"])
        self.assertNotIn("private exception text", self.database.read_bytes().decode("utf-8", errors="ignore"))

    def test_structured_adapters_preserve_deadline_reason_as_error_cause(self) -> None:
        from aidast.agents.main import CodexMainAgent, MainAgentError
        from aidast.agents.native_pipeline import (
            CodexMainAgent as NativeAgent,
            MainAgentError as NativeAgentError,
        )
        from aidast.core.codex_process import CodexProcessTimeout, TimeoutReason

        class Artifact(BaseModel):
            ok: bool

        reasons: tuple[TimeoutReason, ...] = ("total", "idle", "tool")
        for adapter, error_type in [
            (CodexMainAgent, MainAgentError),
            (NativeAgent, NativeAgentError),
        ]:
            for reason in reasons:
                with self.subTest(adapter=adapter.__module__, reason=reason):
                    expired = CodexProcessTimeout(
                        ["codex"], 900, reason=reason,
                        tool_id="item_stuck" if reason == "tool" else None,
                        tool_name="command_execution" if reason == "tool" else None,
                    )
                    with (
                        patch("aidast.agents.main.shutil.which", return_value="codex"),
                        patch.object(adapter, "_require_login"),
                        patch(
                            "aidast.agents.main.codex_process.run_codex",
                            side_effect=expired,
                        ),
                        self.assertRaises(error_type) as caught,
                    ):
                        adapter()._run_structured(
                            prompt="fixture", model_type=Artifact,
                            artifact_name="deadline", operation="Recon Plan generation",
                        )
                    self.assertIs(caught.exception.__cause__, expired)

    def test_structured_adapters_use_absolute_deadline_for_silent_toolless_turns(self) -> None:
        from aidast.agents.main import CodexMainAgent
        from aidast.agents.native_pipeline import CodexMainAgent as NativeAgent

        class Artifact(BaseModel):
            ok: bool

        def completed(command, **_kwargs):
            output = Path(command[command.index("--output-last-message") + 1])
            output.write_text('{"ok":true}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, None, "")

        for adapter in (CodexMainAgent, NativeAgent):
            with self.subTest(adapter=adapter.__module__):
                with (
                    patch(f"{adapter.__module__}.shutil.which", return_value="codex"),
                    patch.object(adapter, "_require_login"),
                    patch(
                        f"{adapter.__module__}.codex_process.run_codex",
                        side_effect=completed,
                    ) as run,
                ):
                    adapter(timeout_seconds=3600)._run_structured(
                        prompt="fixture",
                        model_type=Artifact,
                        artifact_name="silent-tool-disabled",
                        operation="captured Scope interpretation",
                        allow_browser=False,
                    )
                    self.assertEqual(run.call_args.kwargs["idle_timeout"], 3600)

    def test_browser_structured_turn_keeps_no_progress_watchdog(self) -> None:
        from aidast.agents.main import CodexMainAgent
        from aidast.core.codex_process import CODEX_IDLE_TIMEOUT_SECONDS

        class Artifact(BaseModel):
            ok: bool

        def completed(command, **_kwargs):
            output = Path(command[command.index("--output-last-message") + 1])
            output.write_text('{"ok":true}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, None, "")

        with (
            patch("aidast.agents.main.shutil.which", return_value="codex"),
            patch.object(CodexMainAgent, "_require_login"),
            patch(
                "aidast.agents.main.codex_process.run_codex",
                side_effect=completed,
            ) as run,
        ):
            CodexMainAgent(timeout_seconds=3600)._run_structured(
                prompt="fixture",
                model_type=Artifact,
                artifact_name="browser-turn",
                operation="Scope collection",
                allow_browser=True,
            )
            self.assertEqual(
                run.call_args.kwargs["idle_timeout"],
                CODEX_IDLE_TIMEOUT_SECONDS,
            )

    def test_newer_events_page_before_older_events_without_creating_missing_store(self) -> None:
        self.assertEqual(read_model_call_events(self.root), ([], None))
        self.assertFalse(self.database.exists())

        class Agent:
            _main_model = None

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                return None

        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            Agent().run(operation="Scope collection")
            Agent().run(operation="Recon Plan generation")
        latest, before = read_model_call_events(self.root, limit=2)
        self.assertEqual(len(latest), 2)
        self.assertIsNotNone(before)
        older, end = read_model_call_events(self.root, before=before, limit=2)
        self.assertEqual(len(older), 2)
        self.assertIsNone(end)
        self.assertTrue(all(item["event_id"] < before for item in older))

    def test_api_reads_only_metadata_and_reports_corruption_without_contents(self) -> None:
        app = create_app(result_root=self.root)
        with TestClient(app) as client:
            empty = client.get("/api/v1/model-calls")
            self.assertEqual(empty.status_code, 200)
            self.assertEqual(empty.json(), {"events": [], "next_before": None})
            self.assertFalse(self.database.exists())

            class Agent:
                _main_model = "gpt-test"

                @logged_model_call("structured", model_attribute="_main_model")
                def run(self, *, operation: str, prompt: str) -> None:
                    return None

            with using_model_call_sink(SQLiteModelCallSink(self.root)):
                Agent().run(operation="Recon Plan generation", prompt="private prompt")
                Agent().run(operation="Recon Plan generation", prompt="private prompt")
            latest = client.get("/api/v1/model-calls?limit=2")
            self.assertEqual(latest.status_code, 200)
            self.assertEqual(len(latest.json()["events"]), 2)
            older = client.get(f"/api/v1/model-calls?limit=2&before={latest.json()['next_before']}")
            self.assertEqual(older.status_code, 200)
            self.assertIsNone(older.json()["next_before"])
            self.assertNotIn("private prompt", str(latest.json()) + str(older.json()))
            self.assertEqual(client.get("/api/v1/model-calls?limit=201").status_code, 422)
            with sqlite3.connect(self.database) as conn:
                conn.execute(
                    "INSERT INTO codex_call_events "
                    "(call_id,state,occurred_at,operation_code,invocation_kind,usage_status) "
                    "VALUES (?,?,?,?,?,?)",
                    ("a" * 32, "started", "2026-09-27T00:00:00Z", "private prompt", "structured", "absent"),
                )
            tampered = client.get("/api/v1/model-calls")
            self.assertEqual(tampered.status_code, 503)
            self.assertNotIn("private prompt", tampered.text)

        self.database.write_bytes(b"not a sqlite database")
        with TestClient(create_app(result_root=self.root)) as client:
            failed = client.get("/api/v1/model-calls")
            self.assertEqual(failed.status_code, 503)
            self.assertEqual(failed.json(), {"detail": "LLM log unavailable"})

    def test_captured_session_usage_is_optional_and_never_guessed(self) -> None:
        class Agent:
            _validation_model = "gpt-test"

            @logged_model_call("session", model_attribute="_validation_model")
            def run(self, *, operation: str, events: list[dict]) -> None:
                record_session_usage(events)

        agent = Agent()
        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            agent.run(operation="blind Validation assessment", events=[])
            agent.run(operation="blind Validation assessment", events=[
                {"type": "turn.completed", "usage": {
                    "input_tokens": 0, "cached_input_tokens": 2, "output_tokens": 3,
                }},
            ])
            agent.run(operation="blind Validation assessment", events=[
                {"type": "turn.completed", "usage": {"input_tokens": True}},
            ])
            agent.run(operation="blind Validation assessment", events=[
                {"type": "turn.completed", "usage": {"input_tokens": 5}},
                {"type": "turn.completed", "usage": {"input_tokens": 8}},
            ])
        events, _ = read_model_call_events(self.root, limit=20)
        terminal = [event for event in reversed(events) if event["state"] == "success"]
        self.assertEqual([event["usage_status"] for event in terminal], [
            "absent", "reported", "invalid", "ambiguous",
        ])
        self.assertEqual(terminal[0]["input_tokens"], None)
        self.assertEqual(
            (terminal[1]["input_tokens"], terminal[1]["cached_input_tokens"], terminal[1]["output_tokens"]),
            (0, 2, 3),
        )
        self.assertIsNone(terminal[-1]["input_tokens"])

    def test_scan_tokens_include_measured_calls_without_cached_duplication(self) -> None:
        class Agent:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str, lines: list[str]) -> None:
                record_jsonl_usage(lines)

        class Interrupted:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                raise KeyboardInterrupt

        def completed(input_tokens: int | None, output_tokens: int | None, cached: int = 0) -> list[str]:
            return [json.dumps({"type": "turn.completed", "usage": {
                "input_tokens": input_tokens,
                "cached_input_tokens": cached,
                "output_tokens": output_tokens,
            }})]

        agent = Agent()
        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            with model_call_context(scan_id="scan-a", stage="Recon"):
                agent.run(operation="Recon Plan generation", lines=completed(100, 20, 40))
                agent.run(operation="Recon Plan generation", lines=[])
            with model_call_context(scan_id="scan-a", stage="Attack"):
                agent.run(operation="Attack hypothesis planning", lines=completed(10, 4))
            with model_call_context(scan_id="scan-a", stage="Validation"):
                agent.run(operation="blind Validation assessment", lines=completed(1, None))
            with model_call_context(scan_id="scan-a", stage=None):
                agent.run(operation="offline report drafting", lines=completed(2, 3))
            with model_call_context(scan_id="scan-a", stage="Scope"):
                agent.run(operation="Scope collection", lines=completed(7, 8))
            with model_call_context(scan_id="scan-b", stage="Recon"):
                agent.run(operation="Recon Plan generation", lines=completed(900, 900))
            with model_call_context(scan_id="scan-a", stage="Report"):
                with self.assertRaises(KeyboardInterrupt):
                    Interrupted().run(operation="offline report drafting")

        usage = read_scan_token_usage(self.root, "scan-a")
        self.assertEqual(usage["total"], {
            "input_tokens": 112, "output_tokens": 27, "total_tokens": 139,
            "measured_calls": 3, "unreported_calls": 3,
        })
        self.assertEqual(usage["stages"]["Recon"]["total_tokens"], 120)
        self.assertEqual(usage["stages"]["Recon"]["unreported_calls"], 1)
        self.assertEqual(usage["stages"]["Validation"]["unreported_calls"], 1)
        self.assertEqual(usage["unattributed"]["total_tokens"], 5)
        self.assertEqual(usage["stages"]["Report"]["unreported_calls"], 1)

    def test_scan_tokens_accumulate_every_unattributed_stage(self) -> None:
        class Agent:
            _main_model = "gpt-test"

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str, tokens: int | None) -> None:
                record_session_usage([{"type": "turn.completed", "usage": {
                    "input_tokens": tokens, "cached_input_tokens": 0,
                    "output_tokens": tokens,
                }}])

        with using_model_call_sink(SQLiteModelCallSink(self.root)):
            for stage, tokens in ((None, 2), ("Other", 3), ("Legacy", 4), ("Other", None)):
                with model_call_context(scan_id="scan-a", stage=stage):
                    Agent().run(operation="offline report drafting", tokens=tokens)
            with model_call_context(scan_id="scan-a", stage="Scope"):
                Agent().run(operation="Scope collection", tokens=100)
            with model_call_context(scan_id="scan-b", stage="Other"):
                Agent().run(operation="offline report drafting", tokens=200)

        usage = read_scan_token_usage(self.root, "scan-a")
        self.assertEqual(usage["unattributed"], {
            "input_tokens": 9, "output_tokens": 9, "total_tokens": 18,
            "measured_calls": 3, "unreported_calls": 1,
        })
        self.assertEqual(usage["total"], usage["unattributed"])
        self.assertTrue(all(bucket["total_tokens"] == 0 for bucket in usage["stages"].values()))

    def test_resumed_thread_totals_are_not_counted_twice(self) -> None:
        class Agent:
            _validation_model = "gpt-test"

            @logged_model_call("session", model_attribute="_validation_model")
            def resume(self) -> None:
                record_session_usage([{"type": "turn.completed", "usage": {
                    "input_tokens": 200, "cached_input_tokens": 50, "output_tokens": 20,
                }}], resumed=True)

        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            model_call_context(scan_id="scan-a", stage="Validation"),
        ):
            Agent().resume()
        usage = read_scan_token_usage(self.root, "scan-a")
        self.assertEqual(usage["total"]["total_tokens"], 0)
        self.assertEqual(usage["total"]["unreported_calls"], 1)
        events, _ = read_model_call_events(self.root)
        self.assertEqual(events[0]["usage_status"], "ambiguous")

    def test_codex_structured_command_records_json_usage_without_event_text(self) -> None:
        from aidast.agents.main import CodexMainAgent

        class Artifact(BaseModel):
            ok: bool

        def run(command: list[str], **kwargs):
            self.assertIn("--json", command)
            kwargs["stdout"].write('{"type":"item.completed","message":"private content"}\n')
            kwargs["stdout"].write(json.dumps({"type": "turn.completed", "usage": {
                "input_tokens": 12, "cached_input_tokens": 4, "output_tokens": 3,
            }}) + "\n")
            Path(command[command.index("--output-last-message") + 1]).write_text(
                '{"ok":true}', encoding="utf-8",
            )
            return SimpleNamespace(returncode=0, stderr="")

        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            model_call_context(scan_id="scan-a", stage="Recon"),
            patch("aidast.agents.main.shutil.which", return_value="codex"),
            patch.object(CodexMainAgent, "_require_login"),
            patch("aidast.agents.main.codex_process.run_codex", side_effect=run),
        ):
            result = CodexMainAgent(main_model="gpt-6-sol")._run_structured(
                prompt="private prompt", model_type=Artifact,
                artifact_name="token-check", operation="Recon Plan generation",
            )

        self.assertTrue(result.ok)
        self.assertEqual(read_scan_token_usage(self.root, "scan-a")["stages"]["Recon"]["total_tokens"], 15)
        stored = self.database.read_bytes().decode("utf-8", errors="ignore")
        self.assertNotIn("private prompt", stored)
        self.assertNotIn("private content", stored)

    def test_both_codex_adapters_capture_preflight_failure_without_double_counting(self) -> None:
        from aidast.agents.main import CodexMainAgent as MainAgent
        from aidast.agents.main import MainAgentError
        from aidast.agents.native_pipeline import CodexMainAgent as NativeAgent
        from aidast.agents.native_pipeline import MainAgentError as NativeAgentError

        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            patch("aidast.agents.main.shutil.which", return_value=None),
            self.assertRaises(MainAgentError),
        ):
            MainAgent()._run_structured(
                prompt="private prompt", model_type=object,
                artifact_name="recon-plan", operation="Recon Plan generation",
            )
        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            patch("aidast.agents.native_pipeline.shutil.which", return_value=None),
        ):
            with self.assertRaises(NativeAgentError):
                NativeAgent()._run_structured(
                    prompt="private prompt", model_type=object,
                    artifact_name="scope-collection", operation="Scope collection",
                )
            with self.assertRaises(NativeAgentError):
                MainAgent().run_attack_orchestrator(
                    scan_id="scan-1", stage_run_id="stage-1",
                    db_path=self.root / "missing.db",
                    scope_path=self.root / "missing.scope",
                    policy_path=self.root / "missing.policy",
                    attack_tasks=[], selected_skill_names=(), selection_reasons={},
                )
        events, _ = read_model_call_events(self.root)
        self.assertEqual(len(events), 6)
        self.assertEqual(
            [event["operation_code"] for event in events if event["state"] == "error"],
            ["attack_orchestrator", "scope_collection", "recon_plan"],
        )
        self.assertEqual(events[0]["scan_id"], "scan-1")
        self.assertEqual(events[0]["stage"], "Attack")
        self.assertEqual(events[0]["stage_run_id"], "stage-1")
        self.assertNotIn("private prompt", self.database.read_bytes().decode("utf-8", errors="ignore"))

    def test_scope_worker_thread_binds_its_job_without_inheriting_a_scan(self) -> None:
        class Agent:
            _main_model = None

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                return None

        manager = ScopeWorkflowManager(
            self.root, ProgramRegistry(self.root), agent_factory=Agent,
            model_call_sink=SQLiteModelCallSink(self.root),
        )
        manager._collect_with_model_log = lambda *_args: Agent().run(operation="Scope collection")
        finished = Event()

        def worker() -> None:
            try:
                manager._collect("scopejob_" + "a" * 32, {}, ScopeCollectionRequest(), self.root)
            finally:
                finished.set()

        thread = Thread(target=worker)
        thread.start()
        self.assertTrue(finished.wait(timeout=5))
        thread.join(timeout=5)
        events, _ = read_model_call_events(self.root)
        self.assertEqual([event["state"] for event in events], ["success", "started"])
        self.assertEqual(events[0]["scope_job_id"], "scopejob_" + "a" * 32)
        self.assertEqual(events[0]["stage"], "Scope")
        self.assertIsNone(events[0]["scan_id"])

    def test_nested_scan_context_drops_old_case_and_restores_parent(self) -> None:
        class Agent:
            _main_model = None

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                return None

        with (
            using_model_call_sink(SQLiteModelCallSink(self.root)),
            model_call_context(scan_id="scan-1", stage="Validation", case_id="case-1"),
        ):
            Agent().run(operation="blind Validation assessment")
            with model_call_context(scan_id="scan-2", stage="Recon"):
                Agent().run(operation="Recon Plan generation")
            Agent().run(operation="Validation claim comparison")
        events, _ = read_model_call_events(self.root)
        terminal = [event for event in reversed(events) if event["state"] == "success"]
        self.assertEqual([(event["scan_id"], event["case_id"]) for event in terminal], [
            ("scan-1", "case-1"), ("scan-2", None), ("scan-1", "case-1"),
        ])

    def test_attack_capacity_fallback_uses_distinct_configured_validation_model(self) -> None:
        from aidast.agents.main import CodexMainAgent
        from aidast.agents.native_pipeline import CodexMainAgent as NativeAgent

        for adapter in (CodexMainAgent, NativeAgent):
            with self.subTest(adapter=adapter.__module__):
                agent = adapter(
                    main_model="gpt-6-sol",
                    attack_model="gpt-6-sol",
                    validation_model="gpt-5.6-sol",
                )
                self.assertTrue(agent.activate_attack_fallback_model())
                self.assertEqual(agent._attack_model, "gpt-5.6-sol")

    def test_console_entrypoint_enables_store_without_changing_programmatic_main(self) -> None:
        from aidast import cli

        class Agent:
            _main_model = None

            @logged_model_call("structured", model_attribute="_main_model")
            def run(self, *, operation: str) -> None:
                return None

        def dispatch() -> int:
            Agent().run(operation="Recon Plan generation")
            return 0

        with patch.object(cli, "RESULT_ROOT", self.root), patch.object(cli, "main", side_effect=dispatch):
            self.assertEqual(cli.entrypoint(), 0)
        events, _ = read_model_call_events(self.root)
        self.assertEqual([event["state"] for event in events], ["success", "started"])
        self.assertEqual(events[0]["operation_code"], "recon_plan")


if __name__ == "__main__":
    unittest.main()
