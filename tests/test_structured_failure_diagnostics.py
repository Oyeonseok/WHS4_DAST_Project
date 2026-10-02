"""Structured-call diagnostics retain causes without retrying or exposing text."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError

from aidast.agents.main import CodexMainAgent, MainAgentError, _structured_jsonl_failure_diagnostic
from aidast.core.codex_process import CodexProcessTimeout
from aidast.core.model_calls import (
    SQLiteModelCallSink, model_call_context, read_model_call_events, using_model_call_sink,
)


class Artifact(BaseModel):
    ok: bool


def _invoke(run, *, max_result_bytes=1_000_000):
    agent = CodexMainAgent(main_model="gpt-6.1-sol", max_result_bytes=max_result_bytes)
    with patch("aidast.agents.main.shutil.which", return_value="codex"), \
         patch.object(agent, "_require_login"), \
         patch("aidast.agents.main.codex_process.run_codex", side_effect=run) as process:
        with pytest.raises(MainAgentError) as caught:
            agent._run_structured(prompt="private-prompt", model_type=Artifact,
                artifact_name="fixture", operation="offline report drafting")
    assert process.call_count == 1
    return caught.value


@pytest.mark.parametrize("stderr,source,expected", [
    ("", "jsonl", "private-jsonl-error"),
    ("  \n ", "jsonl", "private-jsonl-error"),
    ("private-stderr-error", "stderr", "private-stderr-error"),
])
def test_nonzero_exit_preserves_bounded_diagnostic_and_process_cause(
    tmp_path, stderr, source, expected,
):
    def run(command, **kwargs):
        assert command[command.index("--model") + 1] == "gpt-6.1-sol"
        kwargs["stdout"].write(json.dumps({"type": "turn.failed", "error": {
            "message": "private-jsonl-error", "code": "fixture_failure",
        }}) + "\n")
        return SimpleNamespace(returncode=1, stderr=stderr)

    with using_model_call_sink(SQLiteModelCallSink(tmp_path)), \
         model_call_context(scan_id="scan_fixture", stage="Report"):
        error = _invoke(run)

    assert expected in error.diagnostic
    assert len(error.diagnostic) <= 2_000
    assert error.failure_diagnostics == {
        "failure_code": "nonzero_exit", "exit_code": 1,
        "diagnostic_source": source, "requested_model": "gpt-6.1-sol",
    }
    assert isinstance(error.__cause__, subprocess.CalledProcessError)
    assert error.__cause__.returncode == 1
    assert error.__cause__.stderr == stderr.strip()
    assert "private-jsonl-error" in error.__cause__.output
    assert "private-jsonl-error" not in str(error)
    assert "private-stderr-error" not in str(error)
    events, _ = read_model_call_events(tmp_path)
    assert [event["state"] for event in events] == ["error", "started"]
    assert events[0]["requested_model"] == "gpt-6.1-sol"
    assert events[0]["error_code"] == "agent_error"
    stored = (tmp_path / "logs" / "CodexCalls.db").read_bytes()
    for secret in (b"private-prompt", b"private-jsonl-error", b"private-stderr-error"):
        assert secret not in stored


def test_successful_model_text_is_not_used_as_failure_diagnostic():
    def run(command, **kwargs):
        kwargs["stdout"].write(json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "private-success-text",
        }}) + "\n")
        return SimpleNamespace(returncode=1, stderr="")

    error = _invoke(run)
    assert error.diagnostic == ""
    assert error.failure_diagnostics["diagnostic_source"] == "none"
    assert "exit code 1" in str(error)


def test_jsonl_diagnostic_ignores_malformed_and_non_object_events_and_is_bounded():
    lines = ["not json\n", "[]\n", "{partial\n", json.dumps({
        "type": "error", "message": "x" * 10_000 + "final-failure",
    }) + "\n"]
    diagnostic = _structured_jsonl_failure_diagnostic(lines)
    assert len(diagnostic) == 2_000
    assert "final-failure" in diagnostic
    assert "not json" not in diagnostic


def test_jsonl_diagnostic_only_considers_recent_bounded_events():
    stale = json.dumps({"type": "turn.failed", "error": "stale-failure"})
    progress = json.dumps({"type": "turn.started"})
    recent = json.dumps({"type": "turn.failed", "error": "recent-failure"})
    lines = [stale] + [progress] * 200 + ["x" * 65_537, recent]
    assert _structured_jsonl_failure_diagnostic(lines) == '"recent-failure"'


@pytest.mark.parametrize("reason", ["total", "idle", "tool"])
def test_timeout_keeps_original_reason_and_jsonl_diagnostic_without_a_retry(reason):
    timeout = CodexProcessTimeout(["codex"], 10, reason=reason,
        tool_name="fixture" if reason == "tool" else None,
        tool_id="fixture_item" if reason == "tool" else None)

    def run(command, **kwargs):
        kwargs["stdout"].write('{"type":"turn.failed","error":"private-timeout-detail"}\n')
        raise timeout

    error = _invoke(run)
    assert error.__cause__ is timeout
    assert error.failure_diagnostics["failure_code"] == "timeout"
    assert error.failure_diagnostics["diagnostic_source"] == "jsonl"
    assert "private-timeout-detail" in error.diagnostic
    assert "private-timeout-detail" not in str(error)


@pytest.mark.parametrize("result,code,max_bytes", [
    (None, "missing_result", 1_000_000),
    ('{"ok":true}', "result_budget", 3),
    ('{"ok":"invalid"}', "invalid_result", 1_000_000),
])
def test_result_contract_failure_retains_jsonl_details_and_validation_cause(result, code, max_bytes):
    def run(command, **kwargs):
        kwargs["stdout"].write('{"type":"turn.failed","error":"private-result-detail"}\n')
        if result is not None:
            Path(command[command.index("--output-last-message") + 1]).write_text(result)
        return SimpleNamespace(returncode=0, stderr="")

    error = _invoke(run, max_result_bytes=max_bytes)
    assert error.failure_diagnostics["failure_code"] == code
    assert error.failure_diagnostics["exit_code"] == 0
    assert "private-result-detail" in error.diagnostic
    assert "private-result-detail" not in str(error)
    if code == "invalid_result":
        assert isinstance(error.__cause__, ValidationError)


def test_successful_structured_call_still_returns_artifact_once():
    def run(command, **kwargs):
        kwargs["stdout"].write('{"type":"turn.completed","usage":null}\n')
        Path(command[command.index("--output-last-message") + 1]).write_text('{"ok":true}')
        return SimpleNamespace(returncode=0, stderr="")

    agent = CodexMainAgent(main_model="gpt-6.1-sol")
    with patch("aidast.agents.main.shutil.which", return_value="codex"), \
         patch.object(agent, "_require_login"), \
         patch("aidast.agents.main.codex_process.run_codex", side_effect=run) as process:
        result = agent._run_structured(prompt="fixture", model_type=Artifact,
            artifact_name="fixture", operation="offline report drafting")
    assert result.ok is True
    assert process.call_count == 1
