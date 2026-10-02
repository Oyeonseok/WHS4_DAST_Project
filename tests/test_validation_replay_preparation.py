"""Missing replay planning stays separate from execution and adjudication."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aidast.validation import HttpRuntimeContract

from aidast.validation.orchestration.replay_preparation import (
    CodexReplayPreparer, ReplayPreparationDraft, _validate_attempt_endpoints,
    prepare_missing_http_replay,
)


def test_browser_only_profile_cannot_receive_prepared_http_plan():
    candidate = SimpleNamespace(
        staged=SimpleNamespace(_blind_case=SimpleNamespace(runtime_contract=None, target_kind="finding")),
        profile=SimpleNamespace(profile=SimpleNamespace(runtime_kinds=("browser",))),
    )
    conn, preparer = Mock(), Mock()
    prepared, reason = prepare_missing_http_replay(conn, candidate, "stage", preparer, None)
    assert prepared is candidate
    assert reason == "replay_preparation_runtime_unsupported"
    conn.execute.assert_not_called()
    preparer.prepare.assert_not_called()


def test_planner_requests_structured_plan_without_enabling_browser_tools():
    agent = Mock()
    result = ReplayPreparationDraft(runtime_contract_json=None, reason="Captured context is insufficient.")
    agent._run_structured.return_value = result
    context = {"captured_requests": [{"method": "GET", "url": "https://test/api/Users"}]}
    prepared = CodexReplayPreparer(agent=agent).prepare(context, correction="Fix slots")
    assert prepared.runtime_contract is None
    assert prepared.reason == result.reason
    kwargs = agent._run_structured.call_args.kwargs
    assert kwargs["model_type"] is ReplayPreparationDraft
    assert kwargs.get("allow_browser", False) is False
    assert "Do not execute commands or requests" in kwargs["prompt"]
    assert "https://test/api/Users" in kwargs["prompt"]
    assert "Fix slots" in kwargs["prompt"]


def test_default_planner_schema_has_only_strict_scalar_fields():
    from aidast.agents.main import _codex_output_schema
    schema = _codex_output_schema(ReplayPreparationDraft)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"runtime_contract_json", "reason"}
    choices = schema["properties"]["runtime_contract_json"]["anyOf"]
    assert [choice["type"] for choice in choices] == ["string", "null"]
    assert choices[0]["maxLength"] == 65_536
    assert "$defs" not in schema


def test_planner_decodes_scalar_envelope_to_executable_contract():
    agent = Mock()
    effect = [{"assertion_id": "effect", "kind": "json_equals", "path": ["data", 0, "id"], "expected": 1}]
    target = {"request": {}, "assertions": effect}
    contract = {
        "schema_version": 1, "target": target,
        "positive_control": {"request": {}, "identity_mode": "anonymous", "assertions": [{"assertion_id": "unauthorized", "kind": "status_equals", "expected": 401}]},
        "negative_control": {**target, "identity_mode": "anonymous"},
    }
    agent._run_structured.return_value = ReplayPreparationDraft(
        runtime_contract_json=json.dumps(contract), reason="Captured authenticated user collection.",
    )
    prepared = CodexReplayPreparer(agent=agent).prepare({})
    assert prepared.runtime_contract.target.identity_mode == "case"
    assert prepared.runtime_contract.negative_control.identity_mode == "anonymous"
    assert prepared.runtime_contract.target.assertions[0].path == ("data", 0, "id")


def test_alternate_negative_endpoint_is_limited_to_read_only_replay():
    proof = [{"assertion_id": "effect", "kind": "body_contains", "expected": "marker"}]
    runtime = HttpRuntimeContract.model_validate({
        "schema_version": 1,
        "target": {"request": {}, "assertions": proof},
        "positive_control": {"request": {}, "assertions": proof},
        "negative_control": {
            "endpoint_template": "/__aidast_negative_control_missing__",
            "request": {}, "assertions": proof,
        },
    })
    _validate_attempt_endpoints(
        SimpleNamespace(method="GET", endpoint="https://test/exposed"), runtime,
    )
    with pytest.raises(ValueError, match="read-only"):
        _validate_attempt_endpoints(
            SimpleNamespace(method="POST", endpoint="https://test/register"), runtime,
        )
