from __future__ import annotations

from unittest.mock import patch

import pytest

from aidast.agents.main import CodexMainAgent
from aidast.agents.native_pipeline import CodexMainAgent as NativeCodexMainAgent
from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
from aidast.recon.policy import (
    TargetPolicySelectionProposal,
    TargetPolicySelectionSetProposal,
)
from aidast.scope.models import AssetType


AUTHORIZATION = "Conduct security testing on your own test accounts."
SCOPE = (
    f"## Allowed activities\n\n- {AUTHORIZATION}\n\n"
    "## Prohibited activities\n\n- Denial-of-service testing is prohibited.\n"
)


def compile_policy(agent_type, *, scope=SCOPE, **controls):
    proposal = TargetPolicySelectionSetProposal(policies=[
        TargetPolicySelectionProposal(
            target_id="target_0001", allowed_hosts=["example.com"], **controls,
        ),
    ])
    plan = ReconPlan(
        plan_id="plan_test", scope_id="scope_test", objective="Recon", mode="RECON",
        targets=[ReconPlanTarget(
            asset_type=AssetType.URL, asset="https://example.com/",
            steps=[ReconStep.ENDPOINT_DISCOVERY], constraints=[],
        )],
        global_constraints=[], completion_criteria=["Collect allowed endpoints"],
    )
    agent = agent_type()
    # Only the external model call is replaced; policy binding, normalization,
    # Scope validation, and the final executable policy run as production code.
    with patch.object(agent, "_run_structured", return_value=proposal):
        policies = agent.create_target_policies(
            scope_id="scope_test", scope_markdown=scope, plan=plan,
        )
    return policies[(AssetType.URL.value, "https://example.com/")]


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
@pytest.mark.parametrize("methods", [["GET", "HEAD", "OPTIONS"], ["HEAD"], []])
@pytest.mark.parametrize("evidence", [None, AUTHORIZATION])
def test_active_mode_without_mutation_methods_becomes_read_only(agent_type, methods, evidence):
    policy = compile_policy(
        agent_type, attack_authorization_mode="active_non_destructive",
        attack_allowed_methods=methods, attack_authorization_evidence=evidence,
    )

    assert policy.attack_authorization_mode == "read_only"
    assert policy.attack_authorization_evidence is None
    assert policy.attack_allowed_methods == methods
    assert policy.allowed_methods == ["GET", "HEAD", "OPTIONS"]
    assert not policy.allows_attack_url("https://example.com/", method="POST")
    assert any("read_only" in note for note in policy.policy_notes)


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
def test_read_only_methods_clear_stale_active_evidence(agent_type):
    policy = compile_policy(
        agent_type, attack_authorization_evidence=AUTHORIZATION,
    )

    assert policy.attack_authorization_mode == "read_only"
    assert policy.attack_authorization_evidence is None
    assert policy.attack_allowed_methods == ["GET", "HEAD", "OPTIONS"]


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
def test_recon_mutation_method_from_model_is_repaired_to_read_only(agent_type):
    policy = compile_policy(agent_type, allowed_methods=["POST"])

    assert policy.allowed_methods == ["GET", "HEAD", "OPTIONS"]
    assert any("state-changing methods" in note for note in policy.policy_notes)


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
def test_valid_read_only_policy_keeps_existing_notes(agent_type):
    policy = compile_policy(agent_type, policy_notes=["Operator restriction"])

    assert policy.attack_authorization_mode == "read_only"
    assert policy.attack_authorization_evidence is None
    assert policy.policy_notes == ["Operator restriction"]


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_grounded_active_mutation_methods_are_preserved(agent_type, method):
    policy = compile_policy(
        agent_type, attack_authorization_mode="active_non_destructive",
        attack_allowed_methods=["GET", method],
        attack_authorization_evidence=AUTHORIZATION,
    )

    assert policy.attack_authorization_mode == "active_non_destructive"
    assert policy.attack_authorization_evidence == AUTHORIZATION
    assert policy.attack_allowed_methods == ["GET", method]
    assert policy.allows_attack_url("https://example.com/", method=method)
    assert not policy.allows_url("https://example.com/", method=method)


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
@pytest.mark.parametrize("evidence", [None, "Unlisted security testing permission."])
def test_mutation_methods_still_require_grounded_active_evidence(agent_type, evidence):
    with pytest.raises(RuntimeError, match="active Attack authorization evidence"):
        compile_policy(
            agent_type, attack_authorization_mode="active_non_destructive",
            attack_allowed_methods=["GET", "POST"],
            attack_authorization_evidence=evidence,
        )


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
def test_read_only_mode_does_not_gain_permission_for_mutation_methods(agent_type):
    with pytest.raises(RuntimeError, match="read-only Attack policy"):
        compile_policy(agent_type, attack_allowed_methods=["GET", "POST"])


@pytest.mark.parametrize("agent_type", [CodexMainAgent, NativeCodexMainAgent])
def test_scope_prohibition_still_rejects_active_mutation_methods(agent_type):
    with pytest.raises(RuntimeError, match="POST conflicts with Scope"):
        compile_policy(
            agent_type, scope=SCOPE + "- POST requests are prohibited.\n",
            attack_authorization_mode="active_non_destructive",
            attack_allowed_methods=["GET", "POST"],
            attack_authorization_evidence=AUTHORIZATION,
        )
