from unittest.mock import patch

import pytest

from aidast.agents.main import CodexMainAgent, MainAgentError
from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
from aidast.recon.policy import TargetPolicySelectionProposal, TargetPolicySelectionSetProposal
from aidast.scope.models import AssetType


def test_invalid_excluded_host_output_is_regenerated_before_policy_binding():
    plan = ReconPlan(
        plan_id="plan_test", scope_id="scope_test", objective="Recon", mode="RECON",
        targets=[ReconPlanTarget(
            asset_type=AssetType.DOMAIN, asset="example.com",
            steps=[ReconStep.ENDPOINT_DISCOVERY], constraints=[],
        )],
        global_constraints=[], completion_criteria=["Complete recon"],
    )
    valid = TargetPolicySelectionSetProposal(policies=[TargetPolicySelectionProposal(
        target_id="target_0001", allowed_hosts=["example.com"], excluded_hosts=[],
    )])
    prompts = []

    def model_call(**kwargs):
        prompts.append(kwargs["prompt"])
        if len(prompts) == 1:
            raise MainAgentError(
                "Codex returned an invalid target-policies result: "
                "excluded_hosts must contain host names or leading wildcards",
                failure_code="invalid_result",
            )
        return valid

    agent = CodexMainAgent(executable="codex-test")
    with patch.object(agent, "_run_structured", side_effect=model_call):
        policies = agent.create_target_policies(
            scope_id="scope_test", scope_markdown="## Allowed activities\nRecon allowed.",
            plan=plan,
        )

    assert len(prompts) == 2
    assert "excluded_hosts" in prompts[1]
    assert policies[(AssetType.DOMAIN.value, "example.com")].excluded_hosts == []


@pytest.mark.parametrize("message,code,attempts", [
    ("excluded_hosts must contain host names", "invalid_result", 2),
    ("unrelated validation error", "invalid_result", 1),
    ("excluded_hosts must contain host names", "nonzero_exit", 1),
])
def test_target_policy_retry_is_limited_to_one_specific_validation_error(message, code, attempts):
    agent = CodexMainAgent(executable="codex-test")
    error = MainAgentError(message, failure_code=code)
    with patch.object(agent, "_build_target_policy_prompt", return_value="original"), \
         patch.object(agent, "_run_structured", side_effect=error) as run:
        with pytest.raises(MainAgentError) as caught:
            agent.create_target_policies(
                scope_id="scope_test", scope_markdown="Scope", plan=object(),
            )
    assert caught.value is error
    assert run.call_count == attempts
