"""Bounded impact hypothesis execution."""

import unittest
from unittest.mock import Mock

from aidast.validation import (
    CodexImpactDevelopmentRunner,
    ImpactDevelopmentError,
    ImpactDevelopmentPlan,
    ImpactHypothesisExecutor,
    SkillProfileResolver,
    evaluate_impact,
)


def test_legacy_impact_contract_digest_does_not_gain_empty_precondition() -> None:
    from aidast.validation.contracts.impact_development import (
        ImpactDevelopmentRuntimeContract, impact_contract_document,
    )
    legacy = {
        "schema_version": 1,
        "actions": [{
            "contract_id": "debug-users-password-field",
            "path_id": "bounded-impact-confirmation",
            "endpoint_template": "/debug/{resource}", "method": "GET",
            "request": {"path_parameters": {"resource": "users"},
                        "query_parameters": {}, "headers": {},
                        "json_body": None, "text_body": None},
            "assertions": [{"assertion_id": "password-field-name",
                            "kind": "body_contains", "expected": '"password":',
                            "path": [], "header": None}],
            "credential_roles": [],
        }],
    }
    contract = ImpactDevelopmentRuntimeContract.model_validate(legacy)
    assert impact_contract_document(contract) == legacy


class ImpactHypothesisExecutorTests(unittest.TestCase):
    def setUp(self):
        self.profile = SkillProfileResolver().resolve("hunt-idor").profile
        self.executor = ImpactHypothesisExecutor()
        self.impact = evaluate_impact(0, 1, 2)

    def test_no_port_fails_closed_without_changing_impact(self):
        impact, observations = self.executor.execute(
            profile=self.profile, impact=self.impact,
            evidence_ids=("evidence",), port=None,
        )
        self.assertEqual(impact, self.impact)
        self.assertEqual(observations, ())

    def test_score_one_gap_can_request_a_bounded_improvement(self):
        weak = evaluate_impact(1, 1, 2)
        requests = self.executor.requests(
            profile=self.profile, impact=weak, evidence_ids=("evidence",),
        )
        self.assertEqual({item.path_id for item in requests}, {
            "cross-role-object-access", "sensitive-object-field",
        })
        self.assertTrue(all(item.current_score == 1 for item in requests))

    def test_observed_declared_signal_applies_only_declared_score(self):
        def port(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": "observed",
                "signal_observed": True,
                "signal": {"kind": "other_identity_object_returned"},
                "evidence_ids": ["impact-evidence"],
                "details": {"assertion": "passed"},
            }

        impact, observations = self.executor.execute(
            profile=self.profile, impact=self.impact,
            evidence_ids=("evidence",), known_evidence_ids=("evidence", "impact-evidence"),
            port=port,
        )
        self.assertEqual((impact.boundary, impact.sensitivity, impact.actor_requirements),
                         (2, 1, 2))
        self.assertFalse(impact.underpowered)
        self.assertEqual(len(observations), 1)

    def test_wrong_signal_is_rejected(self):
        def port(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": "observed", "signal_observed": True,
                "signal": {"kind": "invented_signal"},
                "evidence_ids": ["impact-evidence"], "details": {},
            }

        with self.assertRaisesRegex(ImpactDevelopmentError, "expected signal"):
            self.executor.execute(
                profile=self.profile, impact=self.impact,
                evidence_ids=("evidence",), known_evidence_ids=("impact-evidence",),
                port=port,
            )

    def test_foreign_evidence_is_rejected(self):
        def port(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "outcome": "not_observed", "signal_observed": False,
                "signal": {}, "evidence_ids": ["foreign"], "details": {},
            }

        with self.assertRaisesRegex(ImpactDevelopmentError, "unknown evidence"):
            self.executor.execute(
                profile=self.profile, impact=self.impact,
                evidence_ids=("evidence",), known_evidence_ids=("evidence",), port=port,
            )

    def test_agent_plan_can_skip_but_cannot_execute_the_port(self):
        calls = []

        def planner(request):
            return {
                "path_id": request.path_id,
                "proposal_sha256": request.proposal_sha256,
                "disposition": "skip", "preconditions_satisfied": False,
                "evidence_ids": ["evidence"],
                "reason": "The second test identity is not evidenced.",
            }

        impact, observations = self.executor.execute(
            profile=self.profile, impact=self.impact, evidence_ids=("evidence",),
            known_evidence_ids=("evidence",), planner=planner,
            port=lambda request: calls.append(request),
        )
        self.assertEqual(impact, self.impact)
        self.assertEqual(observations, ())
        self.assertEqual(calls, [])

    def test_plan_keeps_attack_source_requests_out_of_validation_evidence(self):
        request = self.executor.requests(
            profile=self.profile, impact=self.impact, evidence_ids=("current-evidence",),
        )[0]
        plan = ImpactDevelopmentPlan(
            path_id=request.path_id, proposal_sha256=request.proposal_sha256,
            disposition="execute", preconditions_satisfied=True,
            evidence_ids=("current-evidence",),
            source_request_ids=("attack-source",),
            reason="Current replay and a verified source request support the bounded action.",
        )
        self.executor._validate_plan(
            request, plan, {"current-evidence"}, {"attack-source"},
        )
        with self.assertRaisesRegex(ImpactDevelopmentError, "unknown source request"):
            self.executor._validate_plan(
                request, plan, {"current-evidence"}, {"foreign-source"},
            )
        misplaced = plan.model_copy(update={
            "evidence_ids": ("current-evidence", "attack-source"),
            "source_request_ids": (),
        })
        with self.assertRaisesRegex(ImpactDevelopmentError, "unknown evidence"):
            self.executor._validate_plan(
                request, misplaced, {"current-evidence"}, {"attack-source"},
            )

    def test_verified_preconditions_require_exact_path_contract_and_evidence(self):
        from aidast.validation.execution.impact_development import (
            VerifiedImpactPreconditions,
        )
        request = self.executor.requests(
            profile=self.profile, impact=self.impact,
            evidence_ids=("current-evidence",),
        )[0]
        document = {
            "path_id": request.path_id,
            "contract_sha256": "a" * 64,
            "required_preconditions": list(request.required_preconditions),
            "source_request_ids": ["attack-source"],
            "evidence_ids": [],
            "details": {"kind": "trusted_test_receipt"},
        }
        receipt = VerifiedImpactPreconditions.model_validate(document)
        self.executor.validate_precondition_receipt(
            request, receipt, action_sha256="a" * 64,
            known_evidence_ids={"current-evidence"},
            known_source_request_ids={"attack-source"},
        )
        for changed in (
            {**document, "required_preconditions": document["required_preconditions"][:1]},
            {**document, "contract_sha256": "b" * 64},
            {**document, "source_request_ids": ["foreign-source"]},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ImpactDevelopmentError):
                    self.executor.validate_precondition_receipt(
                        request, VerifiedImpactPreconditions.model_validate(changed),
                        action_sha256="a" * 64,
                        known_evidence_ids={"current-evidence"},
                        known_source_request_ids={"attack-source"},
                    )

    def test_codex_runner_receives_only_selected_validation_skill(self):
        request = self.executor.requests(
            profile=self.profile, impact=self.impact, evidence_ids=("evidence",),
        )[0]
        plan = ImpactDevelopmentPlan(
            path_id=request.path_id, proposal_sha256=request.proposal_sha256,
            disposition="skip", preconditions_satisfied=False,
            evidence_ids=("evidence",), reason="Required test identity is absent.",
        )
        agent = Mock()
        agent._run_structured.return_value = plan
        runner = CodexImpactDevelopmentRunner(
            attack_skill_name="hunt-idor", agent=agent,
        )
        self.addCleanup(runner.close)

        self.assertIs(runner.plan(request, evidence=({"evidence_id": "evidence"},)), plan)
        prompt = agent._run_structured.call_args.kwargs["prompt"]
        self.assertIn("hunt-idor validation", prompt)
        self.assertIn(request.proposal_sha256, prompt)
        self.assertNotIn("hunt-sqli validation", prompt)
        self.assertTrue(runner.agent_id.startswith("impact_development_agent_"))


if __name__ == "__main__":
    unittest.main()
