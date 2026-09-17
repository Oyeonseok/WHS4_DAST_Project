from __future__ import annotations

import unittest
from unittest.mock import patch

from aidast.agents.main import CodexMainAgent, _codex_output_schema
from aidast.recon.models import ReconPlan, ReconPlanTarget, ReconStep
from aidast.recon.policy import (
    PolicyLimits,
    RestrictionEvidence,
    TargetPolicy,
    TargetPolicyProposal,
    ToolPolicy,
    validate_policy_for_target,
)
from aidast.recon.policy import TargetPolicySetProposal
from aidast.recon.tools.endpoint_discovery import _tool_rate_args
from aidast.scope.models import AssetType, ScopeAsset


def policy(**changes) -> TargetPolicy:
    values = {
        "scope_id": "scope_test",
        "policy_id": "policy_test",
        "asset_type": AssetType.URL,
        "asset": "https://example.com/app",
        "allowed_schemes": ["https"],
        "allowed_hosts": ["example.com"],
        "allowed_ports": [443],
        "allowed_path_prefixes": ["/app"],
        "excluded_path_prefixes": ["/app/logout"],
    }
    values.update(changes)
    return TargetPolicy(**values)


class TargetPolicyTests(unittest.TestCase):
    def test_tool_capabilities_keep_form_submission_disabled_by_default(self) -> None:
        self.assertEqual(
            ToolPolicy().model_dump(),
            {
                "playwright_interaction": True,
                "form_submission": False,
                "katana_headless": True,
                "ffuf_enabled": True,
                "ffuf_recursion": True,
                "mitm_capture_bodies": True,
            },
        )

    def test_main_agent_resets_ungrounded_tool_restrictions(self) -> None:
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(
                playwright_interaction=False,
                ffuf_enabled=False,
                mitm_capture_bodies=False,
            ),
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, "정책 원문"
        )

        self.assertTrue(result.tools.playwright_interaction)
        self.assertTrue(result.tools.ffuf_enabled)
        self.assertTrue(result.tools.mitm_capture_bodies)

    def test_main_agent_accepts_explicitly_grounded_tool_restriction(self) -> None:
        quote = "Automated browser interaction is prohibited."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(playwright_interaction=False),
            restriction_evidence=[RestrictionEvidence(
                field="playwright_interaction", source_quote=quote,
            )],
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(item, quote)

        self.assertFalse(result.tools.playwright_interaction)

    def test_main_agent_resets_ungrounded_execution_tuning(self) -> None:
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_depth=0, max_requests=1),
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, "정책 원문"
        )

        self.assertEqual(result.limits.max_depth, 3)
        self.assertEqual(result.limits.max_requests, 2000)
        self.assertIn("max_depth", result.policy_notes[-1])
        self.assertIn("max_requests", result.policy_notes[-1])

    def test_main_agent_resets_attempted_execution_broadening(self) -> None:
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(timeout_seconds=30),
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, "정책 원문"
        )

        self.assertEqual(result.limits.timeout_seconds, 20)

    def test_main_agent_accepts_only_exactly_grounded_restriction(self) -> None:
        quote = "Crawling is prohibited."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            limits=PolicyLimits(max_depth=0),
            restriction_evidence=[
                RestrictionEvidence(field="max_depth", source_quote=quote)
            ],
        )

        result = CodexMainAgent._normalize_grounded_execution_controls(
            item, f"Rules: {quote}"
        )

        self.assertEqual(result.limits.max_depth, 0)

    def test_grounded_scope_rate_survives_default_cli_path(self) -> None:
        from aidast.cli import _apply_policy_caps, _default_login_mode, _parser

        quote = "Automated tooling: max. 10 requests per second."
        item = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com",
            allowed_hosts=["example.com"], limits=PolicyLimits(requests_per_second=10),
            restriction_evidence=[RestrictionEvidence(
                field="requests_per_second", source_quote=quote)],
        )
        grounded = CodexMainAgent._normalize_grounded_execution_controls(item, quote)
        policy = TargetPolicy(scope_id="scope", policy_id="policy", **grounded.model_dump())
        for command in ("run", "recon"):
            args = _parser().parse_args([command, "https://example.com/program", "--target", "example.com"])
            self.assertIsNone(args.profile)
            self.assertEqual(args.login_mode, _default_login_mode())
            result = _apply_policy_caps(
                {("DOMAIN", "example.com"): policy}, profile=args.profile,
                max_rps=None, max_requests=None, max_depth=None,
                max_concurrency=None, timeout_seconds=None,
            )
            self.assertEqual(result[("DOMAIN", "example.com")].limits, grounded.limits)
            self.assertEqual(grounded.limits.requests_per_second, 10)

    def test_fractional_tool_rates_are_converted_without_rounding_up(self) -> None:
        self.assertEqual(_tool_rate_args("katana", 0.2), ["-delay", "5"])
        self.assertEqual(_tool_rate_args("ffuf", 0.2), ["-p", "5"])
        self.assertEqual(_tool_rate_args("katana", 1.9), ["-rl", "1"])
        self.assertEqual(_tool_rate_args("ffuf", 1.9), ["-rate", "1"])

    def test_main_agent_normalizes_approved_wildcard_host_notation(self) -> None:
        proposal = TargetPolicySetProposal(
            policies=[
                TargetPolicyProposal(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    allowed_hosts=["*.example.com"],
                    include_subdomains=True,
                )
            ]
        )
        plan = ReconPlan(
            plan_id="plan_test",
            scope_id="scope_test",
            objective="정찰",
            mode="RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    steps=[ReconStep.ASSET_DISCOVERY],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["완료"],
        )
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal) as run:
            policies = agent.create_target_policies(
                scope_id="scope_test",
                scope_markdown="정책",
                plan=plan,
            )

        self.assertEqual(
            run.call_args.kwargs["native_skill"],
            ("aidast.skills.target_policy", "aidast-target-policy"),
        )

        result = policies[(AssetType.WILDCARD.value, "*.example.com")]
        self.assertEqual(result.allowed_hosts, ["example.com"])
        self.assertTrue(result.include_subdomains)

    def test_operator_start_url_is_bound_to_one_exact_host_and_path(self) -> None:
        proposal = TargetPolicySetProposal(policies=[TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="admin.shopify.com",
            allowed_hosts=["admin.shopify.com"], allowed_path_prefixes=["/"],
        )])
        plan = ReconPlan(
            plan_id="plan", scope_id="scope", objective="정찰", mode="RECON",
            targets=[ReconPlanTarget(
                asset_type=AssetType.DOMAIN, asset="admin.shopify.com",
                steps=[ReconStep.ENDPOINT_DISCOVERY], constraints=[],
            )],
            global_constraints=[], completion_criteria=["완료"],
        )
        start_url = "https://admin.shopify.com/store/cms-store-nekxd2ks"
        agent = CodexMainAgent(executable="codex-test")
        with patch.object(agent, "_run_structured", return_value=proposal):
            policies = agent.create_target_policies(
                scope_id="scope", scope_markdown="정책", plan=plan,
                execution_start_urls={
                    (AssetType.DOMAIN.value, "admin.shopify.com"): start_url
                },
            )

        result = policies[(AssetType.DOMAIN.value, "admin.shopify.com")]
        self.assertEqual(result.allowed_hosts, ["admin.shopify.com"])
        self.assertEqual(
            result.allowed_path_prefixes, ["/store/cms-store-nekxd2ks"]
        )
        self.assertTrue(result.allows_url(start_url))
        self.assertFalse(result.allows_url("https://admin.shopify.com/store/other"))
        self.assertFalse(result.allows_url("https://accounts.shopify.com/"))

    def test_scope_out_of_scope_hosts_are_compiled_per_wildcard(self) -> None:
        from aidast.cli import _apply_scope_host_exclusions

        wildcard = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.WILDCARD,
            asset="*.shopify.com", allowed_hosts=["shopify.com"],
            include_subdomains=True,
        )
        exclusions = [
            ScopeAsset(
                asset_type=AssetType.DOMAIN, asset="community.shopify.com",
                description="third party", eligibility="ineligible",
                maximum_severity="None",
            ),
            ScopeAsset(
                asset_type=AssetType.WILDCARD, asset="*.email.shopify.com",
                description="third party", eligibility="ineligible",
                maximum_severity="None",
            ),
            ScopeAsset(
                asset_type=AssetType.DOMAIN, asset="outside.example",
                description="other", eligibility="ineligible",
                maximum_severity="None",
            ),
        ]
        result = _apply_scope_host_exclusions(
            {(AssetType.WILDCARD.value, "*.shopify.com"): wildcard}, exclusions
        )[(AssetType.WILDCARD.value, "*.shopify.com")]

        self.assertEqual(
            result.excluded_hosts,
            ["*.email.shopify.com", "community.shopify.com"],
        )
        self.assertFalse(result.allows_host("community.shopify.com"))
        self.assertFalse(result.allows_host("x.email.shopify.com"))
        self.assertTrue(result.allows_host("admin.shopify.com"))

    def test_codex_schema_requires_every_nested_policy_property(self) -> None:
        schema = _codex_output_schema(TargetPolicySetProposal)

        def assert_all_properties_required(node) -> None:
            if isinstance(node, dict):
                self.assertNotIn("default", node)
                properties = node.get("properties")
                if isinstance(properties, dict):
                    self.assertEqual(set(node["required"]), set(properties))
                for value in node.values():
                    assert_all_properties_required(value)
            elif isinstance(node, list):
                for value in node:
                    assert_all_properties_required(value)

        assert_all_properties_required(schema)

    def test_allows_only_matching_origin_path_and_method(self) -> None:
        target = policy()
        self.assertTrue(target.allows_url("https://example.com/app/users"))
        self.assertFalse(target.allows_url("https://example.com/app/logout"))
        self.assertFalse(target.allows_url("https://evil.example/app"))
        self.assertFalse(target.allows_url("https://example.com/app", method="POST"))

    def test_observed_url_keeps_scope_without_authorizing_post(self) -> None:
        target = policy()
        self.assertTrue(target.allows_observed_url("https://example.com/app/checkout"))
        self.assertFalse(target.allows_url(
            "https://example.com/app/checkout", method="POST"
        ))
        self.assertFalse(target.allows_observed_url("https://example.com/app/logout"))
        self.assertFalse(target.allows_observed_url("https://evil.example/app/checkout"))

    def test_browser_support_keeps_origin_method_and_exclusions(self) -> None:
        target = policy()
        self.assertTrue(target.allows_browser_support_url("https://example.com/api/me"))
        self.assertFalse(target.allows_browser_support_url("https://evil.example/api/me"))
        self.assertFalse(target.allows_browser_support_url("https://example.com/app/logout"))
        self.assertTrue(target.allows_browser_support_url(
            "https://example.com/api/me", method="POST"
        ))
        self.assertFalse(target.allows_browser_support_url(
            "https://example.com/app/logout", method="POST"
        ))

    def test_allows_host_applies_exact_and_wildcard_boundaries(self) -> None:
        wildcard = policy(
            asset_type=AssetType.WILDCARD,
            asset="*.example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
            allowed_path_prefixes=["/"],
        )
        self.assertTrue(wildcard.allows_host("example.com"))
        self.assertTrue(wildcard.allows_host("api.example.com"))
        self.assertFalse(wildcard.allows_host("notexample.com"))
        self.assertFalse(wildcard.allows_host("example.com.evil.test"))

    def test_excluded_hosts_override_wildcard_allowance(self) -> None:
        wildcard = policy(
            asset_type=AssetType.WILDCARD,
            asset="*.example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
            excluded_hosts=["blocked.example.com", "*.email.example.com"],
            allowed_path_prefixes=["/"],
        )
        self.assertTrue(wildcard.allows_host("api.example.com"))
        self.assertFalse(wildcard.allows_host("blocked.example.com"))
        self.assertFalse(wildcard.allows_host("a.email.example.com"))
        self.assertFalse(wildcard.allows_url("https://blocked.example.com/"))

    def test_form_submission_cannot_be_enabled_for_recon(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN, asset="example.com",
            allowed_hosts=["example.com"],
            tools=ToolPolicy(form_submission=True),
        )
        with self.assertRaisesRegex(ValueError, "form submission"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_subdomains_require_an_approved_wildcard(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            include_subdomains=True,
        )
        with self.assertRaisesRegex(ValueError, "wildcard"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_policy_rejects_additional_unapproved_host(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com", "other.example"],
        )
        with self.assertRaisesRegex(ValueError, "outside"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_recon_policy_rejects_state_changing_methods(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.DOMAIN,
            asset="example.com",
            allowed_hosts=["example.com"],
            allowed_methods=["GET", "POST"],
        )
        with self.assertRaisesRegex(ValueError, "state-changing"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.DOMAIN, asset="example.com"
            )

    def test_mitm_rules_are_fail_closed(self) -> None:
        rules = policy().mitm_rules()
        self.assertTrue(rules["enforcement_required"])
        self.assertEqual(rules["allowed_hosts"], ["example.com"])
        self.assertEqual(rules["allowed_methods"], ["GET", "HEAD", "OPTIONS"])

    def test_url_policy_cannot_broaden_approved_path(self) -> None:
        proposal = TargetPolicyProposal(
            asset_type=AssetType.URL,
            asset="https://example.com/app",
            allowed_hosts=["example.com"],
            allowed_path_prefixes=["/"],
        )
        with self.assertRaisesRegex(ValueError, "broaden"):
            validate_policy_for_target(
                proposal, asset_type=AssetType.URL, asset="https://example.com/app"
            )


if __name__ == "__main__":
    unittest.main()
