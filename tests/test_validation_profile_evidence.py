"""Profile-specific evidence audit coverage and semantic proof boundaries."""

import unittest

from aidast.validation.contracts.models import BlindAssessment
from aidast.validation.core.profiles import SkillProfileResolver
from aidast.validation.core.profile_evidence import (
    PROFILE_EVIDENCE_RULES, evaluate_profile_evidence, fit_profile_audit,
    validate_rule_coverage,
)
from aidast.validation.contracts.models import canonical_json
from aidast.validation.persistence.evidence_policy import sanitize_metadata


class ProfileEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.resolver = SkillProfileResolver()

    def test_registry_covers_every_packaged_profile_with_distinct_proofs(self):
        names = self.resolver.validate_coverage()
        self.assertEqual(len(names), 58)
        self.assertEqual(set(PROFILE_EVIDENCE_RULES), set(names))
        self.assertEqual(validate_rule_coverage(self.resolver), names)
        self.assertEqual(len({rule.target_fact for rule in PROFILE_EVIDENCE_RULES.values()}), 58)
        for name in names:
            with self.subTest(name=name):
                rule = PROFILE_EVIDENCE_RULES[name]
                profile = self.resolver.resolve(name).profile
                self.assertEqual(rule.target_signal_kind, profile.target_expected_signal.kind)
                self.assertEqual(rule.runtime_kind, profile.runtime_kinds[0])
                self.assertEqual(rule.signal_type, profile.signal_types[0])
                self.assertTrue(all((rule.boundary_fact, rule.sensitivity_fact, rule.actor_fact)))

    def test_evaluator_rejects_a_contract_channel_changed_without_rule_update(self):
        profile = self.resolver.resolve("hunt-idor").profile
        changed = profile.model_copy(update={"signal_types": ("response_diff",)})
        with self.assertRaisesRegex(ValueError, "does not match"):
            evaluate_profile_evidence(changed, "f" * 64, None, ())

    def test_optional_facts_and_ids_fit_the_sealed_evidence_budget(self):
        audit = {"case_id": "case", "profile_id": "hunt-idor",
                 "facts": [{"kind": "assertion_differential", "digest": "d" * 2000}] * 8,
                 "facts_omitted_count": 0,
                 "request_ids": ["r" * 250 + str(i) for i in range(16)],
                 "operation_ids": [], "reported_assertion_ids": [],
                 "provenance_truncated": False}
        fitted = fit_profile_audit(audit)
        self.assertLessEqual(len(canonical_json(sanitize_metadata(fitted)).encode()), 8192)
        self.assertEqual(fitted["case_id"], "case")
        self.assertGreater(fitted["facts_omitted_count"], 0)

    def test_budget_trims_id_lists_before_grounded_facts(self):
        audit = {"case_id": "case", "profile_id": "hunt-idor",
                 "facts": [{"kind": "assertion_differential", "digest": "d" * 900}],
                 "facts_omitted_count": 0,
                 "request_ids": ["r" * 240 + str(i) for i in range(32)],
                 "operation_ids": [], "reported_assertion_ids": [],
                 "provenance_truncated": False}
        fitted = fit_profile_audit(audit)
        self.assertEqual(fitted["facts"], audit["facts"])
        self.assertEqual(fitted["facts_omitted_count"], 0)
        self.assertTrue(fitted["provenance_truncated"])

    def test_idor_replay_signal_does_not_prove_owner_or_actor(self):
        resolved = self.resolver.resolve("hunt-idor")
        observations = [
            {"attempt_id": "t1", "evidence_id": "e-target", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True,
             "details": {"request_ids": ["request-1"], "evaluation": {"assertions": [
                 {"assertion_id": "owner-match", "passed": True},
             ]}, "verified_facts": ["caller_owner_object_binding"]}},
            {"attempt_id": "t2", "evidence_id": "e-target-2", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "t3", "evidence_id": "e-target-3", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "p1", "evidence_id": "e-positive", "attempt_kind": "positive_control",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "n1", "evidence_id": "e-negative", "attempt_kind": "negative_control",
             "outcome": "not_observed", "signal_observed": False},
        ]
        assessment = BlindAssessment.model_validate({
            "case_id": "case", "blind_case_sha256": "f" * 64,
            "reproduced": True, "signal_types": ("authorization_boundary",),
            "target_attempt_ids": ("t1", "t2", "t3"), "control_attempt_ids": ("p1", "n1"),
            "evidence_ids": ("e-target", "e-negative", "e-positive"),
            "impact_boundary": {"score": 2, "evidence_ids": ("e-target", "e-negative"), "reason": "Owner boundary."},
            "impact_sensitivity": {"score": 2, "evidence_ids": ("e-target",), "reason": "Object read."},
            "impact_actor_requirements": {"score": 2, "evidence_ids": ("e-target",), "reason": "Low privilege."},
            "conclusion": "Reproduced.",
        })
        audit = evaluate_profile_evidence(
            resolved.profile, resolved.profile_sha256, assessment, observations,
        )
        self.assertEqual(audit["mode"], "audit")
        self.assertEqual(audit["target_signal_status"], "observed_semantics_unverified")
        self.assertEqual(audit["replay_status"], "complete")
        self.assertEqual(audit["request_ids"], ["request-1"])
        self.assertEqual(audit["reported_assertion_ids"], ["owner-match"])
        self.assertEqual(audit["effective_axes"], [2, 2, 2])
        for axis in audit["axes"].values():
            self.assertEqual(axis["status"], "needs_verified_fact")
            self.assertEqual(len(axis["missing_facts"]), 1)
        self.assertEqual(audit["axes"]["impact_boundary"]["missing_facts"],
                         ["caller_owner_object_binding"])
        self.assertEqual(audit["axes"]["impact_boundary"]["cited_evidence_ids"],
                         ["e-negative", "e-target"])

        failed_positive = [
            {**item, "outcome": "not_observed", "signal_observed": False}
            if item["attempt_kind"] == "positive_control" else item
            for item in observations
        ]
        failed = evaluate_profile_evidence(
            resolved.profile, resolved.profile_sha256, assessment, failed_positive,
        )
        self.assertEqual(failed["replay_status"], "positive_control_failed")
        self.assertEqual(failed["axes"]["impact_boundary"]["status"], "replay_not_grounded")

        partial_targets = [
            {**item, "outcome": "not_observed", "signal_observed": False}
            if item["attempt_id"] == "t3" else item
            for item in observations
        ]
        partial = evaluate_profile_evidence(
            resolved.profile, resolved.profile_sha256, assessment, partial_targets,
        )
        self.assertEqual(partial["replay_status"], "target_inconsistent")
        self.assertEqual(partial["axes"]["impact_boundary"]["status"], "replay_not_grounded")

    def test_uncited_axis_is_separate_from_missing_semantic_fact(self):
        resolved = self.resolver.resolve("hunt-xss")
        assessment = BlindAssessment.model_validate({
            "case_id": "case", "blind_case_sha256": "f" * 64,
            "reproduced": True, "signal_types": ("dom_effect",),
            "target_attempt_ids": ("t1", "t2", "t3"), "control_attempt_ids": ("p1", "n1"),
            "evidence_ids": ("e-target", "e-negative", "e-positive"),
            "impact_boundary": {"score": 1, "evidence_ids": ("e-positive",), "reason": "Claim."},
            "impact_sensitivity": {"score": 0, "evidence_ids": ("e-target",), "reason": "None."},
            "impact_actor_requirements": {"score": 0, "evidence_ids": ("e-target",), "reason": "None."},
            "conclusion": "Reproduced.",
        })
        observations = [
            {"attempt_id": "t1", "evidence_id": "e-target", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "t2", "evidence_id": "e-target-2", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "t3", "evidence_id": "e-target-3", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "p1", "evidence_id": "e-positive", "attempt_kind": "positive_control",
             "outcome": "observed", "signal_observed": True},
            {"attempt_id": "n1", "evidence_id": "e-negative", "attempt_kind": "negative_control",
             "outcome": "not_observed", "signal_observed": False},
        ]
        audit = evaluate_profile_evidence(
            resolved.profile, resolved.profile_sha256, assessment, observations,
        )
        self.assertEqual(audit["axes"]["impact_boundary"]["status"], "missing_replay_citation")
        self.assertEqual(audit["axes"]["impact_sensitivity"]["status"], "not_claimed")


if __name__ == "__main__":
    unittest.main()
