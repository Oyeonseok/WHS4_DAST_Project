"""Profile-aware minimum proof rules for Attack runtime contracts."""

import unittest

from aidast.validation import (
    BlindAssessment, BrowserRuntimeContract,
    HttpRuntimeContract,
    OobRuntimeContract,
    RuntimeSemanticError,
    SkillProfileResolver,
    validate_runtime_semantics,
)
from aidast.validation.contracts.runtime_semantics import (
    bound_profile_proof_assessment, bound_source_leak_axis_citations,
)


def http_attempt(variant, assertion):
    return {
        "request": {"query_parameters": {"variant": variant}},
        "assertions": [assertion],
    }


class ValidationRuntimeSemanticTests(unittest.TestCase):
    def profile(self, name):
        return SkillProfileResolver().resolve(name).profile

    def test_http_status_alone_cannot_prove_security_effect(self):
        contract = HttpRuntimeContract(
            schema_version=1,
            target=http_attempt("target", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
            positive_control=http_attempt("baseline", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
            negative_control=http_attempt("inert", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "header, body, or JSON"):
            validate_runtime_semantics(contract, self.profile("hunt-idor"))

    def test_http_target_and_inert_control_must_be_distinct(self):
        assertion = {
            "assertion_id": "owner", "kind": "json_equals",
            "path": ["owner"], "expected": "other-user",
        }
        same = http_attempt("same", assertion)
        contract = HttpRuntimeContract(
            schema_version=1, target=same,
            positive_control=http_attempt("baseline", assertion), negative_control=same,
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "must differ"):
            validate_runtime_semantics(contract, self.profile("hunt-idor"))

    def test_content_assertion_with_distinct_control_is_accepted(self):
        assertion = {
            "assertion_id": "owner", "kind": "json_equals",
            "path": ["owner"], "expected": "other-user",
        }
        contract = HttpRuntimeContract(
            schema_version=1, target=http_attempt("target", assertion),
            positive_control=http_attempt("baseline", assertion),
            negative_control=http_attempt("inert", assertion),
        )
        self.assertIsNone(
            validate_runtime_semantics(contract, self.profile("hunt-idor"))
        )

    def test_http_negative_control_must_test_the_target_marker(self):
        contract = HttpRuntimeContract(
            schema_version=1,
            target=http_attempt("target", {
                "assertion_id": "owner", "kind": "json_equals",
                "path": ["owner"], "expected": "other-user",
            }),
            positive_control=http_attempt("baseline", {
                "assertion_id": "status", "kind": "status_equals", "expected": 200,
            }),
            negative_control=http_attempt("inert", {
                "assertion_id": "different", "kind": "body_contains", "expected": "denied",
            }),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(contract, self.profile("hunt-idor"))

    def test_source_leak_requires_a_specific_credential_pattern_marker(self):
        def contract(marker):
            proof = {
                "assertion_id": "bounded-signal", "kind": "body_contains",
                "expected": marker,
            }
            return HttpRuntimeContract(
                schema_version=1,
                target=http_attempt("users", proof),
                positive_control=http_attempt("healthy", {
                    "assertion_id": "healthy", "kind": "status_equals", "expected": 200,
                }),
                negative_control=http_attempt("missing", proof),
            )

        profile = self.profile("hunt-source-leak")
        with self.assertRaisesRegex(RuntimeSemanticError, "source-leak proof"):
            validate_runtime_semantics(contract("users"), profile)
        self.assertIsNone(validate_runtime_semantics(contract('"password":'), profile))
        self.assertIsNone(validate_runtime_semantics(contract('"sourcesContent":'), profile))
        self.assertIsNone(validate_runtime_semantics(contract('"openapi":'), profile))

    def test_field_name_only_proof_cannot_raise_pre_impact_sensitivity(self):
        axis = {"score": 1, "evidence_ids": ("evidence",), "reason": "Agent raw score."}
        assessment = BlindAssessment.model_validate({
            "case_id": "case", "blind_case_sha256": "f" * 64,
            "reproduced": True, "signal_types": ("error_signature",),
            "target_attempt_ids": ("target-1", "target-2", "target-3"),
            "control_attempt_ids": ("positive", "negative"),
            "evidence_ids": ("evidence",),
            "impact_boundary": axis, "impact_sensitivity": axis,
            "impact_actor_requirements": {**axis, "score": 2},
            "conclusion": "Only a field name was observed.",
        })
        def runtime(marker):
            proof = {"assertion_id": "proof", "kind": "body_contains", "expected": marker}
            return HttpRuntimeContract(
                schema_version=1, target=http_attempt("users", proof),
                positive_control=http_attempt("healthy", {
                    "assertion_id": "healthy", "kind": "status_equals", "expected": 200,
                }),
                negative_control=http_attempt("missing", proof),
            )

        profile = self.profile("hunt-source-leak")
        bounded, rule = bound_profile_proof_assessment(
            profile, runtime('"password":'), assessment,
        )
        self.assertEqual(rule, "source_leak_field_name_only")
        self.assertEqual([bounded.impact_boundary.score,
                          bounded.impact_sensitivity.score,
                          bounded.impact_actor_requirements.score], [1, 0, 2])
        self.assertIn("field name", bounded.impact_sensitivity.reason)
        value_probe = {"assertion_id": "value", "kind": "json_path_nonempty_string",
                       "path": ["users", 0, "password"], "expected": True}
        declared_value = runtime('"password":').model_dump(mode="json")
        declared_value["target"]["assertions"].append(value_probe)
        declared_value["negative_control"]["assertions"].append(value_probe)
        with_value = HttpRuntimeContract.model_validate(declared_value)
        self.assertIsNone(validate_runtime_semantics(with_value, profile))
        still_bounded, _ = bound_profile_proof_assessment(profile, with_value, assessment)
        self.assertEqual(still_bounded.impact_sensitivity.score, 0)
        declared_value["negative_control"]["assertions"].pop()
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(HttpRuntimeContract.model_validate(declared_value), profile)
        unchanged, rule = bound_profile_proof_assessment(
            profile, runtime('"sourcesContent":'), assessment,
        )
        self.assertIsNone(rule)
        self.assertEqual(unchanged, assessment)
        chain_unchanged, rule = bound_profile_proof_assessment(
            profile, {"runtime_kind": "chain"}, assessment,
        )
        self.assertIsNone(rule)
        self.assertEqual(chain_unchanged, assessment)

    def test_source_leak_positive_axes_require_target_and_negative_control_citations(self):
        axis = lambda score, ids: {
            "score": score, "evidence_ids": ids, "reason": "Blind Agent raw proposal.",
        }
        assessment = BlindAssessment.model_validate({
            "case_id": "case", "blind_case_sha256": "f" * 64,
            "reproduced": True, "signal_types": ("error_signature",),
            "target_attempt_ids": ("t1", "t2", "t3"),
            "control_attempt_ids": ("positive", "negative"),
            "evidence_ids": ("e-positive", "e-negative", "e-target"),
            "impact_boundary": axis(1, ("e-positive",)),
            "impact_sensitivity": axis(0, ("e-target",)),
            "impact_actor_requirements": axis(2, ("e-positive",)),
            "conclusion": "The marker was observed in the target replay.",
        })
        observations = (
            {"evidence_id": "e-positive", "attempt_kind": "positive_control",
             "outcome": "observed", "signal_observed": True},
            {"evidence_id": "e-negative", "attempt_kind": "negative_control",
             "outcome": "not_observed", "signal_observed": False},
            {"evidence_id": "e-target", "attempt_kind": "target",
             "outcome": "observed", "signal_observed": True},
        )
        bounded, rules = bound_source_leak_axis_citations(
            self.profile("hunt-source-leak"), assessment, observations,
        )
        self.assertEqual((bounded.impact_boundary.score,
                          bounded.impact_actor_requirements.score), (0, 0))
        self.assertEqual(set(rules), {
            "impact_boundary_missing_observed_target",
            "impact_boundary_missing_negative_control",
            "impact_actor_requirements_missing_observed_target",
        })
        self.assertEqual(assessment.impact_boundary.score, 1)

        grounded = assessment.model_copy(update={
            "impact_boundary": assessment.impact_boundary.model_copy(update={
                "evidence_ids": ("e-target", "e-negative"),
            }),
            "impact_actor_requirements": assessment.impact_actor_requirements.model_copy(update={
                "evidence_ids": ("e-target",),
            }),
        })
        unchanged, rules = bound_source_leak_axis_citations(
            self.profile("hunt-source-leak"), grounded, observations,
        )
        self.assertEqual(unchanged, grounded)
        self.assertEqual(rules, ())
        other, rules = bound_source_leak_axis_citations(
            self.profile("hunt-idor"), assessment, observations,
        )
        self.assertEqual(other, assessment)
        self.assertEqual(rules, ())

    def test_timing_profile_requires_quantified_duration_assertion(self):
        contract = HttpRuntimeContract(
            schema_version=1,
            target=http_attempt("target", {
                "assertion_id": "body", "kind": "body_contains", "expected": "limited",
            }),
            positive_control=http_attempt("baseline", {
                "assertion_id": "body", "kind": "body_contains", "expected": "ok",
            }),
            negative_control=http_attempt("inert", {
                "assertion_id": "body", "kind": "body_contains", "expected": "limited",
            }),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "duration assertion"):
            validate_runtime_semantics(contract, self.profile("hunt-brute-force"))

    def test_xss_requires_execution_marker_and_distinct_navigation(self):
        selector_attempt = lambda variant: {
            "navigation": {"query_parameters": {"value": variant}},
            "assertions": [{
                "assertion_id": "node", "kind": "selector_exists",
                "selector": "#marker", "expected": True,
            }],
        }
        contract = BrowserRuntimeContract(
            runtime_kind="browser", schema_version=1,
            target=selector_attempt("target"), positive_control=selector_attempt("baseline"),
            negative_control=selector_attempt("inert"),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "execution marker"):
            validate_runtime_semantics(contract, self.profile("hunt-xss"))

    def test_xss_negative_control_must_test_the_target_execution_marker(self):
        def attempt(variant, marker):
            return {
                "navigation": {"query_parameters": {"value": variant}},
                "assertions": [{
                    "assertion_id": "executed", "kind": "console_contains",
                    "expected": marker,
                }],
            }

        contract = BrowserRuntimeContract(
            runtime_kind="browser", schema_version=1,
            target=attempt("target", "target-executed"),
            positive_control=attempt("baseline", "healthy"),
            negative_control=attempt("inert", "different-marker"),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(contract, self.profile("hunt-xss"))

    def test_oob_target_and_inert_trigger_must_be_distinct(self):
        def attempt(variant):
            return {
                "trigger": {"query_parameters": {
                    "callback": "proof-{nonce}.example", "variant": variant,
                }},
                "token_template": "proof-{nonce}.example", "protocols": ["dns"],
            }

        same = attempt("same")
        contract = OobRuntimeContract(
            runtime_kind="oob", schema_version=1, target=same,
            positive_control=attempt("baseline"), negative_control=same,
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "must differ"):
            validate_runtime_semantics(contract, self.profile("hunt-ssrf"))

    def test_oob_negative_control_must_use_the_target_callback_threshold(self):
        def attempt(variant, minimum):
            return {
                "trigger": {"query_parameters": {
                    "callback": "proof-{nonce}.example", "variant": variant,
                }},
                "token_template": "proof-{nonce}.example", "protocols": ["dns"],
                "minimum_callbacks": minimum,
            }

        contract = OobRuntimeContract(
            runtime_kind="oob", schema_version=1,
            target=attempt("target", 2), positive_control=attempt("baseline", 1),
            negative_control=attempt("inert", 1),
        )
        with self.assertRaisesRegex(RuntimeSemanticError, "same callback proof criteria"):
            validate_runtime_semantics(contract, self.profile("hunt-ssrf"))


if __name__ == "__main__":
    unittest.main()
