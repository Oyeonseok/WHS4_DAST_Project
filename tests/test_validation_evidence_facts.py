"""Contract-bound replay fact extraction without semantic overclaiming."""

import unittest

from aidast.validation.contracts.models import BlindAssessment, canonical_sha256
from aidast.validation.core.evidence_facts import extract_replay_facts
from aidast.validation.core.profile_evidence import evaluate_profile_evidence
from aidast.validation.core.profiles import SkillProfileResolver


def assessment(signal_type):
    axis = {"score": 1, "evidence_ids": ("e-t1",), "reason": "Fixture proposal."}
    return BlindAssessment.model_validate({
        "case_id": "case", "blind_case_sha256": "f" * 64,
        "reproduced": True, "signal_types": (signal_type,),
        "target_attempt_ids": ("t1", "t2", "t3"),
        "control_attempt_ids": ("p1", "n1"),
        "evidence_ids": ("e-t1", "e-t2", "e-t3", "e-p1", "e-n1"),
        "impact_boundary": axis, "impact_sensitivity": axis,
        "impact_actor_requirements": axis, "conclusion": "Fixture replay.",
    })


def observations(kind, target_details, negative_details, positive_details=None):
    ledger_key = "request_ids" if kind in {"http", "browser", "oob"} else "operation_ids"
    def with_ledger(details, attempt_id):
        return {**details, ledger_key: [f"ledger-{attempt_id}"]}
    return [
        {"attempt_id": attempt_id, "evidence_id": f"e-{attempt_id}",
         "attempt_kind": "target", "outcome": "observed", "signal_observed": True,
         "details": with_ledger(target_details, attempt_id)}
        for attempt_id in ("t1", "t2", "t3")
    ] + [
        {"attempt_id": "p1", "evidence_id": "e-p1",
         "attempt_kind": "positive_control", "outcome": "observed",
         "signal_observed": True, "details": with_ledger(positive_details or target_details, "p1")},
        {"attempt_id": "n1", "evidence_id": "e-n1",
         "attempt_kind": "negative_control", "outcome": "not_observed",
         "signal_observed": False, "details": with_ledger(negative_details, "n1")},
    ]


class EvidenceFactExtractionTests(unittest.TestCase):
    def test_http_assertion_matches_contract_and_negative_control(self):
        assertion = {"assertion_id": "marker", "kind": "body_contains",
                     "expected": "unique-source-marker"}
        runtime = {
            "schema_version": 1,
            "target": {"request": {"query_parameters": {"v": "target"}},
                       "assertions": [assertion]},
            "positive_control": {"request": {"query_parameters": {"v": "positive"}},
                                 "assertions": [assertion]},
            "negative_control": {"request": {"query_parameters": {"v": "negative"}},
                                 "assertions": [assertion]},
        }
        matched = {"assertion_id": "marker", "kind": "body_contains", "passed": True,
                   "expected_sha256": canonical_sha256("unique-source-marker"),
                   "actual_sha256": canonical_sha256("unique-source-marker")}
        unmatched = {**matched, "passed": False, "actual_sha256": canonical_sha256(None)}
        replay = observations("http", {"evaluation": {"assertions": [matched]},
                                       "verified_facts": ["protected_content_not_field_name"]},
                              {"evaluation": {"assertions": [unmatched]}})
        extracted = extract_replay_facts(
            "hunt-source-leak", runtime, assessment("error_signature"), replay,
            replay_status="complete",
        )
        self.assertEqual(len(extracted.facts), 1)
        fact = extracted.facts[0]
        self.assertEqual(fact["kind"], "assertion_differential")
        self.assertEqual(fact["runtime_kind"], "http")
        self.assertEqual(fact["assertion_kind"], "body_contains")
        self.assertEqual(fact["target_evidence_ids"], ["e-t1", "e-t2", "e-t3"])
        self.assertEqual(fact["negative_evidence_id"], "e-n1")
        self.assertEqual(fact["provenance"], "contract_bound_adapter_summary")
        self.assertNotIn("protected_content_not_field_name", str(extracted))
        missing_ledger = [{**item, "details": {
            key: value for key, value in item["details"].items()
            if key != "request_ids"
        }} if item["attempt_id"] == "t2" else item for item in replay]
        self.assertEqual(extract_replay_facts(
            "hunt-source-leak", runtime, assessment("error_signature"),
            missing_ledger, replay_status="complete",
        ).facts, ())
        resolved = SkillProfileResolver().resolve("hunt-source-leak")
        audit = evaluate_profile_evidence(
            resolved.profile, resolved.profile_sha256,
            assessment("error_signature"), replay, runtime_contract=runtime,
        )
        self.assertEqual(audit["facts"][0]["assertion_kind"], "body_contains")
        self.assertEqual(audit["axes"]["impact_sensitivity"]["status"],
                         "needs_verified_fact")

        forged = observations("http", {"evaluation": {"assertions": [
            {**matched, "expected_sha256": canonical_sha256("different")}
        ]}}, {"evaluation": {"assertions": [unmatched]}})
        self.assertEqual(extract_replay_facts(
            "hunt-source-leak", runtime, assessment("error_signature"), forged,
            replay_status="complete",
        ).facts, ())

    def test_browser_console_and_oob_nonce_are_channel_specific_facts(self):
        browser_assertion = {"assertion_id": "exec", "kind": "console_contains",
                             "expected": "xss-nonce-123"}
        browser = {"runtime_kind": "browser", "schema_version": 1,
                   **{kind: {"navigation": {"query_parameters": {"v": kind}},
                             "assertions": [browser_assertion]}
                      for kind in ("target", "positive_control", "negative_control")}}
        passed = {"assertion_id": "exec", "kind": "console_contains", "passed": True,
                  "expected_sha256": canonical_sha256("xss-nonce-123"),
                  "actual_sha256": canonical_sha256("xss-nonce-123")}
        failed = {**passed, "passed": False, "actual_sha256": canonical_sha256(None)}
        browser_facts = extract_replay_facts(
            "hunt-xss", browser, assessment("dom_effect"),
            observations("browser", {"evaluation": {"assertions": [passed]}},
                         {"evaluation": {"assertions": [failed]}}),
            replay_status="complete",
        ).facts
        self.assertEqual([(fact["runtime_kind"], fact["assertion_kind"])
                          for fact in browser_facts], [("browser", "console_contains")])

        oob_attempt = lambda variant: {
            "trigger": {"query_parameters": {"callback": "https://probe/{nonce}",
                                               "variant": variant}},
            "token_template": "https://probe/{nonce}", "protocols": ["http"],
            "minimum_callbacks": 1,
        }
        oob = {"runtime_kind": "oob", "schema_version": 1,
               "target": oob_attempt("target"),
               "positive_control": oob_attempt("positive"),
               "negative_control": oob_attempt("negative")}
        callbacks = {"matched_callback_count": 1, "matched_protocols": ["http"]}
        negative = {"matched_callback_count": 0, "matched_protocols": []}
        oob_replay = observations("oob", callbacks, negative)
        import hashlib
        for item in oob_replay:
            nonce = hashlib.sha256(item["attempt_id"].encode()).hexdigest()[:16]
            token = f"https://probe/{nonce}"
            item["details"] = {**item["details"], "token_sha256": canonical_sha256(token)}
        oob_facts = extract_replay_facts(
            "hunt-ssrf", oob, assessment("oob_callback"),
            oob_replay, replay_status="complete",
        ).facts
        self.assertEqual([fact["kind"] for fact in oob_facts], ["nonce_callback_differential"])
        self.assertEqual(oob_facts[0]["provenance"], "contract_bound_adapter_summary")
        self.assertNotIn("actual_server_source_principal", str(oob_facts))

    def test_incomplete_replay_yields_no_facts(self):
        extracted = extract_replay_facts(
            "hunt-idor", {}, assessment("authorization_boundary"), [],
            replay_status="target_inconsistent",
        )
        self.assertEqual(extracted.facts, ())

    def test_different_json_paths_are_not_the_same_control_predicate(self):
        target = {"assertion_id": "same-label", "kind": "json_equals",
                  "expected": "marker", "path": ["protected"]}
        negative = {**target, "path": ["public"]}
        runtime = {"schema_version": 1,
                   "target": {"request": {}, "assertions": [target]},
                   "positive_control": {"request": {}, "assertions": [target]},
                   "negative_control": {"request": {}, "assertions": [negative]}}
        passed = {"assertion_id": "same-label", "kind": "json_equals",
                  "passed": True, "expected_sha256": canonical_sha256("marker"),
                  "actual_sha256": canonical_sha256("marker")}
        failed = {**passed, "passed": False,
                  "actual_sha256": canonical_sha256(None)}
        replay = observations("http", {"evaluation": {"assertions": [passed]}},
                              {"evaluation": {"assertions": [failed]}})
        self.assertEqual(extract_replay_facts(
            "hunt-idor", runtime, assessment("authorization_boundary"),
            replay, replay_status="complete",
        ).facts, ())

    def test_compact_native_channels_bind_control_summaries(self):
        from test_validation_multipart_runtime import attempt as multipart_attempt
        from test_validation_grpc_runtime import runtime_document as grpc_document
        from test_validation_websocket_runtime import runtime_document as websocket_document
        from test_validation_concurrent_runtime import _attempt as concurrent_attempt

        multipart = {"runtime_kind": "multipart", "schema_version": 1,
                     "target": multipart_attempt("target"),
                     "positive_control": multipart_attempt("positive"),
                     "negative_control": multipart_attempt("negative")}
        concurrent = {"runtime_kind": "concurrent", "schema_version": 1,
                      "workers": 2, "repeat_count": 1,
                      "release_strategy": "simultaneous", "barrier_timeout_seconds": 1,
                      "target": concurrent_attempt("target"),
                      "positive_control": concurrent_attempt("positive"),
                      "negative_control": concurrent_attempt("negative")}
        passed_multipart = {"assertion_id_sha256": canonical_sha256("body"),
                            "kind": "body_contains", "passed": True,
                            "expected_sha256": canonical_sha256("uploaded"),
                            "actual_sha256": canonical_sha256("uploaded")}
        failed_multipart = {**passed_multipart, "passed": False,
                            "actual_sha256": canonical_sha256(None)}
        passed_compact = {"kind": "json_equals", "passed": True,
                          "expected_sha256": canonical_sha256("target"),
                          "actual_sha256": canonical_sha256("target")}
        failed_compact = {**passed_compact, "passed": False,
                          "actual_sha256": canonical_sha256(None)}
        digest = canonical_sha256({"kind": "success_count_equals", "expected": 2})
        cases = (
            ("multipart", multipart, {"assertions": [passed_multipart]},
             {"assertions": [failed_multipart]}),
            ("grpc", grpc_document(), {"assertions": [
                {**passed_compact, "kind": "protobuf_path_equals"}]},
             {"assertions": [{**failed_compact, "kind": "protobuf_path_equals"}]}),
            ("websocket", websocket_document(), {"assertions": [passed_compact]},
             {"assertions": [failed_compact]}),
            ("concurrent", concurrent, {"aggregate": {"a": [{"h": digest, "p": True}]}},
             {"aggregate": {"a": [{"h": digest, "p": False}]}}),
        )
        for kind, runtime, target, negative in cases:
            with self.subTest(kind=kind):
                facts = extract_replay_facts(
                    "hunt-" + kind, runtime, assessment("state_change"),
                    observations(kind, target, negative), replay_status="complete",
                ).facts
                self.assertEqual(len(facts), 1)
                self.assertEqual(facts[0]["runtime_kind"], kind)


if __name__ == "__main__":
    unittest.main()
