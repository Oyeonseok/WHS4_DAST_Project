"""Strict same-key matching without embeddings or model decisions."""

import unittest

from aidast.validation import (KnownCandidate, KnownMatcher, canonical_payload,
                               normalized_similarity, payload_structure_sha256)


class KnownMatcherTests(unittest.TestCase):
    def candidate(self, identifier, payload, **changes):
        values = {"case_id": identifier, "vuln_class": "idor", "endpoint_template": "/objects/{id}",
                  "parameter_name": "id", "payload_template": payload}
        values.update(changes)
        return KnownCandidate(**values)

    def test_payload_normalization_is_deterministic_and_preserves_types(self):
        left = {"z": "{{runtime:int}}", "a": "e\u0301"}
        right = '{"a":"é","z":"<slot:value:int>"}'
        self.assertEqual(canonical_payload(left), canonical_payload(right))
        self.assertEqual(payload_structure_sha256(left), payload_structure_sha256(right))
        self.assertIn("<slot:int>", canonical_payload(left))

    def test_similarity_empty_and_codepoint_rules(self):
        self.assertEqual(normalized_similarity("", ""), 1)
        self.assertEqual(normalized_similarity("", "a"), 0)
        self.assertAlmostEqual(normalized_similarity("abcd", "abxd"), .75)

    def test_exact_key_is_required_before_threshold(self):
        matcher = KnownMatcher(0.85)
        payload = {"id": "<slot:int>"}
        self.assertIsNone(matcher.match(vuln_class="idor", endpoint_template="/objects/{id}",
            parameter_name="id", payload_template=payload,
            candidates=[self.candidate("wrong", payload, parameter_name="other")]))

    def test_threshold_and_tie_break_are_deterministic(self):
        matcher = KnownMatcher(0.85)
        target = {"value": "abcdefghij"}
        candidates = [self.candidate("case_b", {"value": "abcdefghij"}),
                      self.candidate("case_a", {"value": "abcdefghij"}),
                      self.candidate("case_unconfirmed", target, current_status="KNOWN")]
        match = matcher.match(vuln_class="idor", endpoint_template="/objects/{id}",
                              parameter_name="id", payload_template=target, candidates=candidates)
        self.assertEqual((match.source_case_id, match.similarity), ("case_a", 1.0))
        self.assertIsNone(KnownMatcher(1.0).match(vuln_class="idor", endpoint_template="/objects/{id}",
            parameter_name="id", payload_template=target,
            candidates=[self.candidate("different", {"value": "abcdefghiX"})]))
