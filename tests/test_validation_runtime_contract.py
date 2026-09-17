"""Deterministic HTTP runtime request and assertion contracts."""

import unittest

from aidast.core.request_broker import BrokerResponse
from aidast.validation import (HttpRequestTemplate, HttpRuntimeContract,
                               ResponseAssertion, evaluate_http_response,
                               render_http_request)


class ValidationRuntimeContractTests(unittest.TestCase):
    def test_request_renders_only_declared_path_query_and_json_body(self):
        template = HttpRequestTemplate(
            path_parameters={"id": "object 7"},
            query_parameters={"view": "private"},
            headers={"X-Test-Marker": "validation"},
            json_body={"enabled": True},
        )
        url, headers, body = render_http_request("https://test/items/{id}", template)
        self.assertEqual(url, "https://test/items/object%207?view=private")
        self.assertEqual(headers, {
            "X-Test-Marker": "validation", "Content-Type": "application/json",
        })
        self.assertEqual(body, b'{"enabled":true}')

    def test_request_rejects_missing_path_values_and_credential_headers(self):
        with self.assertRaises(ValueError):
            render_http_request(
                "https://test/items/{id}", HttpRequestTemplate(path_parameters={}),
            )
        with self.assertRaises(ValueError):
            HttpRequestTemplate(headers={"Authorization": "secret"})
        with self.assertRaises(ValueError):
            HttpRequestTemplate(headers={"X-Test": "value\r\nX-Injected: yes"})

    def test_assertion_values_and_json_paths_are_bounded(self):
        with self.assertRaises(ValueError):
            ResponseAssertion(
                assertion_id="large", kind="body_contains", expected="x" * 16_385,
            )
        with self.assertRaises(ValueError):
            ResponseAssertion(
                assertion_id="path", kind="json_equals", expected=1, path=(-1,),
            )

    def test_response_assertions_are_bounded_and_do_not_store_raw_values(self):
        assertions = (
            ResponseAssertion(assertion_id="status", kind="status_equals", expected=200),
            ResponseAssertion(
                assertion_id="marker", kind="json_equals",
                path=("owner", "id"), expected=7,
            ),
            ResponseAssertion(
                assertion_id="duration", kind="duration_at_most_ms", expected=500,
            ),
        )
        result = evaluate_http_response(
            BrokerResponse(200, "https://test/items/7", {}, b'{"owner":{"id":7}}'),
            assertions, duration_ms=20,
        )
        self.assertTrue(result["signal_observed"])
        self.assertEqual([item["passed"] for item in result["assertions"]], [True, True, True])
        self.assertNotIn("owner", str(result))
        self.assertTrue(all(len(item["actual_sha256"]) == 64 for item in result["assertions"]))

    def test_contract_requires_all_three_attempt_kinds(self):
        request = {"request": {}, "assertions": [{
            "assertion_id": "status", "kind": "status_equals", "expected": 200,
        }]}
        contract = HttpRuntimeContract(
            schema_version=1, target=request,
            positive_control=request, negative_control=request,
        )
        self.assertEqual(
            contract.for_attempt("negative_control").assertions[0].assertion_id,
            "status",
        )


if __name__ == "__main__":
    unittest.main()
