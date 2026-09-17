"""Bounded concurrent Validation transport tests using an inert loopback server."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic import ValidationError

from aidast.validation.contracts.concurrent_contract import ConcurrentRuntimeContract
from aidast.validation.contracts.runtime_semantics import (
    RuntimeSemanticError, validate_runtime_semantics,
)
from aidast.validation.contracts.runtime_contract import ResponseAssertion
from aidast.validation.execution.concurrent_adapter import ConcurrentReproductionPort
from aidast.recon.policy import PolicyLimits
import test_validation_request_broker as request_fixture
from aidast.validation import SkillProfileResolver


def _attempt(variant: str) -> dict[str, object]:
    return {
        "request": {"query_parameters": {"variant": variant}},
        "member_assertions": [{
            "assertion_id": "status", "kind": "status_equals", "expected": 200,
        }],
        "aggregate_assertions": [{
            "assertion_id": "successes", "kind": "success_count_equals", "expected": 2,
        }],
        "start_skew_at_most_ms": 100,
    }


class ConcurrentContractTests(unittest.TestCase):
    def test_contract_bounds_workers_repeats_and_group_size(self):
        common = {
            "runtime_kind": "concurrent", "schema_version": 1,
            "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
            "barrier_timeout_seconds": 1,
            "target": _attempt("target"), "positive_control": _attempt("baseline"),
            "negative_control": _attempt("inert"),
        }
        self.assertEqual(ConcurrentRuntimeContract(**common).total_members, 2)
        for changes in (
            {"workers": 1}, {"workers": 21}, {"repeat_count": 0},
            {"workers": 20, "repeat_count": 2}, {"barrier_timeout_seconds": 31},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                ConcurrentRuntimeContract(**(common | changes))

    def test_contract_rejects_non_http_multipart_and_recursive_children(self):
        common = {
            "runtime_kind": "concurrent", "schema_version": 1,
            "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
            "barrier_timeout_seconds": 1,
            "target": _attempt("target"), "positive_control": _attempt("baseline"),
            "negative_control": _attempt("inert"),
        }
        for request in (
            {"endpoint": "ws://127.0.0.1/", "frames": []},
            {"service": "example.Service", "method": "Call"},
            {"runtime_kind": "concurrent", "workers": 2},
        ):
            invalid = dict(common)
            invalid["target"] = _attempt("target") | {"request": request}
            with self.subTest(request=request), self.assertRaises(ValidationError):
                ConcurrentRuntimeContract(**invalid)

    def test_semantics_require_distinct_child_and_matching_member_proof(self):
        common = {
            "runtime_kind": "concurrent", "schema_version": 1,
            "workers": 2, "repeat_count": 1, "release_strategy": "simultaneous",
            "barrier_timeout_seconds": 1,
            "target": _attempt("target"), "positive_control": _attempt("baseline"),
            "negative_control": _attempt("inert"),
        }
        runtime = ConcurrentRuntimeContract(**common)
        profile = SkillProfileResolver().resolve("hunt-race-condition").profile
        self.assertIsNone(validate_runtime_semantics(runtime, profile))
        same_child = runtime.model_copy(update={"negative_control": runtime.target})
        with self.assertRaisesRegex(RuntimeSemanticError, "must differ"):
            validate_runtime_semantics(same_child, profile)
        mismatch = runtime.model_copy(update={"negative_control": runtime.negative_control.model_copy(
            update={"member_assertions": (
                ResponseAssertion(assertion_id="different", kind="status_equals", expected=201),
            )}
        )})
        with self.assertRaisesRegex(RuntimeSemanticError, "same target proof assertions"):
            validate_runtime_semantics(mismatch, profile)


class ConcurrentLoopbackTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def test_barrier_release_distinguishes_synchronized_read_write_from_locked_counter(self):
        class Counter:
            value = 0
            read_barrier = threading.Barrier(2)
            lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path.startswith("/vulnerable"):
                    value = Counter.value
                    Counter.read_barrier.wait(timeout=2)
                    Counter.value = value + 1
                    status = 200
                elif self.path.startswith("/locked"):
                    with Counter.lock:
                        if Counter.value:
                            status = 409
                        else:
                            Counter.value += 1
                            status = 200
                else:
                    status = 404
                self.send_response(status)
                self.end_headers()
                self.wfile.write(str(Counter.value).encode())

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        port = server.server_address[1]
        self.policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [port], "allowed_path_prefixes": ["/"],
            "allowed_methods": ["POST", "GET"], "attack_allowed_methods": ["POST", "GET"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "limits": PolicyLimits(requests_per_second=50, concurrency=2),
        })

        def runtime(path):
            one = {
                "request": {"query_parameters": {"variant": path}},
                "member_assertions": [{
                    "assertion_id": "status", "kind": "status_equals", "expected": 200,
                }],
                "aggregate_assertions": [{
                    "assertion_id": "successes", "kind": "success_count_equals", "expected": 2,
                }],
                "start_skew_at_most_ms": 100,
            }
            return ConcurrentRuntimeContract(
                runtime_kind="concurrent", schema_version=1, workers=2, repeat_count=1,
                release_strategy="simultaneous", barrier_timeout_seconds=2,
                target=one, positive_control=one,
                negative_control=one,
            )

        def execute(path, attempt):
            contract = runtime(path)
            blind = self.blind.model_copy(update={
                "endpoint": f"http://127.0.0.1:{port}{path}", "method": "POST",
                "credential_references": (), "signal_types": ("timing",),
                "runtime_contract": contract.model_dump(mode="json"),
            })
            return ConcurrentReproductionPort().execute(
                blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id=attempt,
                db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
                policy=self.policy,
            )

        vulnerable = execute("/vulnerable", "attempt")
        self.assertEqual(vulnerable.outcome, "observed")
        self.assertTrue(vulnerable.signal_observed)
        self.assertIn("start_skew_ms", vulnerable.details)
        rows = self.conn.execute(
            "SELECT execution_group_id,member_ordinal,status FROM validation_transport_operations "
            "WHERE attempt_id='attempt' ORDER BY member_ordinal"
        ).fetchall()
        self.assertEqual(len({row[0] for row in rows}), 1)
        self.assertEqual([row[1] for row in rows], [0, 1])
        self.assertEqual([row[2] for row in rows], ["completed", "completed"])

        Counter.value = 0
        Counter.read_barrier = threading.Barrier(2)
        locked = execute("/locked", "attempt")
        self.assertEqual(locked.outcome, "not_observed")
        self.assertFalse(locked.signal_observed)

    def test_sender_exception_after_mutation_is_outcome_unknown_not_not_observed(self):
        child = _attempt("target") | {"request": {
            "path_parameters": {"id": "inert"}, "query_parameters": {"variant": "target"},
        }}
        runtime = ConcurrentRuntimeContract(
            runtime_kind="concurrent", schema_version=1, workers=2, repeat_count=1,
            release_strategy="simultaneous", barrier_timeout_seconds=1,
            target=child, positive_control=child, negative_control=child,
        )
        blind = self.blind.model_copy(update={
            "method": "GET", "credential_references": (), "signal_types": ("timing",),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        mutations = []

        def interrupted(request, timeout):
            mutations.append(request.full_url)
            raise ConnectionError("response lost after inert mutation")

        result = ConcurrentReproductionPort(transport=interrupted).execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            policy=self.policy,
        )
        self.assertEqual(result.outcome, "outcome_unknown")
        self.assertIsNone(result.signal_observed)
        self.assertEqual(len(mutations), 2)
        self.assertEqual([row[0] for row in self.conn.execute(
            "SELECT status FROM validation_transport_operations ORDER BY member_ordinal"
        )], ["outcome_unknown", "outcome_unknown"])


if __name__ == "__main__":
    unittest.main()
