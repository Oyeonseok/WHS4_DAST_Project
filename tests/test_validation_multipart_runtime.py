"""Bounded multipart validation tests using inert local bytes only."""

from __future__ import annotations

import base64
import hashlib
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aidast.recon.policy import PolicyLimits
from aidast.validation import ResponseAssertion, SkillProfileResolver
from aidast.validation.contracts.binary import BinaryValue
from aidast.validation.contracts.multipart_contract import (
    MultipartFilePart, MultipartRequestTemplate, MultipartRuntimeContract,
    MultipartTextPart, encode_multipart,
)
from aidast.validation.contracts.runtime_contract import validate_runtime_contract
from aidast.validation.contracts.runtime_semantics import validate_runtime_semantics
from aidast.validation.execution.multipart_adapter import MultipartReproductionPort

import test_validation_request_broker as request_fixture


_INERT_GIF = b"GIF89a"


def binary(raw: bytes = _INERT_GIF) -> BinaryValue:
    return BinaryValue(
        inline_base64=base64.b64encode(raw).decode("ascii"),
        length=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
    )


def valid_file() -> MultipartFilePart:
    return MultipartFilePart(
        name="file", filename="fixture.gif", content_type="image/gif", content=binary(),
    )


def attempt(variant: str, *, marker: str = "uploaded") -> dict[str, object]:
    return {
        "request": {
            "query_parameters": {"variant": variant},
            "fields": [{"name": "note", "value": "inert"}],
            "files": [{
                "name": "file", "filename": "fixture.gif", "content_type": "image/gif",
                "content": binary().model_dump(mode="json"),
            }],
        },
        "assertions": [{
            "assertion_id": "body", "kind": "body_contains", "expected": marker,
        }],
    }


class BinaryAndMultipartContractTests(unittest.TestCase):
    def test_binary_value_verifies_decoded_length_and_digest(self):
        self.assertEqual(binary().resolve(None), _INERT_GIF)
        with self.assertRaises(ValueError):
            BinaryValue(inline_base64="R0lGODlh", length=7,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        with self.assertRaises(ValueError):
            BinaryValue(inline_base64="not-base64!", length=6,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())

    def test_binary_value_accepts_only_one_safe_representation(self):
        with self.assertRaises(ValueError):
            BinaryValue(inline_base64=base64.b64encode(_INERT_GIF).decode("ascii"),
                        artifact_ref="fixture.gif", length=6,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        with self.assertRaises(ValueError):
            BinaryValue(artifact_ref="../fixture.gif", length=6,
                        sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        reference = BinaryValue(artifact_ref="fixture-gif-v1", length=6,
                                sha256=hashlib.sha256(_INERT_GIF).hexdigest())
        self.assertEqual(reference.resolve(lambda ref: _INERT_GIF), _INERT_GIF)
        with self.assertRaises(ValueError):
            reference.resolve(lambda ref: b"wrong")

    def test_multipart_rejects_crlf_filename_and_raw_boundary(self):
        with self.assertRaises(ValueError):
            MultipartFilePart(
                name="file", filename="x\r\nInjected: yes", content_type="image/gif",
                content=binary(),
            )
        with self.assertRaises(ValueError):
            MultipartRequestTemplate(files=(valid_file(),), boundary="chosen")
        with self.assertRaises(ValueError):
            MultipartRequestTemplate(files=(valid_file(),), headers={
                "Content-Type": "multipart/form-data; boundary=chosen",
            })

    def test_encoder_is_deterministic_and_has_no_untrusted_header_syntax(self):
        template = MultipartRequestTemplate(
            path_parameters={"id": 7}, query_parameters={"view": "inert"},
            fields=(MultipartTextPart(name="zeta", value="last"),
                    MultipartTextPart(name="alpha", value="first")),
            files=(valid_file(),),
        )
        runtime = MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target={"request": template, "assertions": [{
                "assertion_id": "body", "kind": "body_contains", "expected": "uploaded",
            }]},
            positive_control=attempt("baseline"), negative_control=attempt("inert"),
        )
        url, headers, body = encode_multipart(runtime.target, "http://127.0.0.1/items/{id}", None)
        self.assertEqual(url, "http://127.0.0.1/items/7?view=inert")
        self.assertTrue(headers["Content-Type"].startswith("multipart/form-data; boundary=aidast-"))
        self.assertEqual(headers["Content-Length"], str(len(body)))
        self.assertLess(body.index(b'name="alpha"'), body.index(b'name="zeta"'))
        self.assertIn(b'filename="fixture.gif"\r\nContent-Type: image/gif\r\n\r\nGIF89a', body)

    def test_contract_dispatch_and_semantics_use_multipart_rules(self):
        runtime = MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target=attempt("target"), positive_control=attempt("baseline"),
            negative_control=attempt("inert"),
        )
        self.assertIsInstance(validate_runtime_contract(runtime.model_dump(mode="json")), MultipartRuntimeContract)
        validate_runtime_semantics(runtime, SkillProfileResolver().resolve("hunt-file-upload").profile)
        mismatched = runtime.model_copy(update={"negative_control": runtime.negative_control.model_copy(
            update={"assertions": (ResponseAssertion(assertion_id="other", kind="body_contains", expected="other"),)}
        )})
        with self.assertRaisesRegex(ValueError, "same target proof assertions"):
            validate_runtime_semantics(mismatched, SkillProfileResolver().resolve("hunt-file-upload").profile)
        duration_mismatch = runtime.model_copy(update={"negative_control": runtime.negative_control.model_copy(
            update={"assertions": (
                ResponseAssertion(assertion_id="body", kind="body_contains", expected="uploaded"),
                ResponseAssertion(assertion_id="duration", kind="duration_at_most_ms", expected=1),
            )}
        )})
        timed_target = runtime.model_copy(update={"target": runtime.target.model_copy(
            update={"assertions": (
                ResponseAssertion(assertion_id="body", kind="body_contains", expected="uploaded"),
                ResponseAssertion(assertion_id="duration", kind="duration_at_most_ms", expected=2),
            )}
        )})
        with self.assertRaisesRegex(ValueError, "same target proof assertions"):
            validate_runtime_semantics(duration_mismatch.model_copy(
                update={"target": timed_target.target}
            ), SkillProfileResolver().resolve("hunt-file-upload").profile)


class MultipartLoopbackTests(unittest.TestCase):
    setUp = request_fixture.ValidationRequestBrokerTests.setUp

    def test_adapter_sends_inert_bounded_body_and_records_only_safe_metadata(self):
        received: list[tuple[str, bytes]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers["Content-Length"])
                received.append((self.headers["Content-Type"], self.rfile.read(size)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"uploaded")

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=2)))
        endpoint = f"http://127.0.0.1:{server.server_address[1]}/upload"
        self.policy = self.policy.model_copy(update={
            "allowed_schemes": ["http"], "allowed_hosts": ["127.0.0.1"],
            "allowed_ports": [server.server_address[1]], "allowed_path_prefixes": ["/upload"],
            "allowed_methods": ["POST"], "attack_allowed_methods": ["POST"],
            "attack_authorization_mode": "active_non_destructive",
            "attack_authorization_evidence": "Inert loopback validation only.",
            "limits": PolicyLimits(requests_per_second=50),
        })
        runtime = MultipartRuntimeContract(
            runtime_kind="multipart", schema_version=1,
            target=attempt("target"), positive_control=attempt("baseline"),
            negative_control=attempt("inert"),
        )
        blind = self.blind.model_copy(update={
            "endpoint": endpoint, "method": "POST", "credential_references": (),
            "signal_types": ("state_change",),
            "runtime_contract": runtime.model_dump(mode="json"),
        })
        result = MultipartReproductionPort().execute(
            blind, attempt_kind="target", batch_no=1, ordinal=1, attempt_id="attempt",
            db_path=self.path, scan_id="scan", stage_run_id="stage", case_id="case",
            policy=self.policy,
        )
        self.assertTrue(result.signal_observed)
        self.assertEqual(len(received), 1)
        content_type, body = received[0]
        self.assertTrue(content_type.startswith("multipart/form-data; boundary=aidast-"))
        self.assertIn(b'name="note"\r\n\r\ninert', body)
        self.assertIn(b'filename="fixture.gif"\r\nContent-Type: image/gif\r\n\r\nGIF89a', body)
        self.assertEqual(tuple(self.conn.execute(
            "SELECT runtime_kind,status FROM validation_transport_operations"
        ).fetchone()), ("multipart", "completed"))
        self.assertEqual(set(result.details), {"response_body_sha256", "response_bytes", "operation_ids"})
        self.assertEqual(result.details["response_bytes"], 8)
        self.assertNotIn("uploaded", str(result.details))
        self.assertEqual(len(result.details["operation_ids"]), 1)


if __name__ == "__main__":
    unittest.main()
