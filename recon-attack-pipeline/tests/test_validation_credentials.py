"""Credential references resolve only at the trusted Validation request boundary."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aidast.pipeline.lifecycle import register_credential_reference
from aidast.recon import db
from aidast.validation import PipelineCredentialResolver


class ValidationCredentialResolverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "Pipeline.db"
        conn = db.init_db(self.path)
        db.insert_scan(conn, scan_id="scan", scope_type="test", scope_value="local")
        self.reference = register_credential_reference(
            conn, scan_id="scan", label="member",
            reference_uri="env://AIDAST_TEST_MEMBER_HEADERS",
            identity_role="member",
        )
        self.unsupported = register_credential_reference(
            conn, scan_id="scan", label="vault-member",
            reference_uri="vault://team/member", identity_role="vault-member",
        )
        conn.close()
        self.resolver = PipelineCredentialResolver(self.path)

    def test_env_reference_resolves_json_headers_without_persisting_values(self):
        value = json.dumps({"Authorization": "Bearer test-value", "X-Role": "member"})
        with patch.dict(os.environ, {"AIDAST_TEST_MEMBER_HEADERS": value}):
            self.assertIsNone(self.resolver.unsupported_reason(self.reference))
            self.assertEqual(self.resolver(self.reference), {
                "Authorization": "Bearer test-value", "X-Role": "member",
            })

    def test_missing_invalid_and_unconfigured_backends_are_unavailable(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                self.resolver.unsupported_reason(self.reference),
                "credential_reference_unavailable",
            )
        with patch.dict(os.environ, {
            "AIDAST_TEST_MEMBER_HEADERS": '{"Authorization":"x\\r\\nInjected: y"}',
        }):
            self.assertEqual(
                self.resolver.unsupported_reason(self.reference),
                "credential_reference_unavailable",
            )
        self.assertEqual(
            self.resolver.unsupported_reason(self.unsupported),
            "credential_reference_unavailable",
        )


if __name__ == "__main__":
    unittest.main()
