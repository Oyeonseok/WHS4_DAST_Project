from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aidast.recon.diagnostics import ReconDiagnostics, diagnostic_endpoint
from aidast.recon.tools.endpoint_discovery import _parse_katana_output


class ReconDiagnosticsTests(unittest.TestCase):
    def test_jsonl_redacts_secrets_and_url_queries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            path = Path(temporary_dir) / "recon.jsonl"
            log = ReconDiagnostics(path)
            log.record(
                "fixture", request_url="https://example.com/api?token=secret-value",
                headers={"Authorization": "Bearer secret-value"},
                body="secret-body", note="token=secret-value",
            )
            raw = path.read_text(encoding="utf-8")
            document = json.loads(raw)

        self.assertNotIn("secret-value", raw)
        self.assertNotIn("secret-body", raw)
        self.assertEqual(document["details"]["request_url"], "https://example.com/api")
        self.assertEqual(document["details"]["headers"], "[REDACTED]")
        self.assertEqual(document["details"]["body"], "[REDACTED]")

    def test_endpoint_schema_keeps_only_route_metadata(self) -> None:
        result = diagnostic_endpoint({
            "method": "GET", "path": "/api/items", "source": "fixture",
            "url": "https://example.com/api/items?session=secret",
            "headers": {"Cookie": "secret"}, "request_body": "secret",
        })
        self.assertEqual(result["url"], "https://example.com/api/items")
        self.assertNotIn("headers", result)
        self.assertNotIn("request_body", result)

    def test_katana_parser_reports_raw_removed_and_parsed_counts(self) -> None:
        events = []
        results = _parse_katana_output(
            "https://example.com/api\nhttps://outside.test/nope\n",
            base_url="https://example.com", source="katana_fixture",
            diagnostic_callback=lambda event, **details: events.append((event, details)),
        )

        self.assertEqual([item["path"] for item in results], ["/api"])
        self.assertEqual(events[0][0], "katana_parser")
        self.assertEqual(events[0][1]["stdout_line_count"], 2)
        self.assertEqual(events[0][1]["route_removed_count"], 1)
        self.assertEqual(events[0][1]["parsed_count"], 1)


if __name__ == "__main__":
    unittest.main()
