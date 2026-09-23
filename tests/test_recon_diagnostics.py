from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aidast.recon.diagnostics import ReconDiagnostics, diagnostic_endpoint
from aidast.recon.activity import activity_from_diagnostic, validated_activity
from aidast.recon.executor import ReconExecutor
from aidast.recon.tools.endpoint_discovery import _parse_katana_output


class ReconDiagnosticsTests(unittest.TestCase):
    def test_executor_persists_safe_activity_without_optional_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            executor = ReconExecutor(
                scan_id="scan_activity_test", scope_type="test", scope_value="example.com",
                db_path=Path(temporary_dir) / "Recon.db",
            )
            try:
                executor._diagnostic("phase_started", phase="playwright_bootstrap",
                                     url="https://example.com/?token=secret", headers={"Cookie": "secret"})
                row = executor.conn.execute(
                    "SELECT details_json FROM audit_events WHERE event_type='recon.activity'"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(json.loads(row[0]), {"phase": "playwright_bootstrap", "state": "started"})
            finally:
                executor.close()

    def test_dashboard_activity_keeps_only_safe_tool_status(self) -> None:
        activity = activity_from_diagnostic("phase_started", {
            "phase": "playwright_interaction", "url": "https://example.com/?token=secret",
            "headers": {"Cookie": "secret"}, "message": "secret", "index": 2,
        })
        self.assertEqual(activity, {"phase": "playwright_interaction", "state": "started", "index": 2})
        self.assertIsNone(activity_from_diagnostic("phase_started", {"phase": ["invalid"]}))
        self.assertEqual(activity_from_diagnostic("task_started", {"task_type": "DNS_RESOLUTION"}),
                         {"phase": "dns_resolution", "state": "started"})
        self.assertEqual(validated_activity({**activity, "url": "secret"}), activity)
        duplicate_activity = activity_from_diagnostic("phase_completed", {
            "phase": "playwright_interaction", "duplicate_count": 3,
            "url": "https://example.com/?token=secret",
        })
        self.assertEqual(duplicate_activity, {
            "phase": "playwright_interaction", "state": "finished", "duplicate_count": 3,
        })
        self.assertIsNone(validated_activity({"phase": ["invalid"], "state": "started"}))

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
