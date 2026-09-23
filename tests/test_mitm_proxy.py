from __future__ import annotations

import tempfile
import runpy
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.mitm_proxy import start_mitmproxy, stop_mitmproxy
from aidast.scope.models import AssetType


class MitmAddonBudgetTests(unittest.TestCase):
    @staticmethod
    def _addon():
        proxy_module = types.ModuleType("mitmproxy")
        proxy_module.ctx = SimpleNamespace(
            log=SimpleNamespace(warn=MagicMock())
        )
        proxy_module.http = SimpleNamespace(
            Response=SimpleNamespace(
                make=lambda status, content, headers: SimpleNamespace(
                    status_code=status, content=content, headers=headers
                )
            )
        )
        addon_path = (
            Path(__file__).resolve().parents[1]
            / "src" / "aidast" / "recon" / "tools" / "mitm_addon.py"
        )
        with patch.dict(sys.modules, {"mitmproxy": proxy_module}):
            namespace = runpy.run_path(str(addon_path))
        addon = namespace["ScopeAndCaptureAddon"]()
        addon.scope_loaded = True
        addon.allowed_hosts = {"example.com"}
        addon.rules = {
            "allowed_hosts": ["example.com"],
            "allowed_schemes": ["https"],
            "allowed_ports": [443],
            "allowed_path_prefixes": ["/"],
            "excluded_path_prefixes": [],
            "excluded_hosts": [],
            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "include_subdomains": False,
            "browser_context_token": "test-token",
            "max_requests": 10,
            "budget_total": 10,
            "budget_used_before": 0,
        }
        return addon

    @staticmethod
    def _flow(path: str, *, headers=None, method="GET", content=b""):
        return SimpleNamespace(
            request=SimpleNamespace(
                pretty_url=f"https://example.com{path}",
                method=method,
                headers=dict(headers or {}),
                content=content,
                get_text=lambda strict=False: content.decode("utf-8", errors="replace"),
            ),
            metadata={},
            response=None,
        )

    def test_loopback_scope_blocks_external_passive_browser_request(self):
        addon = self._addon()
        addon.allowed_hosts = {"127.0.0.1"}
        addon.rules.update(
            allowed_hosts=["127.0.0.1"], allowed_schemes=["http"],
            allowed_ports=[5001],
        )
        flow = self._flow(
            "/css2?family=Roboto",
            headers={
                "x-aidast-browser-token": "test-token",
                "x-aidast-browser-mode": "passive",
                "Sec-Fetch-Dest": "style",
            },
        )
        flow.request.pretty_url = "https://fonts.googleapis.com/css2?family=Roboto"
        addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertTrue(flow.metadata["aidast_policy_blocked"])
        self.assertEqual(addon.request_count, 0)

    def test_blocked_low_priority_requests_do_not_spend_browser_reserve(self):
        addon = self._addon()
        for index in range(8):
            flow = self._flow(f"/crawl/{index}")
            addon.request(flow)
            self.assertIsNone(flow.response)

        blocked = self._flow("/crawl/deferred")
        addon.request(blocked)
        self.assertIsNotNone(blocked.response)
        self.assertTrue(blocked.metadata["aidast_deferred_candidate"])
        self.assertEqual(addon.request_count, 8)

        browser_api = self._flow(
            "/api/me",
            headers={
                "x-aidast-browser-token": "test-token",
                "x-aidast-browser-mode": "same-origin",
                "Sec-Fetch-Mode": "cors",
            },
        )
        addon.request(browser_api)
        self.assertIsNone(browser_api.response)
        self.assertEqual(browser_api.metadata["aidast_priority"], 1)
        self.assertEqual(addon.request_count, 9)

    def test_tool_source_and_static_resource_priority_markers(self):
        addon = self._addon()
        katana = self._flow(
            "/crawl", headers={"X-AIDAST-Source": "katana"}
        )
        addon.request(katana)
        self.assertEqual(katana.metadata["aidast_priority"], 4)
        self.assertNotIn("X-AIDAST-Source", katana.request.headers)

        duplicate = self._flow(
            "/crawl", headers={"X-AIDAST-Source": "katana"}
        )
        before_duplicate = addon.request_count
        addon.request(duplicate)
        self.assertEqual(duplicate.metadata["aidast_priority"], 6)
        self.assertTrue(duplicate.metadata["aidast_duplicate"])
        self.assertEqual(addon.request_count, before_duplicate + 1)

        ffuf = self._flow("/guess", headers={"X-AIDAST-Source": "ffuf"})
        addon.request(ffuf)
        self.assertEqual(ffuf.metadata["aidast_priority"], 5)
        self.assertNotIn("X-AIDAST-Source", ffuf.request.headers)

        static = self._flow(
            "/assets/app.js", headers={"X-AIDAST-Source": "katana"}
        )
        addon.request(static)
        self.assertEqual(static.metadata["aidast_priority"], 6)
        self.assertTrue(static.metadata["aidast_static_resource"])

    def test_different_query_or_post_body_is_not_budget_deduplicated(self):
        addon = self._addon()
        addon.rules["allowed_methods"].append("POST")
        requests = (
            self._flow("/api/items?id=1"),
            self._flow("/api/items?id=2"),
            self._flow("/api/items", method="POST", content=b'{"value":1}'),
            self._flow("/api/items", method="POST", content=b'{"value":2}'),
        )

        for request in requests:
            addon.request(request)

        self.assertEqual(addon.request_count, 4)
        self.assertTrue(all(not request.metadata["aidast_duplicate"] for request in requests))

    def test_repeated_query_key_order_is_distinct_for_budget(self):
        addon = self._addon()
        requests = (
            self._flow("/api?step=one&step=two"),
            self._flow("/api?step=two&step=one"),
        )
        for request in requests:
            addon.request(request)
        self.assertEqual(addon.request_count, 2)
        self.assertTrue(all(not request.metadata["aidast_duplicate"] for request in requests))

    def test_get_body_changes_request_identity(self):
        addon = self._addon()
        for content in (b"first", b"second"):
            addon.request(self._flow("/api/items", content=content))
        self.assertEqual(addon.request_count, 2)

    def test_repeated_static_requests_cannot_bypass_total_budget(self):
        addon = self._addon()
        for _ in range(8):
            flow = self._flow("/assets/app.js")
            addon.request(flow)
            self.assertIsNone(flow.response)
        blocked = self._flow("/assets/app.js")
        addon.request(blocked)
        self.assertIsNotNone(blocked.response)
        self.assertEqual(addon.request_count, 8)
        self.assertTrue(blocked.metadata["aidast_duplicate"])

    def test_static_and_duplicate_responses_do_not_capture_bodies(self):
        addon = self._addon()
        addon.rules["mitm_capture_bodies"] = True
        with tempfile.TemporaryDirectory() as temporary_dir:
            addon.out_path = Path(temporary_dir) / "capture.jsonl"
            for path in ("/assets/app.js", "/api/items", "/api/items"):
                flow = self._flow(path)
                addon.request(flow)
                flow.response = SimpleNamespace(
                    status_code=200, headers={"Content-Type": "text/plain"},
                    content=b"response-payload", get_text=lambda strict=False: "response-payload",
                )
                addon.response(flow)
            import json
            rows = [json.loads(line) for line in addon.out_path.read_text().splitlines()]
            progress = json.loads(addon.out_path.with_suffix(".progress.json").read_text())
        self.assertFalse(rows[0]["capture_bodies"])
        self.assertTrue(rows[1]["capture_bodies"])
        self.assertFalse(rows[2]["capture_bodies"])
        self.assertEqual([row["response_body"] for row in rows], [None, "response-payload", None])
        self.assertEqual(progress["allowed_requests"], 1)


class MitmProxyStartupTests(unittest.TestCase):
    @staticmethod
    def _rules() -> dict:
        return TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.DOMAIN,
            asset="example.com", allowed_hosts=["example.com"],
        ).mitm_rules()

    def test_default_start_uses_a_dynamically_selected_port(self) -> None:
        process = MagicMock()
        with tempfile.TemporaryDirectory() as temporary_dir:
            with (
                patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
                patch("aidast.recon.tools.mitm_proxy._find_free_port", return_value=43123),
                patch("aidast.recon.tools.mitm_proxy.subprocess.Popen", return_value=process) as popen,
                patch("aidast.recon.tools.mitm_proxy._wait_for_proxy_port", return_value=True) as wait,
            ):
                returned_process, proxy_url = start_mitmproxy(
                    Path(temporary_dir) / "capture.jsonl"
                )

        self.assertIs(returned_process, process)
        self.assertEqual(proxy_url, "http://127.0.0.1:43123")
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("-p") + 1], "43123")
        self.assertEqual(wait.call_args.kwargs["process"], process)

    def test_explicit_occupied_port_is_not_mistaken_for_started_proxy(self) -> None:
        occupied = MagicMock()
        occupied.__enter__.return_value = occupied
        with (
            patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
            patch("aidast.recon.tools.mitm_proxy.socket.create_connection", return_value=occupied),
            patch("aidast.recon.tools.mitm_proxy.subprocess.Popen") as popen,
        ):
            process, proxy_url = start_mitmproxy(Path("capture.jsonl"), port=8080)

        self.assertIsNone(process)
        self.assertIsNone(proxy_url)
        popen.assert_not_called()

    def test_temporary_scope_file_is_removed_when_proxy_stops(self) -> None:
        process = MagicMock()
        with (
            patch("aidast.recon.tools.mitm_proxy.shutil.which", return_value="/bin/mitmdump"),
            patch("aidast.recon.tools.mitm_proxy._find_free_port", return_value=43123),
            patch("aidast.recon.tools.mitm_proxy.subprocess.Popen", return_value=process) as popen,
            patch("aidast.recon.tools.mitm_proxy._wait_for_proxy_port", return_value=True),
        ):
            returned, _ = start_mitmproxy(Path("capture.jsonl"), scope_rules=self._rules())
            command = popen.call_args.args[0]
            scope_argument = next(item for item in command if item.startswith("scope_file="))
            scope_path = Path(scope_argument.split("=", 1)[1])
            self.assertTrue(scope_path.is_file())
            stop_mitmproxy(returned)

        self.assertFalse(scope_path.exists())


if __name__ == "__main__":
    unittest.main()
