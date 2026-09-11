from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.endpoint_discovery import (
    _make_default_session_file, discover_endpoints, discover_with_ffuf, discover_with_katana,
)
from aidast.recon.tools.playwright_driver import ManualSessionConfig, PlaywrightDriver
from aidast.scope.models import AssetType


class ReconBrowserTransportTests(unittest.TestCase):
    def setUp(self):
        self.policy = TargetPolicy(scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
                                   asset="https://example.com/api", allowed_hosts=["example.com"],
                                   allowed_path_prefixes=["/api"], allowed_methods=["GET"])
        self.config = ManualSessionConfig(login_url=self.policy.asset, session_file="unused.json")
        self.driver = PlaywrightDriver(self.policy.asset, self.config, target_policy=self.policy,
                                       proxy_url="http://127.0.0.1:8080")

    def test_policy_requires_proxy_before_browser_launch(self):
        with self.assertRaisesRegex(ValueError, "requires a proxy"):
            PlaywrightDriver(self.policy.asset, self.config, target_policy=self.policy)
        with patch("aidast.recon.tools.endpoint_discovery.PlaywrightDriver") as driver:
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_endpoints(self.policy.asset, target_policy=self.policy)
        driver.assert_not_called()

    def test_policy_requires_shared_proxy_for_external_tools(self):
        with patch("aidast.recon.tools.endpoint_discovery.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_with_ffuf(self.policy.asset, wordlist=None, seed_endpoints=[],
                                   auth_headers=None, target_policy=self.policy)
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_with_katana(self.policy.asset, mode="standard", auth_headers=None,
                                     target_policy=self.policy)
            with self.assertRaisesRegex(ValueError, "shared enforcement proxy"):
                discover_endpoints(self.policy.asset, target_policy=self.policy,
                                   mitm_proxy_url="http://127.0.0.1:8080",
                                   playwright_proxy_url="http://127.0.0.1:8081")
        run.assert_not_called()

    def test_route_guard_blocks_scope_methods_and_url_credentials(self):
        for url, method, allowed in [
            ("https://example.com/api/users", "GET", True),
            ("https://example.com/admin?token=secret", "GET", False),
            ("https://outside.example/api", "GET", False),
            ("https://example.com/api", "POST", False),
            ("https://user:secret@example.com/api", "GET", False),
        ]:
            with self.subTest(url=url, method=method):
                route = Mock(request=SimpleNamespace(url=url, method=method))
                self.driver._guard_request(route)
                if allowed:
                    route.continue_.assert_called_once_with()
                    route.abort.assert_not_called()
                else:
                    route.abort.assert_called_once_with("blockedbyclient")
                    route.continue_.assert_not_called()

    def test_route_guard_aborts_policy_errors(self):
        route = Mock(request=SimpleNamespace(url="https://example.com/api", method="GET"))
        self.driver.target_policy = Mock(allows_url=Mock(side_effect=ValueError("secret")))
        self.driver._guard_request(route)
        route.abort.assert_called_once_with("blockedbyclient")

    def test_context_installs_guards(self):
        self.driver.context = Mock()
        self.driver._register_context_handlers()
        self.driver.context.route.assert_called_once_with("**/*", self.driver._guard_request)
        websocket = Mock()
        self.driver.context.route_web_socket.call_args.args[1](websocket)
        websocket.close.assert_called_once_with()

    def test_manual_browser_is_playwright_managed_while_exposing_cdp(self):
        chromium = Mock()
        managed_browser = Mock()
        managed_context = Mock()
        managed_context.pages = []
        managed_page = Mock()
        managed_context.new_page.return_value = managed_page
        managed_browser.new_context.return_value = managed_context
        chromium.launch.return_value = managed_browser
        chromium.executable_path = "/legacy/chromium"
        legacy_context = Mock()
        legacy_context.pages = []
        chromium.connect_over_cdp.return_value = Mock(contexts=[legacy_context])
        self.driver.playwright = SimpleNamespace(chromium=chromium)

        with patch.object(self.driver, "_find_free_port", return_value=9222), patch.object(
            self.driver, "_wait_for_cdp", return_value="ws://127.0.0.1:9222/devtools/browser/id"
        ), patch("aidast.recon.tools.playwright_driver.subprocess.Popen"):
            self.driver._launch_manual_browser()

        self.assertIs(self.driver.browser, managed_browser)
        self.assertIs(self.driver.context, managed_context)
        self.assertIs(self.driver.page, managed_page)
        self.assertEqual(self.driver._browser_kind, "managed")
        self.assertEqual(
            self.driver.get_chrome_ws_url(),
            "ws://127.0.0.1:9222/devtools/browser/id",
        )
        launch = chromium.launch.call_args.kwargs
        self.assertFalse(launch["headless"])
        self.assertIn("--remote-debugging-port=9222", launch["args"])
        self.assertEqual(launch["proxy"]["server"], "http://127.0.0.1:8080")
        chromium.connect_over_cdp.assert_not_called()

    def test_auth_check_uses_policy_transport(self):
        self.config.auth_check_url = "me"
        self.driver.context = Mock()
        with patch.object(self.driver, "get_auth_headers", return_value={}), patch(
            "aidast.recon.tools.playwright_driver._http_request", return_value=(None, {}, b"")
        ) as request:
            self.assertFalse(self.driver.session_is_valid())
        self.assertIs(request.call_args.kwargs["target_policy"], self.policy)
        self.driver.context.request.get.assert_not_called()

    def test_default_sessions_are_scoped_by_run_identity_and_target(self):
        first = _make_default_session_file(self.policy.asset, run_id="run", identity_id="alice")
        self.assertEqual(first, _make_default_session_file(self.policy.asset, run_id="run", identity_id="alice"))
        for url, run, identity in [(self.policy.asset, "run2", "alice"),
                                  (self.policy.asset, "run", "bob"),
                                  ("https://example.com/other", "run", "alice")]:
            self.assertNotEqual(first, _make_default_session_file(url, run_id=run, identity_id=identity))
        malicious = _make_default_session_file(self.policy.asset, run_id="../../secret", identity_id="../token")
        self.assertNotIn("..", Path(malicious).parts)
        self.assertNotIn("token", malicious)
        self.assertNotEqual(_make_default_session_file(self.policy.asset),
                            _make_default_session_file(self.policy.asset))


if __name__ == "__main__":
    unittest.main()
