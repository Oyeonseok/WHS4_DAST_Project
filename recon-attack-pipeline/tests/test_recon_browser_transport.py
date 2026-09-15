from __future__ import annotations

import queue
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aidast.core.http_safety import (
    AUTH_CAPABILITY_HEADER,
    validate_request_capability,
)
from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.endpoint_discovery import (
    _make_default_session_file, discover_endpoints, discover_with_ffuf, discover_with_katana,
)
from aidast.recon.tools.playwright_driver import (
    InteractionConfig,
    ManualSessionConfig,
    PlaywrightDriver,
)
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

    def test_route_guard_issues_capability_for_approved_auth_post(self):
        signing_key = "a" * 32
        self.driver._manual_auth_signing_key = signing_key
        route = Mock(request=SimpleNamespace(
            url="https://example.com/api/login",
            method="POST",
            headers={"Content-Type": "application/json"},
        ))

        with patch.object(self.driver, "_approve_manual_auth_request", return_value=True):
            self.driver._guard_request(route)

        headers = route.continue_.call_args.kwargs["headers"]
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertTrue(validate_request_capability(
            headers[AUTH_CAPABILITY_HEADER],
            signing_key,
            method="POST",
            url=route.request.url,
            max_ttl_seconds=30,
            used_nonces=set(),
        ))
        route.abort.assert_not_called()

        self.driver._phase = "runtime"
        runtime_route = Mock(request=route.request)
        self.driver._guard_request(runtime_route)
        runtime_route.abort.assert_called_once_with("blockedbyclient")

    def test_request_bound_auth_grant_does_not_allow_other_methods_or_hosts(self):
        self.driver._manual_auth_signing_key = "a" * 32
        for url, method in [
            ("https://example.com/api/login", "PUT"),
            ("https://outside.example/api/login", "POST"),
        ]:
            with self.subTest(url=url, method=method):
                route = Mock(request=SimpleNamespace(
                    url=url, method=method, headers={},
                ))
                with patch.object(
                    self.driver, "_approve_manual_auth_request", return_value=True,
                ) as approve:
                    self.driver._guard_request(route)
                route.abort.assert_called_once_with("blockedbyclient")
                approve.assert_not_called()

    def test_unapproved_auth_post_is_blocked_without_a_capability(self):
        self.driver._manual_auth_signing_key = "a" * 32
        route = Mock(request=SimpleNamespace(
            url="https://example.com/api/login", method="POST", headers={},
        ))
        with patch.object(self.driver, "_approve_manual_auth_request", return_value=False):
            self.driver._guard_request(route)
        route.abort.assert_called_once_with("blockedbyclient")
        route.continue_.assert_not_called()

    def test_manual_auth_approval_uses_one_terminal_decision_and_hides_query(self):
        self.driver._manual_auth_commands = queue.Queue()
        self.driver._manual_auth_completion = threading.Event()
        self.driver._manual_auth_approval_pending = threading.Event()
        result = []

        def approve():
            result.append(self.driver._approve_manual_auth_request(
                method="POST",
                url="https://example.com/api/login?token=secret",
            ))

        with patch("builtins.print") as output:
            worker = threading.Thread(target=approve)
            worker.start()
            self.assertTrue(self.driver._manual_auth_approval_pending.wait(timeout=2))
            self.driver._manual_auth_commands.put("y")
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [True])
        rendered = "\n".join(" ".join(map(str, call.args)) for call in output.call_args_list)
        self.assertIn("POST https://example.com/api/login", rendered)
        self.assertNotIn("secret", rendered)

    def test_manual_auth_does_not_reprompt_for_identical_request_retry(self):
        for decision, expected_first in (("n", False), ("y", True)):
            with self.subTest(decision=decision):
                self.driver._manual_auth_decided_requests.clear()
                self.driver._manual_auth_commands = queue.Queue()
                self.driver._manual_auth_commands.put(decision)
                self.driver._manual_auth_completion = threading.Event()
                self.driver._manual_auth_approval_pending = threading.Event()
                fingerprint = "same-request"

                with patch("builtins.print") as output:
                    first = self.driver._approve_manual_auth_request(
                        method="POST",
                        url="https://example.com/api/login",
                        request_fingerprint=fingerprint,
                    )
                    second = self.driver._approve_manual_auth_request(
                        method="POST",
                        url="https://example.com/api/login",
                        request_fingerprint=fingerprint,
                    )

                self.assertEqual(first, expected_first)
                self.assertFalse(second)
                self.assertEqual(output.call_count, 4)

    def test_manual_auth_fingerprint_changes_when_form_body_changes(self):
        first = SimpleNamespace(
            method="POST", url="https://example.com/api/login", post_data_buffer=b"one",
        )
        second = SimpleNamespace(
            method="POST", url="https://example.com/api/login", post_data_buffer=b"two",
        )
        retry = SimpleNamespace(
            method="POST", url="https://example.com/api/login", post_data_buffer=b"one",
        )

        self.assertNotEqual(
            self.driver._manual_auth_request_fingerprint(first),
            self.driver._manual_auth_request_fingerprint(second),
        )
        self.assertEqual(
            self.driver._manual_auth_request_fingerprint(first),
            self.driver._manual_auth_request_fingerprint(retry),
        )

    def test_context_installs_guards(self):
        self.driver.context = Mock()
        self.driver._register_context_handlers()
        self.driver.context.route.assert_called_once_with("**/*", self.driver._guard_request)
        self.driver.context.route_web_socket.assert_not_called()
        self.driver.context.add_init_script.assert_called_once_with(
            script=self.driver._BLOCK_WEBSOCKETS_SCRIPT,
        )

    def test_request_handler_does_not_reenter_playwright_for_page_title(self):
        self.driver.context = Mock()
        self.driver._register_context_handlers()
        handlers = {
            call.args[0]: call.args[1]
            for call in self.driver.context.on.call_args_list
        }
        page = Mock()
        request = SimpleNamespace(
            url="https://example.com/api/users",
            method="GET",
            resource_type="xhr",
            frame=SimpleNamespace(url="https://example.com/api", page=page),
        )

        handlers["request"](request)

        page.title.assert_not_called()
        self.assertEqual(len(self.driver.requests), 1)
        self.assertEqual(self.driver.requests[0]["context"]["page_title"], "")

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
        managed_context.add_init_script.assert_any_call(
            script=self.driver._MATERIAL_SELECT_CLICK_BRIDGE,
        )
        managed_context.add_init_script.assert_any_call(
            script=self.driver._BLOCK_WEBSOCKETS_SCRIPT,
        )
        chromium.connect_over_cdp.assert_not_called()

    def test_material_select_bridge_is_narrowly_scoped(self):
        script = self.driver._MATERIAL_SELECT_CLICK_BRIDGE
        self.assertIn("mat-form-field.mat-form-field-type-mat-select", script)
        self.assertIn('mat-select[role="combobox"][aria-haspopup="listbox"]', script)
        self.assertIn("target.closest('mat-select')", script)
        self.assertNotIn("preventDefault", script)

    def test_manual_auth_dismisses_only_exact_passive_overlays(self):
        page = Mock()
        page.evaluate.side_effect = [2, 0, 0, 0]

        dismissed = self.driver._dismiss_passive_auth_overlays(page)

        self.assertEqual(dismissed, 2)
        script = page.evaluate.call_args_list[0].args[0]
        self.assertIn('aria-label=\\"cookieconsent\\"', script)
        self.assertIn('Close Welcome Banner', script)
        self.assertNotIn('button:has-text', script)
        self.assertEqual(page.wait_for_timeout.call_count, 4)

    def test_manual_auth_revokes_post_grant_before_saving_session(self):
        self.driver._manual_auth_signing_key = "a" * 32
        page = Mock()
        with (
            patch.object(self.driver, "_launch_manual_browser"),
            patch.object(self.driver, "_ensure_page", return_value=page),
            patch.object(self.driver, "_dismiss_passive_auth_overlays", return_value=0),
            patch.object(self.driver, "save_session", return_value=True) as save,
            patch("builtins.input", return_value=""),
            patch("builtins.print"),
        ):
            self.driver.capture_and_start()

        self.assertEqual(self.driver._phase, "runtime")
        self.assertIsNone(self.driver._manual_auth_signing_key)
        save.assert_called_once_with()

    def test_manual_auth_wait_pumps_playwright_while_terminal_input_blocks(self):
        input_started = threading.Event()
        release_input = threading.Event()
        page = Mock()

        def blocking_input(_prompt):
            input_started.set()
            self.assertTrue(release_input.wait(timeout=2))
            return ""

        def pump_events(_milliseconds):
            self.assertTrue(input_started.wait(timeout=2))
            release_input.set()

        page.wait_for_timeout.side_effect = pump_events
        with patch("builtins.input", side_effect=blocking_input):
            self.driver._wait_for_manual_auth_completion(page)

        page.wait_for_timeout.assert_called_with(100)

    def test_safe_actions_use_material_select_trigger_with_forced_hit_test(self):
        self.driver.interaction_config = InteractionConfig(action_wait_ms=0)
        page = Mock()
        page.is_closed.return_value = False
        candidates = Mock()
        candidates.count.return_value = 1
        element = Mock()
        element.is_visible.return_value = True
        element.inner_text.return_value = "Security Question"
        element.get_attribute.side_effect = lambda name: {
            "aria-label": "Selection list for the security question",
            "title": None,
            "id": "mat-select-0",
            "name": "securityQuestion",
        }.get(name)
        element.evaluate.return_value = "mat-select"
        trigger = Mock()
        trigger.count.return_value = 1
        element.locator.return_value = trigger
        candidates.nth.return_value = element
        page.locator.return_value = candidates
        self.driver.page = page

        self.assertEqual(self.driver.trigger_safe_actions(), 1)

        element.click.assert_not_called()
        trigger.click.assert_called_once_with(timeout=1500, force=True)

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
