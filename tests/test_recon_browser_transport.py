from __future__ import annotations

import unittest
import tempfile
import json
import io
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from aidast.recon.policy import TargetPolicy
from aidast.core.http_safety import BROWSER_MODE_HEADER, BROWSER_TOKEN_HEADER
from aidast.recon.tools.endpoint_discovery import (
    _filter_results_by_policy, _make_default_session_file, discover_endpoints,
    discover_with_ffuf, discover_with_katana,
)
from aidast.recon.tools.playwright_driver import (
    InteractionConfig, ManualSessionConfig, PlaywrightDriver,
    _wait_for_manual_login,
)
from aidast.recon.tools.page_identity import canonical_visit_key, screen_fingerprint
from aidast.scope.models import AssetType


class ReconBrowserTransportTests(unittest.TestCase):
    def setUp(self):
        self.policy = TargetPolicy(scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
                                   asset="https://example.com/api", allowed_hosts=["example.com"],
                                   allowed_path_prefixes=["/api"], allowed_methods=["GET"])
        self.config = ManualSessionConfig(login_url=self.policy.asset, session_file="unused.json")
        self.driver = PlaywrightDriver(self.policy.asset, self.config, target_policy=self.policy,
                                       proxy_url="http://127.0.0.1:8080")

    def test_redirect_loop_page_is_not_visited_as_endpoint(self):
        page = Mock(url="https://example.com/api/login/login/login")
        page.goto.return_value = Mock(status=200, headers={"content-type": "text/html"})
        with patch.object(self.driver, "_ensure_page", return_value=page):
            self.assertFalse(self.driver.visit_path("/api/login"))

    @unittest.skipIf(os.name == "nt", "POSIX select fallback")
    def test_manual_login_wait_continues_if_stdin_is_not_selectable(self):
        output = io.StringIO()
        with patch("select.select", side_effect=ValueError("stdin has no fileno")), patch(
            "sys.stdout", output
        ):
            self.assertFalse(_wait_for_manual_login(timeout_seconds=1))
        self.assertIn("자동 진행", output.getvalue())

    def test_policy_requires_proxy_before_browser_launch(self):
        with self.assertRaisesRegex(ValueError, "requires a proxy"):
            PlaywrightDriver(self.policy.asset, self.config, target_policy=self.policy)
        with patch("aidast.recon.tools.endpoint_discovery.PlaywrightDriver") as driver:
            with self.assertRaisesRegex(ValueError, "requires a proxy"):
                discover_endpoints(self.policy.asset, target_policy=self.policy)
        driver.assert_not_called()

    def test_katana_modes_extract_forms_without_automatic_submission(self):
        commands = []

        def run(command):
            commands.append(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch("aidast.recon.tools.endpoint_discovery.shutil.which", return_value="/bin/katana"),
            patch("aidast.recon.tools.endpoint_discovery._run_katana", side_effect=run),
        ):
            discover_with_katana(
                "https://example.com", mode="standard", auth_headers=None
            )
            discover_with_katana(
                "https://example.com", mode="headless", auth_headers=None
            )

        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn("-fx", command)
            self.assertNotIn("-aff", command)
        self.assertNotIn("-hl", commands[0])
        self.assertIn("-hl", commands[1])
        self.assertNotIn("-xhr", commands[0])
        self.assertIn("-xhr", commands[1])

    def test_empty_cdp_headless_output_uses_header_fallback(self):
        calls = []

        def run(command):
            calls.append(command)
            if len(calls) == 1:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return SimpleNamespace(
                returncode=0, stdout="https://example.com/api/profile\n", stderr=""
            )

        with (
            patch("aidast.recon.tools.endpoint_discovery.shutil.which", return_value="/bin/katana"),
            patch("aidast.recon.tools.endpoint_discovery._run_katana", side_effect=run),
        ):
            results = discover_with_katana(
                "https://example.com", mode="headless",
                auth_headers={"Cookie": "session"},
                chrome_ws_url="ws://127.0.0.1:9222/devtools/browser/test",
            )

        self.assertEqual(len(calls), 2)
        self.assertIn("-cwu", calls[0])
        self.assertNotIn("-cwu", calls[1])
        self.assertIn("Cookie: session", calls[1])
        self.assertEqual([item["url"] for item in results], [
            "https://example.com/api/profile"
        ])

    def test_unparseable_cdp_headless_output_uses_header_fallback(self):
        calls = []

        def run(command):
            calls.append(command)
            if len(calls) == 1:
                return SimpleNamespace(
                    returncode=0, stdout='{"not":"katana endpoint data"}\n', stderr=""
                )
            return SimpleNamespace(
                returncode=0,
                stdout='{"request":{"endpoint":"https://example.com/api/profile","method":"GET"}}\n',
                stderr="",
            )

        with (
            patch("aidast.recon.tools.endpoint_discovery.shutil.which", return_value="/bin/katana"),
            patch("aidast.recon.tools.endpoint_discovery._run_katana", side_effect=run),
        ):
            results = discover_with_katana(
                "https://example.com", mode="headless",
                auth_headers={"Cookie": "session"},
                chrome_ws_url="ws://127.0.0.1:9222/devtools/browser/test",
            )

        self.assertEqual(len(calls), 2)
        self.assertIn("-cwu", calls[0])
        self.assertNotIn("-cwu", calls[1])
        self.assertEqual([item["url"] for item in results], [
            "https://example.com/api/profile"
        ])

    def test_playwright_priority_pass_shares_the_page_limit_with_expansion(self):
        self.driver.interaction_config = InteractionConfig(max_pages=2)
        page = Mock(url=self.policy.asset)
        with (
            patch.object(self.driver, "ensure_session"),
            patch.object(self.driver, "_ensure_page", return_value=page),
            patch.object(self.driver, "trigger_safe_actions", return_value=0),
            patch.object(self.driver, "visit_path", return_value=True) as visit,
        ):
            self.driver.run_interaction_pass([])
            self.driver.run_interaction_pass([
                {"method": "GET", "path": "/api/one"},
                {"method": "GET", "path": "/api/two"},
            ])

        self.assertEqual(visit.call_count, 1)
        visit.assert_called_once_with("/api/one")
        self.assertEqual(self.driver._interaction_page_count, 2)

    def test_playwright_interaction_pass_stops_at_action_and_time_limits(self):
        page = Mock(url=self.policy.asset)
        self.driver.interaction_config = InteractionConfig(max_pages=30, max_total_actions=1)
        with (
            patch.object(self.driver, "ensure_session"),
            patch.object(self.driver, "_ensure_page", return_value=page),
            patch.object(self.driver, "trigger_safe_actions", return_value=1),
            patch.object(self.driver, "visit_path") as visit,
        ):
            self.driver.run_interaction_pass([{"method": "GET", "path": "/api/one"}])
        visit.assert_not_called()
        self.assertEqual(self.driver.last_interaction_stop_reason, "action_limit")

        self.driver.interaction_config = InteractionConfig(max_pass_seconds=0)
        with (
            patch.object(self.driver, "ensure_session"),
            patch.object(self.driver, "_ensure_page", return_value=page),
            patch.object(self.driver, "trigger_safe_actions") as action,
        ):
            self.driver.run_interaction_pass([])
        action.assert_not_called()
        self.assertEqual(self.driver.last_interaction_stop_reason, "time_limit")

    def test_fragment_routes_compare_rendered_screens(self):
        page = Mock(url="https://example.com/api#first")
        fingerprints = iter(("same-screen", "same-screen", "same-screen", "different-screen"))
        with (
            patch.object(self.driver, "ensure_session"),
            patch.object(self.driver, "_ensure_page", return_value=page),
            patch.object(self.driver, "_current_screen_fingerprint",
                         side_effect=lambda: next(fingerprints)),
            patch.object(self.driver, "trigger_safe_actions", return_value=1) as action,
        ):
            self.driver.run_interaction_pass([])
            page.url = "https://example.com/api#second"
            self.driver.run_interaction_pass([])
            self.assertEqual(self.driver.last_interaction_duplicate_screens, 1)
            page.url = "https://example.com/api/other-path"
            self.driver.run_interaction_pass([])
            self.assertEqual(self.driver.last_interaction_duplicate_screens, 1)
            page.url = "https://example.com/api#third"
            self.driver.run_interaction_pass([])
        self.assertEqual(action.call_count, 2)

    def test_fragment_navigation_without_http_response_can_be_html(self):
        page = Mock(url="https://example.com/api#first")
        def navigate(url: str, **_kwargs: object) -> None:
            page.url = url
            return None
        page.goto.side_effect = navigate
        page.evaluate.return_value = "text/html"
        with patch.object(self.driver, "_ensure_page", return_value=page):
            self.assertTrue(self.driver.visit_path("/api#second"))
        page.goto.assert_called_once()

    def test_browser_visit_identity_keeps_spa_fragment_and_page_content(self):
        first = canonical_visit_key("https://example.com/api?utm_source=x&b=2&a=1#one")
        same_request = canonical_visit_key("https://example.com/api?a=1&b=2#two")
        self.assertNotEqual(first, same_request)
        self.assertEqual(first.split("#")[0], same_request.split("#")[0])
        snapshot = {"main_text": "Account settings and notification preferences are displayed here.",
                    "controls": ["BUTTON settings", "BUTTON notifications"]}
        self.assertEqual(screen_fingerprint(snapshot, origin="https://example.com"),
                         screen_fingerprint(dict(snapshot), origin="https://example.com"))
        changed = dict(snapshot, main_text="Account security and password controls are displayed here.")
        self.assertNotEqual(screen_fingerprint(snapshot, origin="https://example.com"),
                            screen_fingerprint(changed, origin="https://example.com"))

    def test_manual_launch_is_direct_and_unattached_until_login_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.playwright = Mock()
            self.driver.playwright.chromium.executable_path = "/bin/chromium"
            with patch.object(self.driver, "_ensure_playwright"), patch.object(
                self.driver, "_shutdown_runtime"
            ), patch.object(self.driver, "_find_free_port", return_value=45678), patch.object(
                self.driver, "_attach_manual_browser"
            ) as attach, patch("aidast.recon.tools.playwright_driver.subprocess.Popen") as launch:
                self.driver._launch_manual_browser(manual_login=True)
                command = launch.call_args.args[0]
                self.assertIn("--no-proxy-server", command)
                self.assertNotIn("--ignore-certificate-errors", command)
                self.assertFalse(any(arg.startswith("--proxy-server=") for arg in command))
                self.assertEqual(command[-1], self.config.login_url)
                attach.assert_not_called()

    def test_runtime_launch_uses_managed_headless_browser_with_proxy(self):
        playwright = Mock()
        browser = Mock()
        context = Mock()
        page = Mock()
        playwright.chromium.launch.return_value = browser
        browser.new_context.return_value = context
        context.new_page.return_value = page
        self.driver.playwright = playwright

        with patch.object(self.driver, "_ensure_playwright"), patch.object(
            self.driver, "_shutdown_runtime"
        ), patch.object(self.driver, "_register_context_handlers"), patch.object(
            self.driver, "_register_page_handlers"
        ) as register_page:
            self.driver._launch_manual_browser()

        playwright.chromium.launch.assert_called_once_with(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--proxy-bypass-list=<-loopback>",
            ],
            proxy={"server": "http://127.0.0.1:8080"},
        )
        browser.new_context.assert_called_once_with(ignore_https_errors=True)
        self.assertEqual(self.driver._browser_kind, "managed")
        self.assertIs(self.driver.context, context)
        self.assertIs(self.driver.page, page)
        register_page.assert_called_once_with(page)

    def test_manual_session_applies_policy_to_same_chromium_context(self):
        events = []
        page = Mock(url=self.policy.asset)
        self.driver.context = Mock(pages=[page])
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.session_path.write_text("{}")
            with patch.object(self.driver, "_launch_manual_browser", side_effect=lambda **kwargs: events.append(("launch", kwargs.get("manual_login", False)))), patch.object(
            self.driver, "_attach_manual_browser", side_effect=lambda: events.append(("attach",))
            ), patch.object(self.driver, "_register_authentication_observer", side_effect=lambda: events.append(("auth-observer",))
            ), patch("aidast.recon.tools.playwright_driver._wait_for_manual_login", side_effect=lambda: events.append(("input",))), patch.object(
            self.driver, "save_session", side_effect=lambda: events.append(("save", self.driver._phase)) or True
            ), patch.object(self.driver, "_register_context_handlers", side_effect=lambda: events.append(("policy",))), patch.object(
            self.driver, "_register_page_handlers", side_effect=lambda current: events.append(("page", current is page))
            ):
                self.driver.capture_and_start()
        self.assertEqual(events, [
            ("launch", True), ("attach",), ("auth-observer",), ("input",), ("save", "login"),
            ("policy",), ("page", True),
        ])
        self.assertIs(self.driver.context.pages[0], page)

    def test_unauthenticated_start_never_opens_manual_login(self):
        page = Mock(url=self.policy.asset)
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
                self.driver, "_ensure_page", return_value=page
            ), patch.object(self.driver, "save_session", return_value=True), patch.object(
                self.driver, "_shutdown_runtime"
            ) as shutdown, patch(
                "aidast.recon.tools.playwright_driver._wait_for_manual_login"
            ) as wait:
                self.driver.start_unauthenticated()

        launch.assert_called_once_with()
        page.goto.assert_called_once_with(
            self.policy.asset, wait_until="domcontentloaded", timeout=15_000
        )
        wait.assert_not_called()
        shutdown.assert_not_called()

    def test_automatic_start_does_not_prompt_for_404(self):
        page = Mock(url=self.policy.asset)
        response = SimpleNamespace(status=404, headers={})
        with patch.object(
            self.driver, "_start_unauthenticated", return_value=(page, response)
        ), patch.object(self.driver, "save_session", return_value=True), patch.object(
            self.driver, "capture_and_start"
        ) as login:
            self.assertFalse(self.driver.start_automatic())
        login.assert_not_called()

    def test_automatic_start_does_not_prompt_for_login_text_without_a_control(self):
        page = Mock(url=self.policy.asset)
        page.locator("input[type='password']:visible").count.return_value = 0
        page.locator("body").inner_text.return_value = "Welcome. Log in"
        response = SimpleNamespace(status=200, headers={})
        with patch.object(
            self.driver, "_start_unauthenticated", return_value=(page, response)
        ), patch.object(self.driver, "save_session", return_value=True), patch.object(
            self.driver, "capture_and_start"
        ) as login:
            self.assertFalse(self.driver.start_automatic())
        login.assert_not_called()

    def test_automatic_start_prompts_for_visible_login_link(self):
        page = Mock(url=self.policy.asset)

        def locator(selector):
            result = Mock()
            result.count.return_value = 0
            result.evaluate_all.return_value = []
            result.all_inner_texts.return_value = []
            result.inner_text.return_value = "Welcome"
            if selector == "a[href]:visible":
                result.evaluate_all.return_value = ["https://example.com/login"]
            return result

        page.locator.side_effect = locator
        response = SimpleNamespace(status=200, headers={})
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            with patch.object(
                self.driver, "_start_unauthenticated", return_value=(page, response)
            ), patch.object(self.driver, "_shutdown_runtime"), patch.object(
                self.driver, "capture_and_start"
            ) as login:
                self.assertTrue(self.driver.start_automatic())
            self.assertTrue(self.driver.automatic_auth_marker_path.is_file())
        login.assert_called_once_with()

    def test_automatic_start_prompts_for_visible_password_input(self):
        page = Mock(url="https://example.com/login")

        def locator(selector):
            result = Mock()
            result.count.return_value = 1 if selector == "input[type='password']:visible" else 0
            result.evaluate_all.return_value = []
            result.all_inner_texts.return_value = []
            return result

        page.locator.side_effect = locator
        response = SimpleNamespace(status=200, headers={})
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            with patch.object(
                self.driver, "_start_unauthenticated", return_value=(page, response)
            ), patch.object(self.driver, "_shutdown_runtime"), patch.object(
                self.driver, "capture_and_start"
            ) as login:
                self.assertTrue(self.driver.start_automatic())
        login.assert_called_once_with()

    def test_json_401_without_login_ui_does_not_prompt(self):
        page = Mock(url="https://example.com/api/me")

        def locator(_selector):
            result = Mock()
            result.count.return_value = 0
            result.evaluate_all.return_value = []
            result.all_inner_texts.return_value = []
            return result

        page.locator.side_effect = locator
        response = SimpleNamespace(
            status=401,
            headers={
                "content-type": "application/json",
                "www-authenticate": "Bearer",
            },
        )
        with patch.object(
            self.driver, "_start_unauthenticated", return_value=(page, response)
        ), patch.object(self.driver, "save_session", return_value=True), patch.object(
            self.driver, "capture_and_start"
        ) as login:
            self.assertFalse(self.driver.start_automatic())
        login.assert_not_called()

    def test_automatic_start_reuses_one_authenticated_session_per_origin(self):
        page = Mock(url="https://example.com/api/missing")
        response = SimpleNamespace(status=404, headers={})
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.session_path.write_text("{}", encoding="utf-8")
            self.driver.session_storage_path.write_text("{}", encoding="utf-8")
            self.driver.automatic_auth_marker_path.write_text(
                "authenticated\n", encoding="utf-8"
            )
            with patch.object(
                self.driver, "_start_unauthenticated", return_value=(page, response)
            ) as start, patch.object(
                self.driver, "save_session", return_value=True
            ), patch.object(self.driver, "capture_and_start") as login:
                self.assertTrue(self.driver.start_automatic())
        start.assert_called_once_with(restore_saved_session=True)
        login.assert_not_called()

    def test_none_mode_never_reauthenticates_during_session_check(self):
        self.driver._interactive_authentication_enabled = False
        with patch.object(self.driver, "restore_runtime"), patch.object(
            self.driver, "session_is_valid", return_value=False
        ) as validate, patch.object(self.driver, "capture_and_start") as login:
            self.driver.ensure_session()
        validate.assert_not_called()
        login.assert_not_called()

    def test_endpoint_discovery_uses_automatic_login_detection_when_selected(self):
        with patch(
            "aidast.recon.tools.endpoint_discovery.PlaywrightDriver"
        ) as driver:
            driver.return_value.start_automatic.side_effect = RuntimeError("stop")
            with self.assertRaisesRegex(RuntimeError, "stop"):
                discover_endpoints(
                    self.policy.asset,
                    target_policy=self.policy,
                    mitm_proxy_url="http://127.0.0.1:8080",
                    automatic_login=True,
                )
        driver.return_value.start_automatic.assert_called_once_with()
        driver.return_value.capture_and_start.assert_not_called()

    def test_authentication_observer_keeps_only_secret_free_same_origin_coordinates(self):
        self.driver._phase = "login"
        self.driver._observe_authentication_request(SimpleNamespace(
            method="POST",
            url="https://example.com/rest/user/login?password=private#fragment",
        ))
        self.driver._observe_authentication_request(SimpleNamespace(
            method="POST",
            url="https://identity.example/login?token=private",
        ))

        self.assertEqual(self.driver.authentication_endpoints[0].method, "POST")
        self.assertEqual(self.driver.authentication_endpoints[0].path, "/rest/user/login")
        self.assertEqual(len(self.driver.authentication_endpoints), 1)
        self.assertEqual(self.driver.get_http_results(), [])
        passive = self.driver.drain_authentication_observations()
        self.assertEqual(passive[0]["discovery_kind"], "passive_login_observation")
        self.assertNotIn("private", json.dumps(self.driver.get_http_results()))

    def test_passive_authentication_observation_cannot_use_browser_support_path_bypass(self):
        item = {
            "method": "POST", "path": "/admin/login",
            "url": "https://example.com/admin/login",
            "source": "auth_bootstrap",
            "discovery_kind": "passive_login_observation",
            "browser_supporting_request": True,
        }
        self.assertEqual(_filter_results_by_policy(
            [item], base_url=self.policy.asset, target_policy=self.policy,
            passive_metadata=True,
        ), [])

    def test_expired_restored_session_can_enter_manual_reauthentication(self):
        self.driver.preauthenticated = True
        with patch.object(self.driver, "restore_runtime"), patch.object(
            self.driver, "session_is_valid", return_value=False
        ), patch.object(self.driver, "capture_and_start") as capture:
            self.driver.ensure_session()
        capture.assert_called_once_with()

    def test_manual_reauthentication_accepts_previously_restored_driver(self):
        self.driver.preauthenticated = True
        self.driver.context = Mock(pages=[])
        with patch.object(self.driver, "_launch_manual_browser"), patch.object(
            self.driver, "_attach_manual_browser"
        ), patch.object(self.driver, "_register_authentication_observer"), patch(
            "aidast.recon.tools.playwright_driver._wait_for_manual_login"
        ), patch.object(self.driver, "save_session", return_value=True), patch.object(
            self.driver, "_register_context_handlers"
        ):
            self.driver.capture_and_start()

    def test_cancel_closes_direct_browser_without_session_or_runtime(self):
        with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
            self.driver, "_attach_manual_browser"
        ) as attach, patch("aidast.recon.tools.playwright_driver._wait_for_manual_login", side_effect=KeyboardInterrupt), patch.object(
            self.driver, "save_session"
        ) as save, patch.object(self.driver, "_shutdown_runtime") as close:
            with self.assertRaises(KeyboardInterrupt):
                self.driver.capture_and_start()
        launch.assert_called_once_with(manual_login=True)
        attach.assert_called_once_with()
        save.assert_not_called()
        close.assert_called_once_with()
        self.assertEqual(self.driver._phase, "runtime")

    def test_runtime_shutdown_does_not_wait_for_route_callbacks(self):
        context = Mock()
        context.unroute_all.side_effect = AssertionError(
            "route cleanup must not block complete runtime shutdown"
        )
        process = Mock()
        process.poll.return_value = None
        self.driver.context = context
        self.driver._browser_kind = "cdp"
        self.driver._chrome_process = process

        self.driver._shutdown_runtime()

        context.unroute_all.assert_not_called()
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=3)
        self.assertIsNone(self.driver.context)
        self.assertIsNone(self.driver._chrome_process)

    def test_browser_launch_removes_stale_run_profile_singletons(self):
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.profile_path.mkdir()
            for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
                (self.driver.profile_path / name).symlink_to("stale-target")

            playwright = Mock()
            playwright.chromium.executable_path = "/test/chromium"
            self.driver.playwright = playwright

            with patch.object(self.driver, "_ensure_playwright"), patch.object(
                self.driver, "_shutdown_runtime"
            ), patch.object(self.driver, "_find_free_port", return_value=43210), patch(
                "aidast.recon.tools.playwright_driver.subprocess.Popen"
            ) as popen, patch.object(self.driver, "_attach_manual_browser"):
                self.driver._launch_manual_browser(manual_login=True)

            popen.assert_called_once()
            for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
                self.assertFalse((self.driver.profile_path / name).exists())

    def test_failed_session_save_prevents_runtime_launch(self):
        with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
            self.driver, "_attach_manual_browser"
        ), patch("aidast.recon.tools.playwright_driver._wait_for_manual_login", return_value=False), patch.object(
            self.driver, "save_session", return_value=False
        ), patch.object(self.driver, "_shutdown_runtime") as close:
            with self.assertRaisesRegex(RuntimeError, "could not save"):
                self.driver.capture_and_start()
        launch.assert_called_once_with(manual_login=True)
        close.assert_called_once_with()

    def test_invalid_restored_session_falls_back_to_manual_login(self):
        for url, status in [("https://sso.example.net/login", 200), (self.policy.asset, 403)]:
            with self.subTest(url=url, status=status):
                endpoint_callback = Mock()
                self.driver.session_config.authentication_endpoint_callback = endpoint_callback
                failed_page = Mock(url=url)
                failed_page.goto.return_value = SimpleNamespace(status=status)
                restored_page = Mock(url=self.policy.asset)
                restored_page.goto.return_value = SimpleNamespace(status=200)
                with tempfile.TemporaryDirectory() as directory:
                    self.driver.session_config.session_file = str(Path(directory) / "session.json")
                    self.driver.session_path.write_text("{}")
                    with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
                    self.driver, "_attach_manual_browser"
                    ), patch.object(self.driver, "_register_authentication_observer"
                    ), patch.object(self.driver, "_restore_target_session"), patch.object(
                    self.driver, "_ensure_page", side_effect=[failed_page, restored_page]
                    ), patch("aidast.recon.tools.playwright_driver._wait_for_manual_login", return_value=False), patch.object(
                    self.driver, "save_session", return_value=True
                    ) as save, patch.object(self.driver, "_shutdown_runtime") as close, patch.object(
                    self.driver, "_page_indicates_login_required", return_value=False
                    ), patch.object(self.driver, "session_is_valid", return_value=True):
                        self.driver.start_from_session()
                self.assertEqual(
                    launch.call_args_list,
                    [call(), call(manual_login=True), call()],
                )
                self.assertEqual(save.call_count, 2)
                self.assertEqual(close.call_count, 2)
                endpoint_callback.assert_called_once_with(tuple())

    def test_browser_support_allows_only_marked_non_navigation_requests(self):
        self.driver.browser_context_token = "browser-token-with-enough-length"

        def request(url, resource_type, *, navigation=False):
            return SimpleNamespace(
                url=url, method="GET", resource_type=resource_type,
                all_headers=lambda: {"accept": "*/*"},
                frame=SimpleNamespace(url=self.policy.asset),
                is_navigation_request=lambda: navigation,
            )

        same_origin = Mock(request=request("https://example.com/bootstrap", "xhr"))
        self.driver._guard_request(same_origin)
        headers = same_origin.continue_.call_args.kwargs["headers"]
        self.assertEqual(headers[BROWSER_TOKEN_HEADER], self.driver.browser_context_token)
        self.assertEqual(headers[BROWSER_MODE_HEADER], "same-origin")

        passive = Mock(request=request("https://cdn.example.net/app.js", "script"))
        self.driver._guard_request(passive)
        self.assertEqual(
            passive.continue_.call_args.kwargs["headers"][BROWSER_MODE_HEADER], "passive"
        )

        for blocked_request in (
            request("https://cdn.example.net/api", "xhr"),
            request("https://example.com/outside", "document", navigation=True),
        ):
            route = Mock(request=blocked_request)
            self.driver._guard_request(route)
            route.abort.assert_called_once_with("blockedbyclient")

    def test_loopback_browser_blocks_external_passive_resources(self):
        policy = TargetPolicy(
            scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
            asset="http://127.0.0.1:5001/", allowed_hosts=["127.0.0.1"],
            allowed_schemes=["http"], allowed_ports=[5001],
            allowed_path_prefixes=["/"], allowed_methods=["GET"],
        )
        driver = PlaywrightDriver(
            policy.asset, ManualSessionConfig(login_url=policy.asset, session_file="unused.json"),
            target_policy=policy, proxy_url="http://127.0.0.1:8080",
        )
        driver.browser_context_token = "browser-token-with-enough-length"
        request = SimpleNamespace(
            url="https://fonts.googleapis.com/css2?family=Roboto", method="GET",
            resource_type="stylesheet", all_headers=lambda: {"accept": "text/css"},
            frame=SimpleNamespace(url=policy.asset), is_navigation_request=lambda: False,
        )
        route = Mock(request=request)
        driver._guard_request(route)
        route.abort.assert_called_once_with("blockedbyclient")
        route.continue_.assert_not_called()

    def test_visit_path_does_not_duplicate_an_absolute_path(self):
        page = Mock()
        page.goto.return_value = SimpleNamespace(
            status=200, headers={"content-type": "text/html"}
        )
        with patch.object(self.driver, "_ensure_page", return_value=page):
            self.assertTrue(self.driver.visit_path("/api"))
        self.assertEqual(page.goto.call_args.args[0], "https://example.com/api")

    def test_only_browser_support_observations_cross_the_path_filter(self):
        results = [
            {"method": "GET", "path": "/bootstrap", "source": "browser"},
            {
                "method": "GET", "path": "/session-api", "source": "browser",
                "browser_supporting_request": True,
            },
        ]
        filtered = _filter_results_by_policy(
            results, base_url=self.policy.asset, target_policy=self.policy
        )
        self.assertEqual([item["path"] for item in filtered], ["/session-api"])

    def test_restore_runtime_reuses_persistent_browser_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.session_path.write_text("{}")
            with patch.object(self.driver, "_launch_manual_browser") as launch, patch.object(
                self.driver, "_restore_target_session"
            ) as restore:
                self.driver.restore_runtime(force=True)
        launch.assert_called_once_with()
        restore.assert_called_once_with()

    def test_restore_runtime_retries_one_transient_cdp_launch_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            self.driver.session_config.session_file = str(Path(directory) / "session.json")
            self.driver.session_path.write_text("{}")
            with patch.object(
                self.driver, "_launch_manual_browser",
                side_effect=[RuntimeError("CDP refused"), None],
            ) as launch, patch.object(
                self.driver, "_restore_target_session"
            ) as restore, patch.object(
                self.driver, "_shutdown_runtime"
            ) as shutdown:
                self.driver.restore_runtime(force=True)

        self.assertEqual(launch.call_count, 2)
        shutdown.assert_called_once_with()
        restore.assert_called_once_with()

    def test_restore_session_filters_external_cookies_and_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            self.config.session_file = str(Path(directory) / "session.json")
            self.driver.session_path.write_text(json.dumps({
                "cookies": [{"name": "session", "domain": "example.com", "value": "target"},
                            {"name": "sso", "domain": "external.test", "value": "external-secret"}],
                "origins": [{"origin": "https://example.com", "localStorage": [{"name": "key", "value": "target"}]},
                            {"origin": "https://external.test", "localStorage": [{"name": "key", "value": "external-secret"}]}],
            }))
            self.driver.context = Mock()
            self.driver._restore_target_session()
            self.driver.context.add_cookies.assert_called_once_with([
                {"name": "session", "domain": "example.com", "value": "target"},
            ])
            script = self.driver.context.add_init_script.call_args.kwargs["script"]
            self.assertIn("https://example.com", script)
            self.assertNotIn("external-secret", script)

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

    def test_endpoint_discovery_passes_auth_bootstrap_to_browser(self):
        for options in ({}, {"auth_bootstrap": {
            "hosts": ["login.example.com"], "paths": ["/authorize"],
        }}):
            endpoint_callback = Mock()
            with self.subTest(options=options), patch(
                "aidast.recon.tools.endpoint_discovery.PlaywrightDriver"
            ) as driver:
                driver.return_value.start_unauthenticated.side_effect = RuntimeError("stop before browser launch")
                with self.assertRaisesRegex(RuntimeError, "stop before browser launch"):
                    discover_endpoints(
                        self.policy.asset, target_policy=self.policy,
                        mitm_proxy_url="http://127.0.0.1:8080",
                        authentication_endpoint_callback=endpoint_callback,
                        **options,
                    )
                self.assertEqual(driver.call_args.kwargs["auth_bootstrap"], options.get("auth_bootstrap"))
                self.assertIs(driver.call_args.kwargs["target_policy"], self.policy)
                self.assertIs(
                    driver.call_args.args[1].authentication_endpoint_callback,
                    endpoint_callback,
                )
                driver.return_value.close.assert_called_once_with()

    def test_endpoint_discovery_passes_intigriti_headers_to_browser(self):
        headers = {
            "X-Intigriti-Username": "baekggum",
            "User-Agent": "aidast-recon/0.1 <intigriti:baekggum>",
        }
        with patch(
            "aidast.recon.tools.endpoint_discovery.PlaywrightDriver"
        ) as driver:
            driver.return_value.start_unauthenticated.side_effect = RuntimeError("stop")
            with self.assertRaisesRegex(RuntimeError, "stop"):
                discover_endpoints(
                    self.policy.asset,
                    target_policy=self.policy,
                    mitm_proxy_url="http://127.0.0.1:8080",
                    request_headers=headers,
                )
        self.assertEqual(driver.call_args.kwargs["request_headers"], headers)

    def test_endpoint_discovery_uses_manual_login_only_when_explicit(self):
        with patch(
            "aidast.recon.tools.endpoint_discovery.PlaywrightDriver"
        ) as driver:
            driver.return_value.capture_and_start.side_effect = RuntimeError("stop")
            with self.assertRaisesRegex(RuntimeError, "stop"):
                discover_endpoints(
                    self.policy.asset,
                    target_policy=self.policy,
                    mitm_proxy_url="http://127.0.0.1:8080",
                    interactive_login=True,
                )
        driver.return_value.capture_and_start.assert_called_once_with()
        driver.return_value.start_unauthenticated.assert_not_called()

    def test_route_guard_injects_identity_only_into_target_requests(self):
        self.driver.request_headers = {
            "X-Intigriti-Username": "baekggum",
            "User-Agent": "aidast-recon/0.1 <intigriti:baekggum>",
        }
        self.driver.browser_context_token = "browser-token-with-enough-length"

        def request(url, resource_type, *, frame_url=None):
            return SimpleNamespace(
                url=url, method="GET", resource_type=resource_type,
                all_headers=lambda: {"accept": "*/*"},
                frame=SimpleNamespace(url=frame_url or self.policy.asset),
                is_navigation_request=lambda: False,
            )

        target = Mock(request=request("https://example.com/api/users", "xhr"))
        self.driver._guard_request(target)
        target_headers = target.continue_.call_args.kwargs["headers"]
        self.assertEqual(target_headers["X-Intigriti-Username"], "baekggum")
        self.assertIn("<intigriti:baekggum>", target_headers["User-Agent"])

        third_party = Mock(request=request("https://cdn.example.net/app.js", "script"))
        self.driver._guard_request(third_party)
        third_party_headers = third_party.continue_.call_args.kwargs["headers"]
        self.assertNotIn("X-Intigriti-Username", third_party_headers)
        self.assertNotIn("User-Agent", third_party_headers)

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
        self.driver.context.route_web_socket.assert_not_called()
        websocket_guard = self.driver.context.add_init_script.call_args.args[0]
        self.assertIn("PolicyBlockedWebSocket", websocket_guard)
        self.assertIn("WebSocket blocked by target policy", websocket_guard)

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
        from aidast.paths import RESULT_ROOT
        self.assertTrue(Path(first).is_relative_to(RESULT_ROOT / ".aidast_sessions"))
        self.assertEqual(first, _make_default_session_file(self.policy.asset, run_id="run", identity_id="alice"))
        self.assertEqual(
            first,
            _make_default_session_file(
                "https://example.com/api/other", run_id="run", identity_id="alice"
            ),
        )
        for url, run, identity in [(self.policy.asset, "run2", "alice"),
                                  (self.policy.asset, "run", "bob"),
                                  ("https://other.example.com/api", "run", "alice")]:
            self.assertNotEqual(first, _make_default_session_file(url, run_id=run, identity_id=identity))
        malicious = _make_default_session_file(self.policy.asset, run_id="../../secret", identity_id="../token")
        self.assertNotIn("..", Path(malicious).parts)
        self.assertNotIn("token", malicious)
        self.assertNotEqual(_make_default_session_file(self.policy.asset),
                            _make_default_session_file(self.policy.asset))


if __name__ == "__main__":
    unittest.main()
