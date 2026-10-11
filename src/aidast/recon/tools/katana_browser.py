"""Disposable, policy-proxied Chromium for Katana CDP crawling."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse

from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.playwright_driver import PlaywrightDriver


def _stop_process(process: subprocess.Popen) -> None:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        # A concurrently exiting browser must not block profile cleanup.
        pass


@dataclass
class KatanaBrowserLease:
    chrome_ws_url: str
    process: subprocess.Popen
    temporary_directory: tempfile.TemporaryDirectory

    @property
    def profile_path(self) -> Path:
        return Path(self.temporary_directory.name) / "profile"

    def close(self) -> None:
        try:
            _stop_process(self.process)
        finally:
            self.temporary_directory.cleanup()


def open_katana_browser(
    driver: PlaywrightDriver, proxy_url: str | None,
    target_policy: TargetPolicy | None,
    *, diagnostic_callback: Callable[..., None] | None = None,
) -> KatanaBrowserLease | None:
    """Clone target credentials into a separate browser; never touch the live context."""
    from aidast.core.http_safety import has_request_exclusions
    if has_request_exclusions(target_policy):
        raise ValueError('exclusion hold: unmanaged cloned CDP browser is unsupported')
    if (not proxy_url or target_policy is None or driver.playwright is None
            or not driver.session_path.is_file()):
        return None
    if not target_policy.allows_url(driver.base_url, method="GET"):
        return None
    # A cloned browser has no Playwright Fetch route, so it cannot safely use
    # browser-support exceptions beyond a narrowly approved path prefix.
    if "/" not in target_policy.allowed_path_prefixes:
        return None

    temporary_directory = tempfile.TemporaryDirectory(prefix="aidast-katana-")
    process = None
    step = "copy_session"
    try:
        root = Path(temporary_directory.name)
        private_session = root / "session.json"
        shutil.copyfile(driver.session_path, private_session)
        private_session.chmod(0o600)
        if driver.session_storage_path.is_file():
            private_storage = root / "session.json.sessionstorage.json"
            shutil.copyfile(driver.session_storage_path, private_storage)
            private_storage.chmod(0o600)

        clone = PlaywrightDriver(
            driver.base_url,
            replace(driver.session_config, session_file=str(private_session)),
            proxy_url=proxy_url, target_policy=target_policy,
            request_headers=driver.request_headers,
            browser_context_token=driver.browser_context_token,
        )
        state = clone._filter_storage_state(json.loads(private_session.read_text(encoding="utf-8")))
        profile = root / "profile"
        profile.mkdir(mode=0o700)
        step = "launch_browser"
        port = driver._find_free_port()
        command = [
            driver.playwright.chromium.executable_path,
            f"--remote-debugging-port={port}",
            "--remote-debugging-address=127.0.0.1",
            "--remote-allow-origins=*",
            f"--user-data-dir={profile}",
            "--headless=new", "--no-first-run", "--no-default-browser-check",
            "--disable-dev-shm-usage", "--ignore-certificate-errors",
            f"--proxy-server={proxy_url}", "--proxy-bypass-list=<-loopback>",
            "about:blank",
        ]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        step = "attach_cdp"
        chrome_ws_url = driver._wait_for_cdp(port, timeout_seconds=15)
        browser = driver.playwright.chromium.connect_over_cdp(
            f"http://127.0.0.1:{port}", timeout=10_000,
        )
        if not browser.contexts:
            raise RuntimeError("isolated browser has no context")
        step = "restore_session"
        clone.context = browser.contexts[0]

        # Permit only rendering support traffic during the initial page load.
        # This route can grant the proxy's passive static-resource exception,
        # but it is removed before Katana attaches to avoid a Fetch conflict.
        def bootstrap_guard(route) -> None:
            try:
                if route.request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                    route.abort("blockedbyclient")
                    return
            except Exception:
                route.abort("blockedbyclient")
                return
            clone._guard_request(route)

        clone.context.route("**/*", bootstrap_guard)
        clone._restore_target_session()
        step = "load_target"
        page = clone.context.new_page()
        response = page.goto(driver.base_url, wait_until="domcontentloaded",
                             timeout=driver.session_config.timeout_ms)
        if (response is None or not 200 <= response.status < 300
                or not clone._same_origin(response.url)
                or not clone._same_origin(page.url)
                or clone._login_path(page.url)
                or page.locator("input[type='password']:visible").count() > 0
                or clone._page_indicates_login_required(page)):
            raise RuntimeError("isolated browser did not reach the target page")

        step = "verify_session"
        expected_cookies = {(c["name"], c["value"]) for c in state.get("cookies", [])}
        actual_cookies = {(c["name"], c["value"]) for c in clone.context.cookies(driver.base_url)}
        if not expected_cookies.issubset(actual_cookies):
            raise RuntimeError("isolated browser did not restore target cookies")
        expected_storage = {
            item["name"]: item["value"]
            for origin in state.get("origins", []) if origin.get("origin") == clone._base_origin()
            for item in origin.get("localStorage", [])
        }
        actual_storage = page.evaluate("Object.fromEntries(Object.entries(localStorage))")
        if not isinstance(actual_storage, dict) or any(
            actual_storage.get(key) != value for key, value in expected_storage.items()
        ):
            raise RuntimeError("isolated browser did not restore target storage")

        check_url = driver.session_config.auth_check_url
        if check_url:
            check_url = urljoin(driver.base_url + "/", check_url)
            if not target_policy.allows_url(check_url, method="GET"):
                raise RuntimeError("auth check URL is outside target policy")
            response = page.goto(check_url, wait_until="domcontentloaded", timeout=driver.session_config.timeout_ms)
            if (response is None or not 200 <= response.status < 300
                    or urlparse(response.url).path != urlparse(check_url).path
                    or page.locator("input[type='password']:visible").count() > 0):
                raise RuntimeError("isolated browser failed authentication check")
        step = "release_bootstrap_route"
        clone.context.unroute("**/*", bootstrap_guard)
        if driver.request_headers:
            clone.context.set_extra_http_headers(driver.request_headers)
        return KatanaBrowserLease(chrome_ws_url, process, temporary_directory)
    except Exception as exc:
        if diagnostic_callback is not None:
            try:
                diagnostic_callback("browser_fallback", mode="headless",
                                    step=step, error_type=type(exc).__name__)
            except Exception:
                pass
        if process is not None:
            _stop_process(process)
        temporary_directory.cleanup()
        return None
