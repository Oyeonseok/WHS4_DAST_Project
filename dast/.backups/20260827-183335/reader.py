from __future__ import annotations

import hashlib
import ipaddress
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from playwright.sync_api import Browser, Page, Playwright, Route, sync_playwright

from aidast.scope.models import CaptureReason, CaptureStatus, ProgramPage


_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/127.0.0.0 Safari/537.36"
)


class ProgramPageError(RuntimeError):
    pass


def _host_is_public(host: str) -> bool:
    if host.lower() == "localhost":
        return False

    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        except socket.gaierror:
            return False

    return bool(addresses) and all(address.is_global for address in addresses)


def _validate_public_https_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProgramPageError("program URL must be an absolute HTTPS URL")
    if not _host_is_public(parsed.hostname):
        raise ProgramPageError(f"program URL resolves to a non-public address: {parsed.hostname}")


class PlaywrightProgramPageReader:
    def __init__(
        self, *, timeout_seconds: float = 45.0, max_content_chars: int = 250_000
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_content_chars <= 0:
            raise ValueError("max_content_chars must be positive")
        self._timeout_seconds = timeout_seconds
        self._max_content_chars = max_content_chars

    def read(self, url: str) -> ProgramPage:
        _validate_public_https_url(url)
        try:
            with sync_playwright() as playwright:
                browser = self._launch_browser(playwright)
                try:
                    return self._read_page(browser, url)
                finally:
                    browser.close()
        except ProgramPageError:
            raise
        except Exception as exc:
            raise ProgramPageError(f"failed to render program page: {exc}") from exc

    @staticmethod
    def _launch_browser(playwright: Playwright) -> Browser:
        try:
            return playwright.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
        except Exception as exc:
            raise ProgramPageError(
                "Chromium is unavailable; run `python -m playwright install chromium`"
            ) from exc

    def _read_page(self, browser: Browser, url: str) -> ProgramPage:
        context = browser.new_context(
            locale="en-US",
            user_agent=_BROWSER_USER_AGENT,
            viewport={"width": 1440, "height": 1200},
        )
        context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        page = context.new_page()
        page.route("**/*", self._guard_request)

        try:
            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=int(self._timeout_seconds * 1000),
            )
            if response is not None and response.status >= 400:
                raise ProgramPageError(
                    f"program page returned HTTP {response.status}: {response.url}"
                )

            landing_text = self._wait_for_stable_text(page)
            final_url = page.url
            title = page.title().strip()
            _validate_public_https_url(final_url)
            scope_view = self._read_scope_view(page, final_url, landing_text)
            text = (
                f"=== PROGRAM PAGE: {final_url} ===\n{landing_text}\n\n"
                f"=== SCOPE VIEW: {scope_view[0]} ===\n{scope_view[1]}"
                if scope_view is not None
                else landing_text
            )
            normalized_text = "\n".join(
                line.rstrip() for line in text.splitlines() if line.strip()
            ).strip()
            if not normalized_text:
                raise ProgramPageError("program page rendered without readable text")
            if len(normalized_text) > self._max_content_chars:
                raise ProgramPageError(
                    f"program page exceeds the {self._max_content_chars}-character "
                    "capture budget"
                )
            capture_status, capture_reason = self._classify_capture(
                normalized_text,
                final_url=final_url,
                has_scope_view=scope_view is not None,
            )

            return ProgramPage(
                requested_url=url,
                final_url=final_url,
                title=title,
                captured_at=datetime.now(timezone.utc),
                capture_status=capture_status,
                capture_reason=capture_reason,
                content_sha256=hashlib.sha256(normalized_text.encode("utf-8")).hexdigest(),
                text=normalized_text,
            )
        finally:
            context.close()

    def _read_scope_view(
        self, page: Page, landing_url: str, landing_text: str
    ) -> tuple[str, str] | None:
        candidates = page.get_by_text("Scope", exact=True)
        for index in range(candidates.count()):
            candidate = candidates.nth(index)
            if not candidate.is_visible():
                continue
            try:
                candidate.click(timeout=5_000)
                page.wait_for_timeout(5_000)
                scope_text = self._wait_for_stable_text(page)
            except Exception:
                continue

            scope_url = page.url
            if urlsplit(scope_url).hostname != urlsplit(landing_url).hostname:
                continue
            if len(scope_text) < 100 or scope_text == landing_text:
                continue
            return scope_url, scope_text
        return None

    def _wait_for_stable_text(self, page: Page) -> str:
        deadline = time.monotonic() + self._timeout_seconds
        latest = ""
        stable_samples = 0

        while time.monotonic() < deadline:
            page.wait_for_timeout(500)
            current = page.locator("body").inner_text(timeout=5_000).strip()
            if current == latest and len(current) >= 500:
                stable_samples += 1
                if stable_samples >= 3:
                    return current
            else:
                latest = current
                stable_samples = 0

        return latest

    @staticmethod
    def _guard_request(route: Route) -> None:
        url = route.request.url
        parsed = urlsplit(url)
        if parsed.scheme in {"data", "blob", "about"}:
            route.continue_()
            return
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            route.abort("blockedbyclient")
            return
        if not _host_is_public(parsed.hostname):
            route.abort("blockedbyclient")
            return
        route.continue_()

    @staticmethod
    def _classify_capture(
        text: str, *, final_url: str, has_scope_view: bool
    ) -> tuple[CaptureStatus, CaptureReason]:
        folded = " ".join(text.lower().split())
        if "access denied" in folded:
            return CaptureStatus.BLOCKED, CaptureReason.ACCESS_DENIED
        if "verify you are human" in folded:
            return CaptureStatus.BLOCKED, CaptureReason.BOT_CHALLENGE
        if "enable javascript and cookies to continue" in folded:
            return (
                CaptureStatus.BLOCKED,
                CaptureReason.JAVASCRIPT_RENDER_INCOMPLETE,
            )
        if len(text) < 100:
            return CaptureStatus.BLOCKED, CaptureReason.CONTENT_INCOMPLETE
        if len(text) < 500:
            return CaptureStatus.PARTIAL, CaptureReason.CONTENT_INCOMPLETE
        host = (urlsplit(final_url).hostname or "").lower()
        if host == "hackerone.com" or host.endswith(".hackerone.com"):
            required = ("assets in scope", "asset name", "bounty")
            if not has_scope_view or not all(marker in folded for marker in required):
                return CaptureStatus.PARTIAL, CaptureReason.CONTENT_INCOMPLETE
        elif host == "bugcrowd.com" or host.endswith(".bugcrowd.com"):
            if "targets" not in folded or "in scope" not in folded:
                return CaptureStatus.PARTIAL, CaptureReason.CONTENT_INCOMPLETE
        elif host == "yeswehack.com" or host.endswith(".yeswehack.com"):
            required = ("scopes", "program rules")
            if not all(marker in folded for marker in required):
                return CaptureStatus.PARTIAL, CaptureReason.CONTENT_INCOMPLETE
        elif "in scope" not in folded:
            return CaptureStatus.PARTIAL, CaptureReason.CONTENT_INCOMPLETE
        return CaptureStatus.COMPLETE, CaptureReason.NONE
