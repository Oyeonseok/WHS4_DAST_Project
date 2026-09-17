"""PLAYWRIGHT DRIVER

역할
----
1. 실제 Chromium 브라우저 실행
2. 사용자가 직접 로그인
3. Cookie / localStorage / sessionStorage 저장
4. 로그인 과정 HTTP 요청 관찰
5. Katana / ffuf / ZAP용 인증 Header 생성
6. Katana Headless가 로그인 Browser를 사용할 수 있도록 CDP 제공
7. Katana Headless 종료 후 Browser Context가 죽어도 저장된 세션으로 복구
8. 로그인된 상태에서 안전한 UI Interaction 수행
9. XHR / fetch / WebSocket 관찰

Playwright는 메인 크롤러가 아니다.
"""

from __future__ import annotations

import json
import os
import sys
import socket
import subprocess
import time
import urllib.request

from dataclasses import dataclass, field
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    sync_playwright,
)

from aidast.recon.policy import TargetPolicy
from aidast.auth.endpoints import AuthenticationEndpoint, normalize_origin
from aidast.core.http_safety import BROWSER_MODE_HEADER, BROWSER_TOKEN_HEADER
from aidast.recon.tools.api_secondary_discovery import _http_request


def _wait_for_manual_login(timeout_seconds: int = 300) -> bool:
    """Wait for Enter, but allow unattended runs to continue after a timeout."""
    print(f"  로그인 완료 후 Enter (미입력 시 {timeout_seconds // 60}분 후 자동 진행) > ", end="", flush=True)
    if os.name == "nt":
        import msvcrt
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                msvcrt.getwch()
                return True
            time.sleep(0.2)
        print("\n  [Playwright] 입력 시간 초과: 현재 세션으로 자동 진행합니다.")
        return False
    import select
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout_seconds)
    except (OSError, ValueError, TypeError, AttributeError):
        # Embedded runners and test harnesses may replace stdin with an object
        # that has no selectable file descriptor. There is no reliable way to
        # wait for keyboard input in that case, so continue without blocking.
        print("\n  [Playwright] 대화형 입력을 사용할 수 없어 현재 세션으로 자동 진행합니다.")
        return False
    if ready:
        sys.stdin.readline()
        return True
    print("\n  [Playwright] 입력 시간 초과: 현재 세션으로 자동 진행합니다.")
    return False

# =========================================================
# Configuration
# =========================================================

@dataclass
class ManualSessionConfig:

    # 최초로 열 페이지
    #
    # 로그인 URL을 알면 로그인 URL 지정
    # 모르면 base_url 지정 후 사용자가 직접 이동
    login_url: str

    # 인증정보 저장 파일
    session_file: str

    # 인증 여부 확인 URL
    #
    # 예:
    # /api/me
    # /rest/user/whoami
    #
    # 모르면 None
    auth_check_url: str | None = None

    invalid_auth_statuses: tuple[int, ...] = (
        401,
    )

    authentication_endpoint_callback: Callable[
        [tuple[AuthenticationEndpoint, ...]], None
    ] | None = None

    # Storage 값을 HTTP Header로 변환
    #
    # 예:
    #
    # {
    #     "token": (
    #         "Authorization",
    #         "Bearer ",
    #     )
    # }
    #
    storage_header_map: dict[
        str,
        tuple[str, str],
    ] = field(
        default_factory=dict
    )

    timeout_ms: int = 15_000


@dataclass
class InteractionConfig:

    enabled: bool = True

    max_pages: int = 30

    max_actions_per_page: int = 10

    action_wait_ms: int = 500

    # TargetPolicy가 Scope의 명시적인 금지 근거를 반영해 끄지 않은
    # 경우 form 내부의 상호작용도 탐색 대상에 포함한다.
    allow_form_submission: bool = True

    # 자동으로 누르면 위험할 수 있는 Action
    blocked_words: tuple[str, ...] = (

        # English
        "delete",
        "remove",
        "purchase",
        "buy",
        "checkout",
        "payment",
        "pay",
        "submit",
        "send",
        "transfer",
        "save",
        "update",
        "create",
        "register",
        "logout",
        "sign out",
        "unsubscribe",
        "add to basket",
        "add to cart",
        "change password",
        "reset password",

        # Korean
        "삭제",
        "탈퇴",
        "구매",
        "결제",
        "주문",
        "전송",
        "송금",
        "이체",
        "저장",
        "수정",
        "등록",
        "로그아웃",
        "장바구니",
        "비밀번호 변경",
        "비밀번호 재설정",
    )


# =========================================================
# Driver
# =========================================================

class PlaywrightDriver:

    def __init__(
        self,
        base_url: str,
        session_config: ManualSessionConfig,
        *,
        interaction_config: InteractionConfig | None = None,
        proxy_url: str | None = None,
        target_policy: TargetPolicy | None = None,
        auth_bootstrap: dict | None = None,
        preauthenticated: bool = False,
        browser_context_token: str | None = None,
    ):

        if target_policy is not None and not proxy_url:
            raise ValueError("policy-enforced browser requires a proxy")
        self.preauthenticated = preauthenticated
        self.target_policy = target_policy
        self.auth_bootstrap = auth_bootstrap or {}
        self.base_url = (
            base_url.rstrip("/")
        )

        self.session_config = (
            session_config
        )

        self.interaction_config = (
            interaction_config
            or InteractionConfig()
        )

        self.proxy_url = (
            proxy_url
        )
        self.browser_context_token = browser_context_token

        self.playwright: (
            Playwright | None
        ) = None

        self.browser: (
            Browser | None
        ) = None

        self.context: (
            BrowserContext | None
        ) = None

        self.page: (
            Page | None
        ) = None

        self.requests: list[dict] = []
        self.authentication_endpoints: list[AuthenticationEndpoint] = []
        self._observation_cursor = 0
        self._interaction_visited: set[str] = set()
        self._interaction_page_count = 0
        self._context_serial = 0
        self._action_context = None

        self.websockets: list[dict] = []

        self._phase = "runtime"

        self._auth_expired = False

        # 외부 Chromium Process
        self._chrome_process: (
            subprocess.Popen | None
        ) = None

        self._cdp_port: (
            int | None
        ) = None

        self._chrome_ws_url: (
            str | None
        ) = None

        # cdp / managed
        self._browser_kind: (
            str | None
        ) = None

        # WebSocket Handler 중복 방지
        self._registered_pages: set[int] = set()

    # =====================================================
    # File Paths
    # =====================================================

    @property
    def session_path(
        self,
    ) -> Path:

        return Path(
            self.session_config.session_file
        )

    @property
    def session_storage_path(
        self,
    ) -> Path:

        return Path(
            self.session_config.session_file
            + ".sessionstorage.json"
        )

    @property
    def profile_path(
        self,
    ) -> Path:

        return Path(
            self.session_config.session_file
            + ".profile"
        )

    # =====================================================
    # URL / Origin
    # =====================================================

    @staticmethod
    def _effective_port(
        parsed,
    ) -> int | None:

        if parsed.port is not None:
            return parsed.port

        scheme = (
            parsed.scheme.lower()
        )

        if scheme in {
            "http",
            "ws",
        }:
            return 80

        if scheme in {
            "https",
            "wss",
        }:
            return 443

        return None

    @staticmethod
    def _normalized_scheme(
        scheme: str,
    ) -> str:

        scheme = scheme.lower()

        if scheme == "ws":
            return "http"

        if scheme == "wss":
            return "https"

        return scheme

    def _same_origin(
        self,
        url: str,
    ) -> bool:

        try:

            parsed = urlparse(
                url
            )

            base = urlparse(
                self.base_url
            )

            return (
                self._normalized_scheme(
                    parsed.scheme
                )
                ==
                self._normalized_scheme(
                    base.scheme
                )

                and
                (
                    parsed.hostname
                    or ""
                ).lower()
                ==
                (
                    base.hostname
                    or ""
                ).lower()

                and
                self._effective_port(
                    parsed
                )
                ==
                self._effective_port(
                    base
                )
            )

        except ValueError:

            return False

    def _base_origin(
        self,
    ) -> str:

        parsed = urlparse(
            self.base_url
        )

        origin = (
            f"{parsed.scheme}://"
            f"{parsed.hostname}"
        )

        if parsed.port is not None:

            origin += (
                f":{parsed.port}"
            )

        return origin

    # =====================================================
    # Playwright
    # =====================================================

    def _ensure_playwright(
        self,
    ) -> None:

        if self.playwright is not None:
            return

        self.playwright = (
            sync_playwright()
            .start()
        )

    # =====================================================
    # CDP
    # =====================================================

    @staticmethod
    def _find_free_port(
    ) -> int:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        ) as sock:

            sock.bind(
                (
                    "127.0.0.1",
                    0,
                )
            )

            return int(
                sock.getsockname()[1]
            )

    def _wait_for_cdp(
        self,
        port: int,
        *,
        # A cold Chrome-for-Testing launch on macOS can take well over ten
        # seconds while component caches are initialized.  Keep this above
        # the observed cold-start time so a healthy browser is not mistaken
        # for a refused CDP connection.
        timeout_seconds: float = 30.0,
    ) -> str:

        endpoint = (
            f"http://127.0.0.1:"
            f"{port}/json/version"
        )

        deadline = (
            time.time()
            + timeout_seconds
        )

        last_error: (
            Exception | None
        ) = None

        while time.time() < deadline:

            try:

                with urllib.request.urlopen(
                    endpoint,
                    timeout=1,
                ) as response:

                    payload = json.loads(
                        response.read()
                        .decode(
                            "utf-8"
                        )
                    )

                ws_url = payload.get(
                    "webSocketDebuggerUrl"
                )

                if ws_url:
                    return ws_url

            except Exception as exc:

                last_error = exc

            time.sleep(
                0.25
            )

        raise RuntimeError(
            "Chromium CDP 연결 실패: "
            f"{last_error}"
        )

    # =====================================================
    # Runtime Shutdown
    # =====================================================

    def _shutdown_runtime(
        self,
    ) -> None:

        # Do not call BrowserContext.unroute_all() while tearing down the
        # complete runtime. Playwright can wait forever for an in-flight route
        # callback even with ``ignoreErrors``. The managed browser close or
        # external Chromium process termination below releases every route
        # together with the context.

        # -------------------------------------------------
        # Playwright가 직접 실행한 Browser
        # -------------------------------------------------

        if (
            self._browser_kind
            == "managed"
            and self.browser is not None
        ):

            try:
                self.browser.close()
            except Exception:
                pass

        # -------------------------------------------------
        # CDP 외부 Chromium
        #
        # browser.close()를 호출하지 않고
        # Process를 직접 종료한다.
        # -------------------------------------------------

        if self._chrome_process is not None:

            try:

                if (
                    self._chrome_process.poll()
                    is None
                ):

                    self._chrome_process.terminate()

                    try:

                        self._chrome_process.wait(
                            timeout=3
                        )

                    except subprocess.TimeoutExpired:

                        self._chrome_process.kill()

            except Exception:
                pass

        self.browser = None
        self.context = None
        self.page = None

        self._chrome_process = None

        self._cdp_port = None
        self._chrome_ws_url = None

        self._browser_kind = None

        self._registered_pages.clear()

    # =====================================================
    # Manual Chromium Launch
    # =====================================================

    def _launch_manual_browser(
        self,
        *,
        manual_login: bool = False,
    ) -> None:

        self._ensure_playwright()

        assert self.playwright is not None

        # The operator-facing login flow needs a visible, directly connected
        # Chromium.  Once a session snapshot exists, use Playwright's managed
        # runtime instead of starting a GUI process and attaching over CDP.
        # On macOS the latter can remain alive without ever opening its CDP
        # port; managed headless launch avoids that GUI bootstrap dependency.
        if not manual_login:
            self._launch_managed_runtime()
            return

        # 기존 Runtime 종료
        self._shutdown_runtime()

        executable = self.playwright.chromium.executable_path

        self.profile_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Chromium can leave these profile-local symlinks behind when a CDP
        # process is terminated during session restore.  A retry with the
        # same run-scoped profile then exits before opening its debugging
        # port.  This profile belongs exclusively to this driver/run, and the
        # tracked process has already been stopped by _shutdown_runtime().
        for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
            lock = self.profile_path / name
            try:
                if lock.is_symlink() or lock.exists():
                    lock.unlink()
            except OSError:
                pass

        self.session_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        port = (
            self._find_free_port()
        )

        self._cdp_port = port

        command = [
            executable,

            f"--remote-debugging-port={port}",

            "--remote-allow-origins=*",

            (
                "--user-data-dir="
                f"{self.profile_path}"
            ),

            "--no-first-run",

            "--no-default-browser-check",

            "--disable-dev-shm-usage",

            # Keep WebGL/GPU available for Cloudflare and identity-provider
            # browser checks.  Disabling it makes the login browser look like
            # a software-rendered automation surface and can leave email
            # challenge flows spinning forever.
            "--disable-blink-features=AutomationControlled",

            self.session_config.login_url if manual_login else "about:blank",
        ]

        if manual_login:
            command.insert(-1, "--no-proxy-server")
        elif self.proxy_url:
            command.insert(-1, "--ignore-certificate-errors")
            command.insert(
                -1,
                (
                    "--proxy-server="
                    f"{self.proxy_url}"
                ),
            )
            # Chromium otherwise bypasses configured proxies for loopback.
            command.insert(-1, "--proxy-bypass-list=<-loopback>")

        self._chrome_process = (
            subprocess.Popen(
                command,

                stdout=(
                    subprocess.DEVNULL
                ),

                stderr=(
                    subprocess.DEVNULL
                ),
            )
        )

    def _launch_managed_runtime(self) -> None:
        self._ensure_playwright()
        assert self.playwright is not None

        self._shutdown_runtime()

        launch_options: dict = {
            "headless": True,
            "args": [
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                # Chromium otherwise bypasses configured proxies for loopback.
                "--proxy-bypass-list=<-loopback>",
            ],
        }
        if self.proxy_url:
            launch_options["proxy"] = {"server": self.proxy_url}

        self.browser = self.playwright.chromium.launch(**launch_options)
        self._browser_kind = "managed"
        self.context = self.browser.new_context(ignore_https_errors=True)
        self.context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        self._register_context_handlers()
        self.page = self.context.new_page()
        self._register_page_handlers(self.page)

    def _attach_manual_browser(self) -> None:
        """Attach only after manual login, or to the policy-enforced runtime."""
        port = self._cdp_port
        if port is None or self.playwright is None:
            raise RuntimeError("manual browser is not running")
        self._chrome_ws_url = (
            self._wait_for_cdp(
                port
            )
        )

        self.browser = (
            self.playwright
            .chromium
            .connect_over_cdp(
                (
                    "http://127.0.0.1:"
                    f"{port}"
                )
            )
        )

        self._browser_kind = "cdp"

        contexts = (
            self.browser.contexts
        )

        if not contexts:

            raise RuntimeError(
                "Chromium BrowserContext를 "
                "찾을 수 없습니다."
            )

        self.context = contexts[0]

        # CDP-attached Chromium can still expose webdriver to newly created
        # documents.  Hide only this automation marker; do not spoof cookies,
        # storage, or browser APIs involved in authentication.
        self.context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        if self._phase != "login":
            self._register_context_handlers()

        pages = self.context.pages

        if pages:

            self.page = pages[0]

        else:

            self.page = (
                self.context.new_page()
            )

        if self._phase != "login":
            for page in self.context.pages:
                self._register_page_handlers(page)

    # =====================================================
    # HTTP Network Observation
    # =====================================================

    def _guard_request(self, route) -> None:
        """Apply policy before browser egress; the proxy also checks redirects.

        Do not include URLs or headers in rejection messages: browser URLs may
        contain session tokens. Handler errors abort rather than bypass policy.
        """
        try:
            request = route.request
            parsed = urlparse(request.url)
            strictly_allowed = (
                self.target_policy is not None
                and not parsed.username and not parsed.password
                and self.target_policy.allows_url(request.url, method=request.method)
            )
            support_mode = None if strictly_allowed else self._browser_support_mode(request)
        except Exception:
            strictly_allowed = False
            support_mode = None
        try:
            if strictly_allowed:
                route.continue_()
            elif support_mode and self.browser_context_token:
                # A request can still be delivered to this callback while a
                # CDP target is shutting down. Reading headers in that window
                # raises TargetClosedError; never turn browser shutdown into a
                # Recon failure or attempt to bypass the policy.
                headers = dict(request.all_headers())
                headers[BROWSER_TOKEN_HEADER] = self.browser_context_token
                headers[BROWSER_MODE_HEADER] = support_mode
                route.continue_(headers=headers)
            else:
                route.abort("blockedbyclient")
        except Exception:
            # TargetClosedError (and equivalent CDP teardown races) are safe
            # to ignore because the page/context is already gone.
            return

    def _browser_support_mode(self, request) -> str | None:
        """Classify rendering traffic caused by a page inside the strict boundary."""
        if self.target_policy is None or request.is_navigation_request():
            return None
        try:
            if not self.target_policy.allows_url(request.frame.url):
                return None
            parsed = urlparse(request.url)
            if parsed.username or parsed.password:
                return None
            if self._same_origin(request.url):
                method_allowed = self.target_policy.allows_browser_support_url(
                    request.url, method=request.method
                )
                if (
                    request.method.upper() == "POST"
                    and getattr(request, "resource_type", None) in {"xhr", "fetch"}
                ):
                    # Browser support deliberately ignores the endpoint path
                    # (Admin SPAs call APIs outside /store/<id>) while still
                    # enforcing the exact approved origin and exclusions.
                    method_allowed = self.target_policy.allows_browser_support_url(
                        request.url, method="GET"
                    )
                return "same-origin" if method_allowed else None
            if (
                request.method.upper() in {"GET", "HEAD"}
                and parsed.scheme == "https"
                and self._effective_port(parsed) == 443
                and request.resource_type
                in {"script", "stylesheet", "image", "font", "media"}
            ):
                return "passive"
        except Exception:
            return None
        return None

    @staticmethod
    def _path_matches(path: str, prefix: str) -> bool:
        prefix = str(prefix).rstrip("/") or "/"
        return prefix == "/" or path == prefix or path.startswith(prefix + "/")

    def _register_context_handlers(
        self,
    ) -> None:

        if self.context is None:
            return

        if self.target_policy is not None:
            self.context.route("**/*", self._guard_request)
            # WebSocket messages are outside the HTTP policy contract.  Do
            # not call WebSocketRoute.close() from its synchronous callback:
            # recent Playwright versions can deadlock by re-entering the sync
            # dispatcher.  Blocking construction before application scripts
            # run keeps the channel closed and lets Socket.IO fall back to
            # proxy-observable HTTP polling.
            self.context.add_init_script(
                """
                (() => {
                    class PolicyBlockedWebSocket {
                        static CONNECTING = 0;
                        static OPEN = 1;
                        static CLOSING = 2;
                        static CLOSED = 3;
                        constructor() {
                            throw new DOMException(
                                'WebSocket blocked by target policy',
                                'SecurityError'
                            );
                        }
                    }
                    Object.defineProperty(globalThis, 'WebSocket', {
                        value: PolicyBlockedWebSocket,
                        configurable: false,
                        writable: false
                    });
                })();
                """
            )

        def on_request(
            request,
        ):

            if not self._same_origin(
                request.url
            ):
                return

            # 정적 Resource 제외
            if (
                request.resource_type
                not in {
                    "document",
                    "xhr",
                    "fetch",
                }
            ):
                return

            parsed = urlparse(
                request.url
            )

            from aidast.recon import db
            from aidast.recon.annotations import safe_url, safe_text
            page_url = ''
            page_title = ''
            try:
                page = request.frame.page
                page_url = safe_url(request.frame.url)
                page_title = safe_text(page.title())
            except Exception:
                pass
            context = dict(self._action_context or {})
            context.setdefault('context_key', f'{self._phase}:{page_url}')
            context.setdefault('action_type', 'navigation')
            context.setdefault('association_method', 'request_frame')
            context.update(page_url=page_url, page_title=page_title, auth_state='unknown')
            self.requests.append(
                {
                    "context": context,
                    "observed_at": db.now(),
                    "url": safe_url(request.url),
                    "discovery_kind": "http_request",
                    "method": (
                        request.method.upper()
                    ),

                    "path": (
                        parsed.path
                        or "/"
                    ),

                    "content_type": None,

                    "source": (
                        "playwright_"
                        f"{self._phase}"
                    ),
                    "browser_supporting_request": (
                        self.target_policy is not None
                        and not self.target_policy.allows_url(
                            request.url, method=request.method
                        )
                    ),
                    "traffic_class": (
                        "browser_observation"
                        if self.target_policy is not None
                        and not self.target_policy.allows_url(request.url, method=request.method)
                        else "active"
                    ),
                }
            )

        def on_response(
            response,
        ):

            # auth_check_url을 설정한 경우에만
            # 특정 인증 검사 Endpoint의 실패를
            # 세션 만료 신호로 사용한다.

            check = (
                self.session_config
                .auth_check_url
            )

            if not check:
                return

            if not self._same_origin(
                response.url
            ):
                return

            check_url = urljoin(
                self.base_url + "/",
                check,
            )

            try:

                response_parsed = (
                    urlparse(
                        response.url
                    )
                )

                check_parsed = (
                    urlparse(
                        check_url
                    )
                )

                same_check_endpoint = (
                    response_parsed.path
                    ==
                    check_parsed.path
                )

            except ValueError:

                same_check_endpoint = False

            if (
                same_check_endpoint
                and response.status
                in
                self.session_config
                .invalid_auth_statuses
            ):

                self._auth_expired = True

        self.context.on(
            "request",
            on_request,
        )

        self.context.on(
            "response",
            on_response,
        )

        self.context.on(
            "page",
            self._register_page_handlers,
        )

    # =====================================================
    # WebSocket Observation
    # =====================================================

    def _register_page_handlers(
        self,
        page: Page,
    ) -> None:

        page_id = id(
            page
        )

        if (
            page_id
            in self._registered_pages
        ):
            return

        self._registered_pages.add(
            page_id
        )

        def on_websocket(
            ws,
        ):

            if not self._same_origin(
                ws.url
            ):
                return

            info = {
                "url": ws.url,

                "source": (
                    "playwright_"
                    f"{self._phase}"
                ),

                "sent": [],

                "received": [],
            }

            self.websockets.append(
                info
            )

            ws.on(
                "framesent",
                lambda payload:
                    info["sent"].append(
                        payload
                    ),
            )

            ws.on(
                "framereceived",
                lambda payload:
                    info["received"].append(
                        payload
                    ),
            )

        page.on(
            "websocket",
            on_websocket,
        )

    # =====================================================
    # Page
    # =====================================================

    def _ensure_page(
        self,
    ) -> Page:

        if (
            self.page is not None
        ):

            try:

                if not self.page.is_closed():
                    return self.page

            except Exception:
                pass

        if self.context is None:

            raise RuntimeError(
                "BrowserContext가 없습니다."
            )

        try:

            for page in self.context.pages:

                if not page.is_closed():

                    self.page = page

                    self._register_page_handlers(
                        page
                    )

                    return page

        except Exception:

            raise RuntimeError(
                "BrowserContext가 종료되었습니다."
            )

        self.page = (
            self.context.new_page()
        )

        self._register_page_handlers(
            self.page
        )

        return self.page

    # =====================================================
    # Manual Authentication
    # =====================================================

    def _observe_authentication_request(self, request) -> None:
        if self._phase != "login":
            return
        endpoint = AuthenticationEndpoint.from_request(
            request.method, request.url, target_origin=normalize_origin(self.base_url)
        )
        if endpoint is None:
            return
        key = (endpoint.method, endpoint.origin, endpoint.path)
        if not any(
            (item.method, item.origin, item.path) == key
            for item in self.authentication_endpoints
        ):
            self.authentication_endpoints.append(endpoint)
        if not any(
            item.get("method") == endpoint.method
            and item.get("path") == endpoint.path
            and item.get("source") == "auth_bootstrap"
            for item in self.requests
        ):
            from aidast.recon import db
            self.requests.append({
                "context": {
                    "context_key": "auth_bootstrap",
                    "action_type": "operator_login",
                    "association_method": "passive_request",
                    "auth_state": "authenticating",
                },
                "observed_at": db.now(),
                "url": endpoint.origin + endpoint.path,
                "discovery_kind": "passive_login_observation",
                "method": endpoint.method,
                "path": endpoint.path,
                "content_type": None,
                "source": "auth_bootstrap",
                "browser_supporting_request": True,
                "traffic_class": "browser_observation",
            })

    def _register_authentication_observer(self) -> None:
        if self.context is not None:
            self.context.on("request", self._observe_authentication_request)

    def capture_and_start(self) -> None:
        """Log in once and keep the same Chromium context for Recon."""
        if self.preauthenticated:
            raise RuntimeError("target session expired; log in again before restarting Recon")
        self._phase = "login"
        self.authentication_endpoints.clear()
        try:
            # Keep login direct. Attach CDP only for passive endpoint metadata;
            # routing and policy interception remain disabled until login ends.
            self._launch_manual_browser(manual_login=True)
            self._attach_manual_browser()
            self._register_authentication_observer()
            print("  [Playwright] 직접 연결 로그인 창을 열었습니다. 브라우저에서 로그인해주세요.")
            _wait_for_manual_login()
            if not self.save_session():
                raise RuntimeError("could not save the target session after manual login")
            if self.session_config.authentication_endpoint_callback is not None:
                self.session_config.authentication_endpoint_callback(
                    tuple(self.authentication_endpoints)
                )
            # Do not restart Chromium here. Shopify and other identity-aware
            # services can bind authorization to the live browser context.
            # Active policy enforcement is attached only after login; the login
            # flow contributes only secret-free passive endpoint coordinates.
            self._phase = "runtime"
            self._register_context_handlers()
            for page in self.context.pages:
                self._register_page_handlers(page)
        except BaseException:
            self._shutdown_runtime()
            self._phase = "runtime"
            raise

        self._auth_expired = False
        print("  [Playwright] 로그인한 동일 Chromium 컨텍스트에 정책을 적용했습니다; Recon을 시작합니다.")

    def start_from_session(self) -> None:
        """Restore the pre-Recon snapshot without launching another login flow."""
        if not self.session_path.is_file():
            raise RuntimeError("pre-Recon target session is missing")
        self._phase = "runtime"
        for attempt in range(2):
            try:
                self._launch_manual_browser()
                self._restore_target_session()
                page = self._ensure_page()
                response = page.goto(self.base_url, wait_until="domcontentloaded",
                                     timeout=self.session_config.timeout_ms)
                if self.target_policy is not None and not self.target_policy.allows_url(page.url):
                    raise RuntimeError("login did not return to the approved start URL boundary")
                if response is not None and response.status >= 400:
                    raise RuntimeError("approved start URL returned an error after login")
                if self._page_indicates_login_required(page) or not self.session_is_valid():
                    raise RuntimeError("target session validation failed after login")
                if not self.save_session():
                    raise RuntimeError("could not save the target session after return")
                break
            except RuntimeError as exc:
                self._shutdown_runtime()
                if attempt != 0:
                    raise
                print(f"  [Playwright] 복사된 세션 복원 실패: {exc}")
                print("  [Playwright] Phase 2 Chromium 창에서 직접 로그인한 뒤 Enter를 눌러주세요.")
                self._phase = "login"
                self.authentication_endpoints.clear()
                self._launch_manual_browser(manual_login=True)
                try:
                    self._attach_manual_browser()
                    self._register_authentication_observer()
                    _wait_for_manual_login()
                    if not self.save_session():
                        raise RuntimeError("could not save the Chromium login session")
                    if self.session_config.authentication_endpoint_callback is not None:
                        self.session_config.authentication_endpoint_callback(
                            tuple(self.authentication_endpoints)
                        )
                finally:
                    self._shutdown_runtime()
                    self._phase = "runtime"

        self._auth_expired = False
        print("  [Playwright] 프록시·Scope 적용 및 타깃 복귀 완료; Recon을 시작합니다.")

    @staticmethod
    def _page_indicates_login_required(page: Page) -> bool:
        """Detect Shopify's 200-status permission/login interstitials."""
        try:
            text = page.locator("body").inner_text(timeout=3000).lower()
        except Exception:
            return False
        markers = ("doesn't have permission to view this page",
                   "does not have permission to view this page",
                   "sign in to shopify", "log in to shopify")
        return any(marker in text for marker in markers)

    def _restore_target_session(self) -> None:
        """Restore only target cookies and storage into the proxied CDP context."""
        state = self._filter_storage_state(json.loads(self.session_path.read_text(encoding="utf-8")))
        self.context.add_cookies(state.get("cookies", []))
        origins = json.dumps(state.get("origins", []), ensure_ascii=False)
        indexed_db = json.dumps(state.get("origins", [])[0].get("indexedDB", []) if state.get("origins") else [], ensure_ascii=False)
        self.context.add_init_script(script=f"""
            (() => {{
                const saved = {origins};
                const current = saved.find(item => item.origin === location.origin);
                for (const item of current?.localStorage || []) {{
                    localStorage.setItem(item.name, item.value);
                }}
                // Restore Playwright's IndexedDB snapshot before the app boot
                // script runs.  This is intentionally best-effort: browsers
                // can reject a value that is no longer cloneable.
                const databases = {indexed_db};
                for (const db of databases) {{
                    try {{
                        const request = indexedDB.open(db.name, db.version);
                        request.onupgradeneeded = () => {{
                            const database = request.result;
                            for (const store of db.stores || []) {{
                                if (!database.objectStoreNames.contains(store.name)) {{
                                    database.createObjectStore(store.name);
                                }}
                            }}
                        }};
                        request.onsuccess = () => {{
                            const database = request.result;
                            try {{
                                const transaction = database.transaction((db.stores || []).map(s => s.name), 'readwrite');
                                for (const store of db.stores || []) {{
                                    const objectStore = transaction.objectStore(store.name);
                                    for (const entry of store.entries || []) objectStore.put(entry.value, entry.key);
                                }}
                            }} catch (_) {{}}
                        }};
                    }} catch (_) {{}}
                }}
            }})();
        """)
        self._restore_saved_session_storage()

    # =====================================================
    # Target Storage Filtering
    # =====================================================

    def _filter_storage_state(
        self,
        state: dict,
    ) -> dict:

        base = urlparse(
            self.base_url
        )

        base_host = (
            base.hostname
            or ""
        ).lower()

        base_origin = (
            self._base_origin()
        )

        target_cookies: list[
            dict
        ] = []

        for cookie in state.get(
            "cookies",
            [],
        ):

            domain = (
                cookie.get(
                    "domain",
                    "",
                )
                .lstrip(".")
                .lower()
            )

            if not domain:
                continue

            if (
                base_host == domain
                or base_host.endswith(
                    "." + domain
                )
            ):

                target_cookies.append(
                    cookie
                )

        target_origins = [
            item

            for item in state.get(
                "origins",
                [],
            )

            if (
                item.get(
                    "origin"
                )
                == base_origin
            )
        ]

        return {
            "cookies": (
                target_cookies
            ),

            "origins": target_origins,
        }

    # =====================================================
    # Save Session
    # =====================================================

    def save_session(
        self,
    ) -> bool:

        if self.context is None:
            return False

        try:

            try:
                raw_state = self.context.storage_state(indexed_db=True)
            except TypeError:
                raw_state = self.context.storage_state()

        except Exception:

            # TargetClosedError 포함
            return False

        state = (
            self._filter_storage_state(
                raw_state
            )
        )

        self.session_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.session_path.write_text(
            json.dumps(
                state,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        # ---------------------------------------------
        # sessionStorage
        # ---------------------------------------------

        base_origin = (
            self._base_origin()
        )

        session_storage: dict[
            str,
            dict[str, str],
        ] = {}

        try:

            pages = (
                self.context.pages
            )

        except Exception:

            pages = []

        for page in pages:

            try:

                if page.is_closed():
                    continue

                origin = (
                    page.evaluate(
                        "() => location.origin"
                    )
                )

                if origin != base_origin:
                    continue

                values = (
                    page.evaluate(
                        """
                        () => {
                            const result = {};

                            for (
                                let i = 0;
                                i < sessionStorage.length;
                                i++
                            ) {
                                const key =
                                    sessionStorage.key(i);

                                result[key] =
                                    sessionStorage.getItem(key);
                            }

                            return result;
                        }
                        """
                    )
                )

                if isinstance(
                    values,
                    dict,
                ):

                    session_storage[
                        origin
                    ] = values

            except Exception:

                continue

        self.session_storage_path.write_text(
            json.dumps(
                session_storage,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        print()
        print(
            "  [Playwright] "
            "세션 저장 완료"
        )

        print(
            f"  storage_state : "
            f"{self.session_path}"
        )

        print(
            f"  sessionStorage: "
            f"{self.session_storage_path}"
        )

        return True

    # =====================================================
    # Restore sessionStorage
    # =====================================================

    def _restore_saved_session_storage(
        self,
    ) -> None:

        if self.context is None:
            return

        if not (
            self.session_storage_path
            .exists()
        ):
            return

        try:

            data = json.loads(
                self.session_storage_path
                .read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
        ):

            return

        encoded = json.dumps(
            data,
            ensure_ascii=False,
        )

        script = f"""
        (() => {{
            const savedStorage = {encoded};

            const current =
                savedStorage[
                    window.location.origin
                ];

            if (!current) {{
                return;
            }}

            for (
                const [key, value]
                of Object.entries(current)
            ) {{
                sessionStorage.setItem(
                    key,
                    value
                );
            }}
        }})();
        """

        self.context.add_init_script(
            script=script
        )

    # =====================================================
    # Runtime State
    # =====================================================

    def runtime_is_alive(
        self,
    ) -> bool:

        if self.context is None:
            return False

        try:

            # 단순 pages Property가 아니라
            # 실제 Browser 호출을 수행해 검사
            self.context.storage_state()

            return True

        except Exception:

            return False

    # =====================================================
    # Restore Runtime
    # =====================================================

    def restore_runtime(
        self,
        *,
        force: bool = False,
    ) -> None:
        """Reopen the same persistent Chromium runtime from the saved session."""

        if (
            not force
            and self.runtime_is_alive()
        ):
            return

        if not self.session_path.exists():

            raise RuntimeError(
                "저장된 인증 세션 파일이 없습니다."
            )

        print()
        print(
            "  [Playwright] "
            "저장된 세션으로 Runtime 복구"
        )

        # Keep the browser kind, profile, and launch mode stable across phases.
        # Switching to a managed headless browser causes some sites to require
        # connection verification again even when cookies were restored.
        # A crawler's CDP hand-off can occasionally leave Chromium unable to
        # open its replacement debugging port on the first launch.  Retry once
        # after the normal runtime cleanup; _launch_manual_browser also removes
        # run-scoped profile singleton files before starting the replacement.
        for attempt in range(2):
            try:
                self._launch_manual_browser()
                self._restore_target_session()
                break
            except RuntimeError as exc:
                self._shutdown_runtime()
                if attempt != 0:
                    raise
                print(f"  [Playwright] Runtime 복구 1차 실패, 정리 후 재시도: {exc}")
        self._auth_expired = False

    # =====================================================
    # CDP URL
    # =====================================================

    def get_chrome_ws_url(
        self,
    ) -> str | None:

        if self._chrome_process is None:
            return None

        try:

            if (
                self._chrome_process.poll()
                is not None
            ):

                return None

        except Exception:

            return None

        return (
            self._chrome_ws_url
        )

    # =====================================================
    # State Loading
    # =====================================================

    def _load_auth_state(
        self,
    ) -> dict:

        # -------------------------------------------------
        # Context가 살아 있으면 최신 State 사용
        # -------------------------------------------------

        if self.context is not None:

            try:

                raw_state = (
                    self.context
                    .storage_state()
                )

                state = (
                    self._filter_storage_state(
                        raw_state
                    )
                )

                self.session_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                self.session_path.write_text(
                    json.dumps(
                        state,
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )

                return state

            except Exception:

                # Context가 이미 닫혔으면
                # 저장 파일 Fallback
                pass

        # -------------------------------------------------
        # TargetClosed → File Fallback
        # -------------------------------------------------

        if not self.session_path.exists():

            return {
                "cookies": [],
                "origins": [],
            }

        try:

            return json.loads(
                self.session_path
                .read_text(
                    encoding="utf-8"
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
        ):

            return {
                "cookies": [],
                "origins": [],
            }

    # =====================================================
    # JWT
    # =====================================================

    @staticmethod
    def _looks_like_jwt(
        value: str,
    ) -> bool:

        if not isinstance(
            value,
            str,
        ):
            return False

        # JSON 문자열 형태
        try:

            if (
                value.startswith('"')
                and value.endswith('"')
            ):

                decoded = json.loads(
                    value
                )

                if isinstance(
                    decoded,
                    str,
                ):

                    value = decoded

        except Exception:
            pass

        parts = (
            value.split(".")
        )

        if len(parts) != 3:
            return False

        return all(
            len(part) > 0
            for part in parts
        )

    @staticmethod
    def _clean_token_value(
        value: str,
    ) -> str:

        try:

            decoded = json.loads(
                value
            )

            if isinstance(
                decoded,
                str,
            ):

                return decoded

        except Exception:
            pass

        return value

    # =====================================================
    # Storage Values
    # =====================================================

    def _collect_storage_values(
        self,
        state: dict,
    ) -> dict[str, str]:

        values: dict[
            str,
            str,
        ] = {}

        base_origin = (
            self._base_origin()
        )

        # ---------------------------------------------
        # localStorage
        # ---------------------------------------------

        for origin_info in state.get(
            "origins",
            [],
        ):

            if (
                origin_info.get(
                    "origin"
                )
                != base_origin
            ):

                continue

            for item in origin_info.get(
                "localStorage",
                [],
            ):

                name = (
                    item.get(
                        "name"
                    )
                )

                value = (
                    item.get(
                        "value"
                    )
                )

                if (
                    name
                    and value is not None
                ):

                    values[
                        name
                    ] = str(
                        value
                    )

        # ---------------------------------------------
        # sessionStorage
        # ---------------------------------------------

        if (
            self.session_storage_path
            .exists()
        ):

            try:

                session_data = json.loads(
                    self.session_storage_path
                    .read_text(
                        encoding="utf-8"
                    )
                )

                origin_values = (
                    session_data.get(
                        base_origin,
                        {},
                    )
                )

                if isinstance(
                    origin_values,
                    dict,
                ):

                    for (
                        name,
                        value,
                    ) in (
                        origin_values.items()
                    ):

                        if (
                            name
                            and value is not None
                        ):

                            values[
                                name
                            ] = str(
                                value
                            )

            except Exception:
                pass

        return values

    # =====================================================
    # Auth Headers
    # =====================================================

    def get_auth_headers(
        self,
    ) -> dict[str, str]:
        """
        중요:
        더 이상 context.cookies()에 직접 의존하지 않는다.

        Context가 살아있으면 storage_state() 사용.
        Context가 죽었으면 저장된 session.json 사용.

        따라서 Katana Headless가 CDP Context를
        종료해도 TargetClosedError가 발생하지 않는다.
        """

        headers: dict[
            str,
            str,
        ] = {}

        state = (
            self._load_auth_state()
        )

        # ---------------------------------------------
        # Cookie
        # ---------------------------------------------

        base = urlparse(
            self.base_url
        )

        base_host = (
            base.hostname
            or ""
        ).lower()

        cookie_values: list[
            str
        ] = []

        for cookie in state.get(
            "cookies",
            [],
        ):

            name = (
                cookie.get(
                    "name"
                )
            )

            value = (
                cookie.get(
                    "value"
                )
            )

            domain = (
                cookie.get(
                    "domain",
                    "",
                )
                .lstrip(".")
                .lower()
            )

            if (
                not name
                or value is None
            ):
                continue

            if (
                domain
                and base_host
                and not (
                    base_host == domain

                    or
                    base_host.endswith(
                        "." + domain
                    )
                )
            ):

                continue

            cookie_values.append(
                f"{name}={value}"
            )

        if cookie_values:

            headers[
                "Cookie"
            ] = (
                "; ".join(
                    cookie_values
                )
            )

        # ---------------------------------------------
        # Storage
        # ---------------------------------------------

        storage = (
            self._collect_storage_values(
                state
            )
        )

        # ---------------------------------------------
        # Explicit Mapping
        # ---------------------------------------------

        for (
            storage_key,
            mapping,
        ) in (
            self.session_config
            .storage_header_map
            .items()
        ):

            value = (
                storage.get(
                    storage_key
                )
            )

            if not value:
                continue

            value = (
                self._clean_token_value(
                    value
                )
            )

            (
                header_name,
                prefix,
            ) = mapping

            headers[
                header_name
            ] = (
                f"{prefix}{value}"
            )

        # ---------------------------------------------
        # JWT 자동 탐지
        # ---------------------------------------------

        if (
            "Authorization"
            not in headers
        ):

            candidates: list[
                str
            ] = []

            for (
                key,
                value,
            ) in storage.items():

                lowered = (
                    key.lower()
                )

                if not any(
                    name in lowered

                    for name in (
                        "token",
                        "jwt",
                        "auth",
                    )
                ):

                    continue

                cleaned = (
                    self._clean_token_value(
                        value
                    )
                )

                if self._looks_like_jwt(
                    cleaned
                ):

                    if (
                        cleaned
                        not in candidates
                    ):

                        candidates.append(
                            cleaned
                        )

            # 여러 개면 잘못된 Token 선택 위험
            if len(candidates) == 1:

                headers[
                    "Authorization"
                ] = (
                    "Bearer "
                    + candidates[0]
                )

        return headers

    # =====================================================
    # Session Validation
    # =====================================================

    def session_is_valid(
        self,
    ) -> bool:

        if self.context is None:
            return False

        check = (
            self.session_config
            .auth_check_url
        )

        # 범용 사이트에서 검사 URL을 모르면
        # 임의의 401 하나만으로
        # 세션 만료라고 판단하지 않는다.
        if not check:
            return True

        check_url = urljoin(
            self.base_url + "/",
            check,
        )

        try:

            if self.target_policy is not None:
                # APIRequestContext does not pass through browser route handlers.
                status, _, _ = _http_request(
                    check_url, headers=self.get_auth_headers(),
                    timeout=self.session_config.timeout_ms / 1000,
                    target_policy=self.target_policy, proxy_url=self.proxy_url,
                )
                valid = status is not None and status not in self.session_config.invalid_auth_statuses
                self._auth_expired = not valid
                return valid

            response = (
                self.context
                .request
                .get(
                    check_url,

                    headers=(
                        self.get_auth_headers()
                    ),

                    timeout=(
                        self.session_config
                        .timeout_ms
                    ),
                    max_redirects=0,
                )
            )

            valid = (
                response.status
                not in
                self.session_config
                .invalid_auth_statuses
            )

            self._auth_expired = (
                not valid
            )

            return valid

        except Exception:

            return False

    # =====================================================
    # Session Ensure / Re-login
    # =====================================================

    def ensure_session(
        self,
    ) -> None:

        # Context가 Katana 등에 의해 죽었으면
        # 먼저 저장된 세션으로 복구
        self.restore_runtime()

        if self.session_is_valid():

            return

        print()
        print(
            "  [Playwright] "
            "인증 세션 만료가 감지되었습니다."
        )
        print(
            "  브라우저에서 다시 로그인해주세요."
        )

        # 실제 Visible Browser를 다시 띄움
        self.capture_and_start()

    # =====================================================
    # Visit
    # =====================================================

    def visit_path(
        self,
        path: str,
    ) -> bool:

        page = (
            self._ensure_page()
        )

        url = urljoin(self.base_url.rstrip("/") + "/", path)

        try:

            response = (
                page.goto(
                    url,

                    wait_until=(
                        "domcontentloaded"
                    ),

                    timeout=(
                        self.session_config
                        .timeout_ms
                    ),
                )
            )

        except Exception:

            return False

        if response is None:
            return False

        # 해당 Endpoint가 401이라고 해서
        # 전체 세션 만료라고 판단하지 않음.
        if (
            response.status
            in
            self.session_config
            .invalid_auth_statuses
        ):

            return False

        content_type = (
            response.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        return (
            "text/html"
            in content_type
        )

    # =====================================================
    # Dangerous Path
    # =====================================================

    def _path_looks_dangerous(
        self,
        path: str,
    ) -> bool:

        lowered = (
            path.lower()
        )

        return any(
            word.replace(
                " ",
                "",
            )
            in lowered.replace(
                "-",
                "",
            ).replace(
                "_",
                "",
            ).replace(
                "/",
                "",
            )

            for word in (
                "delete",
                "remove",
                "logout",
                "checkout",
                "purchase",
                "payment",
                "transfer",
                "unsubscribe",
                "resetpassword",
                "deleteaccount",
            )
        )

    # =====================================================
    # Safe UI Actions
    # =====================================================

    def trigger_safe_actions(
        self,
    ) -> int:

        page = (
            self._ensure_page()
        )

        config = (
            self.interaction_config
        )

        # 일반 a[href]는 Katana에게 맡긴다.
        #
        # Playwright는 메뉴/탭/Accordion 등
        # Interaction이 필요한 요소 중심.
        candidates = (
            page.locator(
                '[role="tab"], '
                'button[aria-controls], '
                'button[aria-expanded], '
                'button[aria-haspopup], '
                '[role="button"][aria-controls], '
                '[role="button"][aria-expanded], '
                '[role="button"][aria-haspopup], '
                'summary, '
                'nav button'
            )
        )

        try:

            count = (
                candidates.count()
            )

        except Exception:

            return 0

        actions = 0

        for index in range(
            count
        ):

            if (
                actions
                >=
                config.max_actions_per_page
            ):

                break

            try:

                element = (
                    candidates.nth(
                        index
                    )
                )

                if not element.is_visible():
                    continue

                text = (
                    element.inner_text()
                    or ""
                ).strip().lower()

                aria_label = (
                    element.get_attribute(
                        "aria-label"
                    )
                    or ""
                ).lower()

                title = (
                    element.get_attribute(
                        "title"
                    )
                    or ""
                ).lower()

                element_id = (
                    element.get_attribute(
                        "id"
                    )
                    or ""
                ).lower()

                name = (
                    element.get_attribute(
                        "name"
                    )
                    or ""
                ).lower()

                description = (
                    " ".join(
                        (
                            text,
                            aria_label,
                            title,
                            element_id,
                            name,
                        )
                    )
                )

                # -------------------------------------
                # 위험 Action 제외
                # -------------------------------------

                if any(
                    blocked
                    in description

                    for blocked in (
                        config.blocked_words
                    )
                ):

                    continue

                # -------------------------------------
                # Form Submit 제외
                # -------------------------------------

                tag = (
                    element.evaluate(
                        """
                        el =>
                            el.tagName.toLowerCase()
                        """
                    )
                )

                if tag == "button":

                    button_type = (
                        element.get_attribute(
                            "type"
                        )
                        or ""
                    ).lower()

                    inside_form = (
                        element.evaluate(
                            """
                            el =>
                                !!el.closest('form')
                            """
                        )
                    )

                    if inside_form and (
                        button_type != "button"
                        or not config.allow_form_submission
                    ):

                        continue

                # -------------------------------------
                # Click
                # -------------------------------------

                self._context_serial += 1
                self._action_context = {
                    'context_key': f'action:{self._context_serial}',
                    'action_type': 'click',
                    'action_target': description[:300],
                    'association_method': 'action_time_window',
                }
                try:
                    element.click(timeout=1500)
                    page.wait_for_timeout(config.action_wait_ms)
                finally:
                    self._action_context = None

                actions += 1

                if (
                    self._auth_expired
                    and
                    self.session_config
                    .auth_check_url
                ):

                    self.ensure_session()

                    page = (
                        self._ensure_page()
                    )

            except Exception:

                continue

        return actions

    # =====================================================
    # Interaction Pass
    # =====================================================

    def run_interaction_pass(
        self,
        endpoints: list[dict],
    ) -> None:

        if not (
            self.interaction_config
            .enabled
        ):
            return

        self.ensure_session()

        self._phase = (
            "interaction"
        )

        visited = self._interaction_visited
        pages = self._interaction_page_count
        pages_at_start = pages

        actions = 0

        page = (
            self._ensure_page()
        )

        # ---------------------------------------------
        # SPA Root
        # ---------------------------------------------

        try:
            # Keep the exact page reached during Phase 1 login (Shopify Admin
            # commonly lands on /products?country=...).  Navigating back to
            # the canonical store root can trigger a permission interstitial
            # even though the live authenticated context is valid.
            current_url = page.url
            parsed_current = urlparse(current_url)
            current_is_approved = (
                parsed_current.scheme in {"http", "https"}
                and self._same_origin(current_url)
                and (self.target_policy is None or self.target_policy.allows_url(current_url))
            )
            if not current_is_approved:
                page.goto(
                    self.base_url,
                    wait_until="domcontentloaded",
                    timeout=self.session_config.timeout_ms,
                )

            current_url = page.url
            current_path = urlparse(current_url).path or "/"
            if current_path not in visited and pages < self.interaction_config.max_pages:
                page.wait_for_timeout(500)
                actions += self.trigger_safe_actions()
                pages += 1
                visited.add(current_path)

        except Exception:
            pass

        # ---------------------------------------------
        # Discovered Pages
        # ---------------------------------------------

        for endpoint in endpoints:

            if (
                pages
                >=
                self.interaction_config
                .max_pages
            ):

                break

            method = (
                endpoint.get(
                    "method",
                    "GET",
                )
                .upper()
            )

            if method != "GET":
                continue

            path = (
                endpoint.get(
                    "path"
                )
            )

            if not path:
                continue

            if path in visited:
                continue

            if self._path_looks_dangerous(
                path
            ):

                continue

            visited.add(
                path
            )

            if not self.visit_path(
                path
            ):

                continue

            pages += 1

            try:

                self._ensure_page() \
                    .wait_for_timeout(
                        300
                    )

            except Exception:
                pass

            actions += (
                self.trigger_safe_actions()
            )

        print()
        print(
            f"  [Playwright] "
            f"HTML 방문 : {pages - pages_at_start}개 "
            f"(전체 {pages}/{self.interaction_config.max_pages})"
        )

        print(
            f"  [Playwright] "
            f"UI Action : {actions}개"
        )

        print(
            f"  [Playwright] "
            f"WebSocket : "
            f"{len(self.websockets)}개"
        )

        self._interaction_page_count = pages

    # =====================================================
    # HTTP Results
    # =====================================================

    def drain_observations(self) -> list[dict]:
        """Unmerged requests since the last phase boundary."""
        items = self.requests[self._observation_cursor:]
        self._observation_cursor = len(self.requests)
        return [dict(item) for item in items]

    def get_http_results(
        self,
    ) -> list[dict]:

        unique: dict[
            tuple[str, str],
            dict,
        ] = {}

        for result in self.requests:

            method = (
                result.get(
                    "method",
                    "GET",
                )
                .upper()
            )

            path = (
                result.get(
                    "path"
                )
            )

            if not path:
                continue

            key = (
                method,
                path,
            )

            source = (
                result.get(
                    "source"
                )
            )

            if key not in unique:

                item = dict(
                    result
                )

                item["method"] = method

                item["sources"] = []

                if source:

                    item["sources"].append(
                        source
                    )

                unique[key] = (
                    item
                )

                continue

            if (
                source
                and source
                not in
                unique[key]
                .setdefault(
                    "sources",
                    [],
                )
            ):

                unique[key][
                    "sources"
                ].append(
                    source
                )

        return list(
            unique.values()
        )

    # =====================================================
    # WebSocket Results
    # =====================================================

    def get_websocket_results(
        self,
    ) -> list[dict]:

        return [
            dict(item)
            for item in self.websockets
        ]

    # =====================================================
    # Close
    # =====================================================

    def close(
        self,
    ) -> None:

        # 가능한 경우 최신 Session 저장
        try:

            self.save_session()

        except Exception:
            pass

        self._shutdown_runtime()

        if self.playwright is not None:

            try:

                self.playwright.stop()

            except Exception:
                pass

        self.playwright = None
