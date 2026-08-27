"""LOGIN / SESSION CAPTURE - this is Playwright's only job in the pipeline.

팀 설계대로 Playwright는 엔드포인트를 탐색하지 않는다(그건 katana의 일).
Playwright는 실제 로그인 폼에 자격증명을 입력해서 로그인 세션을 한 번
확보하고, 그 세션(쿠키 + localStorage에 있는 토큰)을 katana/ffuf에
"-H" 커스텀 헤더로 넘겨서 인증된 상태로 크롤링하게 만든다.

Juice Shop은 세션을 쿠키가 아니라 로그인 후 localStorage에 저장하는
JWT로 관리한다(Angular 인터셉터가 Authorization: Bearer 헤더로 붙임).
그래서 쿠키만 복사해서는 인증이 안 되고, localStorage까지 같이 읽어야
한다 - 이게 이 모듈이 쿠키와 localStorage를 둘 다 캡처하는 이유다.

MVP 한계: 로그인 폼 셀렉터(EMAIL_SELECTOR 등)는 Juice Shop 전용으로
하드코딩돼 있다. 다른 타겟에 쓰려면 이 부분을 설정/SKILL.md로 빼내야
한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from playwright.sync_api import sync_playwright

EMAIL_SELECTOR = "#email"
PASSWORD_SELECTOR = "#password"
SUBMIT_SELECTOR = "#loginButton"


@dataclass
class SessionCredentials:
    cookie_header: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    raw_local_storage: dict[str, str] = field(default_factory=dict)

    def as_header_args(self) -> list[str]:
        """katana/ffuf 커맨드에 그대로 붙일 수 있는 -H 인자 목록으로 변환."""
        args: list[str] = []
        if self.cookie_header:
            args += ["-H", f"Cookie: {self.cookie_header}"]
        for key, value in self.extra_headers.items():
            args += ["-H", f"{key}: {value}"]
        return args

    def is_empty(self) -> bool:
        return not self.cookie_header and not self.extra_headers


def _looks_like_jwt(value: str) -> bool:
    return isinstance(value, str) and value.count(".") == 2 and len(value) > 20


def login_and_capture_session(
    base_url: str,
    *,
    email: str,
    password: str,
    login_path: str = "/login",
    timeout_ms: int = 10000,
    proxy: str | None = None,
) -> SessionCredentials:
    """로그인 폼에 자격증명을 입력하고, 로그인 이후 세션(쿠키+localStorage)을
    캡처해서 돌려준다. 실패해도 예외를 던지지 않고 빈 SessionCredentials를
    반환한다 - 로그인이 안 돼도 비로그인 크롤링은 계속 진행되게 하려는
    의도다(MVP는 "완전 실패보다 부분 결과"를 우선한다).

    proxy: "http://127.0.0.1:8080" 같은 mitmproxy 주소. 넘기면 이 로그인
    세션이 그 프록시를 거쳐 나가서 mitm_addon.py가 트래픽을 관찰할 수 있게
    된다. None이면 지금까지처럼 프록시 없이 바로 나간다.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(proxy={"server": proxy} if proxy else None)
        page = context.new_page()

        login_url = base_url.rstrip("/") + login_path
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.fill(EMAIL_SELECTOR, email, timeout=timeout_ms)
            page.fill(PASSWORD_SELECTOR, password, timeout=timeout_ms)
            page.click(SUBMIT_SELECTOR, timeout=timeout_ms)
            page.wait_for_timeout(2000)  # SPA 라우팅 + 토큰 저장 시간 확보
        except Exception as exc:  # noqa: BLE001 - 로그인 실패는 치명적 에러 아님
            print(f"  [경고] 로그인 실패({login_url}): {exc}")
            browser.close()
            return SessionCredentials()

        cookies = context.cookies()
        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies) or None

        try:
            local_storage: dict[str, str] = page.evaluate(
                "() => Object.fromEntries(Object.entries(localStorage))"
            )
        except Exception:
            local_storage = {}

        extra_headers: dict[str, str] = {}
        for value in local_storage.values():
            if _looks_like_jwt(value):
                extra_headers["Authorization"] = f"Bearer {value}"
                break

        browser.close()

    session = SessionCredentials(
        cookie_header=cookie_header, extra_headers=extra_headers, raw_local_storage=local_storage,
    )
    if session.is_empty():
        print("  [경고] 로그인은 됐지만 쿠키/토큰을 못 찾음 - 셀렉터가 이 타겟과 안 맞을 수 있음")
    else:
        print(f"  로그인 세션 확보 (쿠키 {len(cookies)}개, 헤더 {len(extra_headers)}개)")
    return session
