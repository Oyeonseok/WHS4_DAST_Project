"""Playwright 자동 크롤러 — visible 브라우저에서 로그인 후 링크를 따라가며
페이지를 탐색한다. 모든 트래픽은 mitmproxy를 거쳐서 관찰된다.

PoC 한계: JuiceShop(Angular SPA) 전용 동작 가정. 다른 타겟에 쓰려면
URL 정규화와 SPA 라우팅 처리를 일반화해야 한다.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.sync_api import BrowserContext, Page

from aidast.recon.tools.login import SessionCredentials, wait_for_manual_login

# 정적 자산 확장자 - 링크를 따라가봤자 새 엔드포인트가 아니므로 크롤 대상에서 뺀다.
STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".woff", ".woff2", ".ttf", ".ico", ".map",
)

# 401 감지 시 auth 관련으로 취급할 API 경로 접두사.
API_PATH_PREFIXES = ("/api/", "/rest/")

# flow_log를 매번 읽으면 느리니, 이만큼 새 URL을 방문할 때마다 한 번씩 확인한다.
FLOW_CHECK_INTERVAL = 5


def normalize_crawl_url(href: str, base_url: str) -> str | None:
    """discover_links()가 찾아낸 raw href를 크롤 대상 URL로 정규화한다.

    - base_url 기준 상대경로를 절대 URL로 변환
    - SPA 라우팅에 쓰이는 해시 프래그먼트(`/#/search`)는 보존한다
    - base_url과 다른 origin(scheme+host+port)은 거부한다
    - http/https가 아닌 스킴(mailto:, javascript: 등)은 거부한다
    - 정적 자산 확장자는 거부한다
    """
    href = (href or "").strip()
    if not href:
        return None

    # javascript:, mailto:, tel: 등은 urljoin을 태우기 전에 걸러낸다.
    lowered = href.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None

    absolute = urljoin(base_url, href)
    parsed = urlparse(absolute)

    if parsed.scheme not in ("http", "https"):
        return None

    base_parsed = urlparse(base_url)
    if parsed.netloc.lower() != base_parsed.netloc.lower():
        return None

    # 확장자 검사는 쿼리/프래그먼트를 뗀 path 기준으로.
    path_only = parsed.path.lower()
    if path_only.endswith(STATIC_EXTENSIONS):
        return None

    return absolute


def discover_links(page: Page) -> set[str]:
    """현재 페이지에서 발견 가능한 모든 링크 후보를 raw href 문자열로 반환.

    일반 `<a href>`뿐 아니라 Angular `routerLink` 속성을 쓰는 SPA
    네비게이션 요소도 함께 훑는다 - JuiceShop 같은 Angular 앱은 실제
    `<a href>`가 없는 클릭 가능 요소가 많다.
    """
    try:
        hrefs: list[str] = page.evaluate(
            """
            () => {
                const found = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href) found.add(href);
                });
                document.querySelectorAll('[routerLink]').forEach(el => {
                    const routerLink = el.getAttribute('routerLink');
                    if (routerLink) found.add('#/' + routerLink.replace(/^\\//, ''));
                    const href = el.getAttribute('href');
                    if (href) found.add(href);
                });
                return Array.from(found);
            }
            """
        )
    except Exception:  # noqa: BLE001 - 페이지가 언로드 중이거나 죽었을 수 있음
        return set()

    return set(hrefs or [])


def check_for_401(flow_log: Path, last_line: int) -> tuple[bool, int]:
    """flow_log JSONL에서 last_line 이후의 새 줄만 읽어 401(API) 존재 여부를 확인.

    반환값의 두 번째 요소는 다음 호출에 넘길 새 last_line(총 읽은 줄 수)이다.
    """
    if not flow_log.exists():
        return False, last_line

    lines = flow_log.read_text(encoding="utf-8").splitlines()
    new_lines = lines[last_line:]
    found_401 = False

    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            flow = json.loads(line)
        except json.JSONDecodeError:
            continue

        status = flow.get("status_code")
        path = flow.get("path", "")
        if status == 401 and path.startswith(API_PATH_PREFIXES):
            found_401 = True

    return found_401, len(lines)


def crawl(
    context: BrowserContext,
    base_url: str,
    *,
    visited: set[str] | None = None,
    flow_log: Path | None = None,
) -> set[str]:
    """context의 첫 페이지를 재사용해 base_url부터 링크를 따라가며 탐색한다.

    401이 감지되면(flow_log 제공 시) 즉시 방문 목록을 그대로 반환하고
    멈춘다 - 재로그인 처리는 호출자(run_crawl_session)의 몫이다.
    """
    visited = visited if visited is not None else set()

    pages = context.pages
    page = pages[0] if pages else context.new_page()

    frontier: deque[str] = deque()
    if not visited:
        frontier.append(base_url)
    else:
        # 재개(resume) 시에는 이미 방문한 URL들에서 다시 링크를 뽑아 프론티어를
        # 채우기보다, base_url부터 다시 훑는 편이 단순하고 누락이 적다.
        frontier.append(base_url)

    # flow_log에 이미 쌓여 있던(재로그인 이전) 401은 새 크롤 구간에서
    # 재감지하면 안 되므로, 시작 시점의 줄 수를 체크포인트로 삼는다.
    if flow_log is not None:
        flow_log_last_line = len(
            flow_log.read_text(encoding="utf-8").splitlines()
        ) if flow_log.exists() else 0
    else:
        flow_log_last_line = 0
    urls_since_check = 0

    while frontier:
        url = frontier.popleft()
        if url in visited:
            continue

        try:
            page.goto(url, wait_until="networkidle", timeout=15000)
        except Exception as exc:  # noqa: BLE001 - 개별 페이지 실패는 크롤 전체를 막지 않는다
            print(f"  [스킵] 네비게이션 실패({url}): {exc}")
            visited.add(url)
            continue

        try:
            current_url = page.evaluate("() => location.href")
        except Exception:  # noqa: BLE001
            current_url = url

        visited.add(url)
        if current_url != url:
            visited.add(current_url)

        print(f"  [{len(visited)}] {current_url}")

        for href in discover_links(page):
            normalized = normalize_crawl_url(href, base_url)
            if normalized and normalized not in visited:
                frontier.append(normalized)

        urls_since_check += 1
        if flow_log is not None and urls_since_check >= FLOW_CHECK_INTERVAL:
            urls_since_check = 0
            found_401, flow_log_last_line = check_for_401(flow_log, flow_log_last_line)
            if found_401:
                print("  [경고] 401 감지 - 크롤 일시 중단")
                return visited

    # 루프가 정상 종료되기 직전에도 마지막 남은 flow를 한 번 더 확인해준다.
    if flow_log is not None:
        found_401, _ = check_for_401(flow_log, flow_log_last_line)
        if found_401:
            print("  [경고] 401 감지 - 크롤 일시 중단")

    return visited


def run_crawl_session(
    base_url: str,
    *,
    proxy: str,
    login_path: str = "/login",
    flow_log: Path,
) -> SessionCredentials:
    """수동 로그인 -> 크롤 -> (401 시) 재로그인 -> 크롤 재개 흐름을 오케스트레이션한다.

    캡처한 세션 정보(SessionCredentials)를 반환한다 — 호출자가 DB에 저장할 수 있도록."""
    session, context = wait_for_manual_login(base_url, login_path=login_path, proxy=proxy)

    print(f"\n  크롤 세션 시작: {base_url}")
    print(f"  프록시: {proxy}")
    if session.is_empty():
        print("  [경고] 세션이 비어 있음 - 인증 없이 크롤을 진행합니다")

    # crawl()이 401 때문에 조기 반환했는지 판단하기 위한 세션 단위 체크포인트.
    # crawl()은 매 호출 시작 시점을 자기 기준선으로 삼으므로, 여기서는 그
    # 시작 시점의 줄 수를 기억해뒀다가 종료 후 그 이후 구간만 다시 훑는다.
    session_checkpoint = len(flow_log.read_text(encoding="utf-8").splitlines()) if flow_log.exists() else 0
    visited = crawl(context, base_url, flow_log=flow_log)

    hit_401, session_checkpoint = check_for_401(flow_log, session_checkpoint)
    while hit_401:
        print("  401 감지 — 세션 만료. 재로그인이 필요합니다.")

        pages = context.pages
        if pages:
            pages[0].close()
        page = context.new_page()

        login_url = base_url.rstrip("/") + login_path
        page.goto(login_url, wait_until="domcontentloaded")
        input("  재로그인 후 Enter를 눌러주세요... ")

        # 재로그인 후 세션(쿠키+localStorage)을 다시 캡처한다. context 자체가
        # 새 쿠키/토큰을 이미 들고 있으므로, 여기서는 감사 목적으로만 읽어둔다.
        try:
            page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
        except Exception:  # noqa: BLE001
            pass

        session_checkpoint = len(flow_log.read_text(encoding="utf-8").splitlines()) if flow_log.exists() else 0
        visited = crawl(context, base_url, visited=visited, flow_log=flow_log)
        hit_401, session_checkpoint = check_for_401(flow_log, session_checkpoint)

    browser = context.browser
    if browser is not None:
        browser.close()

    print(f"\n  크롤 완료 - 총 {len(visited)}개 URL 방문")
    return session
