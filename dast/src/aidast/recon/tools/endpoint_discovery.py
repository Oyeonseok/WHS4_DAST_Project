"""ENDPOINT_DISCOVERY - katana is the primary crawler (both standard and
headless modes run, so we get an empirical, not guessed, comparison of what
JS-rendering adds), ffuf always runs on top of that regardless of katana
coverage. Both are skipped with a warning if the binary/wordlist isn't
available, so this never blocks an MVP run.

`discover_with_playwright` below is kept but NOT called from
`discover_endpoints` anymore - per the team's design, Playwright's only job
is login/session capture (see tools/login.py), not page discovery. It's
left here for reference only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

API_PREFIXES = ("/api", "/rest", "/graphql")


def _normalize_route(href: str | None, base: str) -> str | None:
    if not href:
        return None
    href = href.strip()
    if href.startswith("#"):
        return None
    full = urljoin(base + "/", href)
    parsed = urlparse(full)
    if parsed.scheme not in ("http", "https"):
        return None
    # urlparse는 scheme만 자동으로 소문자화하고 host는 원본 대소문자를
    # 그대로 보존한다. 호스트명은 대소문자를 구분하지 않으므로(DNS 스펙),
    # 대소문자 그대로 비교하면 "Localhost:3000" 같은 링크를 다른 origin으로
    # 오판해서 같은 사이트 페이지를 조용히 빠뜨리게 된다. path는 대소문자를
    # 구분하는 게 맞으므로 netloc만 소문자로 맞춰서 비교한다.
    if parsed.netloc.lower() != urlparse(base).netloc.lower():
        return None
    return full


def discover_with_playwright(
    base_url: str, *, max_pages: int = 30, timeout_ms: int = 8000
) -> list[dict]:
    """Follows links and captures API-looking requests generated along the way."""
    found: dict[tuple[str, str], dict] = {}
    visited: set[str] = set()
    queue: deque[str] = deque([base_url if base_url.endswith("/") else base_url + "/"])

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        def on_request(request):
            parsed = urlparse(request.url)
            if parsed.netloc.lower() != urlparse(base_url).netloc.lower():
                return
            last_segment = parsed.path.rsplit("/", 1)[-1]
            looks_like_api = any(parsed.path.startswith(p) for p in API_PREFIXES)
            looks_like_page_asset = "." in last_segment
            if looks_like_api or not looks_like_page_asset:
                key = (request.method, parsed.path)
                found.setdefault(
                    key,
                    {
                        "method": request.method,
                        "path": parsed.path,
                        "content_type": None,
                        "source": "playwright",
                    },
                )

        page.on("request", on_request)

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception:
                continue
            page.wait_for_timeout(1000)
            try:
                hrefs = page.eval_on_selector_all(
                    "a", "els => els.map(e => e.getAttribute('href')).filter(Boolean)"
                )
            except Exception:
                hrefs = []
            for href in hrefs:
                norm = _normalize_route(href, base_url)
                if norm and norm not in visited:
                    queue.append(norm)

        browser.close()

    return list(found.values())


def discover_with_katana(
    base_url: str, *, mode: str = "katana_standard", header_args: list[str] | None = None
) -> list[dict]:
    if shutil.which("katana") is None:
        print("  [건너뜀] katana가 설치돼 있지 않음")
        return []
    command = ["katana", "-u", base_url, "-silent", "-jc"]
    source_tag = "katana_standard"
    if mode == "katana_headless":
        command.append("-hl")
        source_tag = "katana_headless"
    # 로그인 세션(쿠키/Authorization)이 있으면 -H로 붙여서 인증된 상태로
    # 크롤링한다. 없으면 그냥 비로그인 크롤링.
    command += header_args or []
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"  [경고] katana({mode}) 실행 실패: {exc}")
        return []
    results = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = urlparse(line)
        results.append(
            {"method": "GET", "path": parsed.path or "/", "content_type": None, "source": source_tag}
        )

    # subprocess.run은 종료코드가 0이 아니어도 예외를 던지지 않는다. 그동안은
    # stdout이 비면 그냥 "0건"으로만 찍혀서 원인(브라우저 미설치, 크래시 등)을
    # 알 방법이 없었다. 결과가 0건일 때는 종료코드/stderr를 같이 보여준다.
    if not results and (completed.returncode != 0 or completed.stderr.strip()):
        print(f"  [경고] katana({mode}) 종료코드 {completed.returncode}, 결과 0건")
        if completed.stderr.strip():
            print(f"  [katana stderr] {completed.stderr.strip()[:500]}")
    else:
        print(f"  katana({mode}) 발견 {len(results)}건")
    return results


def discover_with_ffuf(
    base_url: str, *, wordlist: str | None = None, header_args: list[str] | None = None
) -> list[dict]:
    if shutil.which("ffuf") is None:
        print("  [건너뜀] ffuf가 설치돼 있지 않음")
        return []
    if wordlist is None:
        print("  [건너뜀] ffuf 워드리스트가 지정되지 않음")
        return []

    # -o -(표준출력)로 JSON을 받으면 배너/진행로그가 섞여 파싱이 깨질 수 있어서
    # 임시 파일로 결과를 받는다. 파싱 실패 시에도 원인을 출력해 조용히 0건으로
    # 빠지지 않도록 한다.
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_path = Path(tmp.name)
    tmp.close()
    command = [
        "ffuf", "-u", f"{base_url}/FUZZ", "-w", wordlist,
        "-of", "json", "-o", str(tmp_path), "-s",
        # -ac: SPA/서버가 매칭 안 되는 경로도 200으로 index.html을 돌려주는
        # "soft 404" 패턴을 자동 감지해서 걸러낸다. 이게 없으면 워드리스트
        # 단어 거의 전부가 허위로 매치되는 플러딩이 발생한다.
        "-ac",
    ]
    command += header_args or []
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"  [경고] ffuf 실행 실패: {exc}")
        tmp_path.unlink(missing_ok=True)
        return []

    try:
        payload = json.loads(tmp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError, OSError) as exc:
        print(f"  [경고] ffuf 결과 파싱 실패: {exc}")
        if completed.stderr:
            print(f"  [ffuf stderr] {completed.stderr.strip()[:300]}")
        return []
    finally:
        tmp_path.unlink(missing_ok=True)

    results = []
    for entry in payload.get("results", []):
        fuzz_value = entry.get("input", {}).get("FUZZ", "")
        results.append(
            {
                "method": "GET",
                "path": f"/{fuzz_value}",
                "content_type": entry.get("content-type"),
                "source": "ffuf",
            }
        )
    print(f"  ffuf 발견 {len(results)}건")
    return results


def discover_endpoints(base_url: str, *, header_args: list[str] | None = None) -> list[dict]:
    """katana_standard + katana_headless 결과만 반환한다 (ffuf 제외).

    팀 회의에서 정리된 순서: (1) standard+headless를 둘 다 돌려서 (2) 그
    합집합을 전체로 두고 (3) headless에만 나온 것을 분자로 (4) 비율을
    구한 뒤 (5) 그 결과에 따라 조치를 취하고 나서야 (6) 브루트포스(ffuf)를
    진행한다. 그래서 ffuf는 이 함수에 안 들어있다 - 실행 순서/시점을
    executor.py가 명시적으로 통제한다(ratio 계산·조치가 다 끝난 뒤에
    discover_with_ffuf를 따로 호출).

    origin_discovery의 SPA 판단(main_crawler_mode)은 더 이상 어떤 모드를
    쓸지 결정하는 데 쓰이지 않는다 - 정적 HTML 시그니처만으로는 판단이
    틀릴 수 있다는 게 Juice Shop 테스트에서 확인됐기 때문에, 대신 두 모드를
    다 실행해서 실제 차이(Gap Ratio)로 판단한다. main_crawler_mode는 참고용
    기록으로만 남는다.

    header_args: tools/login.py::SessionCredentials.as_header_args()의 결과.
    로그인 세션이 있으면 katana도 인증된 상태로 크롤링한다.
    """
    results: list[dict] = []
    results.extend(discover_with_katana(base_url, mode="katana_standard", header_args=header_args))
    results.extend(discover_with_katana(base_url, mode="katana_headless", header_args=header_args))
    return results
