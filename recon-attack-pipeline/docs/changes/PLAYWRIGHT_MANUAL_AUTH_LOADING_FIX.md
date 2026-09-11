# Playwright 수동 인증 브라우저 무한 로딩 수정

- 변경일: 2026-09-11
- 대상 명령: `aidast run "<PROGRAM_URL>" --target ...` 또는 `--all-targets`
- 대상 코드: `src/aidast/recon/tools/playwright_driver.py`
- 회귀 테스트: `tests/test_recon_browser_transport.py`

## 1. 배경과 증상

`aidast run`의 Recon 단계는 인증 세션이 없거나 유효하지 않으면
`PlaywrightDriver.ensure_session()`에서 수동 인증 절차를 시작한다. 이때 화면에
Chromium은 정상적으로 나타나지만 대상 페이지가 계속 로딩 상태에 머물고, 로그인
화면을 사용할 수 없는 문제가 발생했다.

겉으로는 사이트 응답이나 프록시 지연처럼 보였지만 실제 정지 범위는 더 넓었다.
문제가 발생한 런타임에서는 `page.title()`과 `page.evaluate()` 같은 Playwright
명령뿐 아니라 로그인 후 실행되는 `context.storage_state()`도 반환되지 않았다.
따라서 사용자가 로그인을 마치더라도 세션 저장과 브라우저 정리 단계가 함께 멈출
수 있었다.

## 2. 수동 인증 워크플로우

수정 전후의 상위 워크플로우는 동일하다.

1. `aidast run`이 승인된 Scope와 `TargetPolicy`를 바탕으로 Recon을 시작한다.
2. Endpoint Discovery가 `PlaywrightDriver.ensure_session()`을 호출한다.
3. 저장된 세션이 유효하지 않으면 `capture_and_start()`가 화면이 보이는 브라우저를
   실행한다.
4. 브라우저가 `login_url`로 이동하고 운영자가 직접 로그인한다.
5. 운영자가 터미널에서 Enter를 누르면 인증 storage state를 파일에 저장한다.
6. 동일 브라우저의 CDP 주소를 Katana Headless에 전달해 인증된 탐색을 이어간다.

이번 수정은 위 단계 중 **3번의 브라우저 생성·연결 방식**만 교체했다. 로그인
판단, 운영자 확인, 세션 필터링, TargetPolicy 및 이후 Katana 흐름은 변경하지
않았다.

## 3. 변경 전 구현

기존 `_launch_manual_browser()`는 Playwright가 제공하는 Chromium 실행 파일을
별도 프로세스로 띄운 뒤, 다시 CDP로 연결했다.

```text
Playwright executable_path 조회
        ↓
subprocess.Popen(Chromium, --remote-debugging-port, --user-data-dir, ...)
        ↓
CDP endpoint 대기
        ↓
chromium.connect_over_cdp(...)
        ↓
기존 contexts[0] 및 pages[0] 재사용
```

주요 특성은 다음과 같았다.

| 항목 | 변경 전 |
|---|---|
| 브라우저 프로세스 소유자 | `subprocess.Popen`으로 애플리케이션이 직접 관리 |
| Playwright 연결 | 실행이 끝난 브라우저에 `connect_over_cdp()`로 사후 연결 |
| Context/Page | 외부 브라우저가 만든 첫 번째 Context와 Page 재사용 |
| 로그인 상태 | 영구 profile 디렉터리와 storage state 파일을 함께 사용 |
| 프록시 | Chromium의 `--proxy-server` 인자로 전달 |
| 런타임 종류 | `_browser_kind = "cdp"` |
| 생존 확인 | `_chrome_process.poll()` 결과에 의존 |

이 구조에서는 브라우저 프로세스가 살아 있고 CDP endpoint도 열려 있어도,
Playwright가 붙은 세션의 명령 처리가 멈추는 상태를 구분하기 어려웠다. 화면에는
페이지가 계속 로딩되는 것처럼 보이지만 Python 쪽 Playwright 호출도 함께
대기하므로 일반적인 navigation timeout만으로 복구되지 않았다.

## 4. 원인 분리 과정

단순히 제한 시간을 늘리기 전에 실제로 어느 경계가 멈추는지 비교했다.

| 가설 | 확인 방법 | 결과 |
|---|---|---|
| 대상 사이트 자체가 응답하지 않음 | 동일 대상에 직접 요청 및 Playwright 관리 브라우저로 접근 | 정상 응답 및 DOM 완료 |
| mitmproxy가 응답을 막음 | 동일 프록시를 통한 HTTP 요청과 Playwright 접근 비교 | 프록시 경유 응답 정상 |
| TargetPolicy가 외부 스크립트를 차단해 DOM이 끝나지 않음 | 외부 요청을 abort한 경우와 중립 응답으로 대체한 경우 비교 | 두 경우 모두 DOM 완료, 무한 대기 재현 안 됨 |
| `--disable-gpu`가 로딩을 막음 | 해당 옵션을 제거한 외부 Chromium+CDP 조합 비교 | 현상 동일 |
| 외부 Chromium에 CDP로 재연결하는 경계가 멈춤 | 외부 프로세스+`connect_over_cdp()`와 Playwright 직접 실행 비교 | 전자에서 재현, 후자에서 정상 |

결론적으로 병목은 네트워크 응답 시간이 아니라 **Playwright가 소유하지 않은
Chromium 프로세스에 CDP로 재연결한 런타임**이었다. 이 상태에서는 페이지 이동뿐
아니라 title, JavaScript 평가, storage state 추출까지 멈췄다. 따라서 timeout을
늘리거나 외부 리소스 차단 정책을 완화해도 근본 문제가 해결되지 않는다.

## 5. 변경 후 구현

Chromium을 별도 프로세스로 먼저 실행하지 않고 Playwright의 기본 연결이 처음부터
브라우저의 권위 있는 제어 채널이 되도록 변경했다.

```text
chromium.launch(headless=False, proxy=..., args=[CDP port, ...])
        ↓
CDP endpoint 확인 및 Katana용 WebSocket URL 보관
        ↓
browser.new_context(...)
        ↓
context.new_page()
```

| 항목 | 변경 전 | 변경 후 |
|---|---|---|
| 브라우저 실행 | `subprocess.Popen(executable, ...)` | `playwright.chromium.launch(headless=False, ...)` |
| 제어 연결 | 실행 후 `connect_over_cdp()` | Playwright 기본 연결을 처음부터 유지 |
| Context/Page | 외부 브라우저의 첫 객체 재사용 | 새 Context와 Page를 명시적으로 생성 |
| 프록시 | Chromium CLI 문자열 조립 | Playwright `proxy={server, bypass}` 옵션 |
| 로그인 상태 | profile과 storage state가 중첩 | 필터링된 storage state 파일을 명시적 세션 계약으로 사용 |
| 런타임 종류 | `cdp` | `managed` |
| CDP 제공 | 외부 브라우저 연결에 사용 | Katana 연동용 endpoint로 계속 제공 |
| 종료 처리 | 프로세스 poll/terminate 중심 | Playwright browser close 중심, 기존 프로세스 정리 호환 유지 |

`get_chrome_ws_url()`도 별도 `_chrome_process`가 반드시 있어야 한다는 가정을
제거했다. 현재 browser와 CDP WebSocket URL이 존재하면 managed 브라우저에서도
Katana가 사용할 주소를 반환한다. 레거시 프로세스가 존재하는 경우에는 기존
`poll()` 생존 검사도 계속 수행한다.

## 6. 유지된 안전 경계

브라우저 실행 구조만 바꿨으며 Recon의 접근 제한을 완화하지 않았다.

- `TargetPolicy`에 따른 Playwright route guard는 그대로 적용된다.
- 정책이 활성화된 Context에서는 service worker를 계속 차단한다.
- WebSocket 차단 정책도 유지한다.
- mitmproxy는 Playwright launch의 proxy 옵션으로 계속 강제한다.
- loopback도 프록시를 우회하지 않도록 `bypass: "<-loopback>"`을 유지한다.
- Scope 밖의 서드파티 요청이 차단될 수 있지만, 이는 승인 범위를 지키기 위한
  기존 fail-closed 동작이다.
- WSLg 그래픽 드라이버 안정성을 위한 `--disable-gpu`도 유지한다.

즉, 외부 리소스를 허용해서 화면을 살린 것이 아니라 브라우저 제어 경로의 교착
가능성을 제거하면서 기존 네트워크 정책을 보존했다.

## 7. 해결된 문제

- 화면이 보이는 Chromium에서 대상 페이지가 무한 로딩되는 현상
- `page.title()`, `page.evaluate()` 등 후속 Playwright 명령이 응답하지 않는 현상
- 로그인 완료 후 `storage_state()`에서 세션 저장이 멈추는 현상
- 종료 과정에서 동일한 정지 상태 때문에 정리가 완료되지 않는 현상
- managed 브라우저에서는 Katana에 CDP URL을 제공할 수 없던 기존 생존 확인 가정

## 8. 회귀 테스트

`test_manual_browser_is_playwright_managed_while_exposing_cdp`를 추가해 다음 계약을
고정했다.

- 수동 인증 브라우저는 `chromium.launch(headless=False)`로 실행한다.
- `connect_over_cdp()`와 `subprocess.Popen()` 경로로 되돌아가지 않는다.
- Playwright가 새 BrowserContext와 Page를 생성한다.
- mitmproxy 주소가 launch proxy 옵션에 포함된다.
- managed 브라우저에서도 Katana용 CDP WebSocket URL을 반환한다.

검증 결과:

- 브라우저 전송 관련 테스트: 8개 통과
- unittest 호환 전체 회귀 테스트: 275개 통과
- `git diff --check`: 통과
- 실제 대상 페이지: 약 18.5초 안에 `document.readyState == "complete"`
- 실제 대상에서 페이지 제목·본문 확인, 프록시 요청 60건 관찰, storage state 저장과
  런타임 종료 완료

실제 계정 자격증명은 사용하지 않았으므로 로그인 폼 제출 이후의 서비스별 인증
성공 여부는 검증 범위에 포함하지 않았다. 이번 검증 범위는 문제가 발생했던
브라우저 로딩, Playwright 제어, 프록시 관찰, 세션 저장과 종료 경로다.

