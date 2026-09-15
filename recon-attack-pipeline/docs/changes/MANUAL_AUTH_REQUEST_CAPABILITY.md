# 수동 인증 POST 요청별 승인 및 일회성 Capability

- 변경일: 2026-09-15
- 대상 단계: Recon의 Playwright 수동 인증
- 대상 코드: `src/aidast/recon/policy.py`, `src/aidast/core/http_safety.py`,
  `src/aidast/recon/tools/playwright_driver.py`,
  `src/aidast/recon/tools/mitm_addon.py`
- 회귀 테스트: `test_recon_browser_transport.py`, `test_recon_policy.py`,
  `test_request_broker.py`

## 1. 변경 목적

사이트마다 `/login`, `/rest/user/login`, `/api/Users/`처럼 인증 endpoint의 이름과
구조가 다르다. 특정 제품의 경로를 코드에 하드코딩하면 다른 애플리케이션에
재사용할 수 없고, endpoint 변경에도 취약하다.

반대로 기존 구현처럼 수동 인증 단계 전체에 같은 origin의 POST를 허용하면 로그인
요청과 무관한 background polling, telemetry 또는 다른 상태 변경 요청도 같은
권한을 사용할 수 있다. 실제 Juice Shop에서는 로그인 화면을 사용하는 동안
`/socket.io/` polling POST가 함께 발생할 수 있으므로 이 차이는 이론적인 문제가
아니다.

새 구현은 endpoint의 의미를 추측하지 않는다. Scope 경계를 통과한 POST를 전송
직전에 보류하고, 운영자가 화면과 요청 정보를 확인해 그 요청 한 건을 승인하도록
한다.

## 2. 변경 전 구현

실행기가 Recon 대상마다 임의 token 하나를 생성해 브라우저와 mitmproxy에 공유했다.
Playwright가 다음 조건을 모두 만족하는 요청에 같은 token header를 붙였다.

1. 현재 phase가 `login`이다.
2. method가 POST다.
3. URL이 TargetPolicy의 scheme, host, port, path 경계 안이다.

프록시는 token이 일치하면 요청을 허용했다. token은 로그인 완료 후 폐기됐지만,
로그인 phase 안에서는 모든 동일 경계 POST가 같은 권한을 공유했다.

```text
login phase + same boundary + POST
                ↓
        공용 임시 token 첨부
                ↓
          프록시에서 허용
```

## 3. 변경 후 구현

실행기는 대상마다 token 대신 서명 key를 만들고 프록시에 전달한다. 이 key는
Playwright와 로컬 프록시 밖으로 노출되지 않으며, 실제 target으로 전달되는
header에도 포함되지 않는다.

수동 인증 중 기본 `allowed_methods`에 없는 POST가 발생하면 다음 순서로 처리한다.

1. Playwright route guard가 요청을 보류한다.
2. URL credentials, Scope boundary, login phase, POST 여부를 먼저 검사한다.
3. 터미널에 query string을 제외한 `method + origin + path`를 표시한다.
4. 운영자가 `y`를 입력한 경우에만 capability를 발급한다.
5. capability를 로컬 제어 header에 넣어 mitmproxy로 보낸다.
6. 프록시가 서명, method, 정확한 request target, 발급·만료 시각과 nonce를 검증한다.
7. 검증에 성공하면 nonce를 소비하고 제어 header를 제거한 뒤 target으로 전달한다.
8. 거부, 변조, 만료, 다른 URL에서의 사용 또는 재사용은 모두 차단한다.
9. SPA가 동일 URL과 동일 body를 자동 재시도하면 기존 판단을 식별해 다시 묻지 않고
   차단한다. body가 바뀐 새 폼 제출은 별도 요청으로 다시 승인할 수 있다.

```text
same-boundary POST 감지
        ↓
운영자에게 요청 1건 승인 요청 ── 거부/Enter ──> abort
        ↓ y
method + exact target + TTL + nonce를 HMAC 서명
        ↓
로컬 프록시 검증 및 nonce 소비
        ↓
제어 header 제거 후 target으로 1회 전달
```

현재 capability TTL은 20초이며 프록시 정책이 허용하는 최대 TTL은 30초다. TTL은
승인 후 실제 전송까지의 짧은 지연만 수용하기 위한 것이며, 유효 시간 안에서도
같은 nonce는 한 번만 사용할 수 있다.

## 4. 기존 방식과의 차이

| 항목 | 변경 전 | 변경 후 |
|---|---|---|
| 사이트별 endpoint 하드코딩 | 없음 | 없음 |
| 승인 단위 | 로그인 phase의 동일 경계 POST 전체 | 정확한 POST 요청 한 건 |
| 운영자 확인 | 로그인 완료 시 한 번 | 상태 변경 요청마다 `y/N` |
| 권한 binding | 공용 token 일치 | method + 정확한 URL target + 시간 + nonce |
| background POST | 같은 token으로 허용 가능 | 별도 승인 없으면 차단 |
| token 재사용 | 로그인 phase 동안 가능 | proxy가 nonce를 소비해 차단 |
| 다른 path/query로 이동 | Scope 안이면 가능 | 서명 대상이 달라져 차단 |
| target에 제어정보 전달 | proxy에서 token header 제거 | proxy에서 capability header 제거 |
| 로그인 완료 후 | browser token 폐기 | browser signing authority 폐기 |
| 동일 요청 자동 재시도 | 매번 다시 처리 | 재질문 없이 차단 |

`ToolPolicy.manual_auth_post`라는 필드 이름은 저장된 정책과 생성 schema의 호환성을
위해 유지했다. 다만 현재 의미는 “POST 자동 허용”이 아니라 “수동 인증 중 POST
요청별 승인 기능 사용”이다. Recon crawler의 `allowed_methods`에는 POST가 추가되지
않는다.

## 5. 일반화 경계

이 방식은 endpoint 이름이나 프레임워크에 의존하지 않으므로 전통적인 HTML form,
SPA의 fetch/XHR 로그인과 회원가입 요청에 동일하게 적용된다. 승인 후보가 되려면
항상 기존 TargetPolicy의 scheme, host, port, 허용 path 안에 있어야 한다.

현재 capability가 허용하는 method는 기존 Scope 계약을 유지하기 위해 POST로
제한한다. PUT, PATCH, DELETE, WebSocket, Scope 밖 origin, 제외 path는 인증
화면에서 발생해도 승인 후보가 되지 않는다. 외부 Identity Provider를 사용하는
OAuth/OIDC 흐름은 해당 origin이 승인된 Scope에 포함되지 않는 한 계속 차단된다.

승인 pattern을 실행 간 자동 재사용하는 기능은 이번 변경에 포함하지 않았다.
승인된 Scope 문서를 런타임이 자동 수정하면 승인 무결성이 깨질 수 있기 때문이다.
반복 실행용 auth profile을 도입하려면 별도의 명시적 승인·서명 절차를 거쳐
TargetPolicy 입력으로 제공해야 하며, 단순 관찰 결과를 곧바로 권한으로 승격해서는
안 된다.

## 6. 터미널 입력과 Playwright 이벤트 처리

로그인 완료 입력과 요청 승인을 서로 다른 `input()` 스레드에서 받으면 stdin
경쟁이 발생한다. 따라서 하나의 terminal reader가 모든 입력을 받고 다음 의미로
분기한다.

- 승인 요청 대기 중 `y` 또는 `yes`: 보류된 요청 한 건 승인
- 승인 요청 대기 중 그 외 입력: 해당 요청 거부
- 승인 요청이 없을 때 Enter: 수동 인증 완료

Playwright 호출은 계속 원래 소유 thread에서 수행한다. terminal reader만 별도
thread에서 대기하고, 소유 thread는 `page.wait_for_timeout()`으로 dispatcher를
계속 움직인다. 따라서 수동 입력을 기다리는 동안 SPA의 허용된 GET 요청이 멈췄던
이전 문제도 다시 발생하지 않는다.

## 7. 검증 계약

회귀 테스트는 다음을 고정한다.

- 운영자가 승인하지 않은 인증 POST는 브라우저에서 차단된다.
- 승인된 POST에는 정적 token이 아니라 요청별 capability가 붙는다.
- capability는 정확한 method와 URL에서만 유효하다.
- 변조된 capability, 다른 path에서의 사용과 nonce replay는 차단된다.
- 동일 URL·동일 body의 자동 재시도는 승인 질문을 반복하지 않는다.
- 입력 body가 바뀌면 새로운 요청으로 구분한다.
- 제어 header는 target 전달 및 캡처 전에 제거된다.
- 인증 phase가 끝나면 브라우저의 signing authority가 폐기된다.
- terminal 입력 대기 중에도 Playwright dispatcher가 계속 동작한다.
