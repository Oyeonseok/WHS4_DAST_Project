# Recon 인증·ID·쿼리 연결 조사 및 개선 — 2026-09-29

현재 승인된 제한 안에서 Juice Shop의 수집 경로는 늘었다. **VulnBank의 성공 경로 수는 증가하지 않았다.** 신규 로그인/ID 기능을 재작성하지 않고 기존 세션·값 연결의 단절을 수정했다. 대상 이름·업무 경로·정답 목록을 발견 코드에 추가하지 않았다.

## 실제 원인

1. **ZAP 단계의 인증 헤더 누락.** 기존 ffuf `/api/transactions` 요청은 Authorization·Cookie가 있으나 필수 쿼리가 없어 400이었다. 인증 없이 account_number를 가진 요청과 `/api/bill-payments/history`의 401은 ZAP OpenAPI 단계에서 생성됐다. 외부 도구용 `get_auth_headers()`는 이미 있었지만 ZAP 계획은 이를 적용하지 않았다.
2. **서로 다른 요청을 경로 하나로 판단.** 쿼리를 제거한 동적 URL·중복 판단 때문에 필요한 파라미터 URL이 사라지거나, 이전의 다른 인증/쿼리 관측이 후속 검증을 막았다. Surface 병합과 요청 검증의 목적이 달랐다.
3. **실제 값 근거가 필수 쿼리로 이어지지 않음.** 기존 JSON callback 연결은 동작하지만 DOM 값 연결과 OpenAPI required query, AI query 실행이 제한됐다. 다중 query·복잡한 식은 이번에도 보수적으로 보류한다.
4. **예산 배분 순서.** 기존 ffuf가 JS/API보다 먼저 활성 요청 몫을 소비했다. 총 500회 정책에서 브라우저 우선 몫 20%를 보호하므로 선행 HTTP probe 1회 이후 일반 활성 단계에는 399회가 남는다. 기본 상세/AI 연결이 있어도 이후 요청은 정책 프록시에서 보류됐다.

401 두 요청의 실제 캡처 시각은 **03:37:42.514241·03:37:42.757245 UTC**, ZAP 단계는 03:37:35.924359–03:37:48.598413 UTC다. DB의 `captured_at`는 나중에 가져온 시각이므로 요청 receipt 시각으로 대조했다. 인증된 ffuf 400은 03:35:30.895994 UTC다. 값과 토큰을 가린 [원인 근거](../../../result/test-runs/09.29/recon-auth-parameters/AuthenticationRootCause.json)를 보존했다.

## 변경한 동작

| 코드 | 변경 |
| --- | --- |
| `api_secondary_discovery.py` | ZAP 인증 replacer, 실제 DOM/inline JS 연결, 요청별 관측, 항상 적용하는 grounded OpenAPI GET fallback |
| `observed_parameters.py` | 실제 input/select/textarea/명시적 textContent 값, 고유 named field, 같은 문서가 선언한 JS의 직접 GET 값 흐름 |
| `js_fetch_bindings.py`·`js_argument_bindings.py` | 쿼리 템플릿·source query 유지, 실제 JSON 값 URI 인코딩, 민감 field 배제 |
| `openapi_get.py` | unique 실제 named DOM 값으로 required query 연결; example/default·remote ref·미해결 값 사용 금지 |
| `request_identity.py`·`mitm_addon.py`·`mitm_proxy.py` | URL·인증 조건에 따른 로컬 요청 identity, auth key 전달, 인증 값 자체는 출력하지 않음 |
| `endpoint_discovery.py` | JS/DOM·API 보강을 ffuf보다 먼저 실행, 활성 몫 소진 후 ffuf 추가 루트 중단 |
| `ai_patterns.py`·`js_evidence.py`·`recon_patterns/SKILL.md` | 전체 단일 query 값 연결, 관련 source 근거, 실제 인증 값의 모델 경계 정제 |

ZAP는 URL 규칙에 Java `Matcher.matches()`를 사용한다. 접두어까지만 맞는 정규식은 계획 파일 검사를 통과해도 실제 헤더를 넣지 못했다. 전체 경로까지 소비하는 **정확한 origin 경계**로 수정하고 Python 회귀도 `fullmatch`로 바꿨다. [ZAP 구현 근거](https://github.com/zaproxy/zap-extensions/blob/main/addOns/replacer/src/main/java/org/zaproxy/zap/extension/replacer/ReplacerParamRule.java)와 [공식 설정 형식](https://www.zaproxy.org/docs/desktop/addons/replacer/automation/)에 맞춘 실제 통합 검사를 수행했다.

ZAP에는 파라미터가 없는 허용 GET만 투영한다. 무근거 ID·schema example·쓰기 작업을 생성하지 않고, 필요한 query는 로컬의 실제 값 fallback에서만 구성한다. 인증 설정 파일은 임시 0600이며 도구 stderr를 사용자 로그로 복사하지 않는다. OpenAPI가 다른 origin을 선언하면 현재는 로컬 주소로 자동 변환하지 않는다.

실제 도구 검사에서 ZAP가 전달받은 값을 사용자 전역 config/log에 저장하는 것도 확인했다. 호출별 0700 임시 프로필로 격리하고 설치된 addon 패키지 버전만 복사하며 config/history는 가져오지 않는다. 성공·실패·타임아웃 뒤 프로필을 삭제한다. 수정 전 이번 실험의 JWT가 남아 있던 16곳만 전역 파일에서 가렸고 다른 내용은 보존했다. [ZapGlobalRedaction.json](../../../result/test-runs/09.29/recon-auth-parameters/ZapGlobalRedaction.json).

## 동일 조건 전체 실측

| 대상 | GET Surface | Surface 2xx 경로 | 원시 GET 관측 경로 | 원시 2xx 경로 | 신규 / 손실 경로 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Juice Shop | 9/71→51/71 | 9→45 | 9→54 | 9→45 | 42 / 0 |
| VulnBank | 12/47→14/47 | 12→12 | 12→14 | 12→12 | 2 / 0 |

| 대상 | DB 원시 GET 응답 건수 | 그중 2xx 응답 건수 | 없는 경로 대조 GET | Surface 내용/대조 검사 통과 경로 |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop | 392→388 | 170→277 | 0→10 | 8→41 |
| VulnBank | 399→399 | 122→131 | 0→2 | 1→12 |

- **Juice Shop:** Surface 신규 42개·손실 0개, 2xx 신규 36개·손실 0개.
- **VulnBank:** Surface 신규 2개·손실 0개, 2xx 신규 0개·손실 0개.

경로 분모 71·47은 서버 소스의 정의 route이며 정적 asset·임의 SPA URL 수가 아니다. route별 쿼리/인증/상태·신규/손실 전체 목록은 [Comparison.json](../../../result/test-runs/09.29/recon-auth-parameters/Comparison.json)에 있다. 원시 응답 건수는 DB에 보존된 GET 기록이며 정적 파일·반복·대조 요청이 섞인다. route 수는 이 기록을 사후 정의 경로와 대조한 별도 지표다. 401/403을 성공으로 세지 않았다.

Juice Shop의 2xx를 그대로 업무상 성공으로 보지 않았다. 실제 없는 경로 대조와 응답 fingerprint·JSON 내용을 사용했고, 동일 SPA shell은 선언된 `/` 외에서 양성 근거로 사용하지 않는다. `내용/대조 검사 통과`는 보수적 보조 지표다. 기준선은 대조 요청을 실행하기 전에 예산을 소진해 본문 판정이 불완전했다. 이 지표의 증가를 새로운 2xx 경로 증가로 해석하면 안 된다. 빈/단순 JSON 등은 의미를 확정하지 않았다.

이전 진단의 **58/71·22/47, 2xx 51·19**는 예산/ffuf 제한을 해제한 결과다. 이번 제한 조건과 직접 비교하지 않는다. 09.29 별도 GET 검증의 56·28도 소스 기반 경로/파라미터를 제공한 다른 시점의 평가 요청이므로 발견의 입력이나 이번 수집률 상한으로 사용하지 않았다.

## 비교 조건과 보존

- 대상별 기존 계정·동일 신원, 동일 원본 session seed를 복사한 뒤 정상 로그인. 신규 계정·거래·카드·권한·비밀번호 생성/변경 없음.
- 각 실행의 정상 로그인 POST는 준비 단계에 별도로 수행했다. Recon DB에는 Juice Shop 두 버전 각각 브라우저의 `/socket.io/` POST 3건도 관측됐다. 위 표는 GET만 집계하며, 수집이 모든 층에서 GET으로만 이루어졌다는 뜻은 아니다. 로그인 기록이나 GET 처리의 서버 측 부수 효과까지 불변으로 보증하지 않는다.
- 두 버전 모두 **500회·0.5 rps·동시 1·개별 15초·깊이 2**. `resources/wordlists/common.txt` 4,752행의 동일 해시, ffuf 루트별 150초, 제품 root selector 유지. 횟수·속도·시간 gate 진단 해제 없음.
- 두 버전의 실제 시작 URL은 대상 origin의 `/`. Bank의 저장 session 시작은 `/dashboard`이나 이 비교 실행기는 `execution_start_urls`를 지정하지 않았다. 이 조건을 숨기거나 개선 버전에만 다르게 적용하지 않았다.
- 실행은 URL 대상의 `HTTP_PROBE`·`ORIGIN_DISCOVERY`·`ENDPOINT_DISCOVERY` 전체다. 네 실행 모두 세 task 성공, DB integrity 정상·FK 오류 0. 보조 단계 오류/스킵은 비교 JSON에 별도 기록했다.
- 각 Recon의 정책 프록시 허용 요청은 399회와 probe 1회로 합계 400회다. 보호된 브라우저 몫을 임의로 해제하지 않았다. 보류 요청은 응답 발견/성공에 포함하지 않는다.
- 초기 미커밋 상태를 기준선 소스로 동결했다. 개선 스냅샷에는 이 작업의 12개 source/skill 파일만 겹쳐 넣었고, 그 사이 다른 팀의 15개 source/metadata 변경은 작업 폴더에 보존하며 실측 비교에서 제외했다. [SourceIsolation.json](../../../result/test-runs/09.29/recon-auth-parameters/SourceIsolation.json) 참조.
- 두 실행 모두 공통으로 관측한 Juice 컬렉션의 ID 집합(116·56·46개)은 같았다. 실제 ID 값은 보고하지 않았다. 서버 데이터 전체의 불변 스냅샷은 없으며 정상 로그인 기록·서버 시각·AI 비결정성은 남는다.

- Juice Shop 실행 시간: 678.83→622.37초.
- VulnBank 실행 시간: 1769.26→765.8초.

시간 차이는 추가 ffuf 루트를 생략하는 동작 등을 포함한 단회 관측이다. 보편적인 속도 향상이나 단일 수정의 인과 효과로 주장하지 않는다.

## 테스트와 실제 도구 검사

- `tests/test_recon_auth_parameters.py`와 기존 일반 가상 앱 회귀: 임의 `/directory`·`/records`·`owner_key`, 중첩 JSON, 실제 DOM 값, URI 인코딩, 실패 후 다른 인증/query 재검증, required query, wrong source/query, 외부 origin 차단, secret·ambiguous·mutation·POST 배제, 유한 예산 순서.
- 최종 실측 소스 회귀 **712개·서브테스트 58개 통과**. [FrozenRegression.log](../../../result/test-runs/09.29/recon-auth-parameters/FrozenRegression.log). 다른 팀의 동시 변경을 포함하는 현재 workspace의 관련 회귀도 **730개·서브테스트 58개 통과**했다. [WorkspaceRegressionFinal.log](../../../result/test-runs/09.29/recon-auth-parameters/WorkspaceRegressionFinal.log).
- 실제 AI 모델에 가상 앱의 코드·field 구조만 전달해 단일 query 연결 계획을 받았고, 실제 scalar는 로컬 연결기로 구성했다. [ModelQueryCheck.json](../../../result/test-runs/09.29/recon-auth-parameters/ModelQueryCheck.json).
- 실제 ZAP가 비공개 프로필에서 가상 로컬 `/records`에 **Authorization·Cookie를 모두 전달하고 200**을 관측했고 사용자 전역 설정이 바뀌지 않았다. [ZapReplacerCheck.json](../../../result/test-runs/09.29/recon-auth-parameters/ZapReplacerCheck.json). 합성 검사 첫 실패는 이전 tool proxy 설정, 이어진 401은 full-match 불일치였고 이를 수정했다. OpenAPI의 기존 `maxMessages` 옵션은 설치된 도구에서 warning으로 처리돼 프록시 물리 요청 gate가 제한의 기준이다.
- 독립 리뷰의 정의된 범위에서 Critical/High 잔여 지적 없음. 사용자 정의 인증 접두어·중복 Cookie 순서·DOM 직접 읽기·모델 입력 정제·ffuf 실제 잔여 몫도 회귀 검증했다.
- 인증 문자열이 로그·진단·비교 JSON에 포함되지 않는지 로컬 대조했다. [ArtifactChecks.json](../../../result/test-runs/09.29/recon-auth-parameters/ArtifactChecks.json). 원시 DB/session의 인증정보는 0700 실험 디렉터리와 0600 session 파일로 보관한다.

## VulnBank의 남은 연결과 다음 개선

현재 `/` 시작 전체 Recon에는 계좌 값이 있는 `/dashboard` HTML이 없었다. 저장 시작 페이지를 별도 읽기 진단하면 200 HTML에서 `accountnumber`의 고유 실제 값과 명세의 `account_number` 필수 query 이름이 연결된다. 그러나 관측된 `/static/openapi.json`의 server는 Scope 밖이며 fallback 후보는 0개다. 이 페이지의 현재 JS에서도 지원하는 직접 DOM→fetch GET 결합은 0개다. **이 진단의 값/경로를 전체 수집률에 합산하지 않았고 거래 조회의 200 개선을 주장하지 않는다.** [bank-saved-start-replay.json](../../../result/test-runs/09.29/recon-auth-parameters/bank-saved-start-replay.json).

다음 우선순위는 승인된 실제 시작 페이지를 파이프라인에 전달하는지 점검하고, 동일 origin에서 관측된 실제 GET·명세 경로의 대응 근거를 갖춘 경우에만 필수 파라미터 계약을 연결하는 것이다. `location` 이동·DOM event·storage의 비인증 값 등 아직 지원하지 않는 흐름도 일반 사례로 확장할 수 있다. origin/경로를 무조건 재매핑하거나 schema example로 ID를 채우는 방식은 사용하지 않는다.

scripts 40개·상세 GET 20개·문서/바이트 한도, 일부 `/api/resource`·배열/data[].id 가정, 복잡한 제어 흐름·여러 동적 query·OpenAPI path/ref는 남는다. 인증 헤더 전달은 정적 세션 snapshot이므로 모든 동적 서명/회전·path별 cookie를 해결했다고 보증하지 않는다. 관리자·merchant·내부망 권한 요구는 정상 일반 계정 수집의 제한이다.

중단·대체한 개선 trial은 최종 비교에서 제외했다. 이전 미커밋 코드·원본 session·완료 기준선은 보존했다. 최신 앱별 전체 검증은 다른 팀의 동시 변경을 제외한 동결 Recon 소스이며, 작업 폴더 전체 제품의 모든 파이프라인 통합 검증을 뜻하지 않는다.
