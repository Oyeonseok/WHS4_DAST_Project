# VulnBank Recon 누락 원인 분석

최종 Surface 22/47을 산출한 `ai-context-benchmark/bank-related`의 DB, 단계 로그, 고정 실행 소스를 분석했다. 현재 작업 폴더에는 후속 파라미터/DOM 연결 변경이 있으므로 기존 실행의 원인과 현재 구현 상태를 구분한다. 분석을 위해 제품 코드를 수정하거나 추가 HTTP 요청을 보내지 않았다.

## 결론

일부 경로는 충분한 발견 근거가 있었는데 후보 추출·메서드 판정·파라미터 연결·보조 도구 실패 때문에 빠졌다. 모든 누락을 숨겨진 경로나 로그인 부족으로 설명할 수 없다. 경로 생성, 실제 HTTP 요청, 최종 Surface 보존이 각각 다른 단계다.

| 경로 | 사용할 수 있었던 근거 | 누락 지점 | 확인한 원인 |
|---|---|---|---|
| `/graphql` | GraphQL 공통 후보에 이미 존재 | 프로토콜 검증 | 검증 함수는 POST만 사용한다. `/graphql` probe 자체는 허용되지만 일반 HTTP helper의 `allows_url(method='POST')`는 당시 GET/HEAD/OPTIONS 정책에서 False다. 요청을 보내지 않고 확인 실패가 되며, GET 메타데이터 경로를 별도로 보존하지 않는다. |
| `/reset-password` | 수집한 `/forgot-password` HTML의 `window.location.href` | 경로 추출 및 UI 탐색 | 리다이렉트는 비밀번호 찾기 POST 성공 후에만 실행된다. form submission은 False다. JS API parser는 이 navigation literal을 추출하지 않고 사용한 common.txt에도 해당 항목이 없다. |
| `/api/bill-payments/history` | 실제 분석한 dashboard JS에 명시적 기본 GET fetch | 메서드 판정 | frozen parser가 이 호출을 UNKNOWN으로 판정한다. adaptive collector는 GET/None만 허용하므로 후보에서 제외한다. 이후 인증 없는 401 원시 기록은 있으나 endpoint는 생성되지 않았다. |
| `/api/virtual-cards/{card_id}/transactions` | 실제 분석한 dashboard JS의 동적 GET | 메서드 판정 및 값 연결 | 같은 UNKNOWN 판정이 발생한다. 추가로 기존 계정의 `/api/virtual-cards` 응답은 `cards: []`여서 해당 컬렉션에서 실제 card_id를 얻을 수 없었다. |
| `/api/transactions` | 발견된 OpenAPI의 필수 account_number 선언, 수집한 대시보드 HTML의 본인 계좌번호 | 정상 요청 구성 | 인증된 요청은 계좌번호 없이 400, 계좌번호를 넣은 별도 요청은 인증 없이 401이었다. 그 계좌번호도 본인 계좌와 다르다. 이전 구현의 동적 query 및 DOM 값 연결 제한, required parameter fallback 제외가 겹쳤다. |
| `/api/v3/user/{user_id}` | 서버 소스에서는 admin HTML의 GET 호출 | 접근 가능한 분석 소스 | 호출 근거는 관리자 페이지에 있으며 일반 계정의 admin 접근은 403이었다. 수집한 OpenAPI의 GET 목록에도 해당 경로가 없다. 이 경우 정상 계정에서 확보한 공개 source 근거가 부족하다. |

## 1. GraphQL: 경로 후보는 있는데 POST 확인에 묶여 있다

- 공통 후보: `/graphql`, `/api/graphql`, `/gql`.
- 당시 `api_probe.graphql=True`, `allowed_paths=['/graphql']`.
- 당시 `allowed_methods=['GET','HEAD','OPTIONS']`.
- `_confirm_graphql()` → `_graphql_request()` → `_http_request(method='POST')` 순서다.
- `_http_request()`가 일반 메서드 허용 검사에서 종료한다.
- 기존 로그는 GraphQL 후보 3개, 확인 0개이며 `/graphql` HTTP 거래도 없다.
- GET `/graphql`은 정보 JSON을 반환하는 별도 서버 경로다. 이 경로의 발견/검증을 GraphQL POST query 실행과 구분해야 한다.

실제 정책과 frozen 함수로 오프라인 확인했다. 네트워크를 호출하면 실패시키는 broker를 넣었고 POST 허용=False, confirmation=False, 네트워크 호출 0을 확인했다.

## 2. JS GET이 UNKNOWN이 되는 재현 가능한 파서 오류

`literal_call_method()`는 URL 앞 최대 160자를 잘라 `_without_comments()`에 전달한다. 그 시작점이 앞선 문자열의 중간이면 lexical 상태를 잃는다. 닫는 따옴표를 새 문자열 시작으로 해석하고 정상적인 `fetch(`까지 제거할 수 있다. 직접 메서드 판정이 None이 되고 enclosing fetch의 UNKNOWN이 최종 판정으로 남는다. collector는 이를 제외한다.

서버 소스가 아닌 **실제 실행에서 저장한 dashboard JS**로 다음 두 판정을 재현했다.

| 대상 | frozen 추출 결과 |
|---|---|
| `/api/bill-payments/history` | UNKNOWN |
| `/api/virtual-cards/${cardId}/transactions` | UNKNOWN |

동일한 가상 `/api/widgets/history` fetch에서도 앞선 문자열 길이만 5자→220자로 바꾸면 GET→UNKNOWN으로 변했다. 현재 작업 폴더의 parser에도 같은 오프라인 예제를 적용해 UNKNOWN을 확인했다. 요청 자체의 메서드가 변한 것이 아니라 분석기가 주변 문맥 때문에 잘못 판정하는 문제다.

## 3. OpenAPI 보완 경로도 두 단계에서 실패했다

실제 수집한 `/static/openapi.json`에는 GET operation 19개가 있다.

1. ZAP import는 `/transfer` POST schema의 `required`가 배열이 아니라는 오류로 실패했다. GET 표적을 찾는 보조 과정이 명세의 다른 POST 정의 오류에 영향을 받았다.
2. fallback은 캡처한 명세의 `servers=[https://vulnbank.org]`를 사용한다. 실습 origin `http://127.0.0.1:5001`과 달라 후보가 0개다. 기존 코드에는 그 origin을 임의로 허용해 요청하는 동작이 없다.
3. 원격 요청 없이 메모리에서 server metadata만 `/`로 바꾼 대조에서는 12개 literal GET 후보가 생성됐다. `/api/bill-payments/history`도 포함됐다.
4. 그 대조에서도 `/api/transactions`와 ID placeholder 경로는 제외됐다. frozen fallback은 `{...}` path와 required 파라미터 작업을 건너뛴다.

외부 명세 origin을 자동으로 승인하는 것은 해결책이 아니다. 발견한 명세와 승인된 배포 origin의 연결 근거를 명시적으로 다뤄야 한다.

## 4. 인증 헤더의 보조 도구 전달도 별도 확인이 필요하다

기존 `_create_zap_plan()`에는 session Cookie/Authorization 설정이나 header replacer가 없다. `discover_api_secondary(headers=...)`의 headers는 직접 HTTP 검증에는 전달되지만 ZAP plan 생성에는 전달되지 않는다.

DB에서 `/api/transactions`, `/api/bill-payments/history`의 인증 없는 요청이 보조 API 단계 부근에 기록된 것은 확인했다. 다만 공통 mitmproxy 캡처만으로 그 개별 요청을 반드시 ZAP가 생성했다고 확정하지 않는다. 도구별 요청 귀속과 헤더 전달은 추가 추적 대상이다.

## 다음 개선 우선순위

1. 주변 문자열에 따라 메서드 판정이 변하는 JS parser 오류를 범용 예제로 수정한다.
2. GraphQL GET 경로 관측과 POST 프로토콜 확인/정책 보류를 분리한다.
3. `window.location.href`, `location.assign` 등 코드에 명시된 navigation URL을 읽기 후보로 추출·검증한다. 비밀번호 찾기 POST를 실행해야 할 필요는 없다.
4. 명세에서 GET 선언과 파라미터 metadata를 분리 수집하여, 전체 import 실패가 선언 수집까지 막지 않도록 한다.
5. 관측된 실제 HTML/JSON 값, 필수 파라미터, 동일한 인증 정보를 연결하고 보조 도구 헤더 전달을 검증한다.
6. 계정의 실제 데이터가 없는 경우는 parser 실패·값 부재·권한 제한으로 구분해 기록한다.

후속 파라미터 연결 코드가 이미 작업 폴더에 추가되고 있다. 위 분석은 기존 22개 실행을 설명하며, 후속 수정 전체의 효과는 같은 계정·데이터·설정으로 새 Recon을 실행해 확인해야 한다.

## 근거

- [오프라인 재현 및 소스 해시 대조](../../../result/test-runs/09.29/get-route-verification/VulnBankDiscoveryDiagnosis.json)
- [인증·파라미터 관측](../../../result/test-runs/09.29/get-route-verification/ReconAuthenticationParameters.json)
- [실행 로그](../../../result/test-runs/09.28/ai-context-benchmark/bank-related.log)
- [단계별 진단](../../../result/test-runs/09.28/ai-context-benchmark/bank-related/recon.jsonl)
- [분석한 고정 소스](../../../result/test-runs/09.28/ai-context-benchmark/related/src/aidast/recon/tools/api_secondary_discovery.py)

분석에 사용한 5개 frozen/overlay 파일의 SHA-256은 해당 실행의 Experiment.source_sha256과 모두 일치했다. 응답 본문·토큰·계좌번호 값은 진단 산출물에 저장하지 않았다.
