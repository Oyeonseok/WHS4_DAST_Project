# GET 경로 실측 확인 (2026-09-29)

기존 집계 기준의 **경로 정의 수는 Juice Shop 71개, VulnBank 47개가 맞다.** 현재 실행 중인 컨테이너 소스와 목록을 대조했고, 모든 경로에 비로그인 및 기존 일반 사용자 로그인 상태로 실제 GET 요청을 보냈다. **HTTP 200을 확인한 경로는 이번 계정·설정·데이터 조건에서 각각 56개, 28개다.**

| 대상 | 정의된 경로 | 비로그인 200 | 일반 사용자 로그인 200 | 로그인 후 200 아님 |
|---|---:|---:|---:|---:|
| OWASP Juice Shop | 71 | 37 | 56 | 15 |
| VulnBank | 47 | 22 | 28 | 19 |

## 확인 조건

- 실측 시간: 2026-09-29 11:50:50 ~ 11:53:26 KST.
- 대상: `http://127.0.0.1:3001/`, `http://127.0.0.1:5001/`.
- 기존 테스트 계정을 정상 로그인했다. 신규 계정·카드·거래·비밀번호·권한을 생성하거나 변경하지 않았다. 앱 자체의 로그인 기록 및 GET 핸들러 부수 효과는 발생할 수 있다.
- ID 경로에는 기존 컬렉션/픽스처의 ID를 우선 사용하고, 수집할 수 없는 ID에는 `1`을 사용했다. 한 경로당 대표 URL을 검증한 것이며 모든 ID 조합을 검증한 것은 아니다.
- `/api/transactions`, `/api/check_balance`에는 본인 계좌번호, `/rest/user/security-question`에는 본인 이메일을 제공했다. 저장 결과에는 이메일·계좌번호·토큰·응답 본문을 남기지 않았다.
- 리다이렉트는 따라가지 않았다. `/redirect`의 허용 대상 파라미터는 지정했지만 외부 사이트로 요청하지 않았다. HTTP 302는 200으로 세지 않았다.
- 관리자·회계·merchant 별도 계정이나 컨테이너 내부 loopback 접속 조건은 사용하지 않았다. 따라서 200 개수는 이 조건에서의 관측값이며 가능한 최대값이 아니다.
- 소스 정의 경로가 분모다. 정적 파일, 임의 SPA URL, 프레임워크 자동 제공 경로(예: Swagger/static), Socket.IO 등을 모두 포함하는 URL 개수가 아니다.

## 200이 아닌 이유

Juice Shop (15개):

- 401 9개: `denyAll`로 차단된 상세/민감 경로 8개 및 `/rest/user/change-password`. 비밀번호 변경에 필요한 값을 넣어 변경 작업을 실행하지 않았다.
- 403 2개: `/api/Quantitys/:id`, `/rest/order-history/orders`의 권한/IP 조건.
- 500 2개: `/dataerasure`는 현재 계정의 security answer 부재(`No answer found!` 확인), `/rest/country-mapping`은 CTF country mapping 설정 부재.
- 302 1개: `/redirect?to=...`의 정상 리다이렉트. 파라미터 없이 최초 요청하면 500이었다.
- 404 1개: `/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility`의 정적 파일 반환 경로.

VulnBank (19개):

- 403 13개: 컨테이너 내부 loopback 전용 `/internal/*`, `/latest/meta-data/*` 12개와 관리자 페이지 1개. 호스트의 loopback 주소로 접속해도 컨테이너에서는 bridge 네트워크 요청으로 보인다.
- 401 5개: merchant 인증 필요 경로 4개, `/api/check_balance` 1개. 후자는 정상 로그인 및 본인 계좌번호를 제공해도 레거시 SQLite의 `no such table: users` 오류를 인증 데코레이터가 401로 감싸 반환했다.
- 302 1개: `/merchant`의 `/merchant/login` 리다이렉트.
- `/api/transactions`는 계좌번호 없이 400, 본인 계좌번호를 보완하면 200이었다. 최종 28개 집계에 포함했다.

## 200만으로 존재 판정하면 생기는 오탐

Juice Shop의 존재하지 않는 `/__aidast_get_route_check_missing_20260929__`도 Angular SPA HTML과 함께 200을 반환했다. VulnBank의 같은 대조 요청은 404였다. 따라서 Juice Shop은 **상태 코드와 소스 정의/응답 내용**을 함께 확인해야 한다. 이번 56개는 소스 정의 목록에 있는 경로에서 확인한 200이며, 정의된 `/` 외에는 임의 경로 대조 HTML과 동일한 본문 해시를 가진 200이 없었다. 응답 데이터의 비어 있음 등 업무상 성공 여부까지 보장하는 검증은 아니다.

## 소스 및 원시 결과

- Juice Shop: version `20.2.0`, image `bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`. 실행 중 compiled server의 명시적 GET, Finale 자동 API, mounted dataerasure GET, Angular `/`을 합쳐 71개이며 기존 목록과 정확히 일치했다.
- VulnBank: image `aidast-lab/vuln-bank:5e5ea5425fcf`. `app.py`, `auth.py`, `merchant_payments.py`의 GET 데코레이터 47개. 세 파일의 실행 컨테이너 SHA-256이 로컬 평가 소스와 모두 일치했다.
- [소스 목록 검증](../../../result/test-runs/09.29/get-route-verification/InventoryVerification.json)
- [기본 GET 요청 기록](../../../result/test-runs/09.29/get-route-verification/Requests.json)
- [필수 파라미터 보완 기록](../../../result/test-runs/09.29/get-route-verification/RequiredParameters.json)
- [최종 집계](../../../result/test-runs/09.29/get-route-verification/FinalSummary.json)
- 기본 목록 GET 236회, ID/대조 확인 GET 15회, 보완 및 신원 확인 GET 9회: 총 GET 260회. 정상 로그인 POST 4회. 타임아웃/연결 실패 없음.

## 전체 경로별 결과

필수 파라미터 보완 결과가 있으면 마지막 결과를 표시했다. 구체적 요청 URL은 원시 기록에 있으며 이메일·계좌번호는 가렸다.

### OWASP Juice Shop

| 경로 패턴 | 비로그인 | 일반 사용자 로그인 |
|---|---:|---:|
| `GET /` | 200 | 200 |
| `GET /.well-known/security.txt` | 200 | 200 |
| `GET /api/Addresss` | 401 | 200 |
| `GET /api/Addresss/:id` | 401 | 200 |
| `GET /api/BasketItems` | 401 | 200 |
| `GET /api/BasketItems/:id` | 401 | 200 |
| `GET /api/Cards` | 401 | 200 |
| `GET /api/Cards/:id` | 401 | 200 |
| `GET /api/Challenges` | 200 | 200 |
| `GET /api/Challenges/:id` | 401 | 401 |
| `GET /api/Complaints` | 401 | 200 |
| `GET /api/Complaints/:id` | 401 | 401 |
| `GET /api/Deliverys` | 200 | 200 |
| `GET /api/Deliverys/:id` | 200 | 200 |
| `GET /api/Feedbacks` | 200 | 200 |
| `GET /api/Feedbacks/:id` | 401 | 200 |
| `GET /api/Hints` | 200 | 200 |
| `GET /api/Hints/:id` | 401 | 401 |
| `GET /api/PrivacyRequests` | 401 | 401 |
| `GET /api/PrivacyRequests/:id` | 401 | 401 |
| `GET /api/Products` | 200 | 200 |
| `GET /api/Products/:id` | 200 | 200 |
| `GET /api/Quantitys` | 200 | 200 |
| `GET /api/Quantitys/:id` | 403 | 403 |
| `GET /api/Recycles` | 200 | 200 |
| `GET /api/Recycles/:id` | 200 | 200 |
| `GET /api/SecurityAnswers` | 401 | 401 |
| `GET /api/SecurityAnswers/:id` | 401 | 401 |
| `GET /api/SecurityQuestions` | 200 | 200 |
| `GET /api/SecurityQuestions/:id` | 401 | 401 |
| `GET /api/Users` | 401 | 200 |
| `GET /api/Users/:id` | 401 | 200 |
| `GET /dataerasure` | 500 | 500 |
| `GET /metrics` | 200 | 200 |
| `GET /profile` | 500 | 200 |
| `GET /promotion` | 200 | 200 |
| `GET /redirect` | 302 | 302 |
| `GET /rest/2fa/status` | 401 | 200 |
| `GET /rest/admin/application-configuration` | 200 | 200 |
| `GET /rest/admin/application-version` | 200 | 200 |
| `GET /rest/basket/:id` | 401 | 200 |
| `GET /rest/captcha` | 200 | 200 |
| `GET /rest/continue-code` | 200 | 200 |
| `GET /rest/continue-code-findIt` | 200 | 200 |
| `GET /rest/continue-code-fixIt` | 200 | 200 |
| `GET /rest/country-mapping` | 500 | 500 |
| `GET /rest/deluxe-membership` | 400 | 200 |
| `GET /rest/image-captcha` | 401 | 200 |
| `GET /rest/languages` | 200 | 200 |
| `GET /rest/memories` | 200 | 200 |
| `GET /rest/order-history` | 500 | 200 |
| `GET /rest/order-history/orders` | 403 | 403 |
| `GET /rest/products/:id/reviews` | 200 | 200 |
| `GET /rest/products/search` | 200 | 200 |
| `GET /rest/repeat-notification` | 200 | 200 |
| `GET /rest/saveLoginIp` | 401 | 200 |
| `GET /rest/track-order/:id` | 200 | 200 |
| `GET /rest/user/authentication-details` | 401 | 200 |
| `GET /rest/user/change-password` | 401 | 401 |
| `GET /rest/user/security-question` | 200 | 200 |
| `GET /rest/user/whoami` | 200 | 200 |
| `GET /rest/wallet/balance` | 401 | 200 |
| `GET /rest/web3/nftMintListen` | 200 | 200 |
| `GET /rest/web3/nftUnlocked` | 200 | 200 |
| `GET /security.txt` | 200 | 200 |
| `GET /snippets/:challenge` | 200 | 200 |
| `GET /snippets/fixes/:key` | 200 | 200 |
| `GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg` | 200 | 200 |
| `GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us` | 200 | 200 |
| `GET /video` | 200 | 200 |
| `GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility` | 404 | 404 |

### VulnBank

| 경로 패턴 | 비로그인 | 일반 사용자 로그인 |
|---|---:|---:|
| `GET /` | 200 | 200 |
| `GET /api/ai/rate-limit-status` | 200 | 200 |
| `GET /api/ai/system-info` | 200 | 200 |
| `GET /api/bill-categories` | 200 | 200 |
| `GET /api/bill-payments/history` | 401 | 200 |
| `GET /api/billers/by-category/<int:category_id>` | 200 | 200 |
| `GET /api/check_balance` | 401 | 401 |
| `GET /api/transactions` | 401 | 200 |
| `GET /api/v1/merchants/me` | 401 | 401 |
| `GET /api/v1/payments` | 401 | 401 |
| `GET /api/v1/payments/<int:payment_id>` | 401 | 401 |
| `GET /api/v1/payments/merchant_id/<int:merchant_id>` | 401 | 401 |
| `GET /api/v3/user/<int:user_id>` | 401 | 200 |
| `GET /api/virtual-cards` | 401 | 200 |
| `GET /api/virtual-cards/<int:card_id>/transactions` | 401 | 200 |
| `GET /blog` | 200 | 200 |
| `GET /careers` | 200 | 200 |
| `GET /check_balance/<account_number>` | 200 | 200 |
| `GET /compliance` | 200 | 200 |
| `GET /dashboard` | 401 | 200 |
| `GET /debug/users` | 200 | 200 |
| `GET /forgot-password` | 200 | 200 |
| `GET /graphql` | 200 | 200 |
| `GET /healthz` | 200 | 200 |
| `GET /internal/config.json` | 403 | 403 |
| `GET /internal/secret` | 403 | 403 |
| `GET /latest/meta-data/` | 403 | 403 |
| `GET /latest/meta-data/ami-id` | 403 | 403 |
| `GET /latest/meta-data/hostname` | 403 | 403 |
| `GET /latest/meta-data/iam/` | 403 | 403 |
| `GET /latest/meta-data/iam/security-credentials/` | 403 | 403 |
| `GET /latest/meta-data/iam/security-credentials/vulnbank-role` | 403 | 403 |
| `GET /latest/meta-data/instance-id` | 403 | 403 |
| `GET /latest/meta-data/local-ipv4` | 403 | 403 |
| `GET /latest/meta-data/public-ipv4` | 403 | 403 |
| `GET /latest/meta-data/security-groups` | 403 | 403 |
| `GET /login` | 200 | 200 |
| `GET /merchant` | 302 | 302 |
| `GET /merchant/dashboard` | 200 | 200 |
| `GET /merchant/login` | 200 | 200 |
| `GET /merchant/register` | 200 | 200 |
| `GET /privacy` | 200 | 200 |
| `GET /register` | 200 | 200 |
| `GET /reset-password` | 200 | 200 |
| `GET /sup3r_s3cr3t_admin` | 401 | 403 |
| `GET /terms` | 200 | 200 |
| `GET /transactions/<account_number>` | 200 | 200 |
