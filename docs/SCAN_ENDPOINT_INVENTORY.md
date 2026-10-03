# VulnBank 및 OWASP Juice Shop 발견 엔드포인트

이 문서는 지정된 완료 스캔의 `Pipeline.db`에서 엔드포인트를 다시 추출한 결과다. 공개 기준 목록이나 소스 코드를 섞지 않았으며, 각 스캔이 실제로 저장한 데이터만 사용했다.

## 읽는 방법

- `verified`: HTTP 관측 등으로 검증된 좌표
- `observed`: 도구가 관측했지만 검증 수준이 `verified`보다 낮은 좌표
- `candidate`: JavaScript·선언·경로 추론 등에서 얻은 후보 좌표
- `정책 제외`: 해당 스캔의 TargetPolicy 때문에 능동 요청 대상에서 제외된 좌표
- `인증`: 두 DB 모두 `auth_required`가 전부 `NULL`이므로 “로그인 불필요”가 아니라 “인증 요구 여부 미판정”을 뜻한다.
- 파라미터는 이름·위치·타입만 싣고 예시 값, 쿠키, 토큰, 요청·응답 본문은 포함하지 않았다.

## 요약

| 대상 | Scan ID | 전체 | Application | Static/support | Runtime support | Verified | Observed | Candidate | 정책 제외 | 파라미터 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OWASP Juice Shop | `scan_e8d30106b1f5497db2edcb41f1bb262a` | 173 | 165 | 6 | 2 | 32 | 13 | 128 | 70 | 86개 엔드포인트 |
| VulnBank | `scan_ab41e72d3ac649b6ac305af304d07311` | 210 | 90 | 120 | 0 | 24 | 124 | 62 | 142 | 39개 엔드포인트 |

전체 원본 인벤토리는 CSV로도 제공한다.

- [Juice Shop CSV](endpoint-inventory/juice-shop-scan_e8d30106b1f5497db2edcb41f1bb262a-endpoints.csv)
- [VulnBank CSV](endpoint-inventory/vulnbank-scan_ab41e72d3ac649b6ac305af304d07311-endpoints.csv)

## OWASP Juice Shop

- Scan ID: `scan_e8d30106b1f5497db2edcb41f1bb262a`
- DB: `AttackRuns/lab-aidast-invalid/juice-shop-5001/scan_e8d30106b1f5497db2edcb41f1bb262a/Pipeline.db`

메서드 분포: `DELETE` 17, `GET` 83, `PATCH` 15, `POST` 34, `PUT` 24

### Application endpoints (165)

| Method | Path | 상태 | 정책 | HTTP | 파라미터 | 발견 출처 |
|---|---|---|---|---|---|---|
| GET | `/` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction,playwright_runtime |
| GET | `/%7B%7Bhref%7D%7D` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/Addresss` | candidate | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| POST | `/api/Addresss` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| DELETE | `/api/Addresss/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/api/Addresss/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Addresss/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Addresss/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Addresss/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Addresss/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/BasketItems` | candidate | 제외: unverified_candidate | 401 | - | mitmproxy,passive_route_inference |
| POST | `/api/BasketItems` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| DELETE | `/api/BasketItems/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/api/BasketItems/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/BasketItems/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/BasketItems/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/BasketItems/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/BasketItems/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Cards` | candidate | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| POST | `/api/Cards` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| GET | `/api/Cards/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Cards/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Cards/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Cards/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Cards/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Challenges` | verified | 허용 범위 | 200 | query:key (string); query:name (string) | adaptive_js,mitmproxy,observed_json_recovery,passive_route_inference,playwright_interaction |
| POST | `/api/Challenges` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/Challenges/:id` | observed | 허용 범위 | 401 | - | adaptive_collection_detail,mitmproxy |
| DELETE | `/api/Challenges/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Challenges/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Challenges/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Challenges/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Complaints` | candidate | 제외: unverified_candidate | 401 | - | mitmproxy,passive_route_inference |
| POST | `/api/Complaints` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| DELETE | `/api/Complaints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Complaints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Complaints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Complaints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Deliverys` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| POST | `/api/Deliverys` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/Deliverys/:id` | verified | 허용 범위 | 200 | - | adaptive_collection_detail,adaptive_js_template,mitmproxy |
| GET | `/api/Deliverys/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Deliverys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Deliverys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Deliverys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Deliverys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Feedbacks` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy,passive_route_inference |
| POST | `/api/Feedbacks` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| GET | `/api/Feedbacks/:id` | observed | 허용 범위 | 401 | - | adaptive_collection_detail,mitmproxy |
| DELETE | `/api/Feedbacks/{a}` | candidate | 허용 범위 | - | path:a (string) | adaptive_js |
| DELETE | `/api/Feedbacks/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Feedbacks/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Feedbacks/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Feedbacks/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Hints` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy,passive_route_inference |
| POST | `/api/Hints` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/Hints/:id` | observed | 허용 범위 | 401 | - | adaptive_collection_detail,mitmproxy |
| PUT | `/api/Hints/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Hints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Hints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Hints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Hints/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Products` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy,passive_route_inference |
| POST | `/api/Products` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/Products/:id` | verified | 허용 범위 | 200 | - | adaptive_collection_detail,mitmproxy |
| PUT | `/api/Products/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Products/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Products/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Products/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Products/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Quantitys` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy,passive_route_inference,playwright_interaction |
| POST | `/api/Quantitys` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/Quantitys/:id` | observed | 허용 범위 | 403 | - | adaptive_collection_detail,adaptive_js_detail_candidate,mitmproxy |
| PUT | `/api/Quantitys/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Quantitys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Quantitys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Quantitys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Quantitys/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Recycles` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy,passive_route_inference |
| POST | `/api/Recycles` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| DELETE | `/api/Recycles/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Recycles/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Recycles/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Recycles/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/SecurityAnswers` | candidate | 제외: unverified_candidate | 401 | - | mitmproxy,passive_route_inference |
| POST | `/api/SecurityAnswers` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| DELETE | `/api/SecurityAnswers/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/SecurityAnswers/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/SecurityAnswers/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/SecurityAnswers/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/SecurityQuestions` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy,passive_route_inference |
| POST | `/api/SecurityQuestions` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/SecurityQuestions/:id` | observed | 허용 범위 | 401 | - | adaptive_collection_detail,mitmproxy |
| DELETE | `/api/SecurityQuestions/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/SecurityQuestions/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/SecurityQuestions/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/SecurityQuestions/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Users` | candidate | 제외: unverified_candidate | 401 | - | mitmproxy,passive_route_inference |
| POST | `/api/Users` | candidate | 허용 범위 | - | - | adaptive_js,passive_route_inference |
| GET | `/api/Users/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| DELETE | `/api/Users/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| GET | `/api/Users/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PATCH | `/api/Users/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| PUT | `/api/Users/{id}` | candidate | 제외: unverified_candidate | - | path:id (string) [id] | passive_route_inference |
| POST | `/b2b/v2/orders` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/dataerasure` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/file-upload` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/profile` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/redirect` | candidate | 허용 범위 | - | query:to (string) | adaptive_js |
| POST | `/rest/2fa/disable` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/2fa/setup` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/2fa/status` | candidate | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| POST | `/rest/2fa/verify` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/admin/application-configuration` | observed | 허용 범위 | - | - | adaptive_js,playwright_interaction |
| GET | `/rest/admin/application-version` | observed | 허용 범위 | - | - | adaptive_js,playwright_interaction |
| GET | `/rest/basket/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| POST | `/rest/basket/{e}/checkout` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| PUT | `/rest/basket/{e}/coupon/{i}` | candidate | 허용 범위 | - | path:e (string); path:i (string) | adaptive_js |
| GET | `/rest/captcha` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| POST | `/rest/chat` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/continue-code` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| GET | `/rest/continue-code-findIt` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| PUT | `/rest/continue-code-findIt/apply/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/rest/continue-code-fixIt` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| PUT | `/rest/continue-code-fixIt/apply/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| PUT | `/rest/continue-code/apply/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/rest/country-mapping` | candidate | 허용 범위 | 500 | - | adaptive_js,mitmproxy |
| GET | `/rest/deluxe-membership` | candidate | 허용 범위 | 400 | - | adaptive_js,mitmproxy |
| POST | `/rest/deluxe-membership` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/image-captcha` | candidate | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| GET | `/rest/languages` | observed | 허용 범위 | - | - | adaptive_js,playwright_interaction |
| GET | `/rest/memories` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| POST | `/rest/memories` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/order-history` | candidate | 허용 범위 | 500 | - | adaptive_js,mitmproxy |
| GET | `/rest/order-history/orders` | observed | 허용 범위 | 403 | - | adaptive_js,mitmproxy |
| PUT | `/rest/order-history/{e}/delivery-status` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/rest/products/:id/reviews` | verified | 허용 범위 | 200 | - | adaptive_js_template,mitmproxy |
| PATCH | `/rest/products/reviews` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/products/reviews` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/products/search` | observed | 허용 범위 | - | query:q (string) | adaptive_js,playwright_interaction |
| GET | `/rest/products/{e}/reviews` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| PUT | `/rest/products/{e}/reviews` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/rest/repeat-notification` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| GET | `/rest/saveLoginIp` | observed | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| GET | `/rest/track-order/{e}` | candidate | 허용 범위 | - | path:e (string) | adaptive_js |
| GET | `/rest/user/authentication-details` | candidate | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| GET | `/rest/user/change-password` | candidate | 허용 범위 | 401 | query:current (string) | adaptive_js,mitmproxy |
| POST | `/rest/user/data-export` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/user/erasure-request` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/user/login` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/user/reset-password` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/user/security-question` | verified | 허용 범위 | 200 | query:email (string) | adaptive_js,mitmproxy |
| GET | `/rest/user/whoami` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| GET | `/rest/wallet/balance` | candidate | 허용 범위 | 401 | - | adaptive_js,mitmproxy |
| PUT | `/rest/wallet/balance` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/rest/web3/nftMintListen` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| GET | `/rest/web3/nftUnlocked` | verified | 허용 범위 | 200 | - | adaptive_js,mitmproxy |
| POST | `/rest/web3/submitKey` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/web3/walletExploitAddress` | candidate | 허용 범위 | - | - | adaptive_js |
| POST | `/rest/web3/walletNFTVerify` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/snippets/:param` | verified | 허용 범위 | 200,404 | path:t (string) | adaptive_js,adaptive_js_detail_candidate,adaptive_js_response_argument,mitmproxy |
| GET | `/snippets/debug/users` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| POST | `/snippets/fixes` | candidate | 허용 범위 | - | - | adaptive_js |
| GET | `/snippets/fixes/:param` | verified | 허용 범위 | 200,404 | path:t (string) | adaptive_js,adaptive_js_detail_candidate,adaptive_js_response_argument,mitmproxy |
| POST | `/snippets/verdict` | candidate | 허용 범위 | - | - | adaptive_js |

### Runtime support endpoints (2)

| Method | Path | 상태 | 정책 | HTTP | 파라미터 | 발견 출처 |
|---|---|---|---|---|---|---|
| GET | `/socket.io` | verified | 허용 범위 | 200 | query:EIO (integer); query:sid (string); query:t (string); query:transport (string) | mitmproxy,playwright_interaction |
| POST | `/socket.io` | observed | 허용 범위 | - | query:EIO (string); query:sid (string); query:t (string); query:transport (string) | playwright_interaction |

### Static 및 문서 자원 (6)

| Method | Path | 상태 | 정책 | HTTP | 파라미터 | 발견 출처 |
|---|---|---|---|---|---|---|
| GET | `/assets/i18n/en.json` | observed | 허용 범위 | - | - | playwright_interaction |
| GET | `/main.js` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/polyfills.js` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/scripts.js` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/snippets/.well-known/security.txt` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| GET | `/styles.css` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |

## VulnBank

- Scan ID: `scan_ab41e72d3ac649b6ac305af304d07311`
- DB: `AttackRuns/lab-aidast-invalid/vuln-bank/scan_ab41e72d3ac649b6ac305af304d07311/Pipeline.db`

메서드 분포: `GET` 178, `POST` 32

### Application endpoints (90)

| Method | Path | 상태 | 정책 | HTTP | 파라미터 | 발견 출처 |
|---|---|---|---|---|---|---|
| GET | `/` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_runtime |
| GET | `/.env` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| GET | `/.env.bak` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| POST | `/admin/approve_loan/{loan_id}` | candidate | 허용 범위 | - | path:loan_id (integer) [id] | passive_declaration |
| POST | `/admin/create_admin` | candidate | 허용 범위 | - | json:password (string); json:username (string) | passive_declaration |
| POST | `/admin/delete_account/{user_id}` | candidate | 허용 범위 | - | path:user_id (integer) [id] | passive_declaration |
| POST | `/api/ai/chat` | candidate | 허용 범위 | - | json:message (string) | passive_declaration |
| GET | `/api/ai/chat/anonymous` | observed | 허용 범위 | 405 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| POST | `/api/ai/chat/anonymous` | candidate | 허용 범위 | - | json:message (string) | adaptive_js |
| GET | `/api/ai/system-info` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/api/bill-categories` | candidate | 허용 범위 | - | - | passive_declaration |
| POST | `/api/bill-payments/create` | candidate | 허용 범위 | - | json:amount (number); json:biller_id (integer) [id]; json:card_id (integer) [id]; json:description (string); json:payment_method (string) | passive_declaration |
| GET | `/api/bill-payments/history` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/api/billers/by-category/{category_id}` | candidate | 허용 범위 | - | path:category_id (integer) [id] | passive_declaration |
| GET | `/api/check_balance` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/check_balance/{account_number}` | candidate | 제외: unverified_candidate | - | path:account_number (string) | passive_route_inference |
| GET | `/api/docs` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/e.json%7C%7CH.call%28n,o%29%7C%7C%21H.call%28t,o%29%7C%7C%28e.line=i%7C%7Ce.line,e.lineStart=s%7C%7Ce.lineStart,e.position=u%7C%7Ce.position,ce%28e,` | observed | 허용 범위 | - | - | katana_auth_standard |
| GET | `/api/docs/oauth2-redirect.html` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/t.json%7C%7Cxe.call%28r,i%29%7C%7C%21xe.call%28e,i%29%7C%7C%28t.line=s%7C%7Ct.line,t.lineStart=u%7C%7Ct.lineStart,t.position=a%7C%7Ct.position,Qe%28t,` | observed | 허용 범위 | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| POST | `/api/login` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| POST | `/api/register` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| POST | `/api/request_loan` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/sup3r_s3cr3t_admin` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/api/transactions` | candidate | 허용 범위 | - | query:account_number (string) | passive_declaration |
| GET | `/api/transactions/{account_number}` | candidate | 제외: unverified_candidate | - | path:account_number (string) | passive_route_inference |
| POST | `/api/transfer` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| POST | `/api/upload_profile_picture` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| POST | `/api/upload_profile_picture_url` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| POST | `/api/v1/forgot-password` | candidate | 허용 범위 | - | json:username (string); path:version (integer) | passive_declaration |
| POST | `/api/v1/merchants/login` | candidate | 허용 범위 | - | json:email (string); json:password (string) | adaptive_js |
| GET | `/api/v1/merchants/me` | observed | 허용 범위 | 401 | - | adaptive_js,mitmproxy,passive_declaration |
| POST | `/api/v1/merchants/register` | candidate | 허용 범위 | - | json:email (string); json:name (string); json:password (string) | adaptive_js |
| GET | `/api/v1/payments` | observed | 허용 범위 | 401 | - | adaptive_js,mitmproxy,passive_declaration |
| POST | `/api/v1/payments/charge` | candidate | 허용 범위 | - | json:amount (number); json:card_number (string); json:currency (string); json:cvv (string); json:description (string); json:expiry_date (string); json:merchant_order_id (string) [id] | adaptive_js |
| GET | `/api/v1/payments/merchant_id/{merchant_id}` | candidate | 허용 범위 | - | path:merchant_id (integer) [id] | passive_declaration |
| GET | `/api/v1/payments/{payment_id}` | candidate | 허용 범위 | - | path:payment_id (integer) [id] | passive_declaration |
| POST | `/api/v1/reset-password` | candidate | 허용 범위 | - | json:new_password (string); json:reset_pin (string); json:username (string); path:version (integer) | passive_declaration |
| POST | `/api/v2/forgot-password` | candidate | 허용 범위 | - | json:username (string); path:version (integer) | passive_declaration |
| POST | `/api/v2/reset-password` | candidate | 허용 범위 | - | json:new_password (string); json:reset_pin (string); json:username (string); path:version (integer) | passive_declaration |
| GET | `/api/v3/forgot-password` | observed | 허용 범위 | 405 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| POST | `/api/v3/forgot-password` | candidate | 허용 범위 | - | json:username (string); path:version (integer) | adaptive_js |
| POST | `/api/v3/reset-password` | candidate | 허용 범위 | - | json:new_password (string); json:reset_pin (string); json:username (string); path:version (integer) | adaptive_js,passive_declaration |
| GET | `/api/virtual-cards` | candidate | 허용 범위 | - | - | passive_declaration |
| POST | `/api/virtual-cards/create` | candidate | 허용 범위 | - | json:card_limit (number); json:card_type (string) | passive_declaration |
| POST | `/api/virtual-cards/{card_id}/toggle-freeze` | candidate | 허용 범위 | - | path:card_id (integer) [id] | passive_declaration |
| GET | `/api/virtual-cards/{card_id}/transactions` | candidate | 허용 범위 | - | path:card_id (integer) [id] | passive_declaration |
| POST | `/api/virtual-cards/{card_id}/update-limit` | candidate | 허용 범위 | - | json:limit (number); path:card_id (integer) [id] | passive_declaration |
| GET | `/blog` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/careers` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/check_balance/{account_number}` | candidate | 허용 범위 | - | path:account_number (string) | passive_declaration |
| GET | `/compliance` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/dashboard` | observed | 허용 범위 | 401 | - | ffuf,mitmproxy |
| GET | `/debug/users` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| GET | `/forgot-password` | verified | 허용 범위 | 200 | query:username (string) | ffuf,katana_auth_standard,mitmproxy,passive_declaration,passive_route_inference,playwright_interaction |
| POST | `/forgot-password` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/graphql` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| GET | `/healthz` | verified | 허용 범위 | 200 | - | ffuf,mitmproxy |
| GET | `/internal/config.json` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/internal/secret` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/latest/meta-data` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/latest/meta-data/ami-id` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/latest/meta-data/hostname` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/latest/meta-data/iam` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/latest/meta-data/iam/security-credentials` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/latest/meta-data/iam/security-credentials/vulnbank-role` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/latest/meta-data/instance-id` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/latest/meta-data/local-ipv4` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/latest/meta-data/public-ipv4` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/latest/meta-data/security-groups` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/login` | verified | 허용 범위 | 200 | query:password (string); query:username (string) | ffuf,katana_auth_standard,mitmproxy,passive_declaration,passive_route_inference,playwright_interaction |
| POST | `/login` | candidate | 허용 범위 | - | json:password (string); json:username (string) | adaptive_js |
| GET | `/merchant` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/merchant/dashboard` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/merchant/login` | verified | 허용 범위 | 200 | query:email (string); query:password (string) | katana_auth_standard,mitmproxy,passive_declaration,passive_route_inference,playwright_interaction |
| GET | `/merchant/register` | verified | 허용 범위 | 200 | query:email (string); query:name (string); query:password (string) | katana_auth_standard,mitmproxy,passive_declaration,passive_route_inference,playwright_interaction |
| GET | `/oauth2-redirect.html` | observed | 허용 범위 | - | - | katana_auth_standard |
| GET | `/privacy` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/register` | verified | 허용 범위 | 200 | query:password (string); query:username (string) | ffuf,katana_auth_standard,mitmproxy,passive_declaration,passive_route_inference,playwright_interaction |
| POST | `/register` | candidate | 허용 범위 | - | json:password (string); json:username (string) | adaptive_js |
| POST | `/request_loan` | candidate | 허용 범위 | - | json:amount (number) | passive_declaration |
| GET | `/reset-password` | verified | 허용 범위 | 200 | query:new_password (string); query:reset_pin (string); query:username (string) | ffuf,mitmproxy,passive_declaration,passive_route_inference |
| POST | `/reset-password` | candidate | 제외: unverified_candidate | - | - | passive_route_inference |
| GET | `/static/:param` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/sup3r_s3cr3t_admin` | candidate | 허용 범위 | - | - | passive_declaration |
| GET | `/terms` | verified | 허용 범위 | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/transactions/{account_number}` | candidate | 허용 범위 | - | path:account_number (string) | passive_declaration |
| POST | `/transfer` | candidate | 허용 범위 | - | json:amount (number); json:description (string); json:to_account (string) | passive_declaration |
| POST | `/upload_profile_picture` | candidate | 허용 범위 | - | form:profile_picture (string) | passive_declaration |
| POST | `/upload_profile_picture_url` | candidate | 허용 범위 | - | json:image_url (string) | passive_declaration |

### Runtime support endpoints (0)

| Method | Path | 상태 | 정책 | HTTP | 파라미터 | 발견 출처 |
|---|---|---|---|---|---|---|

### Static 및 문서 자원 (120)

| Method | Path | 상태 | 정책 | HTTP | 파라미터 | 발견 출처 |
|---|---|---|---|---|---|---|
| GET | `/api/docs/all.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/auth/actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/auth/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/auth/reducers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/auth/selectors.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/auth/spec-wrap-actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/configs/actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/configs/helpers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/configs/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/configs/reducers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/configs/selectors.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/configs/spec-actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/core/plugins/all.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/auth/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/auth/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/auth/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/auth/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/auth/spec-wrap-actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/configs/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/configs/helpers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/configs/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/configs/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/configs/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/configs/spec-actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/deep-linking/helpers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/deep-linking/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/deep-linking/layout.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/download-url.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/error-transformers/hook.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/error-transformers/transformers/not-of-type.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/error-transformers/transformers/parameter-oneof.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/err/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/filter/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/filter/opsFilter.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/layout/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/layout/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/layout/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/layout/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/layout/spec-extensions/wrap-selector.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/logs/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/auth-extensions/wrap-selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/components/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/spec-extensions/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/spec-extensions/wrap-selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/wrap-components/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/oas3/wrap-components/online-validator-badge.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/on-complete/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/request-snippets/fn.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/request-snippets/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/request-snippets/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/safe-render/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/samples/fn.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/samples/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/spec/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/spec/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/spec/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/spec/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/spec/wrap-actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/swagger-js/configs-wrap-actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/core/plugins/swagger-js/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/core/plugins/util/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/view/fn.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/core/plugins/view/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/deep-linking/helpers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/deep-linking/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/deep-linking/layout.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/download-url.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/err/actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/err/error-transformers/hook.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/err/error-transformers/transformers/not-of-type.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/err/error-transformers/transformers/parameter-oneof.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/err/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/err/reducers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/err/selectors.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/filter/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/filter/opsFilter.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/index.css` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/layout/actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/layout/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/layout/reducers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/layout/selectors.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/layout/spec-extensions/wrap-selector.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/logs/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/auth-extensions/wrap-selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/oas3/components/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/reducers.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/selectors.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/spec-extensions/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/oas3/spec-extensions/wrap-selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/oas3/wrap-components/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/oas3/wrap-components/online-validator-badge.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/on-complete/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/request-snippets/fn.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/request-snippets/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/request-snippets/selectors.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/safe-render/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/samples/fn.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/samples/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/spec/actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/spec/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/spec/reducers.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/spec/selectors.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/spec/wrap-actions.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/swagger-js/configs-wrap-actions.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/swagger-js/index.js` | observed | 제외: static_asset | 404 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/swagger-ui-bundle.js` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/swagger-ui-standalone-preset.js` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy,playwright_interaction |
| GET | `/api/docs/swagger-ui.css` | verified | 제외: static_asset | 200 | - | katana_auth_standard,mitmproxy |
| GET | `/api/docs/util/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/view/fn.js` | observed | 제외: static_asset | - | - | katana_auth_standard |
| GET | `/api/docs/view/index.js` | observed | 제외: static_asset | - | - | katana_auth_standard |

