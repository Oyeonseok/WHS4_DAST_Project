# Recon 경로별 발견·누락 표

기준: 09.28 최신 `ai-context-benchmark`의 `related` 실행 Surface와 09.29 별도 GET 실측을 경로별로 대조했다. 두 실행의 시점과 요청 조건이 다르며, 새로운 Recon 재실측 결과는 아니다. 모든 경로는 GET이다.

“발견”은 최종 Surface에 포함되었다는 뜻이다. “원시 기록만 있음”은 HTTP 응답을 받았지만 Surface에 포함되지 않았다는 뜻이다. “미관측”은 해당 실행에서 응답 기록도 없었다는 뜻이다. 별도 GET 상태는 기존 일반 계정과 필요한 조회 파라미터를 사용한 결과이며, 접근 제한 경로도 포함한다.

| 대상 | 전체 정의 | Surface 발견 | 원시 기록만 있음 | 미관측 | 누락 중 별도 GET 200 |
|---|---:|---:|---:|---:|---:|
| OWASP Juice Shop | 71 | 58 | 3 | 10 | 5 |
| VulnBank | 47 | 22 | 12 | 13 | 9 |

## OWASP Juice Shop — 찾은 경로 (58개)

| 경로 | Recon 판정 | Recon 원시 응답 | 별도 인증 GET |
|---|---|---|---:|
| `/` | Surface 포함 | 200 | 200 |
| `/.well-known/security.txt` | Surface 포함 | 200 | 200 |
| `/api/Addresss` | Surface 포함 | 200 | 200 |
| `/api/Addresss/:id` | Surface 포함 | 200,400 | 200 |
| `/api/BasketItems` | Surface 포함 | 200 | 200 |
| `/api/BasketItems/:id` | Surface 포함 | 200,404 | 200 |
| `/api/Cards` | Surface 포함 | 200 | 200 |
| `/api/Cards/:id` | Surface 포함 | 200,400 | 200 |
| `/api/Challenges` | Surface 포함 | 200 | 200 |
| `/api/Challenges/:id` | Surface 포함 | 401 | 401 |
| `/api/Complaints` | Surface 포함 | 200 | 200 |
| `/api/Complaints/:id` | Surface 포함 | 401 | 401 |
| `/api/Deliverys` | Surface 포함 | 200 | 200 |
| `/api/Deliverys/:id` | Surface 포함 | 200,400 | 200 |
| `/api/Feedbacks` | Surface 포함 | 200 | 200 |
| `/api/Feedbacks/:id` | Surface 포함 | 200 | 200 |
| `/api/Hints` | Surface 포함 | 200 | 200 |
| `/api/Hints/:id` | Surface 포함 | 401 | 401 |
| `/api/Products` | Surface 포함 | 200 | 200 |
| `/api/Products/:id` | Surface 포함 | 200,404 | 200 |
| `/api/Quantitys` | Surface 포함 | 200 | 200 |
| `/api/Quantitys/:id` | Surface 포함 | 403 | 403 |
| `/api/Recycles` | Surface 포함 | 200 | 200 |
| `/api/SecurityQuestions` | Surface 포함 | 200 | 200 |
| `/api/SecurityQuestions/:id` | Surface 포함 | 401 | 401 |
| `/api/Users` | Surface 포함 | 200 | 200 |
| `/api/Users/:id` | Surface 포함 | 200,404 | 200 |
| `/profile` | Surface 포함 | 200 | 200 |
| `/promotion` | Surface 포함 | 200 | 200 |
| `/redirect` | Surface 포함 | 500 | 302 |
| `/rest/2fa/status` | Surface 포함 | 200 | 200 |
| `/rest/admin/application-configuration` | Surface 포함 | 200 | 200 |
| `/rest/admin/application-version` | Surface 포함 | 200 | 200 |
| `/rest/basket/:id` | Surface 포함 | 200,401 | 200 |
| `/rest/captcha` | Surface 포함 | 200 | 200 |
| `/rest/continue-code` | Surface 포함 | 200 | 200 |
| `/rest/continue-code-findIt` | Surface 포함 | 200 | 200 |
| `/rest/continue-code-fixIt` | Surface 포함 | 200 | 200 |
| `/rest/deluxe-membership` | Surface 포함 | 200 | 200 |
| `/rest/image-captcha` | Surface 포함 | 200 | 200 |
| `/rest/languages` | Surface 포함 | 200 | 200 |
| `/rest/memories` | Surface 포함 | 200 | 200 |
| `/rest/order-history` | Surface 포함 | 200 | 200 |
| `/rest/order-history/orders` | Surface 포함 | 403 | 403 |
| `/rest/products/:id/reviews` | Surface 포함 | 200 | 200 |
| `/rest/products/search` | Surface 포함 | 200 | 200 |
| `/rest/repeat-notification` | Surface 포함 | 200 | 200 |
| `/rest/saveLoginIp` | Surface 포함 | 200 | 200 |
| `/rest/user/authentication-details` | Surface 포함 | 200 | 200 |
| `/rest/user/security-question` | Surface 포함 | 200 | 200 |
| `/rest/user/whoami` | Surface 포함 | 200 | 200 |
| `/rest/wallet/balance` | Surface 포함 | 200 | 200 |
| `/rest/web3/nftMintListen` | Surface 포함 | 200 | 200 |
| `/rest/web3/nftUnlocked` | Surface 포함 | 200 | 200 |
| `/security.txt` | Surface 포함 | 200 | 200 |
| `/snippets/:challenge` | Surface 포함 | 200,404 | 200 |
| `/snippets/fixes/:key` | Surface 포함 | 200,404 | 200 |
| `/video` | Surface 포함 | 200 | 200 |

## OWASP Juice Shop — 최종 결과에서 못 찾은 경로 (13개)

| 경로 | Recon 판정 | Recon 원시 응답 | 별도 인증 GET |
|---|---|---|---:|
| `/api/PrivacyRequests` | 미관측 | 미관측 | 401 |
| `/api/PrivacyRequests/:id` | 미관측 | 미관측 | 401 |
| `/api/Recycles/:id` | 미관측 | 미관측 | 200 |
| `/api/SecurityAnswers` | 원시 기록만 있음 | 401 | 401 |
| `/api/SecurityAnswers/:id` | 미관측 | 미관측 | 401 |
| `/dataerasure` | 미관측 | 미관측 | 500 |
| `/metrics` | 미관측 | 미관측 | 200 |
| `/rest/country-mapping` | 원시 기록만 있음 | 500 | 500 |
| `/rest/track-order/:id` | 미관측 | 미관측 | 200 |
| `/rest/user/change-password` | 원시 기록만 있음 | 401 | 401 |
| `/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg` | 미관측 | 미관측 | 200 |
| `/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us` | 미관측 | 미관측 | 200 |
| `/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility` | 미관측 | 미관측 | 404 |

## VulnBank — 찾은 경로 (22개)

| 경로 | Recon 판정 | Recon 원시 응답 | 별도 인증 GET |
|---|---|---|---:|
| `/` | Surface 포함 | 200 | 200 |
| `/api/ai/rate-limit-status` | Surface 포함 | 200 | 200 |
| `/api/ai/system-info` | Surface 포함 | 200 | 200 |
| `/api/bill-categories` | Surface 포함 | 200 | 200 |
| `/api/billers/by-category/<int:category_id>` | Surface 포함 | 200 | 200 |
| `/api/v1/merchants/me` | Surface 포함 | 401 | 401 |
| `/api/v1/payments` | Surface 포함 | 401 | 401 |
| `/api/virtual-cards` | Surface 포함 | 200,401 | 200 |
| `/blog` | Surface 포함 | 200 | 200 |
| `/careers` | Surface 포함 | 200 | 200 |
| `/compliance` | Surface 포함 | 200 | 200 |
| `/dashboard` | Surface 포함 | 200 | 200 |
| `/forgot-password` | Surface 포함 | 200 | 200 |
| `/healthz` | Surface 포함 | 200 | 200 |
| `/login` | Surface 포함 | 200 | 200 |
| `/merchant` | Surface 포함 | 302 | 302 |
| `/merchant/login` | Surface 포함 | 200 | 200 |
| `/merchant/register` | Surface 포함 | 200 | 200 |
| `/privacy` | Surface 포함 | 200 | 200 |
| `/register` | Surface 포함 | 200 | 200 |
| `/terms` | Surface 포함 | 200 | 200 |
| `/transactions/<account_number>` | Surface 포함 | 200 | 200 |

## VulnBank — 최종 결과에서 못 찾은 경로 (25개)

| 경로 | Recon 판정 | Recon 원시 응답 | 별도 인증 GET |
|---|---|---|---:|
| `/api/bill-payments/history` | 원시 기록만 있음 | 401 | 200 |
| `/api/check_balance` | 미관측 | 미관측 | 401 |
| `/api/transactions` | 원시 기록만 있음 | 400,401 | 200 |
| `/api/v1/payments/<int:payment_id>` | 원시 기록만 있음 | 401 | 401 |
| `/api/v1/payments/merchant_id/<int:merchant_id>` | 원시 기록만 있음 | 401 | 401 |
| `/api/v3/user/<int:user_id>` | 미관측 | 미관측 | 200 |
| `/api/virtual-cards/<int:card_id>/transactions` | 원시 기록만 있음 | 401 | 200 |
| `/check_balance/<account_number>` | 원시 기록만 있음 | 404 | 200 |
| `/debug/users` | 미관측 | 미관측 | 200 |
| `/graphql` | 미관측 | 미관측 | 200 |
| `/internal/config.json` | 원시 기록만 있음 | 403 | 403 |
| `/internal/secret` | 원시 기록만 있음 | 403 | 403 |
| `/latest/meta-data/` | 원시 기록만 있음 | 403 | 403 |
| `/latest/meta-data/ami-id` | 미관측 | 미관측 | 403 |
| `/latest/meta-data/hostname` | 미관측 | 미관측 | 403 |
| `/latest/meta-data/iam/` | 미관측 | 미관측 | 403 |
| `/latest/meta-data/iam/security-credentials/` | 원시 기록만 있음 | 403 | 403 |
| `/latest/meta-data/iam/security-credentials/vulnbank-role` | 원시 기록만 있음 | 403 | 403 |
| `/latest/meta-data/instance-id` | 미관측 | 미관측 | 403 |
| `/latest/meta-data/local-ipv4` | 미관측 | 미관측 | 403 |
| `/latest/meta-data/public-ipv4` | 미관측 | 미관측 | 403 |
| `/latest/meta-data/security-groups` | 미관측 | 미관측 | 403 |
| `/merchant/dashboard` | 미관측 | 미관측 | 200 |
| `/reset-password` | 미관측 | 미관측 | 200 |
| `/sup3r_s3cr3t_admin` | 원시 기록만 있음 | 401 | 403 |

## 해석 시 주의

- 401/403·302·500이어도 경로에 대한 근거가 있으면 발견으로 집계될 수 있다. 발견 수는 성공 응답 수와 다르다.
- 별도 GET 200은 경로를 알고 직접 호출한 결과다. UI/JS에 발견 근거가 없는 숨겨진 경로도 있으므로 모두 자동 발견 가능했다고 단정하지 않는다.
- 본인 계좌번호를 제공한 `/api/transactions`는 200이었다. Recon에서는 인증된 요청의 계좌번호 부재(400)와 인증 없는 요청(401)을 확인했다.
- Juice Shop은 없는 경로에도 SPA HTML과 함께 200을 반환한다. 이번 별도 검증은 소스에 정의된 목록과 대조했다.
- 긴 Juice Shop 경로와 내부 metadata 경로도 개별 정의로 집계했으며 임의의 와일드카드 경로를 추가하지 않았다.

근거: [Recon 전체 비교](../../../result/test-runs/09.28/ai-context-benchmark/Comparison.json), [별도 GET 검증](GET_ROUTE_LIVE_CHECK.md).
