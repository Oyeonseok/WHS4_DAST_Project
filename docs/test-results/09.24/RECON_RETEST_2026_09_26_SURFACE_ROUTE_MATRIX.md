# Juice Shop Recon Surface GET route O/X 평가

O는 최종 Surface.json에 같은 origin의 GET 경로가 정답 route로 명시되어 있음을 뜻한다. `/api/:param` 같은 일반화 경로는 서로 다른 정적 route의 발견으로 세지 않는다. 이 표는 실제 HTTP 요청 관측과 별개로 최종 공격표면에 남은 경로를 평가한다.

| 실행 | Surface 보존 | 누락 |
| --- | ---: | ---: |
| browser-luna-full-1000 | 25/71 | 46 |
| recon-retest-pinned-policy-2026-09-26 | 18/71 | 53 |

| 정답 경로 | browser-luna-full-1000 O/X | recon-retest-pinned-policy-2026-09-26 O/X |
| --- | --- | --- |
| GET / | O | O |
| GET /.well-known/security.txt | X | X |
| GET /api/Addresss | O | X |
| GET /api/Addresss/:id | X | X |
| GET /api/BasketItems | O | X |
| GET /api/BasketItems/:id | X | X |
| GET /api/Cards | X | X |
| GET /api/Cards/:id | X | X |
| GET /api/Challenges | O | O |
| GET /api/Challenges/:id | X | X |
| GET /api/Complaints | O | X |
| GET /api/Complaints/:id | X | X |
| GET /api/Deliverys | X | X |
| GET /api/Deliverys/:id | X | X |
| GET /api/Feedbacks | O | O |
| GET /api/Feedbacks/:id | X | X |
| GET /api/Hints | X | X |
| GET /api/Hints/:id | X | X |
| GET /api/PrivacyRequests | X | X |
| GET /api/PrivacyRequests/:id | X | X |
| GET /api/Products | O | O |
| GET /api/Products/:id | X | X |
| GET /api/Quantitys | O | O |
| GET /api/Quantitys/:id | X | X |
| GET /api/Recycles | O | O |
| GET /api/Recycles/:id | X | X |
| GET /api/SecurityAnswers | X | X |
| GET /api/SecurityAnswers/:id | X | X |
| GET /api/SecurityQuestions | O | O |
| GET /api/SecurityQuestions/:id | X | X |
| GET /api/Users | O | X |
| GET /api/Users/:id | X | X |
| GET /dataerasure | X | X |
| GET /metrics | X | X |
| GET /profile | X | X |
| GET /promotion | X | X |
| GET /redirect | X | X |
| GET /rest/2fa/status | X | X |
| GET /rest/admin/application-configuration | O | O |
| GET /rest/admin/application-version | O | O |
| GET /rest/basket/:id | O | O |
| GET /rest/captcha | O | O |
| GET /rest/continue-code | O | O |
| GET /rest/continue-code-findIt | O | O |
| GET /rest/continue-code-fixIt | O | O |
| GET /rest/country-mapping | X | X |
| GET /rest/deluxe-membership | O | X |
| GET /rest/image-captcha | X | X |
| GET /rest/languages | O | O |
| GET /rest/memories | X | X |
| GET /rest/order-history | X | X |
| GET /rest/order-history/orders | X | X |
| GET /rest/products/:id/reviews | X | X |
| GET /rest/products/search | O | O |
| GET /rest/repeat-notification | O | O |
| GET /rest/saveLoginIp | O | X |
| GET /rest/track-order/:id | X | X |
| GET /rest/user/authentication-details | O | X |
| GET /rest/user/change-password | X | X |
| GET /rest/user/security-question | X | X |
| GET /rest/user/whoami | O | O |
| GET /rest/wallet/balance | X | X |
| GET /rest/web3/nftMintListen | X | X |
| GET /rest/web3/nftUnlocked | X | X |
| GET /security.txt | X | X |
| GET /snippets/:challenge | X | X |
| GET /snippets/fixes/:key | X | X |
| GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg | X | X |
| GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us | X | X |
| GET /video | X | X |
| GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility | X | X |

### browser-luna-full-1000 Surface 누락 경로

- `GET /.well-known/security.txt`
- `GET /api/Addresss/:id`
- `GET /api/BasketItems/:id`
- `GET /api/Cards`
- `GET /api/Cards/:id`
- `GET /api/Challenges/:id`
- `GET /api/Complaints/:id`
- `GET /api/Deliverys`
- `GET /api/Deliverys/:id`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /profile`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/country-mapping`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/track-order/:id`
- `GET /rest/user/change-password`
- `GET /rest/user/security-question`
- `GET /rest/wallet/balance`
- `GET /rest/web3/nftMintListen`
- `GET /rest/web3/nftUnlocked`
- `GET /security.txt`
- `GET /snippets/:challenge`
- `GET /snippets/fixes/:key`
- `GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg`
- `GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us`
- `GET /video`
- `GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility`

### recon-retest-pinned-policy-2026-09-26 Surface 누락 경로

- `GET /.well-known/security.txt`
- `GET /api/Addresss`
- `GET /api/Addresss/:id`
- `GET /api/BasketItems`
- `GET /api/BasketItems/:id`
- `GET /api/Cards`
- `GET /api/Cards/:id`
- `GET /api/Challenges/:id`
- `GET /api/Complaints`
- `GET /api/Complaints/:id`
- `GET /api/Deliverys`
- `GET /api/Deliverys/:id`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /profile`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/country-mapping`
- `GET /rest/deluxe-membership`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/saveLoginIp`
- `GET /rest/track-order/:id`
- `GET /rest/user/authentication-details`
- `GET /rest/user/change-password`
- `GET /rest/user/security-question`
- `GET /rest/wallet/balance`
- `GET /rest/web3/nftMintListen`
- `GET /rest/web3/nftUnlocked`
- `GET /security.txt`
- `GET /snippets/:challenge`
- `GET /snippets/fixes/:key`
- `GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg`
- `GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us`
- `GET /video`
- `GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility`
