# Juice Shop Recon GET route O/X 평가

기준: `http://127.0.0.1:3001/`의 명시적 application GET route 71개. O는 Recon DB에 같은 origin의 비제외 GET HTTP 요청 URL과 응답이 일치하는 경로가 있다는 뜻이다. 경로는 Express 기본 설정에 맞춰 대소문자를 구분하지 않는다. HTTP 500도 경로 관측 O로 표시하며 정상 동작을 뜻하지 않는다. 정적 파일, generic middleware, SPA fallback URL은 정답지에 포함하지 않는다.

| 실행 | 발견 | 누락 |
| --- | ---: | ---: |
| no-ffuf-150 | 9/71 | 62 |
| smoke-ffuf-150 | 9/71 | 62 |
| smoke-ffuf-300 | 12/71 | 59 |
| seclists-api-500 | 10/71 | 61 |
| seclists-api-1000 | 9/71 | 62 |
| spa-refactor-1000 | 25/71 | 46 |
| path-normalization-1000 | 25/71 | 46 |

| 정답 경로 | no-ffuf-150 O/X | no-ffuf-150 HTTP | smoke-ffuf-150 O/X | smoke-ffuf-150 HTTP | smoke-ffuf-300 O/X | smoke-ffuf-300 HTTP | seclists-api-500 O/X | seclists-api-500 HTTP | seclists-api-1000 O/X | seclists-api-1000 HTTP | spa-refactor-1000 O/X | spa-refactor-1000 HTTP | path-normalization-1000 O/X | path-normalization-1000 HTTP |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GET / | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /.well-known/security.txt | X | — | X | — | O | 200 | X | — | X | — | X | — | X | — |
| GET /api/Addresss | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/Addresss/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/BasketItems | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/BasketItems/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Cards | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Cards/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Challenges | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /api/Challenges/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Complaints | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/Complaints/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Deliverys | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Deliverys/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Feedbacks | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/Feedbacks/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Hints | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Hints/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/PrivacyRequests | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/PrivacyRequests/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Products | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/Products/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Quantitys | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /api/Quantitys/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Recycles | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/Recycles/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/SecurityAnswers | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/SecurityAnswers/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/SecurityQuestions | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/SecurityQuestions/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /api/Users | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /api/Users/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /dataerasure | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /metrics | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /profile | X | — | X | — | O | 500 | X | — | X | — | X | — | X | — |
| GET /promotion | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /redirect | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/2fa/status | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/admin/application-configuration | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /rest/admin/application-version | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /rest/basket/:id | O | 200 | O | 200 | O | 200, 401 | O | 200, 401 | O | 200, 401 | O | 200, 401 | O | 200, 401 |
| GET /rest/captcha | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/continue-code | X | — | X | — | X | — | O | 200 | X | — | O | 200 | O | 200 |
| GET /rest/continue-code-findIt | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/continue-code-fixIt | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/country-mapping | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/deluxe-membership | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/image-captcha | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/languages | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /rest/memories | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/order-history | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/order-history/orders | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/products/:id/reviews | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/products/search | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /rest/repeat-notification | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/saveLoginIp | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/track-order/:id | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/user/authentication-details | X | — | X | — | X | — | X | — | X | — | O | 200 | O | 200 |
| GET /rest/user/change-password | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/user/security-question | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/user/whoami | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 | O | 200 |
| GET /rest/wallet/balance | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/web3/nftMintListen | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /rest/web3/nftUnlocked | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /security.txt | X | — | X | — | O | 200 | X | — | X | — | X | — | X | — |
| GET /snippets/:challenge | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /snippets/fixes/:key | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /video | X | — | X | — | X | — | X | — | X | — | X | — | X | — |
| GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility | X | — | X | — | X | — | X | — | X | — | X | — | X | — |

### no-ffuf-150 누락 경로

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
- `GET /api/Feedbacks`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /profile`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/captcha`
- `GET /rest/continue-code`
- `GET /rest/continue-code-findIt`
- `GET /rest/continue-code-fixIt`
- `GET /rest/country-mapping`
- `GET /rest/deluxe-membership`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/repeat-notification`
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

### smoke-ffuf-150 누락 경로

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
- `GET /api/Feedbacks`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /profile`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/captcha`
- `GET /rest/continue-code`
- `GET /rest/continue-code-findIt`
- `GET /rest/continue-code-fixIt`
- `GET /rest/country-mapping`
- `GET /rest/deluxe-membership`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/repeat-notification`
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

### smoke-ffuf-300 누락 경로

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
- `GET /api/Feedbacks`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/captcha`
- `GET /rest/continue-code`
- `GET /rest/continue-code-findIt`
- `GET /rest/continue-code-fixIt`
- `GET /rest/country-mapping`
- `GET /rest/deluxe-membership`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/repeat-notification`
- `GET /rest/saveLoginIp`
- `GET /rest/track-order/:id`
- `GET /rest/user/authentication-details`
- `GET /rest/user/change-password`
- `GET /rest/user/security-question`
- `GET /rest/wallet/balance`
- `GET /rest/web3/nftMintListen`
- `GET /rest/web3/nftUnlocked`
- `GET /snippets/:challenge`
- `GET /snippets/fixes/:key`
- `GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg`
- `GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us`
- `GET /video`
- `GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility`

### seclists-api-500 누락 경로

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
- `GET /api/Feedbacks`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /profile`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/captcha`
- `GET /rest/continue-code-findIt`
- `GET /rest/continue-code-fixIt`
- `GET /rest/country-mapping`
- `GET /rest/deluxe-membership`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/repeat-notification`
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

### seclists-api-1000 누락 경로

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
- `GET /api/Feedbacks`
- `GET /api/Feedbacks/:id`
- `GET /api/Hints`
- `GET /api/Hints/:id`
- `GET /api/PrivacyRequests`
- `GET /api/PrivacyRequests/:id`
- `GET /api/Products`
- `GET /api/Products/:id`
- `GET /api/Quantitys/:id`
- `GET /api/Recycles`
- `GET /api/Recycles/:id`
- `GET /api/SecurityAnswers`
- `GET /api/SecurityAnswers/:id`
- `GET /api/SecurityQuestions`
- `GET /api/SecurityQuestions/:id`
- `GET /api/Users`
- `GET /api/Users/:id`
- `GET /dataerasure`
- `GET /metrics`
- `GET /profile`
- `GET /promotion`
- `GET /redirect`
- `GET /rest/2fa/status`
- `GET /rest/captcha`
- `GET /rest/continue-code`
- `GET /rest/continue-code-findIt`
- `GET /rest/continue-code-fixIt`
- `GET /rest/country-mapping`
- `GET /rest/deluxe-membership`
- `GET /rest/image-captcha`
- `GET /rest/memories`
- `GET /rest/order-history`
- `GET /rest/order-history/orders`
- `GET /rest/products/:id/reviews`
- `GET /rest/repeat-notification`
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

### spa-refactor-1000 누락 경로

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

### path-normalization-1000 누락 경로

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
