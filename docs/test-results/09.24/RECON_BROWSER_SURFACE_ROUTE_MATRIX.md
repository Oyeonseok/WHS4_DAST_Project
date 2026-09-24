# Juice Shop Recon Surface GET route O/X 평가

O는 최종 Surface.json에 같은 origin의 GET 경로가 정답 route로 명시되어 있음을 뜻한다. `/api/:param` 같은 일반화 경로는 서로 다른 정적 route의 발견으로 세지 않는다. 이 표는 실제 HTTP 요청 관측과 별개로 최종 공격표면에 남은 경로를 평가한다.

| 실행 | Surface 보존 | 누락 |
| --- | ---: | ---: |
| path-normalization-1000 | 25/71 | 46 |
| browser-navigation-1000 | 25/71 | 46 |
| browser-routerlink-1000 | 25/71 | 46 |
| browser-action-capture-full-1000 | 25/71 | 46 |
| browser-luna-full-1000 | 25/71 | 46 |

| 정답 경로 | path-normalization-1000 O/X | browser-navigation-1000 O/X | browser-routerlink-1000 O/X | browser-action-capture-full-1000 O/X | browser-luna-full-1000 O/X |
| --- | --- | --- | --- | --- | --- |
| GET / | O | O | O | O | O |
| GET /.well-known/security.txt | X | X | X | X | X |
| GET /api/Addresss | O | O | O | O | O |
| GET /api/Addresss/:id | X | X | X | X | X |
| GET /api/BasketItems | O | O | O | O | O |
| GET /api/BasketItems/:id | X | X | X | X | X |
| GET /api/Cards | X | X | X | X | X |
| GET /api/Cards/:id | X | X | X | X | X |
| GET /api/Challenges | O | O | O | O | O |
| GET /api/Challenges/:id | X | X | X | X | X |
| GET /api/Complaints | O | O | O | O | O |
| GET /api/Complaints/:id | X | X | X | X | X |
| GET /api/Deliverys | X | X | X | X | X |
| GET /api/Deliverys/:id | X | X | X | X | X |
| GET /api/Feedbacks | O | O | O | O | O |
| GET /api/Feedbacks/:id | X | X | X | X | X |
| GET /api/Hints | X | X | X | X | X |
| GET /api/Hints/:id | X | X | X | X | X |
| GET /api/PrivacyRequests | X | X | X | X | X |
| GET /api/PrivacyRequests/:id | X | X | X | X | X |
| GET /api/Products | O | O | O | O | O |
| GET /api/Products/:id | X | X | X | X | X |
| GET /api/Quantitys | O | O | O | O | O |
| GET /api/Quantitys/:id | X | X | X | X | X |
| GET /api/Recycles | O | O | O | O | O |
| GET /api/Recycles/:id | X | X | X | X | X |
| GET /api/SecurityAnswers | X | X | X | X | X |
| GET /api/SecurityAnswers/:id | X | X | X | X | X |
| GET /api/SecurityQuestions | O | O | O | O | O |
| GET /api/SecurityQuestions/:id | X | X | X | X | X |
| GET /api/Users | O | O | O | O | O |
| GET /api/Users/:id | X | X | X | X | X |
| GET /dataerasure | X | X | X | X | X |
| GET /metrics | X | X | X | X | X |
| GET /profile | X | X | X | X | X |
| GET /promotion | X | X | X | X | X |
| GET /redirect | X | X | X | X | X |
| GET /rest/2fa/status | X | X | X | X | X |
| GET /rest/admin/application-configuration | O | O | O | O | O |
| GET /rest/admin/application-version | O | O | O | O | O |
| GET /rest/basket/:id | O | O | O | O | O |
| GET /rest/captcha | O | O | O | O | O |
| GET /rest/continue-code | O | O | O | O | O |
| GET /rest/continue-code-findIt | O | O | O | O | O |
| GET /rest/continue-code-fixIt | O | O | O | O | O |
| GET /rest/country-mapping | X | X | X | X | X |
| GET /rest/deluxe-membership | O | O | O | O | O |
| GET /rest/image-captcha | X | X | X | X | X |
| GET /rest/languages | O | O | O | O | O |
| GET /rest/memories | X | X | X | X | X |
| GET /rest/order-history | X | X | X | X | X |
| GET /rest/order-history/orders | X | X | X | X | X |
| GET /rest/products/:id/reviews | X | X | X | X | X |
| GET /rest/products/search | O | O | O | O | O |
| GET /rest/repeat-notification | O | O | O | O | O |
| GET /rest/saveLoginIp | O | O | O | O | O |
| GET /rest/track-order/:id | X | X | X | X | X |
| GET /rest/user/authentication-details | O | O | O | O | O |
| GET /rest/user/change-password | X | X | X | X | X |
| GET /rest/user/security-question | X | X | X | X | X |
| GET /rest/user/whoami | O | O | O | O | O |
| GET /rest/wallet/balance | X | X | X | X | X |
| GET /rest/web3/nftMintListen | X | X | X | X | X |
| GET /rest/web3/nftUnlocked | X | X | X | X | X |
| GET /security.txt | X | X | X | X | X |
| GET /snippets/:challenge | X | X | X | X | X |
| GET /snippets/fixes/:key | X | X | X | X | X |
| GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg | X | X | X | X | X |
| GET /this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us | X | X | X | X | X |
| GET /video | X | X | X | X | X |
| GET /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility | X | X | X | X | X |

### path-normalization-1000 Surface 누락 경로

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

### browser-navigation-1000 Surface 누락 경로

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

### browser-routerlink-1000 Surface 누락 경로

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

### browser-action-capture-full-1000 Surface 누락 경로

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
