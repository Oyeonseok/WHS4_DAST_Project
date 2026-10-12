# OWASP Juice Shop v20.2.0 Recon 정답 엔드포인트

기준: v20.2.0의 `server.ts`에 등록된 HTTP 라우트와 `finale-rest`가 생성하는 CRUD 라우트입니다. `{name}`은 경로 변수입니다. v20.2.0 고정 소스: [OWASP 저장소](https://github.com/juice-shop/juice-shop/blob/v20.2.0/server.ts).

**기본 라우트: 144개** (명시적 107개 + 자동 생성 37개; 메서드+경로 기준) = (method 구분 없이) 95개

## 명시적 라우트

| 메서드 | 엔드포인트 | 근거 |
| --- | --- | --- |
| GET | `/` | [server.ts:307](../../resources/lab/juice-shop-v20.2.0-server.ts#L307) |
| GET | `/.well-known/security.txt` | [server.ts:214](../../resources/lab/juice-shop-v20.2.0-server.ts#L214) |
| GET | `/api/Addresss` | [server.ts:468](../../resources/lab/juice-shop-v20.2.0-server.ts#L468) |
| POST | `/api/Addresss` | [server.ts:467](../../resources/lab/juice-shop-v20.2.0-server.ts#L467) |
| DELETE | `/api/Addresss/{id}` | [server.ts:470](../../resources/lab/juice-shop-v20.2.0-server.ts#L470) |
| GET | `/api/Addresss/{id}` | [server.ts:471](../../resources/lab/juice-shop-v20.2.0-server.ts#L471) |
| PUT | `/api/Addresss/{id}` | [server.ts:469](../../resources/lab/juice-shop-v20.2.0-server.ts#L469) |
| POST | `/api/BasketItems` | [server.ts:446](../../resources/lab/juice-shop-v20.2.0-server.ts#L446) |
| PUT | `/api/BasketItems/{id}` | [server.ts:445](../../resources/lab/juice-shop-v20.2.0-server.ts#L445) |
| GET | `/api/Cards` | [server.ts:458](../../resources/lab/juice-shop-v20.2.0-server.ts#L458) |
| POST | `/api/Cards` | [server.ts:457](../../resources/lab/juice-shop-v20.2.0-server.ts#L457) |
| DELETE | `/api/Cards/{id}` | [server.ts:460](../../resources/lab/juice-shop-v20.2.0-server.ts#L460) |
| GET | `/api/Cards/{id}` | [server.ts:461](../../resources/lab/juice-shop-v20.2.0-server.ts#L461) |
| PUT | `/api/Cards/{id}` | [server.ts:459](../../resources/lab/juice-shop-v20.2.0-server.ts#L459) |
| POST | `/api/Challenges` | [server.ts:392](../../resources/lab/juice-shop-v20.2.0-server.ts#L392) |
| GET | `/api/Complaints` | [server.ts:400](../../resources/lab/juice-shop-v20.2.0-server.ts#L400) |
| POST | `/api/Complaints` | [server.ts:401](../../resources/lab/juice-shop-v20.2.0-server.ts#L401) |
| GET | `/api/Deliverys` | [server.ts:472](../../resources/lab/juice-shop-v20.2.0-server.ts#L472) |
| GET | `/api/Deliverys/{id}` | [server.ts:473](../../resources/lab/juice-shop-v20.2.0-server.ts#L473) |
| POST | `/api/Feedbacks` | [server.ts:421](../../resources/lab/juice-shop-v20.2.0-server.ts#L421) |
| PUT | `/api/Feedbacks/{id}` | [server.ts:452](../../resources/lab/juice-shop-v20.2.0-server.ts#L452) |
| POST | `/api/Hints` | [server.ts:395](../../resources/lab/juice-shop-v20.2.0-server.ts#L395) |
| GET | `/api/PrivacyRequests` | [server.ts:464](../../resources/lab/juice-shop-v20.2.0-server.ts#L464) |
| POST | `/api/PrivacyRequests` | [server.ts:463](../../resources/lab/juice-shop-v20.2.0-server.ts#L463) |
| POST | `/api/Products` | [server.ts:388](../../resources/lab/juice-shop-v20.2.0-server.ts#L388) |
| DELETE | `/api/Products/{id}` | [server.ts:390](../../resources/lab/juice-shop-v20.2.0-server.ts#L390) |
| POST | `/api/Quantitys` | [server.ts:449](../../resources/lab/juice-shop-v20.2.0-server.ts#L449) |
| DELETE | `/api/Quantitys/{id}` | [server.ts:448](../../resources/lab/juice-shop-v20.2.0-server.ts#L448) |
| GET | `/api/Recycles` | [server.ts:404](../../resources/lab/juice-shop-v20.2.0-server.ts#L404) |
| POST | `/api/Recycles` | [server.ts:405](../../resources/lab/juice-shop-v20.2.0-server.ts#L405) |
| DELETE | `/api/Recycles/{id}` | [server.ts:409](../../resources/lab/juice-shop-v20.2.0-server.ts#L409) |
| GET | `/api/Recycles/{id}` | [server.ts:407](../../resources/lab/juice-shop-v20.2.0-server.ts#L407) |
| PUT | `/api/Recycles/{id}` | [server.ts:408](../../resources/lab/juice-shop-v20.2.0-server.ts#L408) |
| GET | `/api/SecurityAnswers` | [server.ts:414](../../resources/lab/juice-shop-v20.2.0-server.ts#L414) |
| POST | `/api/SecurityQuestions` | [server.ts:411](../../resources/lab/juice-shop-v20.2.0-server.ts#L411) |
| GET | `/api/Users` | [server.ts:382](../../resources/lab/juice-shop-v20.2.0-server.ts#L382) |
| POST | `/api/Users` | [server.ts:427](../../resources/lab/juice-shop-v20.2.0-server.ts#L427) |
| POST | `/b2b/v2/orders` | [server.ts:667](../../resources/lab/juice-shop-v20.2.0-server.ts#L667) |
| GET | `/dataerasure` | [server.ts:675](../../resources/lab/juice-shop-v20.2.0-server.ts#L675) + [router](https://github.com/juice-shop/juice-shop/blob/v20.2.0/routes/dataErasure.ts) |
| POST | `/dataerasure` | [server.ts:675](../../resources/lab/juice-shop-v20.2.0-server.ts#L675) + [router](https://github.com/juice-shop/juice-shop/blob/v20.2.0/routes/dataErasure.ts) |
| POST | `/file-upload` | [server.ts:328](../../resources/lab/juice-shop-v20.2.0-server.ts#L328) |
| GET | `/metrics` | [server.ts:695](../../resources/lab/juice-shop-v20.2.0-server.ts#L695) |
| GET | `/profile` | [server.ts:685](../../resources/lab/juice-shop-v20.2.0-server.ts#L685) |
| POST | `/profile` | [server.ts:686](../../resources/lab/juice-shop-v20.2.0-server.ts#L686) |
| POST | `/profile/image/file` | [server.ts:329](../../resources/lab/juice-shop-v20.2.0-server.ts#L329) |
| POST | `/profile/image/url` | [server.ts:330](../../resources/lab/juice-shop-v20.2.0-server.ts#L330) |
| GET | `/promotion` | [server.ts:681](../../resources/lab/juice-shop-v20.2.0-server.ts#L681) |
| GET | `/redirect` | [server.ts:678](../../resources/lab/juice-shop-v20.2.0-server.ts#L678) |
| POST | `/rest/2fa/disable` | [server.ts:490](../../resources/lab/juice-shop-v20.2.0-server.ts#L490) |
| POST | `/rest/2fa/setup` | [server.ts:484](../../resources/lab/juice-shop-v20.2.0-server.ts#L484) |
| GET | `/rest/2fa/status` | [server.ts:482](../../resources/lab/juice-shop-v20.2.0-server.ts#L482) |
| POST | `/rest/2fa/verify` | [server.ts:477](../../resources/lab/juice-shop-v20.2.0-server.ts#L477) |
| GET | `/rest/admin/application-configuration` | [server.ts:626](../../resources/lab/juice-shop-v20.2.0-server.ts#L626) |
| GET | `/rest/admin/application-version` | [server.ts:625](../../resources/lab/juice-shop-v20.2.0-server.ts#L625) |
| GET | `/rest/basket/{id}` | [server.ts:622](../../resources/lab/juice-shop-v20.2.0-server.ts#L622) |
| POST | `/rest/basket/{id}/checkout` | [server.ts:623](../../resources/lab/juice-shop-v20.2.0-server.ts#L623) |
| PUT | `/rest/basket/{id}/coupon/{coupon}` | [server.ts:624](../../resources/lab/juice-shop-v20.2.0-server.ts#L624) |
| GET | `/rest/captcha` | [server.ts:634](../../resources/lab/juice-shop-v20.2.0-server.ts#L634) |
| POST | `/rest/chat` | [server.ts:657](../../resources/lab/juice-shop-v20.2.0-server.ts#L657) |
| GET | `/rest/continue-code` | [server.ts:628](../../resources/lab/juice-shop-v20.2.0-server.ts#L628) |
| GET | `/rest/continue-code-findIt` | [server.ts:629](../../resources/lab/juice-shop-v20.2.0-server.ts#L629) |
| PUT | `/rest/continue-code-findIt/apply/{continueCode}` | [server.ts:631](../../resources/lab/juice-shop-v20.2.0-server.ts#L631) |
| GET | `/rest/continue-code-fixIt` | [server.ts:630](../../resources/lab/juice-shop-v20.2.0-server.ts#L630) |
| PUT | `/rest/continue-code-fixIt/apply/{continueCode}` | [server.ts:632](../../resources/lab/juice-shop-v20.2.0-server.ts#L632) |
| PUT | `/rest/continue-code/apply/{continueCode}` | [server.ts:633](../../resources/lab/juice-shop-v20.2.0-server.ts#L633) |
| GET | `/rest/country-mapping` | [server.ts:637](../../resources/lab/juice-shop-v20.2.0-server.ts#L637) |
| GET | `/rest/deluxe-membership` | [server.ts:647](../../resources/lab/juice-shop-v20.2.0-server.ts#L647) |
| POST | `/rest/deluxe-membership` | [server.ts:648](../../resources/lab/juice-shop-v20.2.0-server.ts#L648) |
| GET | `/rest/image-captcha` | [server.ts:635](../../resources/lab/juice-shop-v20.2.0-server.ts#L635) |
| GET | `/rest/languages` | [server.ts:641](../../resources/lab/juice-shop-v20.2.0-server.ts#L641) |
| GET | `/rest/memories` | [server.ts:649](../../resources/lab/juice-shop-v20.2.0-server.ts#L649) |
| POST | `/rest/memories` | [server.ts:331](../../resources/lab/juice-shop-v20.2.0-server.ts#L331) |
| GET | `/rest/order-history` | [server.ts:642](../../resources/lab/juice-shop-v20.2.0-server.ts#L642) |
| GET | `/rest/order-history/orders` | [server.ts:643](../../resources/lab/juice-shop-v20.2.0-server.ts#L643) |
| PUT | `/rest/order-history/{id}/delivery-status` | [server.ts:644](../../resources/lab/juice-shop-v20.2.0-server.ts#L644) |
| PATCH | `/rest/products/reviews` | [server.ts:653](../../resources/lab/juice-shop-v20.2.0-server.ts#L653) |
| POST | `/rest/products/reviews` | [server.ts:654](../../resources/lab/juice-shop-v20.2.0-server.ts#L654) |
| GET | `/rest/products/search` | [server.ts:621](../../resources/lab/juice-shop-v20.2.0-server.ts#L621) |
| GET | `/rest/products/{id}/reviews` | [server.ts:651](../../resources/lab/juice-shop-v20.2.0-server.ts#L651) |
| PUT | `/rest/products/{id}/reviews` | [server.ts:652](../../resources/lab/juice-shop-v20.2.0-server.ts#L652) |
| GET | `/rest/repeat-notification` | [server.ts:627](../../resources/lab/juice-shop-v20.2.0-server.ts#L627) |
| GET | `/rest/saveLoginIp` | [server.ts:638](../../resources/lab/juice-shop-v20.2.0-server.ts#L638) |
| GET | `/rest/track-order/{id}` | [server.ts:636](../../resources/lab/juice-shop-v20.2.0-server.ts#L636) |
| GET | `/rest/user/authentication-details` | [server.ts:620](../../resources/lab/juice-shop-v20.2.0-server.ts#L620) |
| GET | `/rest/user/change-password` | [server.ts:616](../../resources/lab/juice-shop-v20.2.0-server.ts#L616) |
| POST | `/rest/user/data-export` | [server.ts:639](../../resources/lab/juice-shop-v20.2.0-server.ts#L639) |
| POST | `/rest/user/login` | [server.ts:615](../../resources/lab/juice-shop-v20.2.0-server.ts#L615) |
| POST | `/rest/user/reset-password` | [server.ts:617](../../resources/lab/juice-shop-v20.2.0-server.ts#L617) |
| GET | `/rest/user/security-question` | [server.ts:618](../../resources/lab/juice-shop-v20.2.0-server.ts#L618) |
| GET | `/rest/user/whoami` | [server.ts:619](../../resources/lab/juice-shop-v20.2.0-server.ts#L619) |
| GET | `/rest/wallet/balance` | [server.ts:645](../../resources/lab/juice-shop-v20.2.0-server.ts#L645) |
| PUT | `/rest/wallet/balance` | [server.ts:646](../../resources/lab/juice-shop-v20.2.0-server.ts#L646) |
| GET | `/rest/web3/nftMintListen` | [server.ts:662](../../resources/lab/juice-shop-v20.2.0-server.ts#L662) |
| GET | `/rest/web3/nftUnlocked` | [server.ts:661](../../resources/lab/juice-shop-v20.2.0-server.ts#L661) |
| POST | `/rest/web3/submitKey` | [server.ts:660](../../resources/lab/juice-shop-v20.2.0-server.ts#L660) |
| POST | `/rest/web3/walletExploitAddress` | [server.ts:664](../../resources/lab/juice-shop-v20.2.0-server.ts#L664) |
| POST | `/rest/web3/walletNFTVerify` | [server.ts:663](../../resources/lab/juice-shop-v20.2.0-server.ts#L663) |
| GET | `/robots.txt` | [server.ts:226](../../resources/lab/juice-shop-v20.2.0-server.ts#L226) |
| GET | `/security.txt` | [server.ts:214](../../resources/lab/juice-shop-v20.2.0-server.ts#L214) |
| POST | `/snippets/fixes` | [server.ts:692](../../resources/lab/juice-shop-v20.2.0-server.ts#L692) |
| GET | `/snippets/fixes/{key}` | [server.ts:691](../../resources/lab/juice-shop-v20.2.0-server.ts#L691) |
| POST | `/snippets/verdict` | [server.ts:690](../../resources/lab/juice-shop-v20.2.0-server.ts#L690) |
| GET | `/snippets/{challenge}` | [server.ts:689](../../resources/lab/juice-shop-v20.2.0-server.ts#L689) |
| GET | `/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg` | [server.ts:670](../../resources/lab/juice-shop-v20.2.0-server.ts#L670) |
| GET | `/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us` | [server.ts:671](../../resources/lab/juice-shop-v20.2.0-server.ts#L671) |
| GET | `/video` | [server.ts:682](../../resources/lab/juice-shop-v20.2.0-server.ts#L682) |
| GET | `/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility` | [server.ts:672](../../resources/lab/juice-shop-v20.2.0-server.ts#L672) |

## `finale-rest` 자동 생성 라우트

모델 14개의 복수형 및 `/{id}` 경로를 소스가 생성합니다. [Finale의 기본 메서드 표](https://github.com/tommybananas/finale/blob/master/README.md#controllers-and-endpoints)에 따라 collection은 GET/POST, item은 GET/PUT/DELETE로 기록했습니다.

| 메서드 | 엔드포인트 | 근거 |
| --- | --- | --- |
| GET | `/api/BasketItems` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/BasketItems/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/BasketItems/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Challenges` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/Challenges/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Challenges/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/Challenges/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/Complaints/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Complaints/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/Complaints/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Feedbacks` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/Feedbacks/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Feedbacks/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Hints` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/Hints/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Hints/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/Hints/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/PrivacyRequests/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/PrivacyRequests/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/PrivacyRequests/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Products` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Products/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/Products/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Quantitys` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Quantitys/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/Quantitys/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| POST | `/api/SecurityAnswers` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/SecurityAnswers/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/SecurityAnswers/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/SecurityAnswers/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/SecurityQuestions` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/SecurityQuestions/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/SecurityQuestions/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/SecurityQuestions/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| DELETE | `/api/Users/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| GET | `/api/Users/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |
| PUT | `/api/Users/{id}` | [server.ts:500-524](../../resources/lab/juice-shop-v20.2.0-server.ts#L500) |

## 별도 취급할 제공 경로

| 메서드 | 경로 묶음 | 근거 |
| --- | --- | --- |
| GET | `/ftp`, `/ftp/{file}`, `/ftp/quarantine/{file}` | [server.ts:287-290](../../resources/lab/juice-shop-v20.2.0-server.ts#L287) |
| GET | `/infrastructure`, `/infrastructure/{path}` | [server.ts:267-283](../../resources/lab/juice-shop-v20.2.0-server.ts#L267) |
| GET | `/encryptionkeys`, `/encryptionkeys/{file}` | [server.ts:295-297](../../resources/lab/juice-shop-v20.2.0-server.ts#L295) |
| GET | `/support/logs`, `/support/logs/{file}` | [server.ts:299-302](../../resources/lab/juice-shop-v20.2.0-server.ts#L299) |
| GET | `/.well-known`, `/.well-known/{path}` | [server.ts:292-293](../../resources/lab/juice-shop-v20.2.0-server.ts#L292) |
| GET | `/api-docs` 및 하위 자산 | [server.ts:305](../../resources/lab/juice-shop-v20.2.0-server.ts#L305) |
| GET | `/assets/{path}` 및 프런트엔드 정적 파일 | [server.ts:307](../../resources/lab/juice-shop-v20.2.0-server.ts#L307) |
| GET | `/vendor/beercss/{path}`, `/vendor/material-icons/{path}`, `/vendor/fontsource-roboto/{path}` | [server.ts:311-314](../../resources/lab/juice-shop-v20.2.0-server.ts#L311) |

파일별 URL은 빌드 산출물에 따라 달라져 기본 라우트 수에 넣지 않았습니다. `GET /`은 기본 목록에 포함했습니다.

- `/#/...`는 브라우저의 fragment를 사용하는 SPA 화면 경로입니다. HTTP 요청에는 fragment가 전달되지 않으므로 Recon HTTP 엔드포인트 정답 수에 넣지 않았습니다.
- `serveAngularClient()`는 미등록 경로에도 SPA 응답을 줄 수 있습니다. 그 응답만으로 새로운 라우트라고 판정하지 않습니다.
- 인증 또는 `denyAll()`이 걸린 메서드도 등록된 라우트이므로 포함했습니다. 응답이 2xx라는 의미는 아닙니다.

이 목록은 등록 라우트의 정답이며 취약점 목록이 아닙니다. 기존 [챌린지 ground truth](juice-shop-v20.2.0-official-only-ground-truth.md)의 `paths_observed`는 공략 과정의 대상만 다룹니다.
