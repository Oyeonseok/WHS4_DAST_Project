# VulnBank Recon 정답 엔드포인트

기준: `result/lab/vuln-bank`의 Flask 라우트 선언. `app.py`가 등록하는 `auth.py`와 `merchant_payments.py` 라우트도 포함합니다. 메서드가 없는 Flask 데코레이터는 GET으로 기록했습니다. `{name}`은 경로 변수입니다.

**기본 라우트: 79개** (메서드+경로 기준) = (메서드 구분 없이) 74개

| 메서드 | 엔드포인트 | 근거 |
| --- | --- | --- |
| GET | `/` | [app.py:279](../../result/lab/vuln-bank/app.py#L279) |
| POST | `/admin/approve_loan/{loan_id}` | [app.py:982](../../result/lab/vuln-bank/app.py#L982) |
| POST | `/admin/create_admin` | [app.py:1131](../../result/lab/vuln-bank/app.py#L1131) |
| POST | `/admin/delete_account/{user_id}` | [app.py:1046](../../result/lab/vuln-bank/app.py#L1046) |
| POST | `/admin/toggle_suspension/{user_id}` | [app.py:1079](../../result/lab/vuln-bank/app.py#L1079) |
| POST | `/api/ai/chat` | [app.py:2272](../../result/lab/vuln-bank/app.py#L2272) |
| POST | `/api/ai/chat/anonymous` | [app.py:2344](../../result/lab/vuln-bank/app.py#L2344) |
| GET | `/api/ai/rate-limit-status` | [app.py:2422](../../result/lab/vuln-bank/app.py#L2422) |
| GET | `/api/ai/system-info` | [app.py:2383](../../result/lab/vuln-bank/app.py#L2383) |
| GET | `/api/bill-categories` | [app.py:2016](../../result/lab/vuln-bank/app.py#L2016) |
| POST | `/api/bill-payments/create` | [app.py:2066](../../result/lab/vuln-bank/app.py#L2066) |
| GET | `/api/bill-payments/history` | [app.py:2225](../../result/lab/vuln-bank/app.py#L2225) |
| GET | `/api/billers/by-category/{category_id}` | [app.py:2037](../../result/lab/vuln-bank/app.py#L2037) |
| GET | `/api/check_balance` | [auth.py:148](../../result/lab/vuln-bank/auth.py#L148) |
| POST | `/api/login` | [auth.py:109](../../result/lab/vuln-bank/auth.py#L109) |
| GET | `/api/transactions` | [app.py:1591](../../result/lab/vuln-bank/app.py#L1591) |
| POST | `/api/transfer` | [auth.py:169](../../result/lab/vuln-bank/auth.py#L169) |
| POST | `/api/v1/forgot-password` | [app.py:1265](../../result/lab/vuln-bank/app.py#L1265) |
| POST | `/api/v1/merchants/login` | [merchant_payments.py:201](../../result/lab/vuln-bank/merchant_payments.py#L201) |
| GET | `/api/v1/merchants/me` | [merchant_payments.py:239](../../result/lab/vuln-bank/merchant_payments.py#L239) |
| POST | `/api/v1/merchants/register` | [merchant_payments.py:150](../../result/lab/vuln-bank/merchant_payments.py#L150) |
| GET | `/api/v1/payments` | [merchant_payments.py:497](../../result/lab/vuln-bank/merchant_payments.py#L497) |
| POST | `/api/v1/payments/charge` | [merchant_payments.py:252](../../result/lab/vuln-bank/merchant_payments.py#L252) |
| GET | `/api/v1/payments/merchant_id/{merchant_id}` | [merchant_payments.py:550](../../result/lab/vuln-bank/merchant_payments.py#L550) |
| GET | `/api/v1/payments/{payment_id}` | [merchant_payments.py:432](../../result/lab/vuln-bank/merchant_payments.py#L432) |
| POST | `/api/v1/reset-password` | [app.py:1447](../../result/lab/vuln-bank/app.py#L1447) |
| POST | `/api/v2/forgot-password` | [app.py:1315](../../result/lab/vuln-bank/app.py#L1315) |
| POST | `/api/v2/reset-password` | [app.py:1504](../../result/lab/vuln-bank/app.py#L1504) |
| POST | `/api/v3/forgot-password` | [app.py:1363](../../result/lab/vuln-bank/app.py#L1363) |
| POST | `/api/v3/reset-password` | [app.py:1552](../../result/lab/vuln-bank/app.py#L1552) |
| GET | `/api/v3/user/{user_id}` | [app.py:1410](../../result/lab/vuln-bank/app.py#L1410) |
| GET | `/api/virtual-cards` | [app.py:1691](../../result/lab/vuln-bank/app.py#L1691) |
| POST | `/api/virtual-cards/create` | [app.py:1631](../../result/lab/vuln-bank/app.py#L1631) |
| POST | `/api/virtual-cards/{card_id}/fund` | [app.py:1879](../../result/lab/vuln-bank/app.py#L1879) |
| POST | `/api/virtual-cards/{card_id}/toggle-freeze` | [app.py:1742](../../result/lab/vuln-bank/app.py#L1742) |
| GET | `/api/virtual-cards/{card_id}/transactions` | [app.py:1774](../../result/lab/vuln-bank/app.py#L1774) |
| POST | `/api/virtual-cards/{card_id}/update-limit` | [app.py:1812](../../result/lab/vuln-bank/app.py#L1812) |
| GET | `/blog` | [app.py:299](../../result/lab/vuln-bank/app.py#L299) |
| GET | `/careers` | [app.py:295](../../result/lab/vuln-bank/app.py#L295) |
| GET | `/check_balance/{account_number}` | [app.py:499](../../result/lab/vuln-bank/app.py#L499) |
| GET | `/compliance` | [app.py:291](../../result/lab/vuln-bank/app.py#L291) |
| GET | `/dashboard` | [app.py:466](../../result/lab/vuln-bank/app.py#L466) |
| GET | `/debug/users` | [app.py:453](../../result/lab/vuln-bank/app.py#L453) |
| GET | `/forgot-password` | [app.py:1165](../../result/lab/vuln-bank/app.py#L1165) |
| POST | `/forgot-password` | [app.py:1165](../../result/lab/vuln-bank/app.py#L1165) |
| GET | `/graphql` | [app.py:229](../../result/lab/vuln-bank/app.py#L229) |
| POST | `/graphql` | [app.py:240](../../result/lab/vuln-bank/app.py#L240) |
| GET | `/healthz` | [app.py:220](../../result/lab/vuln-bank/app.py#L220) |
| GET | `/internal/config.json` | [app.py:807](../../result/lab/vuln-bank/app.py#L807) |
| GET | `/internal/secret` | [app.py:780](../../result/lab/vuln-bank/app.py#L780) |
| GET | `/latest/meta-data/` | [app.py:827](../../result/lab/vuln-bank/app.py#L827) |
| GET | `/latest/meta-data/ami-id` | [app.py:844](../../result/lab/vuln-bank/app.py#L844) |
| GET | `/latest/meta-data/hostname` | [app.py:850](../../result/lab/vuln-bank/app.py#L850) |
| GET | `/latest/meta-data/iam/` | [app.py:880](../../result/lab/vuln-bank/app.py#L880) |
| GET | `/latest/meta-data/iam/security-credentials/` | [app.py:886](../../result/lab/vuln-bank/app.py#L886) |
| GET | `/latest/meta-data/iam/security-credentials/vulnbank-role` | [app.py:892](../../result/lab/vuln-bank/app.py#L892) |
| GET | `/latest/meta-data/instance-id` | [app.py:856](../../result/lab/vuln-bank/app.py#L856) |
| GET | `/latest/meta-data/local-ipv4` | [app.py:862](../../result/lab/vuln-bank/app.py#L862) |
| GET | `/latest/meta-data/public-ipv4` | [app.py:868](../../result/lab/vuln-bank/app.py#L868) |
| GET | `/latest/meta-data/security-groups` | [app.py:874](../../result/lab/vuln-bank/app.py#L874) |
| GET | `/login` | [app.py:383](../../result/lab/vuln-bank/app.py#L383) |
| POST | `/login` | [app.py:383](../../result/lab/vuln-bank/app.py#L383) |
| GET | `/merchant` | [merchant_payments.py:134](../../result/lab/vuln-bank/merchant_payments.py#L134) |
| GET | `/merchant/dashboard` | [merchant_payments.py:146](../../result/lab/vuln-bank/merchant_payments.py#L146) |
| GET | `/merchant/login` | [merchant_payments.py:142](../../result/lab/vuln-bank/merchant_payments.py#L142) |
| GET | `/merchant/register` | [merchant_payments.py:138](../../result/lab/vuln-bank/merchant_payments.py#L138) |
| GET | `/privacy` | [app.py:283](../../result/lab/vuln-bank/app.py#L283) |
| GET | `/register` | [app.py:303](../../result/lab/vuln-bank/app.py#L303) |
| POST | `/register` | [app.py:303](../../result/lab/vuln-bank/app.py#L303) |
| POST | `/request_loan` | [app.py:909](../../result/lab/vuln-bank/app.py#L909) |
| GET | `/reset-password` | [app.py:1217](../../result/lab/vuln-bank/app.py#L1217) |
| POST | `/reset-password` | [app.py:1217](../../result/lab/vuln-bank/app.py#L1217) |
| GET | `/sup3r_s3cr3t_admin` | [app.py:936](../../result/lab/vuln-bank/app.py#L936) |
| GET | `/terms` | [app.py:287](../../result/lab/vuln-bank/app.py#L287) |
| GET | `/transactions/{account_number}` | [app.py:595](../../result/lab/vuln-bank/app.py#L595) |
| POST | `/transfer` | [app.py:528](../../result/lab/vuln-bank/app.py#L528) |
| POST | `/update_bio` | [app.py:747](../../result/lab/vuln-bank/app.py#L747) |
| POST | `/upload_profile_picture` | [app.py:643](../../result/lab/vuln-bank/app.py#L643) |
| POST | `/upload_profile_picture_url` | [app.py:692](../../result/lab/vuln-bank/app.py#L692) |

## 별도 취급할 제공 경로

| 메서드 | 경로 묶음 | 근거 |
| --- | --- | --- |
| GET | `/static/{path}` | Flask 기본 정적 파일 경로; [app.py:30](../../result/lab/vuln-bank/app.py#L30) |
| GET | `/api/docs` 및 하위 자산 | Swagger UI 블루프린트 [app.py:40-52](../../result/lab/vuln-bank/app.py#L40) |

정적 파일별 URL과 블루프린트 내부 경로는 기본 라우트 수에 넣지 않았습니다.

- Flask가 자동으로 허용하는 HEAD/OPTIONS와 슬래시 리다이렉트는 별도 정답 행으로 세지 않았습니다.

이 목록은 실제 등록 경로의 정답입니다. 취약점 여부, 인증 없이 접근 가능함, 성공 응답을 보장한다는 뜻은 아닙니다.
