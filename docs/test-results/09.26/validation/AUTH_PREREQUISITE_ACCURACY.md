# 인증 전제 후보 Validation 실험 (2026-09-26)

## 입력과 실행

앞선 [단일 실행 번들](SINGLE_RUN_ACCURACY.md)의 격리된 복사본에 공식 정답지에서 `NEEDS_TWO_MERCHANT_IDENTITIES`로 남아 있던 VulnBank 후보 3건을 추가했다. `prepare` 명령은 로그인이나 기록 생성 전에 실행 중인 로컬 컨테이너가 고정된 VulnBank 이미지인지 확인한다. 두 테스트 상인으로 로그인한 뒤 소유한 실습 결제가 없으면 각자 실패 결제 기록을 한 건씩 생성한다. 존재하지 않는 카드 번호를 사용해 결제는 거절됐고, 금액 이동은 없었다. 이 준비용 POST와 Validation의 GET 재생은 분리했다.

상인 A는 ID 1과 결제 1번, 상인 B는 ID 2와 결제 2번을 소유한다. B 인증으로 결제 2번 조회가 200인 것을 먼저 확인했다. A 인증으로 같은 결제의 상세 조회는 404, 기본 목록은 A 결제만 반환했고, `/api/v1/payments/merchant_id/2`는 B 결제를 반환했다. 결제 소유권과 타깃·대조군 응답 해시를 [AuthFixture.json](../../../../result/test-runs/validation-candidates/validation-auth-run-20260926-v2/AuthFixture.json)에 보관했다. 응답 본문과 API 키는 보관하지 않았다.

세 후보는 `hunt-idor` 프로필로 스테이징했다. Attack의 `confirmed` 표시는 Validation 시험을 위한 합성 주장이다. 정답 상태는 번들에 복사하지 않았다. 한 번의 실행 명령에서 세 후보를 순차적으로 실제 Eligibility·Blind·ClaimComparison Agent에 전달했다. 인증 키는 Agent 하위 프로세스의 환경변수에 넘기지 않고 Validation 프로세스 내 `keyring` 참조 백엔드에서만 해석했다. 음성 판정은 고정 소스의 소유자 조건, B의 소유권 대조 조회, A의 양성·음성 대조군, 반복된 타깃 응답이 모두 일치할 때만 명시적 비악용 증거를 부여했다.

```bash
PYTHONPATH=. .venv/bin/python scripts/validation_auth_lab.py prepare \
  --base result/test-runs/validation-candidates/validation-single-run-20260926 \
  --output result/test-runs/validation-candidates/validation-auth-run-20260926-v2
PYTHONPATH=. .venv/bin/python scripts/validation_auth_lab.py run \
  result/test-runs/validation-candidates/validation-auth-run-20260926-v2
PYTHONPATH=. .venv/bin/python scripts/validation_auth_lab.py score \
  result/test-runs/validation-candidates/validation-auth-run-20260926-v2
```

`prepare`는 출력 경로가 이미 있으면 중단한다. 재실험에는 새 출력 경로를 사용한다. 각 실행은 VulnBank의 두 테스트 상인 세션을 다시 확인한다.

## 결과

| 공식 후보 | 기대 | Agent 판정 | 독립 채점 |
| --- | --- | --- | --- |
| `GET /api/v1/payments/{payment_id}`에서 B 소유 결제 조회 | `DISPROVEN` | `DISPROVEN` | `PASS` |
| `GET /api/v1/payments`에 B 소유 결제 포함 여부 | `DISPROVEN` | `DISPROVEN` | `PASS` |
| `GET /api/v1/payments/merchant_id/{merchant_id}`에서 B 목록 조회 | `CONFIRMED` | `CONFIRMED` | `PASS` |

각 후보는 양성 대조군 1회, 음성 대조군 1회, 타깃 3회로 총 5회 GET 재생했다. 15개 재생 시도와 결정문의 인용 증거, 타깃·대조군 응답 본문 해시, 완료된 요청 원장, 실시간 소유권 재확인을 별도 채점기로 확인했다. SQLite 무결성 검사는 `ok`다. [기계 판독 채점 결과](AUTH_PREREQUISITE_ACCURACY.json)에 후보별 결과가 있다.

`merchant_id` 양성 사례의 적용 Impact 점수는 경계 2, 민감도 1, 행위자 요구 1로 `CONFIRMED` 기준을 충족했다. 인증 세 사례에는 Development action이나 Impact hypothesis가 추가로 생성되지 않았다. 앞선 단일 실행의 Impact Development 성공은 `/debug/users` 사례의 관측이며, 이번 결과가 인증 상태 준비를 Agent가 스스로 DEVELOPING 단계에서 수행할 수 있음을 뜻하지는 않는다. 이번 실험은 두 테스트 상인과 소유 결제가 사전에 마련된 조건에서의 Validation 판정 정확도를 확인한다.

증거 포트 강화 직후 첫 재실행에서는 기본 목록 사례가 `INCONCLUSIVE`였다. 쿼리가 있는 음성 대조군의 원본 URL과 저장용 정리 URL을 다르게 비교한 것이 원인이었다. URL 비교를 바로잡고 새 번들 `validation-auth-run-20260926-v2`에서 세 사례를 모두 다시 실행한 결과가 위 표다.
