# VulnBank exhaustive V6 검증 기록 (2026-09-25)

## 결론

- 대상은 의도적으로 취약한 로컬 loopback `http://127.0.0.1:5001/`뿐이다.
- 소스에서 가져온 78개 취약점 신호를 모두 terminal disposition으로 처리했다.
- Attack은 32개 finding을 생성했다.
- Validation은 19개를 `CONFIRMED`, 11개를 `INCONCLUSIVE`, 2개를 `UNDERPOWERED`로 판정했다.
- 19개 confirmed case마다 `Report.md`를 생성했다.
- 19개 confirmed 보고서를 endpoint와 원인으로 보수적으로 묶으면 약 17개 root-cause cluster다. 특히 `/check_balance/{account_number}`의 인증 부재·IDOR·데이터 노출 보고서 3개는 같은 접근통제 원인의 서로 다른 표현이므로 개별 고유 취약점 3개로 부풀리면 안 된다.
- 따라서 “finding 32개”는 고유 취약점 32개라는 뜻이 아니다. Attack 후보, Validation case, 보고서, 고유 root cause는 서로 다른 단위다.

## VulnBank에서 결과적으로 몇 개를 찾았는가

숫자의 의미를 섞지 않기 위해 다음처럼 구분한다.

| 측정 단위 | 수 | 의미 |
|---|---:|---|
| 소스 취약점 신호 | 78 | method-aware import가 생성한 검사 단위 |
| Attack finding | 32 | 동적 검증 후보이며 고유 취약점 수가 아님 |
| Validation `CONFIRMED` | 19 | fresh control/target replay로 확인된 case |
| 생성된 로컬 보고서 | 19 | confirmed case마다 생성된 evidence-bound 초안 |
| 보수적 고유 root-cause cluster | 약 17 | 같은 endpoint와 같은 접근통제 원인을 통합한 수 |
| 현재 그대로 외부 제출 가능한 보고서 | 0 | 정확한 원본 HTTP 요청·응답 및 외부용 첨부가 빠져 있음 |

따라서 현재 AIDAST가 VulnBank에서 **동적으로 확인한 결과는 19개 case**다. 같은
`/check_balance/{account_number}` 접근통제 원인을 여러 표현으로 센 중복을 통합하면
**약 17개의 고유 취약점 원인**으로 보는 것이 가장 보수적이다. 이는 VulnBank에 존재하는
모든 취약점의 총수를 증명한 값이 아니며, 현재 DB에 입력된 78개 신호를 이 실행에서
처리하고 확인한 결과다.

## 실행 식별자와 결과 경로

- Scan ID: `scan_15a2933f312542c8909d60f380ad8466`
- 결과 기준 경로: `$AIDAST_RESULT_ROOT/VulnBank/AIDASTLabBenchmarkV6`
- Pipeline DB: `$AIDAST_RESULT_ROOT/VulnBank/AIDASTLabBenchmarkV6/AttackRuns/scan_15a2933f312542c8909d60f380ad8466/Pipeline.db`
- Coverage Markdown: `$AIDAST_RESULT_ROOT/VulnBank/AIDASTLabBenchmarkV6/FinalResults/CoverageOutcome/CoverageResults.md`
- Coverage JSON: `$AIDAST_RESULT_ROOT/VulnBank/AIDASTLabBenchmarkV6/FinalResults/CoverageOutcome/CoverageResults.json`
- Reports: `$AIDAST_RESULT_ROOT/VulnBank/AIDASTLabBenchmarkV6/FinalResults/Reports/`

## 최종 coverage

| Attack disposition | 수 |
|---|---:|
| candidate | 29 |
| tested_negative | 27 |
| unsupported | 12 |
| policy_excluded | 5 |
| error_terminal | 4 |
| blocked_auth | 1 |
| 합계 | 78 |

Coverage projection의 Validation 결과는 `CONFIRMED 19`, `INCONCLUSIVE 8`, `UNDERPOWERED 2`, `NOT_APPLICABLE 49`다. Validation DB 자체에는 여러 finding/case 관계 때문에 `INCONCLUSIVE 11`이 존재한다.

## 확인된 보고서의 심각도

| Severity | 수 |
|---|---:|
| MEDIUM | 10 |
| LOW | 9 |
| 합계 | 19 |

이 표는 `Pipeline.db`의 `validation_cases.current_status='CONFIRMED'` 행에 저장된
severity를 직접 집계한 authoritative 결과다. 이전 문서에 있던
`CRITICAL 5 / HIGH 7 / MEDIUM 3 / LOW 4` 표는 현재 DB와 일치하지 않아 수정했다.

대표적으로 확인된 원인은 다음과 같다.

- 관리자·merchant 인증 우회 SQL injection
- merchant registration, password-reset, balance, transaction 경로 SQL injection
- 다른 사용자의 profile/card를 조작하거나 조회하는 IDOR
- `/check_balance/{account_number}` 인증 부재 및 금융정보 노출
- reset PIN 응답 노출
- raw SQL, DB schema, Python conversion error, Werkzeug debugger 노출
- virtual-card toggle CSRF

## 이번 반복에서 수정한 구조

1. `source_import.py`
   - 함수 본문 식별자 전체를 취약점으로 추측하지 않고 명시적 소스 주석을 기준으로 신호를 만든다.
   - `request.method == "POST"` 분기 안의 주석을 GET endpoint로 복제하지 않는다.
   - 그 결과 부정확한 108개 신호가 method-aware한 78개 신호로 정규화됐다.

2. `coverage.py`
   - brute-force는 `new_password`보다 `pin`, `otp`, `code`, `token`을 우선한다.
   - race-condition은 `id`, `loan`, `payment`, `transfer`, `amount`를 우선한다.
   - source disclosure는 build artifact 전용 skill 대신 일반 증거 workflow에 연결한다.
   - owned object와 benchmark fixture를 task에 비밀값 없이 전달한다.

3. `vulnbank.py`
   - 두 사용자, 관리자, 두 merchant와 card/category/biller fixture를 만든다.
   - owned loan을 생성하고 관리자 페이지를 최대 32쪽까지 bounded 탐색해 정확한 `loan_id`를 저장한다.
   - credential 원문은 DB가 아니라 process environment reference로만 보관한다.

4. `coverage_attack.py`
   - batch 전체가 실패해도 이미 완료·skip·finding 처리된 task 결과는 보존하고, 미종결 task만 재시도한다.

5. `db_cli.py`
   - coverage task는 durable attempt 없이 `completed`로 전이할 수 없다.
   - 안전한 probe가 없으면 근거를 가진 skip/failed disposition을 남기도록 강제한다.

6. `native_pipeline.py`
   - staged Hunt Skill 경로를 workdir 상대 경로로 전달한다.
   - 각 `SKILL.md`의 경로와 SHA-256 manifest를 config에 넣어 실제 파일이 있는데도 missing으로 오판하는 문제를 줄였다.

7. `skills/attack/live/SKILL.md`
   - 상태 변경 request는 approval envelope가 사전에 없다는 이유만으로 skip하지 않고 policy helper를 통해 task-bound 승인을 요청한다.
   - 다른 vulnerability class의 과거 요청은 현재 task 증거로 재사용하지 않고 현재 annotation을 위해 replay한다.

## 오류와 정직한 제한

- `error_terminal` 4개는 세 차례 bounded 실행 후에도 inconclusive 증거만 남은 항목이다. 취약점이 없다고 확정한 것이 아니다.
- `blocked_auth` 1개는 해당 coverage가 요구한 identity 계약을 충족하지 못했다.
- `unsupported`와 `policy_excluded`는 안전한 단일-object proof, cleanup/invariant, 또는 허용된 mutation 계약이 없었던 항목이다.
- 중단됐던 mass-assignment validation은 별도로 resume했고 최종 `INCONCLUSIVE`가 됐다. confirmed로 부풀리지 않았다.
- “모든 취약점 발견”은 증명할 수 없다. 이번 결과가 증명하는 것은 DB에 기록된 78개 신호가 더 이상 미처리 상태가 아니며, 각 항목에 감사 가능한 disposition이 있다는 점이다.

## 검증

- 관련 회귀 테스트: 46개 통과 후 추가 변경 세트 38개 통과.
- 전체 테스트의 sandbox 실행: 1063개 통과, 6개 skip, 32개 실패. 32개는 모두 sandbox가 loopback socket bind를 `PermissionError`로 차단한 환경 실패였다.
- loopback bind가 허용된 로컬 권한으로 전체 테스트를 다시 실행한 결과: **1084개 통과, 6개 skip, 642 subtest 통과**.
- Pipeline DB: `PRAGMA integrity_check = ok`, foreign-key 오류 0.
- 결과 Markdown/JSON에서 JWT 및 `Authorization: Bearer <token>` 패턴 파일 없음.
- 중단 validation resume 후 Coverage export를 다시 생성해 stale `PENDING`을 제거했다.

## 2026-09-25 보고서 품질 감사

19개 `Report.md`, `Report.json`, `Report.context.json`, 개별 `Report.db`와 Pipeline DB를
다시 교차 검증했다.

### 통과한 항목

- 19/19 `Report.json`이 strict Pydantic schema와 evidence-ID membership 검사를 통과했다.
- 19/19 `Report.md`가 해당 `Report.json`의 결정적 렌더링 결과와 일치했다.
- Pipeline DB와 19개 개별 Report DB의 `PRAGMA integrity_check`가 모두 `ok`였다.
- 보고서 Markdown/JSON에서 JWT, Bearer token, cookie, 개인 이메일 및 로컬 사용자 경로를
  찾지 못했다.
- 영향 설명은 Validation에서 실제 확인한 경계를 넘어 파일 접근, 코드 실행 또는 대량
  데이터 추출을 주장하지 않았다.

### 외부 제출 전에 고쳐야 하는 항목

- 19/19 보고서에 triager가 그대로 재현할 수 있는 raw HTTP 또는 `curl` 요청 블록이 없다.
- 11개 보고서는 정확한 request body/header가 context에 없다고 본문에서 명시한다.
- 17개 보고서는 내부 `vevidence_*` ID만 나열하고 실제 파일은 첨부하지 않았다. 나머지
  2개도 외부 triager가 열 수 있는 증거 첨부가 없다.
- 7개 보고서는 Pipeline DB에 severity가 있는데도 report JSON/Markdown에서 누락됐다.
- 19개 모두 CVSS vector가 비어 있다. HackerOne generic draft에서 선택 필드이지만,
  제출 전에 검증된 영향에 맞춰 계산하거나 생략 사유를 명확히 해야 한다.
- `vcase_b19c6c20b39249129fdfeda859307bdf`에는 remediation section이 없다.
- 15개 보고서에 `1. 1.` 형태의 이중 단계 번호가 있고, Markdown renderer가 URL의 점과
  일반 하이픈까지 과도하게 escape한다.
- `/check_balance/{account_number}`의 인증 부재·IDOR·데이터 노출 3건은 같은 접근통제
  root cause이므로 하나로 통합해야 한다. 같은 endpoint의 SQL injection은 원인이 달라
  별도 보고서로 유지한다.

보고서는 현재도 첫머리에 `Local draft — not submitted.`라고 표시된다. 즉 19개는
감사 가능한 로컬 초안이지 그대로 제출할 완성본이 아니다. 제출 준비 완료 수가 0이라는
판정은 취약점 미확인을 뜻하지 않는다. 19개 confirmed case의 원본 요청·응답을 안전하게
보존하고, 재현 가능한 PoC와 redacted attachment를 생성하는 후속 reporting 단계가
필요하다는 뜻이다.

## 변경 파일 범위 요약

이번 V6 변경 세트는 다음 범위를 포함한다.

- Recon source import: method-aware 주석 추출과 안정적인 parameter metadata
- Attack coverage: 78개 신호의 결정적 manifest, 상태 ledger, bounded exhaustive 실행,
  결과 export
- Benchmark fixture: test identity, credential reference, owned card/loan 등 안전한 seed data
- Request broker/policy: task-bound mutation approval, 비밀값 비저장, durable request/attempt
  강제
- Validation/Chaining: 최신 Attack 이후 stage 재실행, case별 eligibility와 무결성 검사
- Native Agent handoff: staged Hunt Skill 상대 경로 및 SHA-256 manifest
- CLI: source import, benchmark 준비, exhaustive attack 및 coverage 상태/export 명령
- 회귀 테스트: source import, coverage lifecycle/export, benchmark fixture, request guard,
  validation eligibility 및 전체 pipeline 경로
