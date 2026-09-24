# Phase D — 통합 pipeline shakedown (2026-09-23 시작, 09-24 KST 계속)

## 실행 기준

Phase B의 두 대상 최종 Recon이 모두 완료된 뒤 `aidast run`을 순차 실행했다. 공통 상한은 0.5 RPS, 요청 500, depth 2, timeout 15초, 생성 정책 concurrency 1이며 태깅은 25건 배치와 Codex 600초 제한이다. Phase C에서 검증한 일반 사용자 `primary` 세션 번들을 재사용했다. 산출물은 `result/test-runs/09.23/phase-d/Runs/`와 `AttackRuns/` 아래에 대상별로 분리했다.

## Juice Shop

Scan ID: `scan_b96c39ed94034315b911ed9f75287fd5`. 대상 및 시작 URL은 `http://127.0.0.1:3001/`이다. `aidast run`은 exit 0으로 종료됐고, Recon·Attack·Chaining·Validation stage가 모두 `completed`다. Recon 관측치 240건의 태깅 10개 배치는 실패 0건이었다. 프록시에서는 허용 199건, 정책 차단 5건을 기록했다.

| 항목 | 결과 |
| --- | ---: |
| Attack task | 완료 9, skip 2 |
| Attack attempt / HTTP ledger | 13 / 16건 완료 |
| Finding / reproduction spec | 3 / 3건 |
| Chain | 0건; Chaining stage 완료 |
| Validation case | 3건: `CONFIRMED` 1, `INCONCLUSIVE` 2 |
| Validation attempt / evidence / HTTP ledger | 5 / 7 / 5건 완료 |
| Audit event | 84건 |
| DB foreign key 위반 | 0건 |

`CONFIRMED` case는 SQL Injection finding에 연결된다. 해당 case에 validation attempt 5건과 evidence 7건이 연결돼 있다. Authentication Bypass via SQL Injection 및 Unauthenticated Sensitive Configuration Disclosure 후보는 `INCONCLUSIVE`다. 모든 Attack/Validation HTTP ledger는 `completed`이며 `reserved`, `running`, `outcome_unknown` 잔여 요청이 없다. `Recon.db`, `Surface.json`, `ReconReview.json`, `Handoff.json`, `Pipeline.db`가 모두 생성됐다.

이 값은 pipeline 기능 점검 결과다. 정답 데이터셋과의 TP/FP 대조 및 Report 생성은 Phase E에서 수행한다.

## VulnBank

Phase C에서 `/` 시작 URL로는 인증 dashboard를 방문하지 못한 결과가 있었으므로, 먼저 같은 승인 Scope의 `http://127.0.0.1:5001/dashboard`를 시작 URL로 좁히고 검증된 primary 세션 번들을 사용했다. Scan ID는 `scan_489efa6c771844e3b0790e85006a4d08`이다. `aidast run`은 exit 0으로 종료됐다. Recon·Attack·Validation stage는 `completed`, Chaining은 finding 0건으로 `skipped`다. 인증 endpoint 5개와 관측치 23건을 저장했고 태깅 1배치에서 실패 0건이었다. `/dashboard` HTTP 200을 4건 확인했다. 프록시는 허용 21건, 차단 7건을 기록했다.

| 항목 | 결과 |
| --- | ---: |
| Attack task | 완료 2, skip 3 |
| Attack attempt / HTTP ledger | 5 / 5건 완료 |
| Finding / chain / Validation case | 0 / 0 / 0건 |
| Audit event | 53건 |
| DB foreign key 위반 | 0건 |

모든 Attack HTTP ledger는 `completed`이고 잔여 `reserved`, `running`, `outcome_unknown` 요청이 없다. Recon 및 Pipeline 필수 산출물 5개가 모두 생성됐다. finding 0건은 이 dashboard 시작 실행에서 탐지된 후보가 없다는 뜻이며, 공개 `/login`, `/debug` 등의 취약점에 대한 음성 판정이 아니다.

### 공개 루트 통합 실행

계획의 `http://127.0.0.1:5001/` 시작 명령에 맞춘 별도 비로그인 scan `scan_843d0e9fd97548cbac8e66a016d5097f`도 실행했다. `aidast run`은 exit 0으로 종료됐고 Recon·Attack·Chaining·Validation stage가 모두 `completed`다. Recon endpoint 67개, 관측치 304개를 저장했으며 태깅 13배치는 실패 0건이었다. 프록시는 허용 123건, 차단 92건을 기록했다. 저장된 HTTP transaction 123건은 모두 loopback host였다.

| 항목 | 결과 |
| --- | ---: |
| Attack task | 완료 10, skip 1 |
| Attack attempt / HTTP ledger | 30 / 28건; ledger 완료 27, 실패 1 |
| Finding / reproduction spec | 3 / 3건 |
| Chain | 0건; Chaining stage 완료 |
| Validation case | `INCONCLUSIVE` 3건 |
| Validation attempt / evidence / HTTP ledger | 모두 0건 |
| Audit event | 85건 |
| DB foreign key 위반 | 0건 |

finding은 SSRF, password-reset token disclosure, 공개 OpenAPI 보안 설정 후보였다. SSRF와 password-reset 후보는 reproduction spec의 method/path와 연결된 endpoint ID의 method/path가 서로 달라 Validation의 `endpoint_method` 무결성 검사에서 중단됐다. 공개 OpenAPI 후보는 정책 적격성 평가 출력의 schema/근거 검증 실패로 `UNKNOWN`이 됐다. 따라서 세 `INCONCLUSIVE` 모두 실제 replay 음성 결과가 아니다. Attack HTTP ledger의 실패 1건은 `POST /api/v1/forgot-password`에 대한 `RequestGuardError`이며, `reserved`, `running`, `outcome_unknown` 잔여 요청은 없다. Recon 및 Pipeline 필수 산출물 5개가 모두 생성됐다.

## Recon application GET route 수집률

Phase B와 같은 [고정 GET route 기준](../main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)으로 각 통합 실행의 `Recon.db`를 대조했다. VulnBank 인증·공개 실행은 별도 비율로 기록하고, 대상 단계 값은 적중 route의 중복 제거 합집합으로 계산했다.

| 실행 | 적중 / 기준 | 누락 | 수집률 |
| --- | ---: | ---: | ---: |
| Juice Shop primary 인증 | 9 / 71 | 62 | 12.7% |
| VulnBank primary `/dashboard` | 5 / 47 | 42 | 10.6% |
| VulnBank 비로그인 `/` | 11 / 47 | 36 | 23.4% |
| VulnBank 두 실행 합집합 | 16 / 47 | 31 | 34.0% |
| **Phase D 두 대상 합계** | **25 / 118** | **93** | **21.2%** |

Juice Shop은 Phase B보다 기준 route 2개를 더 수집했고, VulnBank 공개 실행은 Phase B와 동일한 11개에 인증 dashboard에서 5개가 추가됐다. 이 비율은 취약점 탐지율이 아니다. Phase B·C와의 실행별 비교, 적중 경로 및 계산 방식은 [Recon 수집률 표](RECON_COVERAGE.md)에 기록했다.

## Phase D 판정

**PASS — 통합 실행 경로.** Juice Shop과 VulnBank 인증·공개 실행에서 Recon → Attack → Chaining → Validation stage가 종료됐다. VulnBank 인증 실행의 Chaining은 finding 0건으로 정당하게 `skipped`됐다. Juice Shop은 재현된 case 1건이 있다. VulnBank 공개 실행의 finding 3건은 모두 사전 무결성·적격성 gate에서 보류됐으므로 탐지 정확도 성공으로 계산하지 않는다. 세 실행의 Recon HTTP transaction과 Attack·Validation HTTP ledger URL에서 범위 밖 host는 0건이었다. 별도 수집률과 ground truth 한계는 Phase B/E에 기록한다.
