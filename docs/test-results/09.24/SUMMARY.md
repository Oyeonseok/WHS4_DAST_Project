# 09.24 실험 요약 — SPA Recon 개선과 Validation 판정 보강

**Juice Shop의 실제 GET 관측과 최종 Surface 보존을 모두 9/71 (12.7%)에서 25/71 (35.2%)로 높였다.** 핵심은 SPA JavaScript 경로 추출·검증과 정적 API 경로 병합 수정이었다. 별도 Validation 실습에서는 준비된 GET 후보 7건의 정답 도달을 1/7에서 7/7로 개선했다.

## 범위와 실험 조건

- 이 폴더의 Recon 문서·O/X 표와 `validation/` 문서를 함께 정리했다. 기본 기록은 **2026-09-24**, Impact 실습은 **09-24~25**, 인증 Runtime 재시험·복구는 **09-26**에 수행됐다.
- Recon 대상: Juice Shop 20.2.0, primary 세션 1개. GET/HEAD/OPTIONS, 0.5 RPS, depth 2, 동시성 1, timeout 15초. 주요 수정 비교는 요청 상한 1,000, SecLists API 목록 174줄, ffuf 150초/root.
- Recon 실행에서는 Attack·Chaining·Validation·외부 태깅을 수행하지 않았다. 아래 Validation 수치는 Juice Shop·VulnBank를 사용한 **별도 격리 실습**이며 Attack 주장은 합성 입력이다.
- Recon 지표는 명시적 application GET route 71개 대비 실제 응답 증거와 최종 Surface의 개별 경로 보존을 나눠 집계한다. HTTP 500도 관측 O가 될 수 있으며 정상 API 응답이나 취약점 발견을 뜻하지 않는다.

## 어떤 Recon 실험을 했고 결과는 어땠나

| 완료 실행 | 실험 내용 | 실제 GET 관측 | Surface 보존 | 저장 HTTP transaction |
| --- | --- | ---: | ---: | ---: |
| `no-ffuf-150` | ffuf 없이 인증 Recon | 9/71 (12.7%) | 9/71 (12.7%) | 125 |
| `smoke-ffuf-150` | 11개 smoke 목록, 상한 150 | 9/71 (12.7%) | 9/71 (12.7%) | 123 |
| `smoke-ffuf-300` | smoke 목록, 상한 300 | 12/71 (16.9%) | 12/71 (16.9%) | 239 |
| `seclists-api-500` | API 목록 174줄, 상한 500 | 10/71 (14.1%) | 8/71 (11.3%) | 397 |
| `seclists-api-1000` | 같은 목록, 상한 1,000 | 9/71 (12.7%) | 9/71 (12.7%) | 520 |
| `spa-refactor-1000` | SPA 백틱 경로 추출·후보 검증 수정 | 25/71 (35.2%) | 9/71 (12.7%) | 422 |
| `path-normalization-1000` | 정적 API 경로 병합 수정 추가 | 25/71 (35.2%) | 25/71 (35.2%) | 466 |
| `browser-navigation-1000` | 보이는 링크 수집 | 25/71 (35.2%) | 25/71 (35.2%) | 467 |
| `browser-routerlink-1000` | Angular 버튼 경로 수집 | 25/71 (35.2%) | 25/71 (35.2%) | 604 |
| `browser-action-capture-full-1000` | 클릭 직후 링크 보존·계획 보정 | 25/71 (35.2%) | 25/71 (35.2%) | 443 |
| `browser-luna-full-1000` | Recon 계획·ffuf root 선택 모델 통일 | 25/71 (35.2%) | 25/71 (35.2%) | 471 |

150 상한 smoke 실행은 ffuf가 정상 종료했지만 **대상에 도달한 목록 요청은 0건**이었다. 300 상한에서는 정답 경로 3개를 추가했으며 `/profile`의 응답은 500이었다. SecLists 상한 500→1,000 비교는 transaction이 123건 증가했지만 GET 적중은 10→9개여서 예산 확대만의 개선은 확인되지 않았다. root 선택과 브라우저 요청도 실행마다 달랐다.

## 바뀐 내용과 정량적 성과

| 변경 | 해결한 문제 | 확인된 효과 |
| --- | --- | --- |
| ffuf 정책 차단 응답 필터 | 프록시가 만든 403을 대상 경로 후보로 저장 | 이전 500 상한의 ffuf 후보 26개 중 25개가 정책 차단 응답임을 확인. 실제 대상 403은 유지하며 정책 응답만 제거하는 회귀 테스트 통과 |
| ffuf 시간 제한 옵션·진단 추가 | 150초/root 고정값과 목록 완료 여부 혼동 | `--ffuf-max-time-seconds`, 목록 줄 수·시간 기록 추가. 이 변경만의 수집률 증가는 측정하지 않음 |
| SPA 백틱 경로 추출·검증 수정 | 기존 추출 0건, 없는 경로 대조 응답 500이면 후보 전체 탈락 | `adaptive_js` 채택 0→19개, 실제 GET 정답 9→25개. 새 정답 16개 모두 HTTP 200 |
| `/api`·`/rest` 정적 경로 병합 수정 | 다른 자원/action 이름이 `:param` 하나로 합쳐짐 | 실제 GET 25개 유지, Surface 정답 9→25개. 숫자·UUID ID 정규화는 유지 |
| SPA 링크·`routerLink`·클릭 직후 후보 수집 | 메뉴 안 화면을 다음 방문 후보로 남기지 못함 | 화면 방문 6→8개, UI 동작 2→4개. GET·Surface는 25/71 유지 |
| Recon 모델 `gpt-6-luna` 지정·필수 작업 보정 | 명시적 execute가 HTTP_PROBE만 수행 | 새 scan에서 HTTP_PROBE·ORIGIN_DISCOVERY·ENDPOINT_DISCOVERY 3개 완료. 모델 변경 자체의 수집률·비용 개선은 미측정 |
| 실제 transaction URL 기반 평가·Surface 평가 분리 | 병합 endpoint 대표 path 뒤에 실제 요청이 가려짐 | 과거 `seclists-api-500` 관측을 9→10개로 정정. SPA 수정 실행의 잘못된 11/71 집계도 25/71로 바로잡음 |

주요 1,000 상한 실행의 시작·최종 비교는 **정답 경로 16개 순증, 약 22.5%p 상승, 2.78배**다. SPA 수정은 요청 관측을 늘렸고 정규화 수정은 그 경로가 최종 공격표면에 남도록 했다. ffuf 후보는 주요 비교에서 `/api` HTTP 500 한 개로 정답지 밖이었으므로, 이 순증을 ffuf 성과로 계산하지 않는다.

Wordlist 비교는 오프라인 분석이다. API 단어 목록 174줄·API endpoint 목록 295줄·common 목록 4,752줄의 단순 정답 경로 일치는 각각 1·0·10개였다. **이 폴더의 기록 시점에는 common 목록으로 실제 Recon을 실행하지 않았다.** 0.5 RPS에서 common 한 root 전체의 이론적 최소 시간은 약 2시간 38분이므로 시간·예산 설계가 다음 과제로 남았다.

## 09.26 후속 실험 — 인증 Runtime 회귀와 복구

| 지표 | 09.24 최종 정상 | 09.26 인증 소실 재시험 | 09.26 Runtime 수정 후 |
| --- | ---: | ---: | ---: |
| 실제 GET / Surface 정답 | 각각 25/71 (35.2%) | 각각 18/71 (25.4%) | 각각 25/71 (35.2%) |
| `adaptive_js` 채택 / 미검증 | 19 / 0 | 12 / 3 | 19 / 0 |
| 저장 HTTP transaction | 471 | 591 | 425 |

관리형 Chromium이 살아 있는데도 프로세스 핸들 부재를 종료로 판단하고, Runtime 재시작 중 빈 storage를 세션 파일에 저장하는 문제가 있었다. `browser.is_connected()` 기반 생존 판정, 인증 상태 보존·복구, JS 검증 직전 세션 확인을 추가했다. 잃었던 7개 경로가 인증 헤더를 가진 HTTP 200과 Surface 항목으로 돌아왔으며 **18→25개, 약 9.9%p 회복**했다. 새 경로 추가 성과는 아니다.

일반 CLI 재시험은 정책 생성 모델의 300초 timeout으로 탐색 전에 실패했다. 완료 비교는 이전 승인 정책을 검증·고정한 래퍼를 사용했다. 중단된 인증 복구 시도와 ENDPOINT_DISCOVERY가 빠진 probe-only 실행은 수집률 집계에서 제외했다.

## 별도 Validation 실습 — 반증 근거와 Impact 개발

| 실험 | 변경·확인 내용 | 결과 |
| --- | --- | --- |
| 첫 GET 후보 7건 실행 | 음성 신호 부재를 장애로 분류해 반증하지 못함 | 정답 PASS 1/7 (14.3%), UNRESOLVED 6/7. 공식 후보 중 별도 인증 준비 3건은 미실행 |
| 프로필 연결 수정 | 무인증 노출 가설을 `hunt-idor`에서 `hunt-auth-bypass`로 수정 | Juice Shop 4건이 BLOCKED 오분류에서 INCONCLUSIVE로 이동했으나 아직 정답 DISPROVEN에는 미도달 |
| 명시적 부정 증거·Development 계약 검사 | 고정 소스/라우트/정책/대조군 해시와 target 응답을 결합; 실행 계약 없는 개발 차단 | 새 실습 번들의 최신 단계 PASS 7/7 (100.0%): 음성 DISPROVEN 6, 양성 CONFIRMED 1. 최신 단계 기본 GET 총 35회, Development 동작 0건 |
| 기본 Validation 경로 분리 점검 | 실습 전용 부정 증거 어댑터 없이 VulnBank 2건 실행 | 2건 모두 INCONCLUSIVE, Development 동작 0건. 실습의 7/7을 기본 경로 전체 성능으로 해석하지 않음 |
| Impact Development 실습, 09.24~25 | 출처 GET·고유 마커·JSON 위치·계약을 계획과 새 증거에 연결 | v2~v5는 skip/UNRESOLVED. v6은 추가 GET 1회·민감도 1→2·CONFIRMED, v7은 강화한 필드명/JSON 경로 assertion으로 당시 채점 PASS |

정답 도달은 첫 실습 대비 **6건 증가, 약 85.7%p 상승**했다. 음성 6건의 최신 target 18회 모두 명시적 부정 증거가 있었고, 양성 target 3회에는 노출 신호가 있었다. 결과는 합성 Attack 주장과 지정한 GET 재현 계약에 한정된다.

Impact v7의 PASS는 당시 기준이다. [09.26 강화된 재채점 기록](../09.26/_archive/validation/REAL_AGENT_ACCURACY.md)에서는 저장된 사전조건 영수증이 없는 과거 v7을 `UNRESOLVED`로 처리한다. 과거 성공을 현재 증거 기준의 통과로 소급하지 않는다.

## 검증 기록과 남은 과제

- 원본에 기록된 Recon 검증: SPA·평가기 78개/12 subtests, 정규화까지 96개/12 subtests, 브라우저·모델 보정까지 230개/35 subtests, 09.26 Runtime 수정 후 233개/35 subtests 통과. 완료 비교 DB의 foreign key 위반 0건.
- 원본에 기록된 Validation 검증: 후속 판정 변경 `434 passed, 4 skipped, 395 subtests passed`; Impact 관련 `561 passed, 4 skipped, 511 subtests passed`. 대상 격리 DB 무결성 `ok`.
- Recon 최종 누락은 46/71개. 정답지의 parameter route 20개 중 관측은 basket 1개여서 실제 목록 ID 기반 상세 조회와 중첩 화면 탐색이 다음 과제다.
- 인증 상태·ffuf root·모델·브라우저 요청량이 달라 transaction 총량을 처리 속도나 비용 개선으로 해석하지 않는다. 반복 안정성, 전체 탐지 recall·F1, 태깅 정확도는 측정하지 않았다.

## 원본 근거

- 전체 실행·분석: [README](_archive/README.md), [인증 Recon](_archive/09.24_AUTH_JUICE_SHOP_RECON.md), [기존 리팩토링 요약](_archive/RECON_REFACTOR_SUMMARY.md), [재개 기록](_archive/RESUME_RECON_REFACTOR.md), [SPA 진단](_archive/SPA_RECON_DIAGNOSIS.md), [ffuf 외 병목](_archive/NON_FFUF_RECON_COVERAGE_ANALYSIS.md), [wordlist 선정](_archive/WORDLIST_SELECTION.md).
- 변경별 기록: [1. ffuf 필터](_archive/REFACTOR_01_FFUF_PROXY_FILTER.md), [2. 시간 제한](_archive/REFACTOR_02_FFUF_TIME_LIMIT.md), [3. SPA 검증](_archive/REFACTOR_03_SPA_JS_VALIDATION.md), [4. 정규화](_archive/REFACTOR_04_STATIC_ROUTE_NORMALIZATION.md), [5. 화면 탐색](_archive/REFACTOR_05_BROWSER_NAVIGATION.md), [6. 인증 Runtime](_archive/REFACTOR_06_AUTHENTICATED_RUNTIME.md), [09.26 재시험](_archive/RECON_RETEST_2026_09_26.md).
- 경로별 근거: [초기 GET](_archive/RECON_GET_ROUTE_MATRIX.md)·[Surface](_archive/RECON_SURFACE_ROUTE_MATRIX.md), [브라우저 GET](_archive/RECON_BROWSER_GET_ROUTE_MATRIX.md)·[Surface](_archive/RECON_BROWSER_SURFACE_ROUTE_MATRIX.md), [재시험 GET](_archive/RECON_RETEST_2026_09_26_GET_ROUTE_MATRIX.md)·[Surface](_archive/RECON_RETEST_2026_09_26_SURFACE_ROUTE_MATRIX.md), [인증 복구 GET](_archive/RECON_AUTH_RECOVERY_GET_ROUTE_MATRIX.md)·[Surface](_archive/RECON_AUTH_RECOVERY_SURFACE_ROUTE_MATRIX.md), [71개 정답지](_archive/JUICE_SHOP_GET_GROUND_TRUTH.json).
- Validation: [첫 실행](_archive/validation/VALIDATION_LAB_FIRST_RUN.md), [장애 분류](_archive/validation/VALIDATION_BLOCKER_CLASSIFICATION.md), [후속 판정](_archive/validation/VALIDATION_LAB_FOLLOWUP.md), [Impact 개발](_archive/validation/VALIDATION_IMPACT_DEVELOPMENT_LAB.md).
- 실행 원본 위치: Recon은 `result/test-runs/09.24/<실행명>/`, Validation은 `result/test-runs/validation-candidates/<번들명>/`. 각 원본 문서에 scan ID·DB·로그·채점 경로가 기록돼 있다.
