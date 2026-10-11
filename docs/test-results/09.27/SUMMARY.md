# 09.27 실험 요약 — 미검증 API 후보의 분리와 GET 검증

**정답 GET 관측·Surface 보존은 29/71 (40.8%)로 유지됐다.** 이번 성과는 수집률 증가보다 OpenAPI 후보를 실제 응답으로 검증하고, 검증되지 않은 HTML 응답 경로를 최종 검증 Surface와 분리한 데 있다.

## 범위와 실험 조건

- 기록 범위: 후보 GET 검증 재측정 문서와 GET·Surface O/X 표 3개. 날짜는 **2026-09-27**.
- 대상: 로컬 OWASP Juice Shop `http://127.0.0.1:3001/`.
- 이전 09.26 상세 GET 실행과 동일한 승인 Scope·인증 세션·고정 TargetPolicy, 요청 상한 1,000, 0.5 RPS, 동시성 1, depth 2, wordlist를 사용했다.
- ffuf root는 `/`, `/api`, `/rest`, `/socket.io` 4개로 고정했다. Recon만 실행했고 POST 후보 검증은 수행하지 않았다. GraphQL 능동 probe는 정책이 허용하지 않아 건너뛰었다.
- 수집률 분모는 명시적 application GET route 71개. O는 비제외 GET 응답 증거 또는 최종 Surface의 개별 route 보존이며, 모든 응답이 정상 JSON이라는 뜻은 아니다.

## 어떤 실험을 했고 결과는 어땠나

OpenAPI·GraphQL에서 얻은 경로를 응답 확인 전에는 `candidate`로 저장했다. 정책이 허용한 GET 후보를 최대 20개까지 검증하면서 같은 디렉터리의 없는 경로를 대조했다. **후보가 2xx JSON 양성 응답을 반환할 때만 `verified`로 승격**하고, 미검증 후보는 Surface의 `candidate_endpoints`로 따로 내보냈다.

| 지표 | 09.26 비교 기준 | 09.27 변경 후 | 변화 |
| --- | ---: | ---: | --- |
| 저장 HTTP transaction | 518 | 553 | +35건, 약 6.8% 증가 |
| 정답 GET의 실제 응답 증거 | 29/71 (40.8%) | 29/71 (40.8%) | +0개, 0.0%p |
| 최종 Surface의 정답 GET | 29/71 (40.8%) | 29/71 (40.8%) | +0개, 0.0%p |
| 정답 GET 누락 | 42/71 (59.2%) | 42/71 (59.2%) | 변화 없음 |

`/api-docs`의 Swagger UI 내장 명세에서 ZAP이 GET 후보 **2개**를 보고했다. `/b2b`, `/b2b/v2`는 이번 실행에서 모두 HTTP 200이었지만 `text/html; charset=UTF-8` 응답이어서 **2/2개를 `non_positive_json`으로 유지하고 승격 0개**였다. 프록시의 HTTP 200 관측만으로도 승격하지 않았다. 이 두 경로는 `candidate_endpoints`에만 있으며 71개 정답 경로에는 포함되지 않는다.

## 바뀐 내용과 정량적 성과

| 변경 | 목적 | 확인된 효과 |
| --- | --- | --- |
| API 2차 탐색 결과를 candidate로 저장 | 명세에서 보고한 경로와 실제 검증 경로 구분 | ZAP 후보 2개를 검증 전 상태로 보존 |
| 정책 허용 GET·대조 경로·JSON 응답 검증 | HTML fallback을 API 검증 성공으로 오인하지 않기 | HTML 200 후보 2개 모두 미승격, 해당 후보의 verified 승격 0개 |
| Surface의 `candidate_endpoints` 분리 | 후속 분석에서 미검증 후보를 확인 가능하게 유지 | 후보 2개를 별도 내보내고 기존 정답 Surface 29개 유지 |

최종 DB endpoint 상태는 **verified 45개, observed 2개, candidate 2개**, 합계 49개다. verified 45개에는 정적 리소스로 제외된 8개가 들어 있으므로 45를 application GET 수집률의 분자로 쓰지 않는다. 새 정답 GET은 0개였고 추가 transaction 35건을 탐색 정확도나 처리 속도 개선으로 해석하지 않는다.

## 검증 기록과 남은 과제

- 완료 scan ID: `scan_66fa5635f7b146e2966443226ede122d`. DB 상태 `completed`, `PRAGMA foreign_key_check` 위반 0건.
- 원본에 기록된 관련 테스트: **420개, 124 subtests 통과**, `git diff --check` 통과.
- 이번 검증은 2개 HTML 후보가 검증 Surface로 승격되지 않는 동작을 확인했다. 전체 후보 분류 정확도·오탐률과 취약점 탐지 precision/recall은 측정하지 않았다.
- 남은 GET 경로 42개를 발견하는 개선은 별도 과제이며, 이번 변경만으로 수집률 확대는 확인되지 않았다.

## 원본 근거

- [후보 GET 검증 재측정](_archive/CANDIDATE_GET_VERIFICATION_RETEST.md).
- [실제 GET 경로별 O/X](_archive/CANDIDATE_GET_ROUTE_MATRIX.md), [최종 Surface 경로별 O/X](_archive/CANDIDATE_GET_SURFACE_ROUTE_MATRIX.md).
- 비교 기준: [09.26 상세 GET 실험](../09.26/_archive/recon-openapi/GET_DETAIL_RETEST.md).
- 실행 원본 위치: 이전 `result/test-runs/09.26/juice-get-detail-pinned-1000/`, 이번 `result/test-runs/09.27/candidate-get-verification-1000/`의 Recon DB·Surface·로그.
