# 09.26 실험 요약 — 상세 GET 수집과 실제 Validation Agent 정답 검증

**목록에서 관측한 실제 ID를 사용해 Juice Shop GET 관측·Surface 보존을 25/71 (35.2%)에서 29/71 (40.8%)로 높였다.** Validation은 실제 Agent 단일 실행에서 준비된 7건 모두 독립 채점 PASS를 받았고, 별도 인증 전제 후보 3건도 실제 Agent 판정과 정답이 일치했다.

## 범위와 실험 조건

- 기록 범위: `recon-openapi/`의 Swagger·목록 ID 실험과 경로별 O/X, `validation/`의 통제 기준선·실제 Agent·단일 실행·인증 전제 실험 및 JSON. 실행 날짜는 **2026-09-26**.
- Recon: Juice Shop 20.2.0, primary 세션, 동일 승인 Scope·고정 TargetPolicy, 상한 1,000요청, 0.5 RPS, 동시성 1, depth 2, SecLists API 목록 174줄, ffuf 150초/root. Recon만 실행했다.
- Validation: 로컬 Juice Shop·VulnBank에 실제 GET 재생. Attack 주장은 합성 실습 입력이고 정답지는 Agent에게 제공하지 않았다. 공식 후보 10건 중 기본 GET 준비 7건과 인증 준비가 필요한 3건을 별도 조건으로 평가했다.
- Recon 수집률은 고정 application GET route 71개 대비 응답 증거·개별 Surface 보존 비율이다. Validation PASS는 결정·출처·대조군·증거 인용을 독립 채점한 결과다.

## Recon 실험과 정량적 결과

| 실험 | 바뀐 내용 | 실제 GET 관측 / Surface | HTTP transaction | 성과 |
| --- | --- | --- | ---: | --- |
| 직전 인증 Runtime 정상 실행 | 비교 기준 | 각각 25/71 (35.2%) | 425 | 기준 |
| Swagger UI 내장 OpenAPI 반영 | `/api-docs` 명세를 확인해 ZAP에 전달 | 각각 25/71 (35.2%) | 508 | 명세 0→1개, 2차 API 후보 0→2개. 정답 GET 순증 0개 |
| 목록 JSON의 실제 ID로 상세 GET 확인 | 목록에서 ID를 읽고 대응 상세 URL 검증, ffuf root 4개 고정 | 각각 29/71 (40.8%) | 518 | 정답 GET 4개 순증, 약 5.6%p 상승; 적중 개수 16.0% 증가 |

새로 확인한 경로는 `/api/BasketItems/1`, `/api/Feedbacks/1`, `/api/Products/1`, `/api/Users/1`이다. **4개 모두 HTTP 200과 Surface 항목이 있으며 응답 `data.id=1`이 선택 ID와 일치했다.** 목록이 비어 있거나 ID가 없으면 상세 GET을 만들지 않는다.

Challenges·Complaints·Quantitys·SecurityQuestions 상세 URL에도 요청했지만 401·401·403·401이었고, 검증된 Surface에 연결되지 않아 수집 성공으로 세지 않았다. 정답 GET 누락은 **46→42개**다.

Swagger 명세는 `/b2b/v2`의 POST orders를 설명해 GET 정답지 확장에 직접 기여하지 않았다. ZAP 후보 `/b2b`, `/b2b/v2`에는 해당 Recon의 HTTP transaction이 연결되지 않았고 별도 GET도 HTML 200/401이어서 검증된 GET 성과로 세지 않았다. Swagger·인증 Runtime 변경이 함께 있는 작업 트리였으므로 명세 반영 단독 인과 효과는 분리할 수 없다.

목록 ID 실험은 루트 선택 실패 후 38개 root로 대체된 첫 시도를 중단·제외하고 `/`, `/api`, `/rest`, `/socket.io` 4개를 고정해 완료했다. 이후 상세 응답 ID 일치 검증을 코드에 보강했지만, **29/71은 보강 직전 완료 scan의 값**이다. 저장된 4개 응답이 강화 조건을 충족하는 것까지 확인했으며 최종 코드 전체의 추가 Recon 재실행 값은 아니다.

## Validation 실험과 정량적 결과

| 실험 | 조건 | 결과 | 해석 |
| --- | --- | --- | --- |
| 프로필 증거 기준선 | Eligibility Agent 지연으로 중단 후 명시적 통제 평가기, 실제 로컬 GET | 음성 정답 PASS 6/6, 양성 1건 UNDERPOWERED/UNRESOLVED; 감사 결합 7/7 | 재생·증거·감사 저장 경로 검증. 실제 Agent 판단 성능 집계에서 제외 |
| 실제 Agent 주 실행 | 실제 Eligibility·Blind·ClaimComparison, 준비 7건 | 단계 완료 6/7 (85.7%), 독립 채점 PASS 5/7 (71.4%), 미완료 1, 양성 UNDERPOWERED 1 | Blind 신호 분류는 7/7 일치했지만 최종 정답 7/7은 아님 |
| 실패 단계·양성 별도 재검증 | PrivacyRequests 새 비교 세션 재개, 별도 Impact 계약 | 음성 합계 PASS 6/6, 별도 양성 CONFIRMED 1/1·채점 PASS | 재개·설정이 다른 결과이므로 단일 실행 7/7로 합치지 않음 |
| 기본 실행기 보강 후 단일 실행 | 실제 Agent, 새 Unblind 세션, 양성 Impact 계약 포함 | 단계 완료 7/7 (100.0%), 정답 PASS 7/7 (100.0%): DISPROVEN 6, CONFIRMED 1 | 명령 한 번·단일 DB에서 별도 재개 없이 완료. 기본 재생 35회+Impact GET 1회=36회 |
| 인증 전제 후보 3건 | 두 merchant 신원·소유 결제를 사전 준비, 실제 Agent | 완료·정답 PASS 3/3 (100.0%): DISPROVEN 2, CONFIRMED 1 | 사례당 대조군 2회+target 3회, 총 GET 15회 |

실제 Agent 주 실행 대비 보강된 단일 실행은 **완료 6→7건**, 독립 채점 정답 **5→7건**으로 개선됐다. PrivacyRequests가 같은 실행 안에서 DISPROVEN으로 끝났고, `/debug/users`는 추가 Impact GET과 영수증을 거쳐 적용 B/S/A **(2,2,2)**로 CONFIRMED가 됐다.

공식 후보 10건은 최종적으로 **기본 7건+별도 인증 3건 모두 평가됐고 각 정답과 일치**했다. 이는 조건이 다른 두 최종 실행의 후보 범위 집계이며 **10건을 한 번의 동일 설정에서 완료한 결과나 제품 전체 정확도 100%를 뜻하지 않는다.**

## 바뀐 내용과 판정 근거

| 변경 | 해결한 문제 | 확인된 성과 |
| --- | --- | --- |
| 목록 ID 기반 상세 GET | ID가 필요한 route를 구체 URL로 만들지 못함 | Recon 정답 4개 추가, 요청·Surface 모두 29/71 |
| 상세 응답 ID 일치 검사 | 200 오류 JSON을 상세 자원으로 오인 가능 | 저장된 성공 응답 4개 모두 선택 ID 일치. 최종 코드 재실행은 미측정 |
| 기본 Validation 실행기에 Impact 연결 | `/debug/users`를 재현해도 필드명 신호만으로 민감도 0 제한 | 단일 실행에서 Impact 가설 1건 성공, 양성 CONFIRMED·전용 채점 PASS |
| 봉인 Blind 입력 전달·Unblind 새 세션 | PrivacyRequests ClaimComparison 지연·timeout | 보강 단일 실행에서 재개 없이 7/7 단계 완료 |
| 영수증 결합·정규화 해시·채점 강화 | 저장 영수증 해시 불일치, 검증 증거 결합 부족 | 새 양성 DB에서 일반·Impact 채점 모두 PASS, 저장 영수증 해시 일치 |
| 인증 증거 포트·URL 비교 수정 | 쿼리 포함 음성 대조군 원본 URL과 정리 URL 불일치 | 새 인증 v2 번들에서 3건 모두 PASS |
| 인증 비악용 근거·keyring 처리 | 타인 객체 가설의 소유권·응답 관계 확인 필요 | 실시간 소유권·고정 소스·반복 응답으로 음성 2건 반증, merchant별 목록 경로의 타인 결제 노출 1건 확증 |

인증 후보의 상세 조회는 타인 결제에 404, 기본 목록은 자기 결제만 반환해 DISPROVEN이었다. `/api/v1/payments/merchant_id/{merchant_id}`는 다른 merchant의 결제를 반환해 CONFIRMED, 적용 축 **(2,1,1)**이었다. 인증 준비용 POST와 Validation GET은 분리했으며 결제는 거절돼 금액 이동이 없었다. 이번 실험이 Agent의 자율 인증 준비 Development를 검증한 것은 아니다.

## 검증 기록과 남은 과제

- 완료 Recon scan: Swagger `scan_f0ef760c69064abf97a165a7f0c9b801`, 상세 GET `scan_754c94acc938409791ab6571302795c3`. 각각 DB `completed`, foreign key 위반 0건.
- Validation 원본에 기록된 SQLite 무결성은 `ok`. 단일 실행 감사 결합 7/7, Impact 영수증 해시 일치, 인증 재생 15건의 원장·응답 해시·증거 인용 채점 완료.
- 프로필 기준선의 독립 B/S/A 정답 라벨은 0개, 축 강제 적용 준비 프로필은 0/58개다. 감사 기록이 있다는 사실을 축 점수 정확도로 해석하지 않는다.
- 표본이 작고 후보별 반복이 없다. 한 번의 성공으로 세션 지연 해결의 보편성·일반 정확도·신뢰구간을 주장하지 않는다. Recon의 미검증 명세 후보 처리와 남은 GET 42개가 후속 과제다.

## 원본 근거

- Recon: [Swagger 실험](_archive/recon-openapi/README.md), [목록 ID 상세 GET](_archive/recon-openapi/GET_DETAIL_RETEST.md), [Swagger GET](_archive/recon-openapi/GET_ROUTE_MATRIX.md)·[Surface](_archive/recon-openapi/SURFACE_ROUTE_MATRIX.md), [상세 GET](_archive/recon-openapi/GET_DETAIL_ROUTE_MATRIX.md)·[Surface](_archive/recon-openapi/GET_DETAIL_SURFACE_ROUTE_MATRIX.md).
- Validation 기준선: [보고서](_archive/validation/PROFILE_EVIDENCE_BASELINE.md)·[JSON](_archive/validation/PROFILE_EVIDENCE_BASELINE.json).
- 실제 Agent·단일 실행: [주 실행/재개](_archive/validation/REAL_AGENT_ACCURACY.md)·[JSON](_archive/validation/REAL_AGENT_ACCURACY.json), [단일 실행](_archive/validation/SINGLE_RUN_ACCURACY.md)·[JSON](_archive/validation/SINGLE_RUN_ACCURACY.json).
- 인증 전제 후보: [보고서](_archive/validation/AUTH_PREREQUISITE_ACCURACY.md)·[JSON](_archive/validation/AUTH_PREREQUISITE_ACCURACY.json).
- 실행 원본 위치: `result/test-runs/09.26/juice-openapi-1000/`, `juice-get-detail-pinned-1000/`; Validation은 `result/test-runs/validation-candidates/validation-*-20260926*`와 `validation-profile-evidence-v3`. 각 보고서에 실제 번들 이름·DB·채점 경로가 기록돼 있다.
