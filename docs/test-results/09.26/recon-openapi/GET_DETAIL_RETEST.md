# Juice Shop 목록 ID 기반 상세 GET 재측정 (2026-09-26)

기준 실행은 `result/test-runs/09.26/juice-openapi-1000/`이고, 이번 완료 실행은 `result/test-runs/09.26/juice-get-detail-pinned-1000/`이다. 동일한 승인 Scope, 인증 세션, 고정 TargetPolicy, 1,000 요청 상한, 0.5 RPS, 동시성 1, 깊이 2, 동일 워드리스트를 사용했다. 이전 실행에서 선택된 ffuf 루트 4개(`/`, `/api`, `/rest`, `/socket.io`)를 이번에는 고정했다. 루트 선택 Agent 실패 시 38개로 대체된 첫 시도는 비교 조건이 달라 중단했으며, 완료 실행의 결과에 포함하지 않았다. Recon만 실행했다.

| 지표 | 기준 실행 | 이번 실행 |
| --- | ---: | ---: |
| 완료된 scan의 HTTP transaction | 508 | 518 |
| 정답 GET 경로의 실제 응답 증거 | 25/71 (35.2%) | **29/71 (40.8%)** |
| 최종 Surface의 정답 GET 경로 | 25/71 (35.2%) | **29/71 (40.8%)** |

새로 확인된 경로는 `GET /api/BasketItems/1`, `GET /api/Feedbacks/1`, `GET /api/Products/1`, `GET /api/Users/1`이다. 모두 목록 JSON의 실제 `id`에서 만든 GET이며 HTTP 200 응답과 Surface 항목이 있다. `Challenges/1`, `Complaints/1`, `Quantitys/1`, `SecurityQuestions/1`에도 GET을 시도했지만 각각 401, 401, 403, 401 응답으로, 검증된 Surface 항목과 연결되지 않아 정답 경로로 세지 않았다. 목록이 비어 있거나 유효한 ID가 없으면 상세 GET을 만들지 않는다.

재측정 뒤 상세 URL이 `200` 오류 JSON을 반환하는 경우를 거르는 검증을 추가했다. 최종 코드는 상세 응답의 `id`가 목록에서 선택한 `id`와 같아야 Surface에 남긴다. 완료 실행에 저장된 위 네 상세 응답의 `data.id`는 모두 `1`로 이를 만족한다. 최종 코드 전체로 Recon을 다시 실행한 수치는 아니며, 이 문서의 29/71은 검증 보강 직전 완료 실행의 DB 결과다.

완료 scan ID는 `scan_754c94acc938409791ab6571302795c3`이다. `Recon.db`의 scan 상태는 `completed`이고 `PRAGMA foreign_key_check`는 빈 결과다. [HTTP 경로별 O/X](GET_DETAIL_ROUTE_MATRIX.md)와 [Surface 경로별 O/X](GET_DETAIL_SURFACE_ROUTE_MATRIX.md)에 전체 71개 비교가 있다.

실행 시 사용한 정책 고정 스크립트는 `docs/test-results/09.24/run-recon-retest-pinned-policy-2026-09-26.sh`, ffuf 루트 고정 래퍼는 `docs/test-results/09.26/recon_get_detail_pinned_roots.py`이다. 평가에는 `docs/test-results/09.24/evaluate_recon_get_routes.py`와 `docs/test-results/09.24/JUICE_SHOP_GET_GROUND_TRUTH.json`을 사용했다.
