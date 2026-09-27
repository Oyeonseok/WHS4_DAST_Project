# Juice Shop 후보 GET 검증 재측정 (2026-09-27)

ZAP OpenAPI·GraphQL 결과를 응답 확인 전에는 `candidate`로 보관하고, 정책이 허용한 GET 후보만 최대 20개 검증하는 변경을 적용한 뒤 OWASP Juice Shop에서 Recon을 재실행했다. 후보와 같은 디렉터리의 존재하지 않는 경로를 대조하고, 실제 후보가 2xx JSON 응답을 돌려줄 때만 `verified`로 승격한다. POST 검증은 수행하지 않는다. `Surface.json`은 검증 전 후보를 `candidate_endpoints`에 따로 내보낸다.

이전 실행(`result/test-runs/09.26/juice-get-detail-pinned-1000`)과 이번 실행(`result/test-runs/09.27/candidate-get-verification-1000`)은 같은 승인 Scope, 인증 세션, 고정 TargetPolicy, 1,000 요청 상한, 0.5 RPS, 동시성 1, 깊이 2, 워드리스트 및 ffuf 루트 4개(`/`, `/api`, `/rest`, `/socket.io`)를 사용했다. 두 실행 모두 Recon만 수행했다.

| 지표 | 이전 | 이번 |
| --- | ---: | ---: |
| 완료된 scan의 HTTP transaction | 518 | 553 |
| 정답 GET 경로의 실제 응답 증거 | 29/71 (40.8%) | **29/71 (40.8%)** |
| 최종 Surface의 정답 GET 경로 | 29/71 (40.8%) | **29/71 (40.8%)** |

이번 OpenAPI 탐색은 `/api-docs`의 Swagger UI 내장 명세를 확인했고 ZAP이 GET 후보 2개를 보고했다. `/b2b`와 `/b2b/v2` 모두 HTTP 200이었지만 응답이 `text/html; charset=UTF-8`였다. 검증기는 두 후보를 `non_positive_json`으로 남겼고, 프록시 캡처의 200 응답도 후보를 승격하지 않았다. 두 경로는 최종 Surface의 `candidate_endpoints`에만 있으며 정답 GET 경로 71개에 속하지 않는다. GraphQL 능동 probe는 고정 정책이 허용하지 않아 건너뛰었다. 따라서 이번 재측정에서 새로 확보한 정답 GET 경로는 없다.

완료 scan ID는 `scan_66fa5635f7b146e2966443226ede122d`다. DB 상태는 `completed`, `PRAGMA foreign_key_check`는 빈 결과이며, endpoint 상태는 `verified` 45개(정적 리소스로 제외된 8개 포함), `observed` 2개, `candidate` 2개다. 관련 테스트는 420개와 서브테스트 124개가 통과했고 `git diff --check`도 통과했다.

[HTTP 경로별 비교](CANDIDATE_GET_ROUTE_MATRIX.md)와 [Surface 경로별 비교](CANDIDATE_GET_SURFACE_ROUTE_MATRIX.md)에 정답지 71개 전체 O/X가 있다. 평가는 `docs/test-results/09.24/evaluate_recon_get_routes.py`와 `docs/test-results/09.24/JUICE_SHOP_GET_GROUND_TRUTH.json`으로 수행했다. O는 해당 URL의 HTTP 응답 관측을 뜻하며, 그 응답이 정상 API JSON이라는 뜻은 아니다.
