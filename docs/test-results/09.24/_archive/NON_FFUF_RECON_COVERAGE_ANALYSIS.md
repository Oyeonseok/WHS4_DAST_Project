# ffuf 외 Recon 수집 병목 분석

기준은 [Juice Shop 20.2.0 GET 정답지](JUICE_SHOP_GET_GROUND_TRUTH.json)와 인증 세션 1개로 실행한 `seclists-api-500`, `seclists-api-1000`의 완료된 DB·진단 로그다. 이 두 실행은 ffuf 프록시 차단 필터 및 시간 설정 리팩토링 **이전** 결과다. 따라서 새 코드의 전체 수집률을 증명하지 않는다.

## 관측값

| 구분 | 500건 상한 | 1,000건 상한 | 해석 |
| --- | ---: | ---: | --- |
| 실제 저장 HTTP transaction | 397 | 520 | 대상 요청은 123건 증가 |
| DB의 wordlist 형태 GET 경로 | 197 | 298 | 목록 앞부분을 101개 더 시도 |
| GET 정답 경로 관측 | 10/71 | 9/71 | 실제 요청 URL 기준. 두 실행 모두 낮음 |
| `adaptive_js` 채택 | 0 | 0 | JS 기반 후보가 공격표면으로 이어지지 않음 |
| API 2차 Discovery | 0 | 0 | OpenAPI·GraphQL 감지되지 않음 |

정답지 71개는 `/api/` 30개, `/rest/` 27개, 그 외 14개다. 1,000건 실행의 관측은 각각 2, 6, 1개였다. 정답지에는 구체적인 ID 값을 만들어야 하는 parameter route가 20개 포함되며, 이 중 이번 세션에서 관측한 것은 `/rest/basket/:id` 1개다. 그러므로 9/71은 **전체 서버 route 정의 대비 관측 비율**이지, 이 한 계정에서 접근 가능한 경로만의 recall이 아니다.

1,000건 실행의 정책은 GET/HEAD/OPTIONS에 대해 `allowed_path_prefixes=['/']`, `excluded_path_prefixes=[]`였다. `/api`나 `/rest`를 Scope에서 제외한 결과는 아니다.

## ffuf 이외의 직접적인 병목

1. **SPA 번들 경로 추출이 비어 있다.** 현재 `_JS_API_PATH`는 작은따옴표와 큰따옴표로 둘러싸인 `/api`·`/rest` 경로만 찾는다. 고정된 실행 이미지의 `main.js`(1,207,722바이트, SHA-256 `1fbe46da9b367d28f7c3b80ef6648c593ac18a18c40edc115d0af0639f967aa7`)에 이 정규식의 일치는 0개다. 백틱 문자열을 별도로 추출하면 26개가 GET 정답지의 **경로 문자열**과 정확히 일치한다. 이 26개 중 23개는 1,000건 실행에서 관측되지 않았다. 문자열 일치만으로 해당 URL의 GET 성공이나 실제 호출을 증명하지는 않는다.
2. **후보 검증용 기준 요청이 500을 반환한다.** DB에서 `/api/__aidast_missing_control__`와 `/rest/__aidast_missing_control__`는 각각 HTTP 500이었다. 현재 구현은 상태가 500 이상인 기준 응답을 버리고, 기준 응답이 없는 prefix의 후보를 모두 건너뛴다. 따라서 백틱 경로 추출을 추가해도 이 조건을 별도로 고치지 않으면 채택 결과가 계속 0일 수 있다.
3. **브라우저 탐색이 좁은 화면에 머물렀다.** 1,000건 실행에서 Playwright는 HTML 화면 6개를 방문했고 UI action은 1개였다. 초기화·크롤러·브라우저 상호작용이 합쳐진 결과가 정답 9개였다. Katana headless는 23개 결과를 남겼지만 `Too many consecutive failures, stopping crawl`(10회 연속 실패) 경고와 함께 종료됐다. 로그만으로 개별 실패의 원인은 확정할 수 없다. 한 세션에서 아직 열지 않은 화면의 지연 API 요청은 브라우저 HTTP 관측에 들어오지 않는다.
4. **API 2차 단계는 이 앱에서 경로를 늘리지 못했다.** 실행 로그에서 OpenAPI와 GraphQL 모두 확인되지 않았고 이 단계의 신규 endpoint는 0개였다. 이 단계는 명세·GraphQL 발견 시 확장하는 구조이므로, 현재 결과에서는 일반 REST route의 대체 발견 경로가 되지 못했다.

ffuf 자체는 작동한다. 11개 smoke 목록과 상한 300건 실행에서는 정답 3개를 추가해 12/71이었다. 다만 SecLists 174줄 일반 API 단어 목록은 정답지와 단순 경로로 일치하는 항목이 `/profile` 1개뿐이고, 그 항목은 106번째라 150초/root 실행 구간에 도달하지 않았다. 목록을 바꾸거나 시간을 늘리는 것만으로 SPA 추출·검증의 두 병목은 해결되지 않는다.

## 평가 품질과 다음 순서

- 500건 실행에서 프록시가 만든 HTTP 403 후보 25개가 ffuf 발견으로 저장됐고 `/rest/languages`의 `normalized_path`가 `/rest/:param`으로 합쳐졌다. 그 결과 최종 Surface는 8/71만 보존했다. 초기 O/X 평가도 endpoint의 대표 `path`를 사용해 실제 `/rest/continue-code` 200 요청을 놓쳤다. 실제 transaction URL로 다시 평가한 관측은 **10/71**이다. 이 진단 뒤 구현된 ffuf 차단 응답 필터와 SPA 수정의 [재실행 결과](REFACTOR_03_SPA_JS_VALIDATION.md)에서도 경로 병합이 별도 문제로 남았다.
- 다음 리팩토링은 (1) SPA JS 백틱 경로 추출, (2) 기준 요청이 500일 때도 `unknown`과 검증된 endpoint를 구분하는 후보 검증, (3) 브라우저의 실제 화면·API 트리거 범위 계측 순으로 진행하는 것이 수집률 개선 가설을 가장 직접적으로 시험한다.
- 변경 후에는 동일한 이미지·계정·Scope·요청 상한으로 Recon을 새로 실행하고 [O/X 평가기](evaluate_recon_get_routes.py)로 정답 경로 순증을 비교한다. JS 문자열 후보 수와 실제 HTTP 확인 수는 분리해서 기록한다.

원본 증거: `result/test-runs/09.24/seclists-api-500/Recon.db`, `result/test-runs/09.24/seclists-api-1000/Recon.db`, `result/test-runs/09.24/seclists-api-1000/run.log`, `result/test-runs/09.24/logs/scan_d2cc268e8f0946e78df0ceebd28be15b/recon.jsonl`, `result/test-runs/09.24/seclists-api-500/analysis-input/main.js`.
