# Recon POST 허용 A/B 실험 — 2026-09-29

## 결론

일반 POST 제한을 해제하면 **VulnBank의 GraphQL 발견은 개선된다.** 그러나 이번 동일 조건의 전체 Recon 비교에서 기존 GET 경로 수집 수 합계는 **66/118로 동일했다.** Juice Shop은 1개 감소했고 VulnBank는 `/graphql` 1개가 추가됐다. 한 번의 전체 A/B 실행이므로 Juice Shop의 감소를 POST의 인과적 효과라고 단정하지 않는다.

## 실제 측정

기존 서버 정의 GET 목록 71개·47개에 대해 최종 Surface의 **GET 메서드와 경로**를 대조했다. HTTP 응답을 받았다는 사실, 최종 Surface 포함, 200 응답을 각각 구분했다. JSON/JS 문자열이나 SPA의 임의 200 경로를 분모에 추가하지 않았다.

| 대상 | A: 일반 POST 제한 | B: 일반 POST 허용 | 변화 |
|---|---:|---:|---|
| Juice Shop GET 경로 | 52/71 (73.2%) | 51/71 (71.8%) | -1, `/profile` 누락 |
| VulnBank GET 경로 | 14/47 (29.8%) | 15/47 (31.9%) | +1, `/graphql` 발견 |
| 합계 | 66/118 (55.9%) | 66/118 (55.9%) | 수집 수 동일 |

| 대상 | 실제 GET 응답이 기록된 정의 경로 A → B | Surface 포함 및 GET 200인 경로 A → B | 전체 메서드 Surface 항목 A → B |
|---|---:|---:|---:|
| Juice Shop | 55 → 54 | 46 → 45 | 66 → 65 |
| VulnBank | 14 → 15 | 12 → 13 | 22 → 23 |

마지막 열은 정답 GET 목록 외의 메서드와 경로도 포함한다. 새로운 성공 요청과 새로운 엔드포인트 발견은 동일한 지표가 아니다.

## POST가 만든 구체적인 차이

### VulnBank: GraphQL 탐지와 후속 GET 검증 활성화

- A: GraphQL 확인 0개. Recon DB의 실제 POST 거래 0건.
- B: 기존 탐지기가 `POST /graphql`로 확인과 introspection을 수행했고, 두 요청 모두 인증 정보가 있는 200 응답을 받았다.
- 이후 ZAP GraphQL 단계가 활성화되어 HAR 엔트리 18개를 산출했다. 최종적으로 `GET /graphql`이 검증되어 Surface에 추가됐다. DB에는 query string을 사용한 GET과 별도의 GET `/graphql` 200 응답이 모두 있다.
- B의 실제 POST `/graphql` 거래는 16건: 200 5건, 400 11건. 생성한 모든 GraphQL 쿼리가 성공한 것은 아니다.
- 별도 반복 검사에서는 동일 탐지기를 각 조건으로 3회 실행했다. A는 전송 0건·탐지 0/3, B는 POST 6건 모두 200·탐지와 introspection 3/3이었다. 이 검사에는 별도 30회 예산을 적용했으며 전체 Recon 수집 수에 합산하지 않았다.

`POST /graphql` 자체는 DB와 `candidate_endpoints`에 남지만, 최종 `endpoints`로 승격되지는 않았다. `verification_status=candidate`, `exclude_reason=unverified_candidate`였다. 현재 `_verify_get_candidates()`가 비 GET 후보를 `non_get_method`로 보존하고, 프록시 적재도 스펙 후보를 200만으로 승격하지 않기 때문이다. **POST 프로토콜 검증의 성공 근거를 최종 검증 상태에 연결하는 개선은 별도로 필요하다.**

### Juice Shop: Surface 증가는 없고 실제 상태 변경은 발생

- A/B 모두 POST Surface 경로는 `/rest/user/login`, `/socket.io`, `/api/BasketItems`로 동일했다. `/api/BasketItems`는 A에서도 메타데이터로 이미 발견됐다.
- 실제 Recon POST 거래는 A 12건, B 16건이었다. A는 `/socket.io/`만 전송됐고, B에는 `POST /api/BasketItems/` 200 응답이 추가됐다.
- 비교 계정의 장바구니를 별도 GET으로 확인했을 때 A는 상품 0개, B는 상품 1개·수량 1이었다. **폼 제출 설정이 False여도 일반 POST를 허용한 탐색 도구가 상태를 바꿀 수 있음을 실제 관측했다.** 원본 앱에는 이 요청을 보내지 않았다.
- A에는 GET `/profile` 200 응답 2건이 있지만 B에는 해당 요청이 없었다. 이 한 경로의 차이를 POST의 직접적인 원인으로 확정할 근거는 없다. 크롤러·브라우저·AI 선택과 요청 예산의 실행 변동도 남아 있다.

## 실험 조건과 적용 범위

- 제품 코드 전체를 한 번 동결한 동일 `FrozenSource.zip`과 동일 launcher를 A/B에 사용했다. 발견 과정에는 정답 경로 목록이나 서버 소스를 전달하지 않았다.
- 실제 `ReconExecutor`의 HTTP probe → origin discovery → endpoint discovery → DB/Surface export를 실행했다. Playwright, Katana standard/headless, ffuf, adaptive JS, AI pattern inference, API secondary/ZAP 경로를 포함한다.
- A는 일반 `allowed_methods=[GET, HEAD, OPTIONS]`, B는 여기에 POST만 추가했다. 기존 브라우저 지원 POST와 정상 로그인 예외는 A에서도 유지했다. A가 모든 POST를 차단하는 조건은 아니다.
- 양쪽 모두 `form_submission=False`. 자동 입력·폼 제출 기능을 추가한 실험이 아니다.
- 동일 조건: 요청 예산 1,500회, 5 rps, 동시 1, 깊이 2, timeout 15초, common.txt, ffuf 호출별 max-time 60초. 요청 예산과 프록시 경계는 해제하지 않았다.
- 동일 원본 Docker 이미지 ID의 별도 복제본을 조건마다 생성했다. VulnBank는 원본 PostgreSQL의 한 스냅샷을 A/B에 동일하게 복원했다. Juice Shop은 동일 초기 데이터와 동일 비교 계정을 사용했다. 각 대상의 A/B JWT 사용자 ID와 브라우저 인증된 GET 200을 확인했다.
- **실제 시작 URL은 각 복제본의 `/`였다.** VulnBank의 세션 메타데이터에는 `/dashboard`가 저장돼 있지만 launcher는 `execution_start_urls`를 넘기지 않았다. 인증 세션을 복원한 루트 시작 비교이며, 저장된 대시보드 시작 페이지를 적용하는 CLI 실행 전체를 재현한 결과는 아니다.
- 이전 58/71·22/47과는 코드·요청 제한·시작 조건·Juice Shop 데이터가 다르므로 직접적인 전후 비교로 사용하지 않는다.
- 정상 로그인 setup POST는 별도로 집계했다. 위 POST 거래 수에는 별도 반복 검사와 장바구니 GET 검사를 포함하지 않는다.
- 최종 네 실행 모두 Recon task 3개 성공, DB integrity/foreign key 검사 통과. A/B source·launcher·wordlist hash, 계정, 이미지 ID, limits, 폼 설정이 같고 정책은 실험 origin port와 POST 허용 여부만 다름을 evaluator에서 검증했다.
- 초기 세션 origin 재바인딩 실패와 VulnBank POST 실행의 프록시 시작 timeout은 본 실행 전 실패한 시도로 보존하고 집계에서 제외했다. 실패를 수집률 0으로 처리하지 않았다.
- 운영 Scope/Recon 정책을 변경하지 않았다. POST는 실험용 TargetPolicy에서만 허용했다. 실험 컨테이너·익명 볼륨·네트워크는 정리했고 원본 3개 컨테이너가 실행 중임을 확인했다.

## 해석

이번 결과는 **POST 허용이 필요한 프로토콜 탐지에는 효과가 있지만, 허용 자체가 URL·ID·쿼리 연결과 폼 탐색 기능을 추가하지는 않는다**는 점을 보여준다. POST 응답에서 발견한 URL/파라미터를 후보로 보존하고, 의미가 확인된 조회 POST의 검증 근거를 Surface에 연결하는 처리가 필요하다. `/reset-password` 같은 JS navigation URL 추출 문제는 일반 POST 허용만으로 해결되지 않았다.

## 근거 산출물

- [경로별 A/B CSV](../../../result/test-runs/09.29/recon-post-comparison/RouteComparison.csv)
- [전체 비교 JSON 및 조건 검증](../../../result/test-runs/09.29/recon-post-comparison/Comparison.json)
- [GraphQL 반복 검사](../../../result/test-runs/09.29/recon-post-comparison/FocusedGraphQL.json)
- [장바구니 상태 변경 확인](../../../result/test-runs/09.29/recon-post-comparison/JuiceSideEffect.json)
- [실행 launcher](../../../result/test-runs/09.29/recon-post-comparison/RunComparison.py)
- [고정 소스 manifest](../../../result/test-runs/09.29/recon-post-comparison/SourceManifest.json)
- [임시 자원 정리 확인](../../../result/test-runs/09.29/recon-post-comparison/Cleanup.json)

세션·원시 요청/응답 본문·DB는 gitignore된 로컬 실행 디렉터리에만 보관한다. 위 문서에는 인증정보나 응답 본문을 포함하지 않았다.
