# 09.24 Juice Shop Recon 리팩토링 요약

## 범위와 평가 기준

로컬 OWASP Juice Shop 20.2.0(`http://127.0.0.1:3001/`)에서 **인증 세션 1개로 Recon만** 실행했다. 주요 비교 실행은 승인 Scope의 최대 1,000요청, 0.5 RPS, 동시성 1, depth 2, timeout 15초와 동일한 SecLists API wordlist 174줄을 사용했다. Attack·Validation·외부 태깅은 실행하지 않았다. 실행 명령, 고정 이미지 digest, wordlist SHA-256, scan ID와 원본 파일은 [전체 실험 기록](README.md)에 있다.

정답지는 고정 이미지의 명시적 GET route **71개**다. 지표는 두 가지로 나눴다.

- **GET 요청 관측:** Recon DB에 같은 origin의 실제 GET 요청 URL과 HTTP 응답이 남았는가. HTTP 500도 경로 관측으로 세되 정상 동작으로 보지 않는다.
- **Surface 보존:** 최종 `Surface.json`에 정답 경로가 개별 GET route로 남았는가. `/api/:param`은 여러 정적 경로의 발견으로 세지 않는다.

## 성능 변화

| 완료 실행 | 적용 상태 | GET 요청 관측 | 최종 Surface 보존 | `adaptive_js` 채택 |
| --- | --- | ---: | ---: | ---: |
| `seclists-api-1000` | 기존 수집·정규화 | **9/71 (12.7%)** | **9/71 (12.7%)** | 0 |
| `spa-refactor-1000` | SPA 경로 추출·후보 검증 수정 | **25/71 (35.2%)** | **9/71 (12.7%)** | 19 |
| `path-normalization-1000` | 정적 API 경로 병합 수정 추가 | **25/71 (35.2%)** | **25/71 (35.2%)** | 19 |
| `browser-action-capture-full-1000` | SPA 메뉴 `routerLink` 및 클릭 직후 링크 수집 추가 | **25/71 (35.2%)** | **25/71 (35.2%)** | 19 |
| `browser-luna-full-1000` | Recon 계획·ffuf root 선택 모두 `gpt-6-luna` | **25/71 (35.2%)** | **25/71 (35.2%)** | 19 |

최초 실행과 최종 실행을 비교하면 **실제 GET 요청과 최종 Surface 모두 정답 경로가 16개 증가**했다. 71개 대비 **12.7% → 35.2%, 약 22.5%p 상승, 2.78배**다. SPA 수정은 서버에 실제 요청해 확인한 경로를 늘렸고, 정규화 수정은 그중 최종 Surface에서 사라지던 경로를 보존했다. 정규화 수정 전후의 GET 요청 정답은 25개로 같고 Surface만 **9개 → 25개**로 변했다. 이전 실행은 [요청별 O/X](RECON_GET_ROUTE_MATRIX.md), [Surface별 O/X](RECON_SURFACE_ROUTE_MATRIX.md)에, 브라우저·모델 수정 실행은 [브라우저 요청별 O/X](RECON_BROWSER_GET_ROUTE_MATRIX.md), [브라우저 Surface O/X](RECON_BROWSER_SURFACE_ROUTE_MATRIX.md)에 71개 경로 전체가 표시돼 있다.

## 변경사항과 확인된 효과

| 순서 | 변경 | 확인된 효과 |
| --- | --- | --- |
| 1. ffuf 정책 차단 응답 필터 | 정책 프록시가 생성한 `Blocked by AI-DAST TargetPolicy` 403을 ffuf 발견 후보에서 제외. [기록](REFACTOR_01_FFUF_PROXY_FILTER.md) | 실제 대상 응답이 없는 후보의 Surface 혼입을 방지. 대상 서버가 반환한 일반 403은 유지. |
| 2. ffuf 시간 제한·진단 | `--ffuf-max-time-seconds`와 wordlist 줄 수·root별 시간 진단을 추가. 기본값은 150초. [기록](REFACTOR_02_FFUF_TIME_LIMIT.md) | 목록을 끝까지 실행했는지와 시간 제한을 구분해 기록. 이 변경만으로 수집률 향상을 주장하지 않는다. |
| 3. SPA JS 경로 추출·검증 | 백틱 안의 정적 `/api`·`/rest` 경로를 읽고, 없는 경로의 기준 응답이 500이어도 구별되는 2xx 비 HTML 후보를 채택. 동적 `${...}` 경로와 정책 403은 제외. [기록](REFACTOR_03_SPA_JS_VALIDATION.md) | `adaptive_js` 채택 **0→19개**, 실제 GET 정답 **9→25개**. 새 정답 경로 16개는 모두 HTTP 200으로 확인. |
| 4. 정적 API 경로 정규화 | `/api`·`/rest` 아래에서는 형제 경로 수만으로 자원·action 이름을 `:param`으로 합치지 않음. 숫자·UUID ID 정규화는 유지. [기록](REFACTOR_04_STATIC_ROUTE_NORMALIZATION.md) | 최종 Surface 정답 **9→25개**. 기존에 병합됐던 16개 정적 경로가 각자 남고 개별 `source_tools`도 보존. |
| 5. 브라우저 SPA 화면 탐색 | 보이는 `<a href>`와 Angular 버튼 `routerLink`를 방문 후보로 넣고 안전한 클릭 직후에도 링크를 수집. [기록](REFACTOR_05_BROWSER_NAVIGATION.md) | 방문 화면 **6→8개**, 실제 GET·Surface 정답 **25/71 유지**. 이 Juice Shop 세션에서는 엔드포인트 수집률 개선이 확인되지 않음. |
| Recon 모델·계획 보정 | Recon 계획·정책 생성과 ffuf root 선택 모델을 `gpt-6-luna`로 지정하고 명시적 `--execute`가 probe-only 계획으로 끝나지 않게 필수 웹 단계를 포함. [기록](REFACTOR_05_BROWSER_NAVIGATION.md) | 모델 변경 첫 실행의 누락된 ENDPOINT_DISCOVERY를 재현·수정했고, 새 실행에서 세 작업 완료. 모델 변경만의 수집률 향상은 주장하지 않음. |
| 평가기 정정 | 병합된 endpoint의 대표 `path` 대신 실제 HTTP transaction URL로 요청 O/X를 계산하고 Surface O/X를 별도 생성. [평가기](evaluate_recon_get_routes.py) | 수집과 저장을 혼동하지 않게 됨. 과거 `seclists-api-500` 요청 관측도 **9→10개**로 정정. |

ffuf 자체가 이번 주된 경로 순증을 만든 것은 아니다. 같은 SecLists 174줄의 1,000건 실행에서 ffuf 반환 후보는 수정 전후 모두 `/api` HTTP 500 한 개였고, 정답지의 application GET route가 아니었다. 수정 뒤 GET 16개 순증은 SPA 후보 검증 단계의 실제 HTTP 요청에서 확인됐다.

## 검증과 한계

- 최종 정규화 수정 후 완료된 scan은 `scan_9b9185ab83f14a1ebee0cd26bd3b8463`이다. `Recon.db`의 상태는 `completed`, 저장 HTTP transaction은 466건, 최종 정답 경로는 요청·Surface 모두 **25/71**이다. 코드·평가기 관련 테스트는 **96 passed, 12 subtests passed**였고 DB 참조 무결성 검사와 `git diff --check`를 통과했다.
- 브라우저 수정과 Recon 모델 통일 후의 유효 최종 scan은 `scan_44d42b7a76f242dbab7f4c1da2bc1c01`이다. 실제 GET·Surface 모두 **25/71**이고 브라우저 HTML 방문은 **8개**다. 관련 테스트는 **230 passed, 35 subtests passed**였고 비교 DB의 참조 무결성 검사도 통과했다. [브라우저 비교 GET O/X](RECON_BROWSER_GET_ROUTE_MATRIX.md), [Surface O/X](RECON_BROWSER_SURFACE_ROUTE_MATRIX.md)에 각 실행의 71개 경로를 대조했다.
- 이 수치는 **고정 이미지의 route 정의 대비 관측·보존 비율**이다. 71개에는 parameter route 20개가 포함되며, 현재 세션에서 관측한 것은 `/rest/basket/:id` 하나다. 모든 route에 현재 계정이 접근 가능한지, 다른 앱에서도 같은 개선폭이 나오는지는 측정하지 않았다.
- 실행마다 정적 리소스·브라우저 요청량이 달라 HTTP transaction 총수나 실행 시간을 처리 속도 개선으로 해석하지 않는다. 기존 1,000건 실행은 ffuf root 4개, SPA·최종 실행은 3개였다. **개별 정답 경로의 요청 증거와 최종 Surface 보존**을 성능 개선 근거로 삼는다.
- 다음 평가 대상은 현재 미관측인 parameter route 19개에 이미 관측한 데이터의 실제 ID를 적용하는 방법과 중첩 메뉴 뒤 화면의 API 요청이다. 큰 SecLists `common.txt`는 아직 실제 Recon에 사용하지 않았다.
