# Recon 정적 API 경로 병합 수정

## 재현과 원인

[세 번째 재실행](REFACTOR_03_SPA_JS_VALIDATION.md)에서 실제 GET 요청으로 확인한 정답 경로는 **25/71**이었지만 최종 Surface에는 **9/71**만 남았다. `/api/Addresss`, `/api/BasketItems` 등 서로 다른 HTTP 200 요청이 `/api/:param` 한 endpoint로, `/rest/captcha`, `/rest/continue-code` 등은 `/rest/:param`으로 병합됐다.

`src/aidast/recon/judgment.py`의 `adaptive_path_fingerprints()`는 같은 위치에 서로 다른 세그먼트가 5개 이상이면 변수로 학습한다. 그러나 `/api/*`, `/rest/*`의 첫 하위 세그먼트는 자원명 또는 정적 route 이름일 수 있다. 이 위치에 형제 경로가 많다는 사실만으로 ID라고 판정한 것이 원인이다. 이후 `merge_and_normalize()`와 DB reconciliation이 이 fingerprint를 사용해 서로 다른 경로와 증거를 합쳤다.

## 수정

`/api`와 `/rest` **하위의 모든 깊이**에서는 형제 경로 수만으로 `:param`으로 바꾸지 않는다. 처음에는 첫 하위 세그먼트만 보호했지만, 코드 검토에서 `/api/v1/*`, `/rest/user/*`가 같은 방식으로 병합되는 것을 발견해 범위를 넓혔다. `normalize_path()`의 숫자·UUID 등 명시적 ID 정규화는 그대로 적용한다. `/users/alice`처럼 API 네임스페이스 밖에서 기존에 지원하던 반복 이름 세그먼트 학습도 유지한다. 영문 slug를 ID로 쓰는 API에서는 보수적으로 개별 경로를 남긴다.

## 자동 검증

[회귀 테스트](test_recon_static_api_paths.py)는 다수의 `/api/*`·`/rest/*` 및 중첩된 `/api/v1/*`·`/rest/user/*` 정적 경로를 독립된 Surface 경로로 유지하는 동작을 확인한다. 숫자 `/api/Users/123`·`/api/Users/456`과 UUID `/rest/items/<uuid>`는 각각 `:id`로 정규화되는 것도 확인한다. 실제 DB observation·HTTP transaction·reconciliation·Surface export를 거친 뒤 각 경로와 증거가 연결되는 통합 테스트도 있다. 이 테스트들은 각 수정 전 대응하는 병합 실패를 확인한 뒤 통과시켰다.

```bash
.venv/bin/python -m pytest -q \
  docs/test-results/09.24/test_recon_static_api_paths.py \
  tests/test_recon_judgment.py \
  tests/test_recon_parameter_metadata.py
```

결과: **18 passed**. 이전 scan의 ffuf 입력 seed 43개를 수정된 `merge_and_normalize()`에 넣은 오프라인 확인에서는 `/api/:param`·`/rest/:param`이 생성되지 않고 API·REST 정적 경로 24개가 유지됐다. 이 수치는 전체 Recon 재실행 결과가 아니다.

SPA 후보·평가기·Recon 주변 회귀 테스트까지 함께 실행한 최종 확인은 **96 passed, 12 subtests passed**였다.

```bash
.venv/bin/python -m pytest -q \
  docs/test-results/09.24/test_recon_static_api_paths.py \
  docs/test-results/09.24/test_adaptive_js_recon_refactor.py \
  tests/test_recon_judgment.py \
  tests/test_recon_parameter_metadata.py \
  tests/test_recon_adaptive_js.py \
  tests/test_api_secondary_policy.py \
  tests/test_recon_browser_transport.py \
  tests/test_recon_diagnostics.py \
  docs/test-results/09.24/test_evaluate_recon_get_routes.py
```

`git diff --check`와 완료된 DB의 `PRAGMA foreign_key_check`도 통과했다.

## 로컬 Recon 재실행 조건

[실행 스크립트](run-path-normalization-1000.sh)를 사용해 기존 `spa-refactor-1000` Scope를 새 출력 디렉터리로 복사했다. 고정 Juice Shop 20.2.0 이미지 digest는 `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`다. `primary` 세션 하나, 최대 1,000요청, 0.5 RPS, 동시성 1, depth 2, timeout 15초, 동일한 SecLists `common-api-endpoints-mazen160.txt` 174줄(SHA-256 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059`), ffuf root별 150초를 적용했다. Recon만 실행한다.

```bash
bash docs/test-results/09.24/run-path-normalization-1000.sh \
  > result/test-runs/09.24/path-normalization-1000/run.log 2>&1
```

첫 실행 `scan_a7955e0307e94347b353b5e6a008a264`는 중첩 경로 문제를 코드 검토에서 확인해 완료 전에 중단했다. 해당 미완료 출력은 `result/test-runs/09.24/path-normalization-aborted/`에 별도로 보관하며 O/X 평가에 넣지 않는다. 최종 수정 코드로 위 명령을 새 출력 디렉터리에서 다시 실행했다.

## 완료된 재실행 결과

최종 scan ID는 `scan_9b9185ab83f14a1ebee0cd26bd3b8463`이고 상태는 `completed`다. [GET 요청 O/X 표](RECON_GET_ROUTE_MATRIX.md)와 [Surface O/X 표](RECON_SURFACE_ROUTE_MATRIX.md)는 완료된 DB·Surface에 새 실행을 추가해 재생성했다.

| 지표 | 수정 전 `spa-refactor-1000` | 정규화 수정 후 |
| --- | ---: | ---: |
| 실제 GET 요청 정답 경로 | 25/71 | **25/71** |
| 최종 Surface에 명시된 정답 경로 | 9/71 | **25/71** |
| `adaptive_js` 채택 | 19개 | 19개 |
| ffuf 반환 후보 | 1개 | 1개 |
| 저장 HTTP transaction | 422건 | 466건 |

새로 Surface에 남은 16개 정답 경로는 `/api/Addresss`, `/api/BasketItems`, `/api/Challenges`, `/api/Complaints`, `/api/Feedbacks`, `/api/Quantitys`, `/api/Recycles`, `/api/SecurityQuestions`, `/rest/captcha`, `/rest/continue-code`, `/rest/continue-code-findIt`, `/rest/continue-code-fixIt`, `/rest/deluxe-membership`, `/rest/languages`, `/rest/repeat-notification`, `/rest/saveLoginIp`다. 기존에 Surface에 남던 정답 경로는 사라지지 않았다. 예를 들어 `/api/Addresss`, `/api/BasketItems`, `/rest/captcha`의 `source_tools`에는 `adaptive_js`와 `mitmproxy`가 개별 경로에 보존됐다.

두 완료 실행은 같은 이미지·인증 세션·Scope 제한·SecLists 174줄과 ffuf root `/`, `/api`, `/rest` 및 root별 150초를 사용했다. 수정 후 실행의 정책 프록시는 466건을 허용하고 5건을 차단했다. 1,000건 상한은 소진되지 않았다. HTTP transaction 수 차이는 이번 실행의 실제 요청량 차이이며 정규화 수정의 단독 효과로 해석하지 않는다. 핵심 결과는 **같이 관측된 25개 정답 경로가 최종 공격표면에도 25개 모두 명시됐다**는 점이다.

증거는 `result/test-runs/09.24/path-normalization-1000/`의 `Recon.db`, `Surface.json`, `run.log`, `input-snapshot/`, `session-output/`와 `result/test-runs/09.24/logs/scan_9b9185ab83f14a1ebee0cd26bd3b8463/recon.jsonl`에 보관했다. 기존 인증 입력 `Session.json`은 수정하지 않았다. 이 평가는 고정 이미지의 명시적 GET route 71개에 대한 것이며, 인증 세션에서 모두 접근 가능하다는 뜻은 아니다. 아직 요청되지 않은 parameter route와 화면 전환 뒤 API는 이 수정으로 자동 발견되지 않는다.
