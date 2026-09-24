# Recon SPA JS 경로 추출·검증 리팩토링

## 원인과 수정

기존 `adaptive_js` 단계는 따옴표로 둘러싸인 `/api`·`/rest` 경로만 읽었다. 고정 Juice Shop `main.js`에는 백틱 문자열 경로가 있지만 기존 정규식은 이 경로를 하나도 추출하지 못했다. 또한 존재하지 않는 경로를 조회하는 `/api`·`/rest` 기준 요청이 HTTP 500을 반환하면 해당 prefix의 후보를 전부 버렸다. [실행 DB 기반 분석](NON_FFUF_RECON_COVERAGE_ANALYSIS.md)에 두 현상의 관측 근거가 있다.

`src/aidast/recon/tools/api_secondary_discovery.py`에서 백틱으로 감싼 정적 경로를 추출하도록 변경했다. `${id}`처럼 변수가 포함된 경로는 구체 URL을 만들 수 없으므로 기존처럼 제외한다. 기준 요청이 500일 때는 후보가 **서로 다른 2xx 비 HTML 응답**을 반환해야만 채택한다. 401·403 등은 존재 여부를 확정하기 어려워 `unverified_count`로 계측하고 채택하지 않는다. 정책 프록시가 생성한 `Blocked by AI-DAST TargetPolicy` 403도 제외한다. 기준 응답이 500 미만이면 기존 fingerprint 비교를 유지한다.

## 자동 검증

추가한 [회귀 테스트](test_adaptive_js_recon_refactor.py)는 백틱 정적 경로와 동적 경로 제외, 기준 500일 때 정상 200 JSON 채택·인증 오류 보류·기준과 같은 응답 제외·정책 403 제외를 확인한다. 구현 전 이 테스트는 **2 failed**였고 수정 뒤 통과했다.

```bash
.venv/bin/python -m pytest -q \
  docs/test-results/09.24/test_adaptive_js_recon_refactor.py \
  tests/test_recon_adaptive_js.py \
  tests/test_api_secondary_policy.py \
  tests/test_recon_browser_transport.py \
  tests/test_recon_diagnostics.py \
  docs/test-results/09.24/test_evaluate_recon_get_routes.py
```

SPA 수정 직후 결과는 **76 passed, 12 subtests passed**였다. 이후 실제 요청 URL 기준 O/X 평가와 Surface 평가 회귀 테스트를 추가해 같은 명령을 다시 실행한 결과는 **78 passed, 12 subtests passed**였다.

## 로컬 전체 Recon 재실행 조건

[실제 호출 스크립트](run-spa-refactor-1000.sh)를 아래와 같이 실행했다.

```bash
bash docs/test-results/09.24/run-spa-refactor-1000.sh \
  > result/test-runs/09.24/spa-refactor-1000/run.log 2>&1
```

- 대상: Juice Shop 20.2.0 `http://127.0.0.1:3001/`, 이미지 digest `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`.
- 인증: 기존 `primary` Session.json 하나. Recon만 실행.
- Scope: 기존 `seclists-api-1000`의 승인 Scope를 새 출력 디렉터리로 복사. 최대 1,000 요청, 0.5 RPS, 동시성 1, depth 2, timeout 15초.
- ffuf: SecLists `common-api-endpoints-mazen160.txt` 174줄, SHA-256 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059`, root별 최대 150초.
- 출력: `result/test-runs/09.24/spa-refactor-1000/` 아래 별도 Recon DB·Surface·Scope·실행 로그. scan ID `scan_e50899446c564570a1d69d27cf9283d9`.

고정 `main.js` SHA-256은 `1fbe46da9b367d28f7c3b80ef6648c593ac18a18c40edc115d0af0639f967aa7`이다. 변경 정규식으로 정적 후보 39개가 추출되며, 그중 GET 정답지와 문자열이 맞는 경로는 26개다. 현 구현은 최초 후보 30개까지만 확인하므로 이 30개 중 정답지와 문자열이 맞는 경로는 20개다. 이 수치는 **오프라인 문자열 일치**이며 실제 HTTP 확인이나 Recon 수집률이 아니다.

## 결과와 해석

[GET 요청 O/X 표](RECON_GET_ROUTE_MATRIX.md)와 [최종 Surface O/X 표](RECON_SURFACE_ROUTE_MATRIX.md)를 별도로 만들었다. 두 표 모두 동일한 71개 정답지를 사용한다.

| 측정 | 기존 `seclists-api-1000` | 수정 후 `spa-refactor-1000` |
| --- | ---: | ---: |
| `adaptive_js` 채택 | 0개 | 19개 |
| 실제 GET 요청에서 관측한 정답 경로 | 9/71 | **25/71** |
| 최종 Surface에 보존된 정답 경로 | 9/71 | **9/71** |
| 저장된 HTTP transaction | 520건 | 422건 |
| ffuf 후보 | 1개(`/api`, 500) | 1개(`/api`, 500) |

새로 GET 200 응답이 확인된 16개는 `/api/Addresss`, `/api/BasketItems`, `/api/Complaints`, `/api/Feedbacks`, `/api/Products`, `/api/Recycles`, `/api/SecurityQuestions`, `/api/Users`, `/rest/captcha`, `/rest/continue-code`, `/rest/continue-code-findIt`, `/rest/continue-code-fixIt`, `/rest/deluxe-membership`, `/rest/repeat-notification`, `/rest/saveLoginIp`, `/rest/user/authentication-details`다. 나머지 채택 후보 3개는 기존에도 관측됐다. 새 실행에서 기존에 관측됐던 정답 경로가 사라지지는 않았다.

처음 평가기는 요청 transaction을 연결된 endpoint의 `path`로 판정해 **11/71**로 잘못 계산했다. 실제 DB에서는 `/api/Addresss`, `/api/BasketItems` 등 서로 다른 HTTP 200 요청들이 한 `endpoint_id`의 `/api/:param`으로, `/rest/captcha`, `/rest/continue-code` 등은 `/rest/:param`으로 병합돼 있었다. 평가기를 각 transaction의 실제 `url` 경로로 바꾸고 병합 사례를 회귀 테스트에 추가했다. 같은 방식으로 과거 `seclists-api-500`도 **9/71에서 10/71**로 정정됐다. 그 실행의 `/rest/continue-code` 200 요청이 종전에는 다른 endpoint 경로 뒤에 가려져 있었다.

**Surface 9/71이 그대로인 것은 별도 Recon 저장 문제다.** 최종 Surface에는 `/api/:param`, `/rest/:param`이라는 모호한 경로가 남고, 실제 요청한 여러 정적 route의 개별 이름은 사라진다. 따라서 25/71은 *HTTP 요청 관측률*이며, 현재 사용자에게 제공되는 공격표면의 명시적 route 보존률은 9/71이다. 이 병합을 막는 것이 다음 리팩토링 우선순위다.

이번 ffuf root는 `/`, `/api`, `/rest` 3개로, 기존 실행의 4개에서 `/socket.io`가 빠졌다. SPA 단계의 선행 발견에 따라 root 선택이 달라진 것이므로 총 HTTP transaction 520→422건을 같은 요청 집합의 감소로 해석하지 않는다. 0.5 RPS와 root별 150초 제한은 동일했다. 새 실행의 프록시 허용은 422건, 차단은 5건으로 1,000건 예산에는 도달하지 않았다.

원본은 `result/test-runs/09.24/spa-refactor-1000/`의 `Recon.db`, `Surface.json`, `run.log`, `input-snapshot/`, `session-output/`에 있다. 진단 로그 복사본은 `result/test-runs/09.24/logs/scan_e50899446c564570a1d69d27cf9283d9/recon.jsonl`이다. 기존 인증 입력 `Session.json`은 이동하거나 수정하지 않았다.
