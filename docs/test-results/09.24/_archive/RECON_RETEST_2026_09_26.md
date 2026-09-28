# Juice Shop 인증 Recon 재시험 (2026-09-26)

후속 인증 Runtime 수정과 재실행 결과는 [여섯 번째 리팩토링 기록](REFACTOR_06_AUTHENTICATED_RUNTIME.md)에 있다. 정답 GET·Surface가 모두 18/71에서 25/71로 회복됐다.

## 입력과 실행 과정

- 대상: 로컬 Juice Shop 20.2.0 (`http://127.0.0.1:3001/`), 승인 Scope와 `primary` 세션 하나. Recon만 실행했다.
- 코드: `17abc86`. 요청 상한 1,000, 0.5 RPS, 동시성 1, depth 2, 요청 timeout 15초, ffuf 루트별 150초.
- ffuf 목록: SecLists `Discovery/Web-Content/common-api-endpoints-mazen160.txt`, 고정 커밋 `8420764ea28d5cdc1a8bbb8311736a2235be28c4`, 174줄, SHA-256 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059`.
- 정답: [71개 GET 경로](JUICE_SHOP_GET_GROUND_TRUTH.json). 기준은 Juice Shop 서버의 명시적 route이며, 모든 route가 이 인증 계정의 UI에서 접근 가능하다는 뜻은 아니다.

먼저 [일반 Recon 명령](run-recon-retest-2026-09-26.sh)을 실행했다. 계획의 HTTP_PROBE, ORIGIN_DISCOVERY, ENDPOINT_DISCOVERY 세 작업은 생성됐으나 TargetPolicy 생성 모델 호출이 300초 후 `Codex target policy generation timed out`으로 끝났다. 이 시도는 탐색 결과로 채점하지 않았다. 원본 로그는 `result/test-runs/09.24/recon-retest-2026-09-26/run.log`이다.

그다음 [고정 정책 실행 명령](run-recon-retest-pinned-policy-2026-09-26.sh)으로 재시험했다. [테스트 래퍼](recon_with_pinned_policy.py)는 **정책 생성 모델 호출만** 이전에 승인된 `browser-luna-full-1000/Scope/.../TargetPolicy.json`으로 대체한다. 래퍼는 Scope ID, 정확한 타깃, 현재 Scope에 대한 정책 검증을 수행한다. 정책 파일 SHA-256은 `4e5b13b7b5cbbf436a34ee9de36602fbbd7529a7b44950caaa5c6aa3695c8462`이다. 탐색, 모델의 ffuf 루트 선택, 정책 프록시, DB·Surface 저장은 일반 Recon 경로를 사용했다. 실제 명령은 다음과 같다.

```bash
PYTHONUNBUFFERED=1 bash docs/test-results/09.24/_archive/run-recon-retest-pinned-policy-2026-09-26.sh \
  > result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26/run.log 2>&1
```

완료 scan은 `scan_462db4f79a044d9f8e4eb428d40b0dc7`이며 DB 상태 `completed`, `PRAGMA foreign_key_check` 결과는 비어 있다. 원본 `Recon.db`, `Surface.json`, `Scope/`, 실행 로그와 진단 로그 사본은 `result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26/`에 보존했다.

## 결과

| 지표 | 직전 `browser-luna-full-1000` | 이번 고정 정책 재시험 |
| --- | ---: | ---: |
| Playwright HTML 방문 | 8 | 8 |
| Playwright UI 동작 | 4 | 4 |
| Katana 고유 후보 | 22 | 22 |
| ffuf 고유 후보 | 1 | 1 |
| adaptive JS 채택 후보 | 19 | 12 |
| 저장 HTTP transaction | 471 | 591 |
| 정답 GET 경로 중 유효한 요청·응답 증거 | **25/71** | **18/71** |
| 최종 Surface의 정답 GET 경로 | **25/71** | **18/71** |

이번 ffuf 루트는 `/FUZZ`(1개), `/api/FUZZ`(0개), `/rest/FUZZ`(0개), `/assets/i18n/FUZZ`(0개)였다. 네 번째는 정적 자산 경로라 이 정답지의 API 탐색에 직접 도움이 되지 않았다. 루트 수가 직전 3개에서 이번 4개로 달라졌으므로 전체 HTTP transaction 수를 성능 향상으로 해석할 수 없다.

[실제 응답 증거 O/X](RECON_RETEST_2026_09_26_GET_ROUTE_MATRIX.md)와 [Surface O/X](RECON_RETEST_2026_09_26_SURFACE_ROUTE_MATRIX.md)에 71개 경로 전체와 누락 목록을 보존했다. 이전 실행 대비 O에서 X가 된 7개는 `/api/Addresss`, `/api/BasketItems`, `/api/Complaints`, `/api/Users`, `/rest/deluxe-membership`, `/rest/saveLoginIp`, `/rest/user/authentication-details`이다. 반대로 새로 O가 된 정답 경로는 없다.

두 표를 만든 명령:

```bash
.venv/bin/python docs/test-results/09.24/_archive/evaluate_recon_get_routes.py \
  --ground-truth docs/test-results/09.24/_archive/JUICE_SHOP_GET_GROUND_TRUTH.json \
  --run browser-luna-full-1000=result/test-runs/09.24/browser-luna-full-1000/Recon.db \
  --run recon-retest-pinned-policy-2026-09-26=result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26/Recon.db \
  --surface-run browser-luna-full-1000=result/test-runs/09.24/browser-luna-full-1000/Surface.json \
  --surface-run recon-retest-pinned-policy-2026-09-26=result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26/Surface.json \
  --output docs/test-results/09.24/_archive/RECON_RETEST_2026_09_26_GET_ROUTE_MATRIX.md \
  --surface-output docs/test-results/09.24/_archive/RECON_RETEST_2026_09_26_SURFACE_ROUTE_MATRIX.md
```

## 원인 확인과 해석

7개 URL은 아예 요청하지 않은 것이 아니다. 새 DB에 요청은 기록됐지만 앞의 API 네 경로 및 뒤의 두 경로는 HTTP 401, `/rest/deluxe-membership`은 HTTP 400이었다. 이 일곱 요청의 `Authorization` 헤더는 모두 없었다. 반면 같은 실행의 초기 브라우저 요청에는 `Authorization`이 있었고, `/rest/basket/8`은 인증 헤더가 있는 요청에서 200, 헤더가 없는 요청에서 401이었다. `adaptive_js` 단계는 후보 12개를 채택하고 3개를 미검증으로 분류했다.

실행 후 저장된 브라우저 runtime state에는 `token` localStorage 키가 없었다. 입력 `Session.json`의 원본 `storage.json`에는 키가 남아 있으며, 그 토큰을 이용한 별도 로컬 확인에서 `/api/Addresss`가 200, 인증 없이 같은 URL은 401이었다. 즉 입력 계정이나 서버 route의 부재로 7개가 사라진 것은 아니다. **실행 도중 브라우저 runtime의 인증 상태가 비워져 후반부 JS 후보 검증이 익명 요청으로 진행된 것**까지 확인했다. 어느 UI 방문 또는 복원 단계가 키를 지웠는지는 이번 로그만으로 특정할 수 없다.

O/X의 O는 단순 URL 시도가 아니라 Recon DB에서 비제외 endpoint에 연결된 GET 응답 증거가 있고, Surface에는 개별 경로가 남았다는 뜻이다. 따라서 401/400 시도만으로 route 발견 성공을 세지 않는다. `18/71`은 이 계정과 정책, 한 번의 실행 조건에서의 **증거 기반 수집률**이다. 전체 앱의 탐색 가능률이나 익명·관리자 계정의 커버리지를 뜻하지 않는다.
원시 HTTP transaction URL만 보면 정답 경로 27개에 요청을 시도했지만, 이 중 9개는 endpoint 증거로 채택되지 않았다. 따라서 `27/71`을 발견률로 해석하면 인증 실패 및 오류 응답까지 성공으로 세게 된다.

관련 회귀 테스트 명령은 [이전 검증 기록](REFACTOR_05_BROWSER_NAVIGATION.md)의 `pytest` 목록과 같으며 이번에 `230 passed, 35 subtests passed`였다. 이 테스트들은 현재의 runtime 인증 소실을 잡지 못했다. 다음 수정 우선순위는 단계 사이에 인증 헤더·인증 확인 endpoint 상태를 검증하고, 세션이 사라지면 원본 인증 상태로 복구하거나 명시적으로 실패하게 하는 것이다. 이후 동일 입력으로 다시 실행해 `25/71` 회복 여부를 확인해야 한다.
