# Recon 인증 Runtime 복구 리팩토링 (2026-09-26)

## 재현된 문제와 수정

[재시험](RECON_RETEST_2026_09_26.md)에서 인증 세션으로 시작한 Recon의 정답 GET·Surface 수집률이 각각 25/71에서 18/71로 떨어졌다. 손실된 7개 경로의 요청에는 `Authorization`이 없었고 401 또는 400을 받았다. 원본 세션의 토큰은 같은 시점에 유효했다.

`PlaywrightDriver.runtime_is_alive()`는 관리형 Chromium의 프로세스 핸들이 없다는 이유로 살아 있는 브라우저도 종료된 것으로 판단했다. 단계마다 Runtime을 불필요하게 다시 열었고, 새 문서가 로드되기 전 `get_auth_headers()`가 빈 브라우저 storage를 실행용 세션 파일에 저장할 수 있었다. `auth_check_url`이 없는 경우 `ensure_session()`은 그 상태를 정상으로 간주했다.

- 관리형 브라우저는 `browser.is_connected()`로 생존을 판정해 컨텍스트를 유지한다. 기존 CDP 프로세스 판정은 유지한다.
- 사전 인증 세션의 실행용 인증 상태를 메모리에 보관한다. 필요한 인증 헤더가 사라지면 승인된 상태로 브라우저를 재시작하고 시작 URL·응답·헤더·설정된 인증 확인 경로를 검사한다. 복구 실패는 오류로 종료한다.
- `adaptive_js` 요청 직전에 세션을 확인한다. 복구 오류를 후보 추출 실패로 삼키지 않도록 확인을 `try` 블록 밖에서 수행한다.

변경 코드는 `src/aidast/recon/tools/playwright_driver.py`와 `src/aidast/recon/tools/endpoint_discovery.py`이다. 관리형 브라우저 생존, storage 소실 복구, JS 검증 직전 복구 실패 전파에 대한 테스트는 `tests/test_recon_browser_transport.py`와 `tests/test_recon_adaptive_js.py`에 추가했다. 세 테스트 모두 해당 수정 전 실패와 수정 후 통과를 확인했다.

## 실제 재시험 과정

대상은 로컬 Juice Shop 20.2.0 (`http://127.0.0.1:3001/`)이며, 승인 Scope와 `primary` 인증 세션 하나를 사용했다. 일반 CLI의 TargetPolicy 모델 호출이 앞선 재시험에서 300초 타임아웃된 탓에, 동일하게 승인된 정책 파일을 [테스트 래퍼](recon_with_pinned_policy.py)로 고정했다. 래퍼는 정책 생성 호출만 대체하고 Scope ID·타깃·정책 근거를 다시 검증한다. 탐색 도구, ffuf 루트 선택, 정책 프록시, DB 및 Surface 저장은 일반 Recon 흐름이다. 정책 SHA-256은 `4e5b13b7b5cbbf436a34ee9de36602fbbd7529a7b44950caaa5c6aa3695c8462`이다.

요청 상한 1,000, 0.5 RPS, 동시성 1, depth 2, 요청 timeout 15초, ffuf 루트별 150초로 실행했다. wordlist는 SecLists 고정 커밋 `8420764ea28d5cdc1a8bbb8311736a2235be28c4`의 `common-api-endpoints-mazen160.txt` 174줄, SHA-256 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059`이다. 실제 명령:

```bash
mkdir -p result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26
RECON_TEST_RUN_ROOT=result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26 \
  PYTHONUNBUFFERED=1 \
  bash docs/test-results/09.24/_archive/run-recon-retest-pinned-policy-2026-09-26.sh \
  > result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/run.log 2>&1
```

수정 중 생존 판정 문제를 발견하기 전에 시작한 `recon-auth-recovery-2026-09-26` 실행은 중단했고 수집률 비교에서 제외했다. 완료 실행의 scan ID는 `scan_a620de92e0694ba997d3584e593b8ba1`이다. `Recon.db`, `Surface.json`, `Scope/`, 실행 로그와 진단 로그 사본은 `result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/`에 있다.

정답 71개 경로의 O/X 표 생성 명령:

```bash
.venv/bin/python docs/test-results/09.24/_archive/evaluate_recon_get_routes.py \
  --ground-truth docs/test-results/09.24/_archive/JUICE_SHOP_GET_GROUND_TRUTH.json \
  --run baseline=result/test-runs/09.24/browser-luna-full-1000/Recon.db \
  --run auth-loss=result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26/Recon.db \
  --run managed-runtime-fix=result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/Recon.db \
  --surface-run baseline=result/test-runs/09.24/browser-luna-full-1000/Surface.json \
  --surface-run auth-loss=result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26/Surface.json \
  --surface-run managed-runtime-fix=result/test-runs/09.24/recon-managed-runtime-fix-2026-09-26/Surface.json \
  --output docs/test-results/09.24/_archive/RECON_AUTH_RECOVERY_GET_ROUTE_MATRIX.md \
  --surface-output docs/test-results/09.24/_archive/RECON_AUTH_RECOVERY_SURFACE_ROUTE_MATRIX.md
```

## 결과와 제한

| 지표 | 이전 정상 실행 | 인증 소실 실행 | 수정 후 완료 실행 |
| --- | ---: | ---: | ---: |
| `adaptive_js` 채택 / 미검증 | 19 / 0 | 12 / 3 | **19 / 0** |
| HTML 화면 방문 | 8 | 8 | 7 |
| ffuf 고유 후보 | 1 | 1 | 1 |
| 저장 HTTP transaction | 471 | 591 | 425 |
| 정답 GET 응답 증거 | 25/71 | 18/71 | **25/71** |
| 최종 Surface 정답 GET | 25/71 | 18/71 | **25/71** |

[GET O/X](RECON_AUTH_RECOVERY_GET_ROUTE_MATRIX.md)와 [Surface O/X](RECON_AUTH_RECOVERY_SURFACE_ROUTE_MATRIX.md)에서 71개 전체를 확인할 수 있다. 손실됐던 `/api/Addresss`, `/api/BasketItems`, `/api/Complaints`, `/api/Users`, `/rest/deluxe-membership`, `/rest/saveLoginIp`, `/rest/user/authentication-details`는 수정 후 모두 `Authorization`이 있는 HTTP 200 요청과 Surface 경로로 돌아왔다. 최종 Runtime storage에도 토큰이 남아 있다. 관리형 브라우저의 반복 복구 로그도 사라졌다.

수정 후 DB 상태는 `completed`이고 `PRAGMA foreign_key_check`는 비어 있다. 관련 Recon 테스트는 `233 passed, 35 subtests passed`였다. 이번 결과는 **인증 소실로 인한 7개 경로 손실의 복구**를 입증한다. 남은 46개 정답 경로의 탐색률은 개선되지 않았고, 인증 확인 URL이 없는 일반 사이트에서 헤더가 존재하지만 서버가 거부하는 토큰까지 자동 판별하지는 못한다. 총 transaction 수와 HTML 방문 수는 브라우저 동작·ffuf 루트 선택 차이의 영향도 받아 단독 성능 지표로 해석하지 않는다.
