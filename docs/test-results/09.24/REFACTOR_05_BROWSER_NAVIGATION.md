# Recon 브라우저 화면 탐색 리팩토링

## 문제와 수정

직전 완료 실행에서 Playwright는 허용된 30개 화면 중 6개만 방문했고, 두 탐색 패스의 UI 동작은 합계 2개였다. Katana의 23개 headless 결과는 주로 JS·CSS·API 요청이라 Angular 화면 이동 후보를 충분히 공급하지 못했다. Juice Shop의 고정 `main.js`에는 `<button routerLink="/basket">` 형태의 메뉴와 `useHash: true`가 들어 있다. 기존 Playwright는 메뉴 버튼을 누르더라도 새로 나타난 화면 링크를 다음 방문 후보로 모으지 않았다.

`PlaywrightDriver`가 현재 화면과 안전한 UI 동작 뒤의 **보이는 동일 origin 링크**를 큐에 추가하도록 했다. `<a href>`와 버튼의 `routerLink`를 모두 읽고, 현재 앱이 hash URL을 쓰면 `/basket`을 `/#/basket` 방문 후보로 바꾼다. 각 클릭 직후에도 후보를 모아 다음 클릭으로 메뉴가 닫히기 전의 링크를 남긴다. Scope 허용 URL, 동일 origin, 위험 경로 차단, 중복 화면 판정, 30페이지·동작·시간 제한을 계속 적용한다.

## 실행 조건과 실제 명령

다섯 유효 실행은 동일한 로컬 Juice Shop 20.2.0 이미지 `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`, 승인 Scope, `primary` 인증 세션 하나를 사용했다. Recon만 실행했다. 최대 1,000요청, 0.5 RPS, 동시성 1, depth 2, 요청 timeout 15초다. ffuf 목록은 SecLists 고정 커밋 `8420764ea28d5cdc1a8bbb8311736a2235be28c4`의 `common-api-endpoints-mazen160.txt` **174줄**, SHA-256 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059`이며 root별 제한은 150초다. 스크립트에는 실제 `aidast recon ... --execute` 명령 전문과 Scope·세션 경로가 있다.

```bash
bash docs/test-results/09.24/run-path-normalization-1000.sh \
  > result/test-runs/09.24/path-normalization-1000/run.log 2>&1
bash docs/test-results/09.24/run-browser-navigation-1000.sh \
  > result/test-runs/09.24/browser-navigation-1000/run.log 2>&1
PYTHONUNBUFFERED=1 bash docs/test-results/09.24/run-browser-routerlink-1000.sh \
  > result/test-runs/09.24/browser-routerlink-1000/run.log 2>&1
PYTHONUNBUFFERED=1 bash docs/test-results/09.24/run-browser-action-capture-full-1000.sh \
  > result/test-runs/09.24/browser-action-capture-full-1000/run.log 2>&1
PYTHONUNBUFFERED=1 bash docs/test-results/09.24/run-browser-luna-full-1000.sh \
  > result/test-runs/09.24/browser-luna-full-1000/run.log 2>&1
```

첫 번째는 이전 기준 실행이다. 두 번째는 `<a href>` 수집만, 세 번째는 Angular 버튼 `routerLink`까지, 네 번째는 각 안전한 클릭 직후 수집까지 적용했다. 네 번째 실행부터 Recon 계획·정책 모델에 `gpt-6-luna`를 지정했고, 다섯 번째는 ffuf root 선택 모델까지 같은 값으로 통일했다. 따라서 HTTP transaction 총량 차이를 브라우저 수정 단독 효과로 해석하지 않는다. ffuf가 실제로 선택한 root는 순서대로 3·3·5·3·3개였다. 모델 변경 뒤 명시적 `--execute` 요청이 probe만 수행하지 않도록 계획을 보정한 뒤 유효 실행을 진행했다.

모델 지정 직후의 별도 실행 `browser-action-capture-1000` (`scan_6a07b2bac7d2416f9f3ced907f71b0d2`)은 `gpt-6-luna`가 HTTP_PROBE 하나만 제안해 ENDPOINT_DISCOVERY를 수행하지 않았다. DB 상태는 `completed`지만 GET 수집률 평가의 비교 입력에서 **제외**했다. 출력과 명령은 같은 이름의 실행 스크립트 및 `result/test-runs/09.24/browser-action-capture-1000/`에 보존했다. 이후 `--execute`에서 선택한 웹 타깃에 HTTP_PROBE·ORIGIN_DISCOVERY·ENDPOINT_DISCOVERY를 포함하는 검증을 추가했고, 새 출력 경로에서 3개 작업이 실제 생성·완료된 것을 확인했다.

## 측정 결과

| 실행 | scan ID | 방문 HTML 화면 | UI 동작 | Playwright HTTP 후보 | 저장 transaction | GET O/X | Surface O/X |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `path-normalization-1000` | `scan_9b9185ab83f14a1ebee0cd26bd3b8463` | 6 | 2 | 25 | 466 | 25/71 | 25/71 |
| `browser-navigation-1000` | `scan_fbc1709e427c4c5299ffbc9f7c99a531` | 6 | 2 | 25 | 467 | 25/71 | 25/71 |
| `browser-routerlink-1000` | `scan_b38393bbbb60488497fd3ef7a12e8061` | 8 | 4 | 25 | 604 | 25/71 | 25/71 |
| `browser-action-capture-full-1000` | `scan_b03428ad533d4ec1a18ffda7613fe8cc` | 8 | 4 | 25 | 443 | 25/71 | 25/71 |
| `browser-luna-full-1000` | `scan_44d42b7a76f242dbab7f4c1da2bc1c01` | 8 | 4 | 25 | 471 | 25/71 | 25/71 |

다섯 DB의 scan 상태는 모두 `completed`이고 `PRAGMA foreign_key_check` 결과는 비어 있다. [실제 GET 요청 O/X 표](RECON_BROWSER_GET_ROUTE_MATRIX.md)와 [최종 Surface O/X 표](RECON_BROWSER_SURFACE_ROUTE_MATRIX.md)에 71개 정답 경로의 O/X 및 누락 목록을 따로 기록했다. 표 생성 명령:

```bash
.venv/bin/python docs/test-results/09.24/evaluate_recon_get_routes.py \
  --ground-truth docs/test-results/09.24/JUICE_SHOP_GET_GROUND_TRUTH.json \
  --run path-normalization-1000=result/test-runs/09.24/path-normalization-1000/Recon.db \
  --run browser-navigation-1000=result/test-runs/09.24/browser-navigation-1000/Recon.db \
  --run browser-routerlink-1000=result/test-runs/09.24/browser-routerlink-1000/Recon.db \
  --run browser-action-capture-full-1000=result/test-runs/09.24/browser-action-capture-full-1000/Recon.db \
  --run browser-luna-full-1000=result/test-runs/09.24/browser-luna-full-1000/Recon.db \
  --surface-run path-normalization-1000=result/test-runs/09.24/path-normalization-1000/Surface.json \
  --surface-run browser-navigation-1000=result/test-runs/09.24/browser-navigation-1000/Surface.json \
  --surface-run browser-routerlink-1000=result/test-runs/09.24/browser-routerlink-1000/Surface.json \
  --surface-run browser-action-capture-full-1000=result/test-runs/09.24/browser-action-capture-full-1000/Surface.json \
  --surface-run browser-luna-full-1000=result/test-runs/09.24/browser-luna-full-1000/Surface.json \
  --output docs/test-results/09.24/RECON_BROWSER_GET_ROUTE_MATRIX.md \
  --surface-output docs/test-results/09.24/RECON_BROWSER_SURFACE_ROUTE_MATRIX.md
```

화면 방문은 2개 늘었지만 **정답 API 경로는 하나도 늘지 않았다**. 새 화면에서 발생한 요청이 이미 관측한 `/rest/basket/:id`, `/rest/products/search` 등의 경로에 머물렀다. 남은 X 46개는 값이 필요한 parameter route 19개와 정적 route 27개다. 현재 결과는 화면 탐색 후보 증가만 입증한다. 다음 수집률 개선 후보는 이미 관측한 목록 응답에서 실제 ID를 얻어 허용된 GET parameter route를 확인하는 방법과, 중첩 메뉴 뒤의 화면을 여는 방법이다. 임의 ID 대입이나 더 큰 ffuf 목록만으로 이 수치를 개선했다고 주장하지 않는다.

## 검증과 증거

메뉴 노출 후 링크 수집, 버튼 `routerLink`의 hash 경로 변환, 클릭 직후 링크 보존, 모델 전달, probe-only 계획 보정의 실패 테스트를 먼저 확인하고 수정했다. ffuf root 선택에도 Recon 모델을 전달하는 회귀 테스트를 추가했다. 최종 관련 테스트는 **230 passed, 35 subtests passed**였고 `git diff --check`를 통과했다.

```bash
.venv/bin/python -m pytest -q \
  docs/test-results/09.24/test_recon_static_api_paths.py \
  docs/test-results/09.24/test_adaptive_js_recon_refactor.py \
  tests/test_recon_judgment.py tests/test_recon_parameter_metadata.py \
  tests/test_recon_adaptive_js.py tests/test_api_secondary_policy.py \
  tests/test_recon_browser_transport.py tests/test_recon_diagnostics.py \
  docs/test-results/09.24/test_evaluate_recon_get_routes.py \
  tests/test_recon_workflow.py tests/test_scope_workflow.py \
  tests/test_ffuf_root_selection_skill.py tests/test_pipeline_cli.py \
  tests/test_recon_policy.py tests/test_merged_cli_contract.py
git diff --check
```

각 실행의 `Recon.db`, `Surface.json`, `Scope/`, `run.log`, 정책 프록시 진행 기록은 `result/test-runs/09.24/<실행명>/`에 있다. 진단 JSONL은 `result/test-runs/09.24/logs/<scan ID>/recon.jsonl`에 보존했다. 기존 `Session.json` 입력은 수정하지 않았다.
