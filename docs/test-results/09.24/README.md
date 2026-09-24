# 09.24 Juice Shop 인증 Recon 평가

[지금까지의 변경사항과 수집 성능 요약](RECON_REFACTOR_SUMMARY.md): 기존 1,000건 실행 대비 실제 GET 요청·최종 Surface의 정답 경로가 각각 **9/71→25/71**로 증가했다.

브라우저 화면 탐색의 다음 실험은 [다섯 번째 리팩토링 기록](REFACTOR_05_BROWSER_NAVIGATION.md)에 있다. 화면 방문은 **6→8개**였지만 실제 GET·Surface 정답은 모두 **25/71**로 유지됐다. [브라우저 GET O/X 표](RECON_BROWSER_GET_ROUTE_MATRIX.md)와 [브라우저 Surface O/X 표](RECON_BROWSER_SURFACE_ROUTE_MATRIX.md)를 별도로 생성했다. 후속 Recon 계획과 ffuf root 선택 모델은 `gpt-6-luna`로 지정했다.

## 범위와 정답

- 대상: 로컬 OWASP Juice Shop 20.2.0, `http://127.0.0.1:3001/`, 승인 Scope `scope_local_lab_juice_shop`. 실행 컨테이너의 package version과 이미지 참조 digest가 정답지의 `20.2.0` 및 `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`와 일치함을 재확인했다.
- 인증: `primary` 세션 1개 재사용. Recon만 실행했고 Attack, Chaining, Validation은 실행하지 않았다. 인증 관측을 외부 모델에 보내는 `--tag-after`도 실행하지 않았다.
- 기존 다섯 실행의 Recon 구현 기준: Git HEAD `d18be679c18f4f1d0baa3a0367211f81f6275d5f`; 당시 `src/aidast`의 로컬 변경은 없었다. `spa-refactor-1000`은 ffuf·SPA 리팩토링이, `path-normalization-1000`은 추가로 정적 API 경로 병합 수정이 적용된 작업 트리에서 실행했다.
- ffuf 버전: `2.1.0-dev` (`ffuf -V`).
- [GET route 정답지](JUICE_SHOP_GET_GROUND_TRUTH.json): 고정 이미지의 Express GET pattern 70개와 Angular 진입점 `/` 1개, 합계 71개. 근거는 [기존 runtime/source 대조](../main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)다. 정적 파일, Socket.IO transport, generic middleware, SPA fallback URL은 제외한다. 인증 상태에서 모두 접근 가능한 route라는 뜻은 아니다.
- [GET 요청 O/X 결과표](RECON_GET_ROUTE_MATRIX.md): 같은 origin의 비제외 GET transaction **실제 요청 URL**과 응답이 정답 경로와 일치하면 O. [최종 Surface O/X 표](RECON_SURFACE_ROUTE_MATRIX.md)는 사용자에게 제공되는 Surface.json에 개별 route가 남았는지를 따로 평가한다. `:id` 같은 path parameter는 concrete 값 한 칸과 일치한다. [Express 기본 route 설정](https://expressjs.com/en/4x/api.html#app.settings.table)에 따라 정적 경로 구간은 대소문자를 구분하지 않고 비교한다. 500 응답도 요청 관측 O로 표기하고 HTTP 상태를 함께 표시한다. X는 이번 실행의 미관측이며 route 부재를 뜻하지 않는다. 완료되지 않은 scan은 평가기가 거부한다.

## Wordlist

| 실험 | Wordlist | 출처/고정값 |
| --- | --- | --- |
| `no-ffuf-150` | 없음 | ffuf 미실행 |
| `smoke-ffuf-150`, `smoke-ffuf-300` | [11개 smoke 파일](wordlists/ffuf-smoke-wordlist.txt) | 로컬 common 목록에서 선택한 기능 확인용 경로, SHA-256 `1da6b8d0c5f49c9759982099ffb9b4c7a8fa4a2c6de7f99fc805fe264b295584` |
| `seclists-api-500`, `seclists-api-1000`, `spa-refactor-1000`, `path-normalization-1000`, `browser-navigation-1000`, `browser-routerlink-1000`, `browser-action-capture-full-1000`, `browser-luna-full-1000` | [SecLists API 파일](wordlists/common-api-endpoints-mazen160.txt) | [SecLists 원본](https://github.com/danielmiessler/SecLists/blob/8420764ea28d5cdc1a8bbb8311736a2235be28c4/Discovery/Web-Content/common-api-endpoints-mazen160.txt), commit `8420764ea28d5cdc1a8bbb8311736a2235be28c4`, 174줄, SHA-256 `cd774e12b54e075ac7c34b95b9f2ad908461e0ae43c57fc82976020575adb059` |

SecLists의 API 경로 후보를 수정 없이 사용했다. 이 목록만으로 Juice Shop의 모든 route를 추론할 수는 없다. ffuf는 root 선택, 150초/root 시간 제한, 전체 요청 예산을 적용한다. 따라서 목록 파일 174줄을 지정했더라도 모든 조합이 서버에 도달했는지는 별도로 확인한다.

## 실행 과정과 명령

1. 승인 Scope를 재사용하고 고정된 `127.0.0.1:3001` origin으로 TargetPolicy를 생성했다.
2. 기존 `primary` 세션 번들을 검증하고 인증 상태에서 Recon을 수행했다. 능동 탐색 허용 method는 GET/HEAD/OPTIONS, 속도는 최대 0.5 RPS, depth 2, 실제 concurrency 1, timeout 15초였다.
3. 각 실행의 `Recon.db`, `Surface.json`, diagnostic log를 `result/test-runs/09.24/`에 보관했다. DB의 완료 상태와 실제 GET transaction URL로 요청 O/X를, Surface.json의 최종 GET 경로로 Surface O/X를 생성했다.

이전 세 실행의 원래 셸 호출 전문은 저장되지 않았다. 아래는 남아 있는 DB·진단 로그의 조건으로 **재구성한 재현 명령**이다. 기존 scan ID를 재현한다는 뜻은 아니다. 공통 인자:

```bash
SESSION=result/test-runs/09.23/phase-c/sessions/29784ce2455caab98f3e025b/986a1b7135f4986150aa5fa0/60cc869d838607505f62c5a6/Session.json
BASE=(.venv/bin/python -m aidast recon https://lab.aidast.invalid/juice-shop
  --target http://127.0.0.1:3001/ --start-url http://127.0.0.1:3001/
  --session-bundle "$SESSION" --login-mode none --max-rps 0.5
  --max-depth 2 --max-concurrency 1 --timeout-seconds 15
  --diagnostic-logs --execute)
```

| 실행 | scan ID | 재현 명령의 추가 인자 | ffuf 확인 |
| --- | --- | --- | --- |
| `no-ffuf-150` | `scan_cb8cf297f5914274864786fbad3b0a80` | `"${BASE[@]}" --max-requests 150 --db-path result/test-runs/09.24/no-ffuf-150/Recon.db --surface-path result/test-runs/09.24/no-ffuf-150/Surface.json` | wordlist 미지정, 실행 안 됨 |
| `smoke-ffuf-150` | `scan_e389332715b649a9b37c16e42810a5af` | `"${BASE[@]}" --max-requests 150 --ffuf-wordlist result/test-runs/09.24/wordlists/ffuf-smoke-wordlist.txt --db-path result/test-runs/09.24/smoke-ffuf-150/Recon.db --surface-path result/test-runs/09.24/smoke-ffuf-150/Surface.json` | ffuf 프로세스는 실행, 실제 대상 요청 0건(예산 보류) |
| `smoke-ffuf-300` | `scan_b036c505db6449c8a8e11dd6965f5f6c` | `"${BASE[@]}" --max-requests 300 --ffuf-wordlist result/test-runs/09.24/wordlists/ffuf-smoke-wordlist.txt --db-path result/test-runs/09.24/smoke-ffuf-300/Recon.db --surface-path result/test-runs/09.24/smoke-ffuf-300/Surface.json` | root 4개, 반환 후보 8개, wordlist 형태 고유 경로 33개 도달 |

SecLists 실험은 실제 호출을 [실행 스크립트](run-seclists-api-500.sh)에 저장했다(실행된 복사본과 SHA-256 동일). 실행 명령은 `bash result/test-runs/09.24/run-seclists-api-500.sh > result/test-runs/09.24/seclists-api-500/run.log 2>&1`이며 `--max-requests 500`과 위 SecLists 파일을 사용했다. scan ID는 `scan_e4e4555da4744f82a904ebd9a5466965`, raw output은 `result/test-runs/09.24/seclists-api-500/`, 진단 로그는 `result/test-runs/09.24/logs/<scan ID>/recon.jsonl`이다. 생성된 정책과 Scope의 복사본은 raw output의 `input-snapshot/`에 있다.
`run.log`에 기록된 새 브라우저 상태 파일은 실행 후 `seclists-api-500/session-output/`으로 옮겼다. 기존 인증 입력 `Session.json`은 09.23 원본을 그대로 사용했다.

상한 1,000건 재실험은 [Scope 생성 스크립트](prepare_juice_scope_1000.py)로 **별도 승인 Scope**를 `result/test-runs/09.24/seclists-api-1000/Scope/`에 게시하고 [실행 스크립트](run-seclists-api-1000.sh)를 `bash docs/test-results/09.24/run-seclists-api-1000.sh > result/test-runs/09.24/seclists-api-1000/run.log 2>&1`로 실행했다. 원래 500건 Scope는 수정하지 않았다. 재사용한 인증 세션, SecLists 파일, root 선택, 0.5 RPS, 동시성 1, depth 2, timeout 15초, ffuf `-maxtime 150`초/root는 같았다. 생성된 TargetPolicy의 `max_requests=1000`을 확인했다. scan ID는 `scan_d2cc268e8f0946e78df0ceebd28be15b`이며 DB·Surface·정책 스냅샷·새 브라우저 상태 파일은 `seclists-api-1000/`, 진단 로그는 `result/test-runs/09.24/logs/<scan ID>/recon.jsonl`에 있다. Recon만 실행했고 태깅은 실행하지 않았다. SPA 리팩토링 후 재실행 조건과 실제 호출은 [세 번째 리팩토링 기록](REFACTOR_03_SPA_JS_VALIDATION.md)에 있다.

정적 API 경로 병합 수정 후에는 [네 번째 실행 스크립트](run-path-normalization-1000.sh)를 `bash docs/test-results/09.24/run-path-normalization-1000.sh > result/test-runs/09.24/path-normalization-1000/run.log 2>&1`로 실행했다. 같은 승인 Scope·인증 세션·wordlist를 사용했다. scan ID `scan_9b9185ab83f14a1ebee0cd26bd3b8463`의 DB·Surface·정책 스냅샷은 `path-normalization-1000/`, 진단 로그는 `result/test-runs/09.24/logs/<scan ID>/recon.jsonl`에 있다. [수정·검증 기록](REFACTOR_04_STATIC_ROUTE_NORMALIZATION.md)에 원인과 중단한 첫 시도도 명시했다.

브라우저 탐색 수정의 네 유효 재실행은 [다섯 번째 기록](REFACTOR_05_BROWSER_NAVIGATION.md)의 각 실행 스크립트와 명령 전문으로 재현할 수 있다. HTTP_PROBE만 수행한 `browser-action-capture-1000`은 ENDPOINT_DISCOVERY가 없어 O/X 비교에서 제외했다.

## 실행 결과

| 실행 | GET 요청 정답 | Surface 보존 | HTTP transaction | ffuf 결과 |
| --- | ---: | ---: | ---: | --- |
| `no-ffuf-150` | 9/71 | 9/71 | 125 | 실행 안 됨 |
| `smoke-ffuf-150` | 9/71 | 9/71 | 123 | 프로세스 실행, 대상에 도달한 wordlist 경로 0 |
| `smoke-ffuf-300` | 12/71 | 12/71 | 239 | 반환 후보 8, 추가 정답 route 3개(`/profile`은 500) |
| `seclists-api-500` | 10/71 | 8/71 | 397 | 반환 후보 26(그중 정책 403이 25개) |
| `seclists-api-1000` | 9/71 | 9/71 | 520 | 반환 후보 1(`/api`, HTTP 500) |
| `spa-refactor-1000` | **25/71** | **9/71** | 422 | 반환 후보 1(`/api`, HTTP 500) |
| `path-normalization-1000` | **25/71** | **25/71** | 466 | 반환 후보 1(`/api`, HTTP 500) |
| `browser-navigation-1000` | 25/71 | 25/71 | 467 | 반환 후보 1 |
| `browser-routerlink-1000` | 25/71 | 25/71 | 604 | 반환 후보 1 |
| `browser-action-capture-full-1000` | 25/71 | 25/71 | 443 | 반환 후보 1 |
| `browser-luna-full-1000` | 25/71 | 25/71 | 471 | 반환 후보 1 |

SecLists 실행은 root `/`, `/api`, `/rest`, `/socket.io` 네 곳을 선택했다. 네 ffuf 프로세스 모두 150초 제한으로 종료됐다. DB에서 확인되는 서로 다른 wordlist 형태의 GET 경로는 각 root별로 **74, 73, 50, 0개**, 합계 197개다. 이는 wordlist 174개 × root 4개 = 696개 조합을 모두 서버에 보낸 실험이 아니다. HTTP transaction에 남은 경로 형태로 센 수치이므로 ffuf만의 정확한 전송 건수로 사용하지 않는다. 프록시 진행 기록은 실행 전 사용 1건과 프록시 허용 399건으로 총 400건이며, DB에 적재된 transaction은 397건이다. 프록시는 후속 요청 121건을 예산으로 보류했다. 목록의 `profile`(106번째), `users`(158번째)는 해당 root에서 시도된 구간에 들어가지 않았다.

ffuf가 반환한 26개 중 `/api`는 HTTP 500 transaction이 있으나 정답지의 application GET route가 아니다. `/rest/connect`부터 `/rest/group`까지 25개는 `endpoint_observations.evidence_json`에 HTTP **403**으로 기록됐고, 해당 URL의 대상 HTTP transaction은 없다. 정책 프록시의 예산 보류 응답이 ffuf 후보로 들어온 것이다. 이 25개를 새 공격표면이나 발견 endpoint로 세지 않는다.

같은 실행에서 실제 200 응답이 있는 `/rest/languages`의 DB `normalized_path`는 `/rest/:param`으로 저장됐다. wordlist에 `languages`가 없는데도 이 endpoint의 `source_tools`에 `ffuf`가 포함됐다. 다수의 `/rest/*` 후보가 경로 정규화 및 source 병합에 영향을 준 것으로 보인다. 평가기는 실제 transaction URL을 사용한다. 예전 endpoint `path` 기준 평가는 `/rest/continue-code`의 HTTP 200 관측을 놓쳐 이 실행을 9/71로 낮게 기록했다. 수정된 값은 **10/71**이며 최종 Surface에는 8/71만 남았다.

상한 1,000건 실행은 동일한 네 root에 대해 DB에서 확인되는 서로 다른 wordlist 형태의 GET 경로가 각각 **74, 74, 75, 75개**, 합계 298개였다. 500건 실행의 197개보다 101개 더 서버에 도달했고, HTTP transaction은 123건 더 저장됐다. ffuf의 프록시 차단 응답이 후보로 들어간 500건 실행과 달리, 1,000건 실행에서는 ffuf 후보가 `/api` 1개뿐이었다. GET 요청 정답은 **10/71→9/71**, Surface는 **8/71→9/71**이었다. 실행별 브라우저 요청과 경로 병합이 달라 이 차이만으로 상한 증가의 효과를 단정할 수 없다. 각 root가 150초 만에 종료되어 174개 목록의 최대 75번째까지만 관측됐다. `profile`(106번째)과 `users`(158번째)는 이번에도 시도되지 않았다. 경로 형태 일치는 ffuf만의 정확한 전송 건수가 아니다.

평가표 재생성 명령:

```bash
.venv/bin/python docs/test-results/09.24/evaluate_recon_get_routes.py \
  --ground-truth docs/test-results/09.24/JUICE_SHOP_GET_GROUND_TRUTH.json \
  --run no-ffuf-150=result/test-runs/09.24/no-ffuf-150/Recon.db \
  --run smoke-ffuf-150=result/test-runs/09.24/smoke-ffuf-150/Recon.db \
  --run smoke-ffuf-300=result/test-runs/09.24/smoke-ffuf-300/Recon.db \
  --run seclists-api-500=result/test-runs/09.24/seclists-api-500/Recon.db \
  --run seclists-api-1000=result/test-runs/09.24/seclists-api-1000/Recon.db \
  --run spa-refactor-1000=result/test-runs/09.24/spa-refactor-1000/Recon.db \
  --run path-normalization-1000=result/test-runs/09.24/path-normalization-1000/Recon.db \
  --surface-run no-ffuf-150=result/test-runs/09.24/no-ffuf-150/Surface.json \
  --surface-run smoke-ffuf-150=result/test-runs/09.24/smoke-ffuf-150/Surface.json \
  --surface-run smoke-ffuf-300=result/test-runs/09.24/smoke-ffuf-300/Surface.json \
  --surface-run seclists-api-500=result/test-runs/09.24/seclists-api-500/Surface.json \
  --surface-run seclists-api-1000=result/test-runs/09.24/seclists-api-1000/Surface.json \
  --surface-run spa-refactor-1000=result/test-runs/09.24/spa-refactor-1000/Surface.json \
  --surface-run path-normalization-1000=result/test-runs/09.24/path-normalization-1000/Surface.json \
  --output docs/test-results/09.24/RECON_GET_ROUTE_MATRIX.md \
  --surface-output docs/test-results/09.24/RECON_SURFACE_ROUTE_MATRIX.md
```

기존 세 실행의 상세 관측과 한계는 [인증 Recon 기록](09.24_AUTH_JUICE_SHOP_RECON.md)에 있다. ffuf root가 실행마다 달라 요청 상한 변화만으로 성능 차이를 설명할 수 없다. 또한 정답지는 명시적 route만 포함하므로 수집된 정적 파일과 유효한 middleware 경로의 가치를 이 비율에 반영하지 않는다.

SPA 수집 단계와 ffuf 후보 오염의 원인 분석은 [SPA Recon 진단](SPA_RECON_DIAGNOSIS.md)에 정리했다.

SecLists 목록을 다시 고른 근거와 실행 시간 계산은 [wordlist 선정 기록](WORDLIST_SELECTION.md)에 정리했다. `common.txt`를 후속 비교의 주 목록으로 정했으며, 아직 이 목록으로 실제 Recon을 실행하지는 않았다.

첫 번째 코드 수정과 검증은 [ffuf 정책 프록시 차단 응답 필터링](REFACTOR_01_FFUF_PROXY_FILTER.md)에 기록했다. 이 변경은 위에 보존한 과거 scan의 결과를 소급 변경하지 않는다.

두 번째 수정은 [ffuf root별 시간 제한 설정과 입력 크기 기록](REFACTOR_02_FFUF_TIME_LIMIT.md)이다. 기존 기본값 150초를 유지하면서 `--ffuf-max-time-seconds`로 조정할 수 있게 했다. 아직 `common.txt`로 실제 Recon은 실행하지 않았다.

ffuf 외 수집 병목과 근거 수치는 [Recon 수집률 원인 분석](NON_FFUF_RECON_COVERAGE_ANALYSIS.md)에 정리했다.

SPA 백틱 경로 추출과 HTTP 500 기준 응답 검증을 수정한 후 동일한 1,000건 정책으로 재실행했다. 실제 요청 관측은 **9/71→25/71**, 최종 Surface 보존은 **9/71→9/71**이다. 원인과 남은 경로 병합 문제는 [세 번째 리팩토링 검증](REFACTOR_03_SPA_JS_VALIDATION.md)에 정리했다.

정적 API 경로 병합 수정 후 동일한 정책으로 다시 실행했다. 실제 요청 관측은 **25/71로 동일**했고 최종 Surface 보존은 **9/71→25/71**로 개선됐다. [네 번째 리팩토링 검증](REFACTOR_04_STATIC_ROUTE_NORMALIZATION.md)에 개별 경로와 남은 범위를 정리했다.
