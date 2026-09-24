# Recon 리팩토링 재개 지점 (2026-09-24)

## 현재 상태

- 진행 중인 Recon 또는 ffuf 실행은 없다. 이 지점에서 안전하게 중단할 수 있다.
- 사용자는 로컬 OWASP Juice Shop의 인증된 세션 하나로 Recon만 실험하고, 리팩토링을 하나씩 진행하기로 했다. Attack·Validation·외부 태깅은 이 실험 범위에 없다.
- 첫 번째 수정: `src/aidast/recon/tools/endpoint_discovery.py`에서 정책 프록시가 생성한 `Blocked by AI-DAST TargetPolicy` 응답을 ffuf `-fr`로 제외했다. 일반적인 대상 서버 403은 남긴다.
- 두 번째 수정: `--ffuf-max-time-seconds`로 root별 시간 제한을 조정하고, ffuf 진단에 wordlist 줄 수와 설정된 시간을 기록한다. [변경·검증](REFACTOR_02_FFUF_TIME_LIMIT.md), [회귀 테스트](test_ffuf_time_limit.py).
- 세 번째 수정: SPA JS 백틱 정적 경로를 추출하고, 없는 경로 기준 응답이 HTTP 500일 때 서로 다른 2xx 비 HTML 후보만 채택한다. [수정·재실행 결과](REFACTOR_03_SPA_JS_VALIDATION.md), [회귀 테스트](test_adaptive_js_recon_refactor.py).
- 네 번째 수정: `/api`·`/rest` 하위 정적 경로를 형제 수만으로 `:param`으로 병합하지 않는다. [수정·완료된 재실행 결과](REFACTOR_04_STATIC_ROUTE_NORMALIZATION.md), [회귀 테스트](test_recon_static_api_paths.py).
- O/X 평가기를 실제 GET transaction URL 기준으로 수정하고, 최종 [Surface O/X 표](RECON_SURFACE_ROUTE_MATRIX.md)를 별도로 생성했다. 병합된 endpoint 대표 경로만 사용하던 이전 평가는 일부 경로를 누락했다.
- [수정 근거·검증](REFACTOR_01_FFUF_PROXY_FILTER.md), [회귀 테스트](test_ffuf_policy_response_filter.py). 수정 전 테스트는 정책 차단 403이 후보로 들어와 실패했고, 수정 후 통과했다.
- 최종 확인 명령:

  ```bash
  .venv/bin/python -m pytest -q \
    docs/test-results/09.24/test_ffuf_policy_response_filter.py \
    docs/test-results/09.24/test_ffuf_time_limit.py \
    tests/test_ffuf_root_selection_skill.py \
    tests/test_tool_annotation_evidence.py \
    tests/test_recon_browser_transport.py \
    tests/test_recon_adaptive_js.py \
    tests/test_recon_diagnostics.py \
    tests/test_mitm_proxy.py \
    tests/test_request_broker.py
  ```

  당시 결과: **113 passed, 22 subtests passed**. `git diff --check`도 통과했다. 로컬 테스트 서버 포트 바인딩을 위해 이 명령은 샌드박스 권한 상승으로 실행했다. 세 번째 수정과 O/X 평가기 변경 뒤 관련 테스트 재실행은 **78 passed, 12 subtests passed**였다. 명령은 [세 번째 수정 기록](REFACTOR_03_SPA_JS_VALIDATION.md)에 있다.

  네 번째 수정까지 포함한 관련 회귀 테스트는 **96 passed, 12 subtests passed**였고 `git diff --check`, 완료된 DB의 `PRAGMA foreign_key_check`도 통과했다. 명령과 결과는 [네 번째 수정 기록](REFACTOR_04_STATIC_ROUTE_NORMALIZATION.md)에 있다.

## 실험 자료

- [09.24 전체 기록](README.md), [71개 GET 정답지](JUICE_SHOP_GET_GROUND_TRUTH.json), [O/X 결과표](RECON_GET_ROUTE_MATRIX.md).
- 기존 SecLists 174줄로 요청 상한 500→1,000 비교: 실제 HTTP transaction 397→520건, 실제 GET 요청 정답 **10/71→9/71**(평가기 정정 후). [상한 1,000 실행 스크립트](run-seclists-api-1000.sh), 원본 DB와 로그는 `result/test-runs/09.24/seclists-api-1000/` 및 `result/test-runs/09.24/logs/scan_d2cc268e8f0946e78df0ceebd28be15b/`.
- 수정 후 동일한 1,000건 정책의 재실행은 `adaptive_js` 0→19 후보, 실제 GET 요청 정답 **9/71→25/71**, 최종 Surface 명시 경로 **9/71→9/71**이다. [재실행 스크립트](run-spa-refactor-1000.sh), 원본은 `result/test-runs/09.24/spa-refactor-1000/`에 있다.
- 정적 경로 병합 수정 후 동일 정책의 완료된 재실행은 실제 GET 요청 정답 **25/71**, 최종 Surface **25/71**이다. [실행 스크립트](run-path-normalization-1000.sh), 원본은 `result/test-runs/09.24/path-normalization-1000/`에 있다. 앞선 미완료 시도는 `path-normalization-aborted/`에 분리하고 평가에서 제외했다.
- [Wordlist 선정 기록](WORDLIST_SELECTION.md): SecLists의 고정 커밋 `common.txt`를 다음 주 목록으로 정했다. 파일은 [wordlists/common.txt](wordlists/common.txt)에 있으며 **아직 이 목록으로 Recon은 실행하지 않았다**.
- [ffuf 외 병목 분석](NON_FFUF_RECON_COVERAGE_ANALYSIS.md): SPA JS 경로 추출 0건, 백틱 경로의 정답지 일치 26개 중 미관측 23개, 기준 요청 HTTP 500, 브라우저 UI action 1개를 확인했다.
- 현재 ffuf는 root별 150초, 0.5 RPS이며 이전 1,000건 실행에서 각 root의 74~75번째 항목까지만 도달했다. `common.txt`는 4,752개 항목이므로 시간 제한과 요청 예산을 먼저 설계해야 한다.

## 재개할 때

1. 이 문서와 [첫 번째 수정 기록](REFACTOR_01_FFUF_PROXY_FILTER.md), [두 번째 수정 기록](REFACTOR_02_FFUF_TIME_LIMIT.md)을 읽고 `git status --short`를 확인한다. 작업 트리에는 Recon 외의 다른 변경도 있으므로 되돌리거나 덮어쓰지 않는다.
2. 네 수정과 전체 Juice Shop Recon 재실행까지 끝났다. [GET 요청 O/X 표](RECON_GET_ROUTE_MATRIX.md)와 [Surface O/X 표](RECON_SURFACE_ROUTE_MATRIX.md)를 함께 본다. 마지막 실행은 두 지표 모두 **25/71**이다.
3. 다음 우선순위는 브라우저가 열지 않은 화면의 API 요청과 ID 값을 넣어야 하는 parameter route의 발견 범위다. 정답지 71개 중 parameter route가 20개이며 현재 세션에서 관측한 것은 `/rest/basket/:id` 1개다. 큰 SecLists 목록 `common.txt`는 root별 150초와 총 요청 예산을 설계한 뒤 별도로 비교한다. 이번 정규화 수정은 영문 slug ID의 API 경로를 자동 병합하지 않는 보수적인 선택이다.

재개 요청 예시: **“09.24/RESUME_RECON_REFACTOR.md부터 읽고, Recon 리팩토링의 다음 항목을 이어서 진행해줘.”**
