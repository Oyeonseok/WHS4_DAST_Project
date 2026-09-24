# Recon 리팩토링 2: ffuf root별 시간 제한 설정과 입력 크기 기록

## 근거

이전 SecLists 174줄 실험은 ffuf가 네 root에서 각각 150초 후 종료되어 최대 75번째 항목까지만 대상에 도달했다. 이 값은 `endpoint_discovery.py`에 고정되어 있었고, 진단 로그에도 wordlist 크기와 적용 시간 제한이 함께 기록되지 않았다. `common.txt` 4,752줄 실험에서는 이 정보 없이 완료 여부를 판단할 수 없다.

## 변경

- `aidast recon`과 `aidast run`에 `--ffuf-max-time-seconds`를 추가했다. 기본값은 이전과 같은 150초이며, 양의 정수만 받는다.
- CLI → `ReconExecutor` → endpoint discovery → ffuf 호출까지 값을 전달하고, ffuf의 `-maxtime`과 Python subprocess 제한(`설정값 + 30초`)에 적용한다.
- `ffuf_roots` 진단 이벤트에 `wordlist_lines`와 `max_time_seconds`를 기록한다. 줄 수는 파일의 물리적 줄 수이며 실제 대상 요청 건수나 완료 건수는 아니다.
- 정책의 요청 상한, RPS, 프록시의 강제 차단 규칙은 바꾸지 않았다. 이전 실험은 기본 150초로 재현 가능하다.

## 검증

먼저 [회귀 테스트](test_ffuf_time_limit.py)를 작성했고, 수정 전에는 CLI 옵션 인식 실패 및 ffuf 함수 인자 부재로 **2 failed**였다. 수정 후에는 **2 passed**였다. 관련 테스트 명령:

```bash
.venv/bin/python -m pytest -q \
  docs/test-results/09.24/test_ffuf_time_limit.py \
  tests/test_ffuf_root_selection_skill.py \
  tests/test_tool_annotation_evidence.py \
  tests/test_recon_browser_transport.py \
  tests/test_recon_adaptive_js.py \
  tests/test_recon_diagnostics.py
```

결과는 **76 passed, 9 subtests passed**였다. `aidast recon --help`와 `aidast run --help`에도 옵션이 표시됐고 `git diff --check`를 통과했다.

## 다음 측정의 조건

예를 들어 `--ffuf-max-time-seconds 400`은 각 root의 최대 실행 시간만 늘린다. 174줄을 0.5 RPS로 한 root에서 전부 시도하려면 이론적으로 348초 이상이지만, 네 root의 요청과 이전 Playwright·Katana 요청을 합치면 현재 1,000건 정책의 낮은 우선순위 예산을 넘을 수 있다. `common.txt` 4,752줄 전체 실험은 시간뿐 아니라 요청 예산도 별도 설계가 필요하다.

이번 변경으로 **실제 시도한 wordlist 항목 수는 아직 기록되지 않는다.** 다음 단계는 정책 프록시가 본 ffuf 허용·차단 요청을 집계해 진단 로그에 남기는 것이다. 새 코드로 전체 Juice Shop Recon을 재실행한 수집률도 아직 측정하지 않았다.
