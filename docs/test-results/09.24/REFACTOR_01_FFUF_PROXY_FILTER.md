# Recon 리팩토링 1: ffuf의 정책 프록시 차단 응답 제외

## 근거

`seclists-api-500` 실행에서 ffuf 후보 26개 중 25개는 프록시가 요청을 대상에 전달하지 않고 반환한 HTTP 403이었다. 이 후보들은 대상 HTTP transaction이 없는데도 ffuf 관측으로 저장되어 Surface 경로 정규화와 source 병합에 섞였다. 대상이 직접 반환한 403은 실제 관측이므로 보존해야 한다.

## 변경

`src/aidast/recon/tools/endpoint_discovery.py`의 ffuf 명령 생성에서 정책 프록시를 사용하는 경우 `-fr 'Blocked by AI-DAST TargetPolicy'`를 추가했다. 이 문구는 `src/aidast/recon/tools/mitm_addon.py`가 차단 요청에 반환하는 본문이다. ffuf가 결과를 저장하기 전에 해당 본문을 필터링한다. 일반적인 대상 403은 필터링하지 않는다. 요청 상한, RPS, root 선택, wordlist, 150초/root 제한은 바꾸지 않았다.

## 검증

회귀 테스트는 실제 ffuf와 로컬 테스트 프록시를 사용한다. `/blocked`에 정책 프록시와 동일한 403 본문, `/denied`에 대상 서버의 다른 403 본문을 반환한다.

```bash
.venv/bin/python -m pytest -q docs/test-results/09.24/test_ffuf_policy_response_filter.py
```

수정 전에는 `/blocked`, `/denied` 두 후보가 나와 실패했고, 수정 후에는 `/denied`만 남아 **1 passed**였다. 관련 기존 테스트는 다음 명령으로 **96 passed, 22 subtests passed**였다.

```bash
.venv/bin/python -m pytest -q \
  tests/test_ffuf_root_selection_skill.py \
  tests/test_tool_annotation_evidence.py \
  tests/test_recon_browser_transport.py \
  tests/test_mitm_proxy.py \
  tests/test_request_broker.py
```

이 검증은 차단 응답의 ffuf 후보 유입을 막는 동작을 확인한 것이다. 전체 Juice Shop Recon을 새 코드로 재실행한 수집률은 아직 측정하지 않았으며, 이전 DB와 O/X 결과는 수정하지 않았다.
