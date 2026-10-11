# Validation 재현 요청 보완과 대조군 실행

대상: `scan_177ab14bb55b413f9affd9cd33325bf8`의 두 보류 결과에서 확인한 검증 흐름.

| 후보 | 저장된 판정 | 실제 실행 내역 | 확인한 원인 |
| --- | --- | --- | --- |
| Authenticated user can enumerate all user profiles (`GET /api/Users`) | INCONCLUSIVE | 요청 0회 | `http_runtime_contract_missing`으로 즉시 종료 |
| Login authentication bypass through email SQL injection | UNDERPOWERED | 양성 1회, 음성 1회, 타깃 3회 | authentication 문자열 재현은 성공했으나 기존 영향 평가에서 보호된 계정 접근 증거 부족 |

## 수정 방향

사용자가 요청한 개선은 검증 명세가 부족한 후보도 요청과 대조군을 보완하여 실제 검증을 수행하는 것이다. 초기에 추가했던 모든 Finding 저장의 runtime contract 필수 제한과 로그인 세션 증거에 따른 sensitivity 강제 제한은 제거했다. 기존 Attack 저장 정책과 판정 기준을 유지한다.

## 변경

- native Validation은 HTTP 재현 명세가 없으면 별도 준비 단계에서 기존 요청 URL, 재현 조건, 관찰된 효과와 프로필로 타깃·양성·음성 요청을 구성한다. 준비 단계에는 요청 실행 도구를 제공하지 않는다.
- Codex의 출력은 엄격한 스칼라 DTO(`runtime_contract_json`, `reason`)로 받는다. Python에서 내부 JSON을 HTTP 계약으로 검증하여 실행한다. 동적 요청 딕셔너리를 Codex의 strict output schema로 직접 전달하지 않는다.
- 준비된 계약은 `validation_replay_plans`에 case/stage 단위로 저장한다. 원래 Attack 기록을 바꾸지 않고 명세·프로필 해시를 결합한다. 재개할 때 동일 계약과 완료된 요청 결과를 재사용한다.
- 인증이 필요한 API의 음성 대조군은 `identity_mode=anonymous`로 동일 URL을 비인증 상태에서 요청할 수 있다. HTTP 및 체인 HTTP 실행에서 해당 요청의 credential references를 비워 Authorization/Cookie가 섞이지 않게 한다. 기본값 `case`는 기존 계약 해시를 유지한다.
- 유효한 계약은 기존 실행 흐름의 양성 1회, 음성 1회, 타깃 3회로 검증한다. 기존 정책, 예산 및 판정 기준은 적용된다.
- 준비 출력이 잘못되거나 Codex 호출이 실패하면 제한된 보완 재시도 후 해당 후보의 실패 사유를 남긴다. 한 후보의 준비 오류 때문에 전체 Validation을 중단하지 않는다. 정보 부족이나 HTTP 외 전용 프로필은 요청을 실행하지 못한 이유를 명시한다.
- HTTP의 선택적 `session_verification`으로 반환 토큰과 보호된 GET 응답을 추가 확인할 수 있다. 필수 조건이나 추가 점수 제한으로 사용하지 않는다. 토큰은 메모리에서만 사용하고 증거에는 저장하지 않는다.
- 대시보드는 재현 여부와 영향 평가를 보여주고 UNDERPOWERED를 “영향 입증 부족”으로 구분한다. 기존 요청 미실행 기록과 새 준비 실패 사유도 표시한다.

## 검증

```sh
.venv/bin/python -m pytest tests/test_validation_*.py tests/test_attack_cli.py tests/test_native_helper_broker.py tests/test_web_dashboard.py -q --tb=short
.venv/bin/python -m pytest tests/test_validation_replay_preparation.py tests/test_validation_coordinator.py -q --tb=short
cd WebUI
node --test tests/*.test.mjs
npm run build
```

Node 24.18.0으로 검증 관련 변경만 추출한 커밋 후보의 프런트엔드 테스트 117개와 번역 검사, TypeScript 검사, Vite 빌드를 통과했다. 분리된 커밋 후보에서 Python 검사도 **561 passed, 4 skipped, 486 subtests passed**로 통과했다. Skip 4건은 선택적 live acceptance 검사다. 결과는 `result/test-runs/09.29/validation-fix/Verification.json`에 기록한다.

회귀 검사는 실제 fixture transport에서 양성·음성·타깃 5회 실행, 인증 정보 제거, 재개 시 명세와 완료된 요청 재사용, 잘못된 준비 출력 재시도, Codex 호출 실패의 후보 단위 격리를 확인한다.

## 적용 범위

기존 스캔 판정은 변경하지 않았다. 이번 작업에서 Juice Shop에 새 공격 요청을 보내 두 후보를 재판정하지 않았다. 기존 후보는 재검증하거나 새 스캔에서 수정된 흐름을 실행해야 한다.

자동 보완은 HTTP 프로필을 지원한다. 브라우저/OOB 전용 프로필의 명세 자동 생성은 지원하지 않는다. 선택적 세션 확인은 JSON bearer 토큰 방식이다.

프런트엔드는 재빌드했다. 대시보드에서 새 스캔이 실행 중인 것을 확인하여 서버 재시작은 수행하지 않았다. 실행 중인 프로세스에 새 Python 코드가 적용됐다고 보장하지 않는다.
