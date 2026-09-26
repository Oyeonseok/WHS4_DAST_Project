# Validation Impact Development 실습 (2026-09-24~25)

## 목적과 입력

영향도 근거가 약한 후보에서 Validation의 실제 Impact Development 에이전트가 계획을 만들고, 허용된 요청을 실행하고, 새 증거를 최종 판정에 반영하는지 확인한다. 기존 후보 DB와 정답 DB는 그대로 사용한다. 별도 출력 폴더에 7개 후보를 격리 적재하지만 실행기는 VulnBank `GET /debug/users` 한 건만 선택한다. 입력 출처와 로컬 앱 준비 방법은 [후보 인벤토리](../../../test-plans/VALIDATION_CANDIDATE_INVENTORY.md)에 있다.

준비기는 실행 중인 고정 VulnBank의 신원과 관찰값을 다시 확인하고 JSON 구조와 응답 해시를 검사한다. 이 실습을 켜면 `/debug/users`의 최초 target 신호를 `users` 필드명으로 제한한다. 별도의 불변 실행 계약은 같은 GET에서 `"password":` 필드명 구문과 `users[0].account_number == "ADMIN001"` JSON 값을 요구한다. 이는 [고정 VulnBank `database.py`](https://github.com/Commando-X/vuln-bank/blob/5e5ea5425fcf309373a0655dd111ecfb45037cbf/database.py#L255)의 교육용 샘플 값이다. 비밀번호 값이나 응답 본문은 실습 산출물에 저장하지 않는다. 계약은 `hunt-source-leak` 프로필의 `bounded-impact-confirmation` 경로에 연결되며, 요청은 로컬 TargetPolicy와 Validation 실행 포트가 제한한다.

정답은 [별도 JSON](../../../../resources/lab/validation-impact-answer-key.json)에 둔다. 목표는 최종 `CONFIRMED`와 민감도 점수 **최초 1 이하 → 최종 2 이상**이다. `CONFIRMED`만으로는 통과하지 않는다. 실제 에이전트의 `execute` 계획, 양성·음성 대조군과 target 3회, 현 단계의 GET 요청 기록, 계약 assertion 성공, 새 증거가 최종 민감도 평가에 인용된 사실을 모두 요구한다. 채점기는 [독립 스크립트](../../../../scripts/score_validation_impact_lab.py)이며 후보에게 정답지를 전달하지 않는다.

## 재현

기존 [로컬 기능 테스트 환경](../../../test-plans/LOCAL_FUNCTIONAL_LAB.md)에 따라 두 앱을 실행한 뒤, 저장소 루트에서 새 출력 이름을 골라 실행한다. 준비기는 기존 출력 폴더를 덮어쓰지 않는다.

```bash
.venv/bin/python scripts/prepare_validation_lab.py \
  --impact-probe \
  --output result/test-runs/validation-candidates/validation-impact-next
.venv/bin/python scripts/run_validation_impact_lab.py \
  result/test-runs/validation-candidates/validation-impact-next
.venv/bin/python scripts/score_validation_impact_lab.py \
  result/test-runs/validation-candidates/validation-impact-next
```

매 실행의 `Pipeline.db`, `CandidateFindingMap.json`, `ImpactDevelopmentScore.json`은 해당 폴더에 남는다. `result/`는 Git에서 제외된다. 실습 준비에는 원본 `CandidateInventory.db`, `CandidateAnswerKey.db`, `LocalControlObservations.json`과 승인된 `Scope.md`가 필요하다.

## 이번 실행 결과

첫 실행 폴더는 `result/test-runs/validation-candidates/validation-impact-v1`이다. 처음에는 실제 Blind Validation 에이전트가 영향 축 `(경계 1, 민감도 1, 요구 조건 2)`을 기록하고 `CONFIRMED`로 끝냈지만, 기존 코드는 점수 1을 이미 충분하다고 보고 Impact Development를 제안하지 않았다. 이에 점수 0 또는 1에서 선언된 개선 가능 점수가 더 높고 실행 계약이 있을 때만 경로를 제안하도록 변경했다.

수정 후 동일 격리 DB의 최신 단계 `stage_ccb6fa61729b4c869b569cb865d3cd39`에서 실제 Impact Development 에이전트가 `execute`를 선택했다. 양성 대조군은 관측, 음성 대조군은 미관측, target 3회는 관측이었다. 실행 포트는 추가 `GET http://127.0.0.1:5001/debug/users` 한 번을 수행했고 HTTP 200과 당시 선언한 `"password"` 문자열 assertion 성공을 기록했다. 새 증거 `vevidence_987e6034dee647429d9eafe169f6e35a`가 최종 민감도 평가에 인용됐다. 최종 영향 축은 `(1, 2, 2)`, 상태는 `CONFIRMED`였다. **당시 정답 기준에서는 PASS**였다. 이 문자열은 JSON 값에도 나타날 수 있으므로 현재 기본 fixture의 assertion은 필드명 구문 `"password":`로 강화했다.

강화된 기본 fixture로 새로 준비한 `validation-impact-v2`의 단계 `stage_4f1a25fcd1f846bcbfed212197ae9d7e`에서는 Blind 에이전트의 최초 민감도 점수가 0이었다. Impact Development 에이전트는 `skip`을 선택했고 추가 GET은 없었다. 계획 이유는 동일 GET의 Attack 출처 기록과 강한 영향 신호의 고유성이 계획 입력에서 충분히 입증되지 않았다는 것이다. 최종 상태는 `INCONCLUSIVE`, 현재 정답지의 채점 결과는 **UNRESOLVED**다. 출처 GET은 격리 DB의 `attack_http_requests`에 있으나 현재 planner 입력은 그 연결을 명시적으로 전달하지 않는다. 이 차이는 다음 리팩토링 대상으로 남긴다. 정답 기준을 낮추거나 `skip`을 성공으로 간주하지 않았다.

후속 실험 `validation-impact-provenance-v3`에서는 출처 GET이 계획에 전달됐지만 일반적인 `password` 키는 고유 마커로 인정받지 못했다. `v4`·`v5`의 기본 관리자 사용자명도 충분한 고유 마커가 아니라고 판단해 모두 `skip`했다. 이 세 실행의 채점은 `UNRESOLVED`였다. 정답 기준을 낮추거나 `skip`을 성공으로 간주하지 않았다.

`validation-impact-provenance-v6`에서는 무결성 검사를 통과한 Attack GET 요청 ID·URL·상태와, 같은 응답 해시에 묶인 소스 공개 샘플 식별값을 계획 증거로 분리해 전달했다. 실제 에이전트는 두 사전 조건이 충족됐다고 판단하고 `execute`를 선택했다. 최신 단계 `stage_ca659bd468384967a9d5461563db175a`에서 추가 GET 한 번이 HTTP 200으로 완료됐고, 두 assertion이 통과했다. Impact Development 증거가 최종 민감도 평가에 인용됐으며 민감도는 **1→2**, 최종 상태는 `CONFIRMED`, 독립 채점은 **PASS**였다. SQLite 무결성 검사도 `ok`였다.

리뷰에서 v6의 사전 관측값은 출처 요청과 해시에만 연결됐고, 계획에 넘기기 전에 마커의 실제 위치를 재확인하지 않았다는 문제가 드러났다. 또한 본문 문자열 assertion은 계정 식별값이 다른 JSON 위치에 있어도 통과할 수 있었다. 일반 코디네이터는 이제 사전 관측값을 자동으로 검증 증거라고 전달하지 않는다. 이 실습 실행기는 고정 소스 파일 해시와 현재 응답의 JSON 구조·응답 해시를 다시 확인한 뒤에만 마커 영수증을 전달한다. 새 GET의 마커 assertion은 `users[0].account_number` 경로에서 평가한다.

수정 후 새 격리 실행 `validation-impact-provenance-v7`의 단계 `stage_c4c440c44d214beab7a777e8312a911f`에서 실제 에이전트가 `execute`를 선택했다. 추가 GET 한 번이 HTTP 200으로 완료됐고 필드명 구문과 JSON 경로 assertion이 모두 통과했다. 최종 상태는 `CONFIRMED`, 독립 채점은 **PASS**, SQLite 무결성 검사는 `ok`였다. 재현에 필요한 산출물은 해당 `result/test-runs/validation-candidates/` 폴더에 있다.

이 결과는 소스에 공개된 교육용 샘플 값과 현재 응답이 일치하는 경우의 **영향도 보강**을 입증한다. 상태가 `UNDERPOWERED`에서 `CONFIRMED`로 바뀌는 실행이나 여러 개발 경로의 선택 품질까지 입증하지는 않는다. 실제 계정번호나 비밀값을 일반적인 Impact 계획 마커로 사용하는 근거가 아니다.

## 검증

채점기의 손상 사례는 실행 계획, 대조군, 출처 요청, 응답 해시, 새 요청 기록, assertion 증거 등의 결손을 거부한다. 관련 Validation·실습·Attack 회귀 테스트는 **561 passed, 4 skipped, 511 subtests passed**였다. 과거 v1~v5 계약도 새 무결성 검사로 읽혔다.
