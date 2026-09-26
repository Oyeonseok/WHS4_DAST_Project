# Validation 상태 전이 리팩토링 후 재실험 (2026-09-25)

## 변경 사항

앞선 [실험](VALIDATION_TRANSITION_EXPERIMENT.md)에서 관측한 세 문제를 수정했다.

1. Impact 가설이 있을 때 계획 전에 `processing_phase=developing`을 기록하고, 정상 반환 후 Blind 평가를 고정하기 전에 `blind_replay`로 돌린다. 기존 blocker 개발 경로와 같은 중간 단계가 계획 시점에 보인다.
2. `ImpactDevelopmentPlan`에 `source_request_ids`를 추가했다. 계획의 `evidence_ids`에는 현 Validation 단계의 증거만, `source_request_ids`에는 무결성 검사를 통과한 Attack 출처 요청만 넣을 수 있다. 양쪽의 외부 ID는 거부한다. 옛 계획의 필드 생략은 빈 목록으로 읽는다.
3. 이전 `UNDERPOWERED` 단계와 Blind 입력·범위·재현 결과·응답 해시가 같은 재검증에서는, 새 Blind 평가만으로 영향 축이 상승하지 못하게 한다. 개발 전 Agent 원점수와 실제 적용 점수는 `blind_assessment_pre_impact` 증거에 남긴다. 응답이나 범위가 달라지면 새 평가를 그대로 쓴다. 재현을 새로 긍정 판정으로 바꾸는 규칙은 아니다.
4. 리뷰에서 발견된 경계도 고쳤다. Blind Agent가 `reproduced=False`라고 한 양성 재현을 확정하지 않는다. 중단 후 재개는 봉인된 개발 전 평가와 그 평가가 인용한 Development 증거·사용 상태를 복원한다. 동일 재현 결과 비교에는 실제 평가가 인용한 완전한 배치만 사용한다. 채점기는 저장된 감사 기록의 이전 단계·요청·점수 연결을 독립적으로 확인한다.

## 재실험 결과

각 사례는 별도의 DB에서 실행했다. 아래 세 실행은 **기존 고정 관찰값으로 준비한 DB**와 주입된 HTTP 응답을 사용했다. 실행 경계와 요청 장부는 Native 포트를 통과하지만, 이번 재실험이 로컬 VulnBank 서버에 실제 네트워크 GET을 보냈다는 뜻은 아니다. 실험 당시 로컬 `127.0.0.1:5001` 서버는 실행 중이지 않았다.

| 모드 | 산출물 | 정답지 결과 |
| --- | --- | --- |
| Blind 축·Impact 계획 통제 | [`validation-transition-refactor-controlled-v1`](../../../../result/test-runs/validation-candidates/validation-transition-refactor-controlled-v1) | 6/6 `PASS` |
| Blind 축 통제·실제 Impact Agent | [`validation-transition-refactor-impact-agent-v3`](../../../../result/test-runs/validation-candidates/validation-transition-refactor-impact-agent-v3) | 6/6 `PASS` |
| Blind·Impact Agent 모두 실제 실행 | [`validation-transition-refactor-full-agent-v1`](../../../../result/test-runs/validation-candidates/validation-transition-refactor-full-agent-v1) | 2 `PASS`, 4 `BASELINE_NOT_UNDERPOWERED` |

실제 Impact Agent를 사용하고 Blind 축만 통제한 모드에서는 `verified_marker`와 `minimal_threshold`가 `UNDERPOWERED → CONFIRMED`, `weak_marker`·`false_marker`·`no_action`·`partial_boundary`는 `UNDERPOWERED`를 유지했다. 계획이 필요한 다섯 사례에서 Agent는 검증된 `lab-source-*` 요청을 `source_request_ids`에 따로 인용했고, 계획 시점의 단계는 `developing`이었다. `false_marker`는 GET 응답을 받았으나 거짓 마커 assertion이 실패했다. `partial_boundary`는 민감도만 상승해 `(0,2,2)`로 남았다.

완전 실제 Agent 모드의 사례별 결과는 다음과 같다.

| 사례 | 최초 판정 | 두 번째 Blind 원점수 → 적용 점수 | 최종 판정 | 채점 |
| --- | --- | --- | --- | --- |
| `verified_marker` | `INCONCLUSIVE` | 재검증 없음 | — | `BASELINE_NOT_UNDERPOWERED` |
| `minimal_threshold` | `INCONCLUSIVE` | 재검증 없음 | — | `BASELINE_NOT_UNDERPOWERED` |
| `weak_marker` | `INCONCLUSIVE` | 재검증 없음 | — | `BASELINE_NOT_UNDERPOWERED` |
| `false_marker` | `CONFIRMED` | 재검증 없음 | — | `BASELINE_NOT_UNDERPOWERED` |
| `no_action` | `UNDERPOWERED (0,0,2)` | `(0,0,2) → (0,0,2)` | `UNDERPOWERED` | `PASS` |
| `partial_boundary` | `UNDERPOWERED (0,0,2)` | `(1,1,2) → (0,0,2)` | `UNDERPOWERED (0,2,2)` | `PASS` |

`partial_boundary`는 실제 Blind Agent의 더 높은 두 번째 점수가 같은 재현 응답만으로 판정을 올리지 못하고, 새 Impact 관측만 민감도 축에 반영된 사례다. 완전 실제 Agent 모드의 양성 2건은 최초 상태가 실험의 `UNDERPOWERED` 시작 조건을 충족하지 않았다. 따라서 **Blind·Impact Agent가 모두 실제인 인과적 양성 전이는 이번 재실험에서도 0건**이다. 이는 초기 Blind 평가의 재현 여부 판단과 점수 변동이 별도 개선 대상임을 남긴다.

### 완전 실제 Agent 실행의 진입 실패 원인

여섯 사례가 모두 Development에 실패한 것은 아니다. `partial_boundary`는 계획 시점 `processing_phase=developing`, 실제 Impact Agent의 `execute` 계획, 새 GET의 `observed` 증거와 `succeeded` 가설을 기록했다. 다만 새 증거가 민감도만 2로 올렸고 경계는 0이어서 `UNDERPOWERED`로 남았다. `no_action`에는 실행 계약이 없어 계획·GET이 없었다.

나머지 네 사례는 실습 실행기가 첫 판정이 `UNDERPOWERED`일 때만 두 번째 단계를 실행하므로 Impact Agent에 도달하지 않았다. `verified_marker`·`minimal_threshold`·`weak_marker`의 실제 Blind 평가는 `reproduced=null`이었다. 일반 후보 준비기는 `/debug/users` target assertion에 `"password"`를 쓰지만, Impact 실습 준비기는 약한 baseline을 만들려고 이를 일반 문자열 `users`로 바꾼다. 저장된 관측에는 이 assertion의 성공 여부·응답 해시·길이가 있으며 본문 내용은 없다. 반면 연결된 `hunt-source-leak` 프로필은 소스·맵·자격 증명 패턴·내부 코드의 선언된 표식을 재현 증거로 요구한다. 또한 후보 유형 `excessive_data_exposure`를 `hunt-source-leak`에 매핑해 메커니즘 이름과 실제 `/debug/users` 사례 사이에도 간극이 있다. 따라서 이 세 사례에서 메커니즘을 확정하지 않은 판단은 입력 증거로 설명된다. `false_marker`는 같은 약한 target assertion으로 `(1,1,2)`를 받아 첫 단계부터 `CONFIRMED`였다. 이것은 Impact 개발 성공이 아니라 약한 재현 신호의 과대평가 가능성을 보여준다. 사례마다 Impact 계약 해시는 다르므로 이 한 실행만으로 순수한 Agent 무작위성을 입증하지는 않는다.

해결은 두 경로로 나누어야 한다. 현재 `UNDERPOWERED → DEVELOPING` 실험에는 실제 취약 메커니즘을 약하게나마 입증하는, 프로필 증명 기준에 맞는 안전한 baseline assertion과 그보다 강한 별도 Impact assertion을 갖춘 후보를 준비한다. 기존 `users` 사례는 증거 부족·오분류를 확인하는 음성 대조군으로 남긴다. 제품 판정에는 프로필의 요구 신호와 재현 assertion의 연결을 기계적으로 검증하는 계약을 추가하고, 일반 문자열만으로 `reproduced=true` 또는 민감도 상승이 허용되지 않는 회귀 테스트를 둔다. `INCONCLUSIVE`에서 새 증거를 얻는 동작이 필요하다면 이는 Impact 점수 보강과 다른 Proof Development 경로로 설계하고, 개발 후 재현 여부를 다시 평가해야 한다. `reproduced=null`을 임의로 `true`로 바꾸거나 모든 최초 판정을 강제로 `UNDERPOWERED`로 만드는 방식은 정답을 조작한다.

리뷰 수정 후 새 봉인 형식을 사용한 실제 Impact Agent 양성 확인은 [`validation-transition-refactor-impact-agent-v4/verified_marker`](../../../../result/test-runs/validation-candidates/validation-transition-refactor-impact-agent-v4/verified_marker)에서 `UNDERPOWERED → CONFIRMED`, `PASS`, SQLite `ok`였다. 이 한 건은 앞의 6건 집계에 중복 합산하지 않는다.

## 검증 범위

19개 격리 DB의 SQLite 무결성과 저장된 채점 결과를 현재 채점기로 대조했다. Validation 핵심 테스트 132개·120 subtests, 전송·정책 경계 테스트 32개·35 subtests, 실습 테스트 29개가 통과했다. `compileall`과 `git diff --check`도 통과했다. 이전 실험 산출물은 과거 코드·채점 기준의 역사적 기록으로 유지했다.

## 후속 작업: 프로필 증명 신호와 실제 Agent 재실험

위 표와 집계는 수정 전 실행의 역사적 결과다. 이후 `/debug/users`의 약한 baseline 증명을 일반 문자열 `users`에서 비밀 값이 없는 정확한 JSON 필드 이름 `"password":`로 바꿨다. `hunt-source-leak` 프로필의 HTTP 재현 assertion은 선언된 소스·맵·자격 증명 패턴 신호와 일치해야 한다. 기존 `users` 계약은 일곱 번째 격리 DB `weak_source_signal`에 보존했으며, 무결성 게이트가 `runtime_profile_semantics`로 거부한다. 필드 이름 하나만 확인한 경우 Blind Agent가 민감도 1 또는 2를 주어도 적용 점수는 0으로 제한한다. 감사 증거에는 Agent 원점수, 적용 점수, 사용한 규칙을 모두 남긴다. 새 Impact 관측이 성공하면 이후 민감도를 높일 수 있다.

실제 Blind·Impact Agent 재실험의 범위는 [새 실행 폴더](../../../../result/test-runs/validation-candidates/validation-proof-signal-full-agent-v3)다. 여섯 사례를 각기 다른 DB에서 실행했다. Eligibility만 고정된 실습 fixture를 사용했다. 요청은 Native 실행 경계를 통과했지만 HTTP 응답은 저장된 로컬 관찰값으로 주입했다. 따라서 이 결과가 실시간 VulnBank 서버의 가용성을 검증하지는 않는다.

| 사례 | 실제 최초 축 | 최종 판정·축 | 새 채점 결과 | 해석 |
| --- | --- | --- | --- | --- |
| `verified_marker` | `(1,0,2)` `UNDERPOWERED` | `(1,2,1)` `CONFIRMED` | `PASS` | 실제 Agent 양성 전이 |
| `minimal_threshold` | `(1,0,2)` `UNDERPOWERED` | `(1,2,2)` `CONFIRMED` | `BASELINE_AXIS_MISMATCH` | 양성 전이는 관측됐으나 정답지의 요구 조건 0 사례가 아님 |
| `weak_marker` | `(1,0,2)` `UNDERPOWERED` | `(1,0,2)` `UNDERPOWERED` | `PASS` | 고유 마커 부족으로 계획 건너뜀 |
| `false_marker` | `(1,0,2)` `UNDERPOWERED` | `(1,0,2)` `UNDERPOWERED` | `PASS` | 실행된 추가 assertion 실패 |
| `no_action` | `(1,0,2)` `UNDERPOWERED` | `(1,0,2)` `UNDERPOWERED` | `PASS` | 개발 계약과 요청 없음 |
| `partial_boundary` | `(1,0,2)` `UNDERPOWERED` | `(1,2,2)` `CONFIRMED` | `BASELINE_AXIS_MISMATCH` | 실제 경계 축이 정답지의 0이 아니므로 음성 사례 전제 불충족 |

이 실행에서 모든 사례가 `UNDERPOWERED`로 시작했고, 양성으로 설계한 두 사례는 `DEVELOPING` 시점의 계획을 거쳐 `CONFIRMED`가 됐다. 세 음성 사례는 `UNDERPOWERED`를 유지했다. `partial_boundary`는 실제 Blind Agent가 경계 축 1을 부여했으므로 기대한 음성 사례로 채점할 수 없다. 따라서 시나리오 기준 결과는 **4 `PASS`, 2 `BASELINE_AXIS_MISMATCH`**다. 실제 Agent가 정확히 `minimal_threshold`와 `partial_boundary`의 시작 축을 만들지는 못했다. 이 두 특수 경계를 다시 시험하려면 후보 증거 또는 정답지의 시나리오 정의를 별도로 재설계해야 한다. 기존 정답지는 관측 결과에 맞춰 바꾸지 않았다.

### 시작 축 증거 사전 검사

위 불일치를 재발시키지 않도록 준비기에 Impact 실행 전 증거의 해시를 추가했다. 여섯 사례의 Blind 재현 계약·접근 역할·Attack 출처 요청이 동일했고, 계약에만 있는 미실행 Impact 기능은 해시에서 제외했다. `minimal_threshold`의 요구 조건 0과 `partial_boundary`의 경계 0은 이 공통 증거만으로 뒷받침되지 않는다. 따라서 새 [격리 실습 폴더](../../../../result/test-runs/validation-candidates/validation-axis-evidence-v1)의 두 사례는 실제 Blind 모드 실행 전 `shared_replay_evidence`로 거부한다. 기존 v3 실행은 이 사전 검사가 없던 시점의 관측으로 유지한다.

로컬 VulnBank 원본의 `/debug/users`는 인증 검사 없이 사용자 정보를 반환하며, 새 준비 과정은 실행 중인 로컬 서버의 고정 GET 관찰값을 다시 확인했다. 두 특수 사례의 통제 fixture 모드는 같은 로컬 서버에 Native GET을 보내 각각 `minimal_threshold`: `UNDERPOWERED → CONFIRMED`, `partial_boundary`: `UNDERPOWERED → UNDERPOWERED`였고 두 채점 결과 모두 `PASS`였다. 이 결과는 판정식의 두 경계를 확인하지만 실제 Blind Agent가 시작 축 0을 판단한다는 근거는 아니다. 공식 후보에서 다른 접근 조건·관찰값이 확보될 때까지 두 사례의 실제 Agent 판정은 보류한다.

## Development 진입 조건 강화 재검증

Impact 실행 전에 별도의 신뢰된 검증기가 경로, 불변 액션 해시, 모든 사전 조건, 출처 요청과 현재 증거를 확인해 영수증을 봉인하도록 했다. Agent가 `preconditions_satisfied=true`라고 선언해도 영수증이 없으면 계획·추가 요청을 시작하지 않는다. 영수증이 있으면 계획이 해당 Validation 증거 ID를 인용해야 실행한다. 이미 영향 기준을 충족한 재현 후보도 추가 Impact 개발을 시작하지 않는다. `BLOCKED` prerequisite 재시도는 이전 완료 액션과 현재 차단·계약·재현·범위·정책 조건이 같을 때 건너뛰며, 이전 결과가 `outcome_unknown`이면 수동 검토로 보낸다.

새 [격리 실행 폴더](../../../../result/test-runs/validation-candidates/validation-admission-v2)에서 최초 Blind 축과 Eligibility만 fixture로 고정하고 Impact 계획에는 실제 Agent를 사용했다. Native 요청 장부와 실행 계약을 거쳤고 HTTP 응답은 기록된 로컬 관찰값에 맞춘 주입 전송이었다.

| 사례 | 최초 → 최종 | 영수증 인용 | 채점 |
| --- | --- | --- | --- |
| `verified_marker` | `UNDERPOWERED → CONFIRMED` | 있음, 계획 단계 `developing` | `PASS` |
| `false_marker` | `UNDERPOWERED → UNDERPOWERED` | 있음, 추가 assertion 실패 | `PASS` |

두 사례 모두 영수증을 현재 단계 증거에 저장하고 Agent 실행 계획이 그 ID를 인용했다. 별도의 `weak_marker` 회귀 테스트는 영수증이 없을 때 Agent를 호출하지 않고 개발을 건너뛰는 동작을 확인한다. `BLOCKED` 회귀 테스트는 같은 조건의 재실행 방지, 응답이 바뀐 경우 새 실행, 이전 결과가 불명확한 경우 `INCONCLUSIVE`를 확인했다. 이 실행은 Blind Agent의 독립적인 축 판단이나 실시간 VulnBank 연결을 입증하지 않는다.

### Blind 축 인용 근거 강화

이후 `hunt-source-leak`의 개발 전 Blind 평가에 축별 인용 검사를 추가했다. 양수 경계 축은 관측된 target과 관측되지 않은 negative control을 함께 인용해야 한다. 양수 민감도·요구 조건 축은 관측된 target을 인용해야 한다. 인용이 부족하면 해당 축의 적용 점수를 0으로 제한하고 `blind_assessment_pre_impact`에 Agent 원점수·적용 점수·규칙 ID를 남긴다. 비밀 값이 없는 필드 이름만 관측했을 때 민감도를 0으로 제한하는 기존 규칙은 그대로 적용된다.

통제 fixture의 이전 축 인용은 positive control 하나만 가리켰다. 이를 target 및 negative control 인용으로 수정했다. 일부러 control만 인용하도록 되돌린 회귀 사례에서는 원점수 `(1,0,2)`가 적용 점수 `(0,0,0)`으로 제한되고 최종 판정은 `UNDERPOWERED`였다. 정상 fixture는 양성 전환을 유지했다. 이 변경은 **증거 종류와 인용 관계**를 확인하며, 동일한 재현 증거에서 서로 다른 숫자 축을 만들어 내지 않는다. 따라서 `minimal_threshold`와 `partial_boundary`의 기존 `BASELINE_AXIS_MISMATCH`는 여전히 후보 증거 재설계가 필요한 실험 전제 문제다. 다른 취약점 프로필의 축별 의미 규칙은 아직 추가하지 않았다.

새 [실제 Agent 격리 실행](../../../../result/test-runs/validation-candidates/validation-axis-grounding-real-v1/verified_marker)에서는 Blind·Impact Agent를 모두 실행하고 Eligibility와 HTTP 응답만 통제했다. Blind 원점수 `(1,1,2)`에서 필드 이름 규칙으로 `(1,0,2)`가 적용돼 최초 `UNDERPOWERED`였고, Impact Development 후 `(1,2,2)` `CONFIRMED`가 됐다. 두 단계의 새 축 인용 규칙 위반은 없었으며 정답지 채점은 `PASS`, SQLite 무결성은 `ok`였다. 응답은 주입 전송이므로 실시간 서버 연결 성공을 뜻하지 않는다.
