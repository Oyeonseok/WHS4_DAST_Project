# Validation 상태 전이 실제 Agent 실험 (2026-09-25)

## 실험 질문과 판정 기준

`UNDERPOWERED`에서 시작한 후보가 Impact Development의 **새 관측 때문에** `CONFIRMED`로 바뀌는가? 약한 마커, 실패한 assertion, 실행 계약 부재, 부분적인 영향 보강은 확정 판정을 피하는가? [6개 시나리오와 정답지](../../../test-plans/VALIDATION_TRANSITION_LAB.md)는 이 질문에 맞춰 실험 전에 고정했다.

각 시나리오는 별도 `Pipeline.db`에서 두 단계로 실행했다. 첫 단계에는 Impact Development 포트를 연결하지 않고, 첫 판정이 `UNDERPOWERED`일 때만 두 번째 단계를 실행했다. 두 번째 단계는 로컬 VulnBank의 실제 GET 재현과 Native Impact Development 포트를 사용했다. `TransitionTrace.json`에는 두 단계의 Blind Agent 영향 축, 계획, 계획 시점의 `processing_phase`, 가설 결과와 중단 원인을 기록했다. 독립 [채점기](../../../../scripts/score_validation_transition_lab.py)는 정답지와 DB의 단계·요청·증거·assertion 기록을 대조한다. 두 번째 Blind 평가가 이미 충분하면 `NON_CAUSAL_BASELINE`으로 분류한다.

입력의 Attack `confirmed` 주장은 합성 실습 데이터다. 소스 마커는 고정된 교육용 VulnBank 샘플과 현재 로컬 GET의 구조·해시를 재확인해 사용했다. 응답 본문과 비밀번호 값은 아래 보고서에 싣지 않았다. 이 실험은 VulnBank `GET /debug/users`의 한 실행 경로를 여섯 조건으로 바꿔 본 것이며, 다른 취약점 종류나 앱 전체에 대한 성능 수치는 아니다.

## 실험 A: 초기 영향 축 통제, Impact Agent 실제 실행

산출물: [`validation-transition-impact-agent-v2`](../../../../result/test-runs/validation-candidates/validation-transition-impact-agent-v2). 모든 사례에서 최초 및 두 번째 Blind 평가의 영향 축은 실험용 고정값이다. Impact 계획의 `execute`·`skip` 판단은 실제 Agent가 했다.

| 시나리오 | 최초 → 두 번째 판정 | 실제 Agent 및 실행 관측 | 정답지 채점 |
| --- | --- | --- | --- |
| `verified_marker` | `UNDERPOWERED (1,0,2)` → 실행 중단 | `execute` 계획이 Attack 출처 요청 ID를 Validation `evidence_ids`에 포함; 계획 검증에서 거부 | `EXECUTION_ERROR` |
| `minimal_threshold` | `UNDERPOWERED (1,0,0)` → 실행 중단 | 같은 증거 ID 오류 | `EXECUTION_ERROR` |
| `weak_marker` | `UNDERPOWERED (1,0,2)` → `UNDERPOWERED (1,0,2)` | `skip`, 추가 GET 없음 | `PASS` |
| `false_marker` | `UNDERPOWERED (1,0,2)` → `UNDERPOWERED (1,0,2)` | `execute`, 추가 GET 1회·HTTP 200; 거짓 마커 assertion 실패, `not_observed` | `GAP_DEVELOPING_PHASE` |
| `no_action` | `UNDERPOWERED (1,0,2)` → `UNDERPOWERED (1,0,2)` | 실행 계약 없음, 추가 GET 없음 | `PASS` |
| `partial_boundary` | `UNDERPOWERED (0,0,2)` → 실행 중단 | 같은 증거 ID 오류 | `EXECUTION_ERROR` |

세 중단 사례에서는 새 Impact 요청이 실행되지 않았다. 계획의 `lab-source-*` ID는 무결성을 확인한 **Attack 출처 요청**으로 계획 맥락에는 제공됐지만, 현재 Validation 단계에 생성된 `vevidence_*` ID가 아니다. `_validate_plan`이 현재 단계의 증거 ID만 허용해 이를 거부한 것은 저장 경계상 일관된다. Agent가 두 ID 공간을 혼동한 이유는 계획 입력·출력 계약에서 더 명확히 해야 한다. 중단도 실패한 단계와 Agent 계획을 trace에 남겨 재현할 수 있다.

계획이 실행된 `false_marker`는 추가 GET이 성공해도 assertion 하나가 실패하면 영향 점수를 올리지 않았다. `weak_marker`와 `no_action`도 추가 GET 없이 `UNDERPOWERED`를 유지했다. 이 세 사례는 근거가 없을 때 무조건 `CONFIRMED`하지 않는 동작을 보여준다. 다만 `false_marker`의 채점 결과는 단계 누락 때문에 전체 통과가 아니다.

## 실험 B: Blind Agent와 Impact Agent 모두 실제 실행

산출물: [`validation-transition-full-agent-v3`](../../../../result/test-runs/validation-candidates/validation-transition-full-agent-v3). 두 단계의 영향 축도 실제 Blind Agent가 판단했다. 기준 축과 달라져도 실험자가 점수를 보정하지 않았다.

| 시나리오 | 최초 판정·영향 축 | 두 번째 Blind 평가 → 최종 판정 | 실제 계획·관측 | 채점 |
| --- | --- | --- | --- | --- |
| `verified_marker` | `INCONCLUSIVE` | 두 번째 단계 없음 | 최초 `reproduced=null` | `BASELINE_NOT_UNDERPOWERED` |
| `minimal_threshold` | `UNDERPOWERED (0,0,2)` | `(1,1,2)` → `CONFIRMED (1,2,2)` | `execute`, 새 관측 성공 | `NON_CAUSAL_BASELINE` |
| `weak_marker` | `UNDERPOWERED (0,1,1)` | `(1,1,2)` → `CONFIRMED (1,1,2)` | `skip`, 추가 GET 없음 | `NON_CAUSAL_BASELINE` |
| `false_marker` | `CONFIRMED (1,1,2)` | 두 번째 단계 없음 | 개발 전 확정 | `BASELINE_NOT_UNDERPOWERED` |
| `no_action` | `UNDERPOWERED (1,0,2)` | `(0,0,1)` → `INCONCLUSIVE` | 실행 계약·추가 GET 없음 | `UNRESOLVED` |
| `partial_boundary` | `CONFIRMED (1,1,2)` | 두 번째 단계 없음 | 개발 전 확정 | `BASELINE_NOT_UNDERPOWERED` |

`minimal_threshold`는 최종 민감도가 2로 올랐지만, 두 번째 Blind 평가의 `(1,1,2)`는 이미 `CONFIRMED` 조건을 충족했다. 따라서 이번 `UNDERPOWERED → CONFIRMED`를 Development의 인과적 성과로 볼 수 없다. `weak_marker`는 Development를 건너뛰고도 두 번째 Blind 평가만으로 `CONFIRMED`가 됐다. 이 두 건은 판정의 재실행 간 변동을 드러내며, 개발 성공 건수에 포함하지 않는다. `false_marker`의 최초 `CONFIRMED`도 거짓 assertion의 성공이 아니라 해당 assertion을 실행하기 전 Blind 판정이다. `no_action`의 두 번째 평가에서는 재현·영향 판단이 낮아져 `INCONCLUSIVE`로 끝났다.

## 결론과 다음 개선 순서

이번 실제 Agent 전체 경로의 **인과적으로 입증된 `UNDERPOWERED → DEVELOPING → CONFIRMED`는 0건**이다. 통제된 계획·평가를 사용한 앞선 실행에서는 영향 보강으로 양성 2건이 `CONFIRMED`에 도달했으므로 실행 포트와 증거 연결 자체는 시험 가능하다. 실제 Agent 실험에서는 계획 증거 ID 오류와 Blind 평가 변동이 그 경로의 입증을 막았다.

1. **처리 단계 기록:** 일반 blocker 개발 경로의 `_develop`은 `developing`을 기록하지만 Impact 경로의 `_develop_impact`는 계획 시점에 여전히 `blind_replay`다. 실행 계약이 있거나 실제로 계획을 시작할 때 `developing`을 기록하고, 종료·건너뜀·실패 시 단계 이력을 검증할 수 있어야 한다. 실험 A에서 계획이 있었던 4건 모두 `blind_replay`였다.
2. **계획 증거 ID 계약:** `verified_attack_source_requests`의 `lab-source-*`와 현재 단계의 `vevidence_*`를 입력과 프롬프트에서 구분하고, 계획의 `evidence_ids` 허용 집합을 명시한다. 무결성 게이트는 유지한 채 실제 Agent가 유효한 ID만 인용하는지 재실험한다.
3. **Blind 평가의 재현성:** 동일한 GET 관측을 다시 평가할 때 축과 `reproduced`가 달라지는 원인을 추적한다. 판정 근거와 불확실성을 남기고, Impact 전후의 원래 Blind 축을 보존해 Development가 바꾼 축만 별도로 평가한다.
4. **인과 채점 유지:** 최종 `CONFIRMED`만 세지 않고 두 번째 Blind 평가의 개발 전 점수, Native GET, assertion, 새 증거 인용, 처리 단계까지 함께 확인한다. 음성 사례가 `CONFIRMED`가 되는 경로도 회귀 실험에 포함한다.

두 실험 폴더의 12개 DB 모두 SQLite 무결성 검사가 `ok`였다. `TransitionScore.json`은 사례별 상세 검사 결과이고 `TransitionTrace.json`은 실행 순서의 관측값이다. 이 보고서의 건수는 이 두 **이번 실행 폴더**만 집계한다. 계측이 부족하거나 동작을 바꿨던 이전 시험 폴더는 집계하지 않았다.

이후 코드 변경과 새 실행의 결과는 [리팩토링 후 재실험](VALIDATION_TRANSITION_REFACTOR.md)에 분리해 기록했다.
