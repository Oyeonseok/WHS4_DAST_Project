# Validation 상태 전이 실습 환경 (2026-09-25)

## 목적

약한 영향 근거에서 시작한 Validation이 Impact Development를 거쳐 판정을 올리는지, 그리고 근거가 부족하거나 실행 결과가 실패했을 때 확정 판정을 피하는지 검사한다. 이 실습은 기존의 [격리 후보 데이터 준비기](../../scripts/prepare_validation_lab.py)를 한 번 실행한 뒤 각 시나리오를 독립 `Pipeline.db`로 복제한다. Attack의 `confirmed` 주장은 실습을 위한 합성 입력이다. 원본 후보 DB·정답 DB는 수정하지 않는다.

준비기는 고정 로컬 Juice Shop과 VulnBank의 GET 관찰값, VulnBank `/debug/users` 응답 해시, 교육용 관리자 샘플을 담은 고정 소스 파일의 해시를 재확인한다. 비밀번호 값이나 전체 응답 본문은 저장하지 않는다. [정답지](../../resources/lab/validation-transition-answer-key.json)는 실습 DB와 별도 경로에 둔다.

## 시나리오

| 시나리오 | 통제 기준 영향 축 `(경계, 민감도, 요구 조건)` | 개발 조건 | 기대되는 최종 판정 |
| --- | --- | --- | --- |
| `verified_marker` | `(1,0,2)` | 검증된 소스 마커와 성공하는 JSON assertion | `CONFIRMED`, 축 `(1,2,2)` |
| `minimal_threshold` | `(1,0,0)` | 같은 마커, 합계 임계값을 막 넘는 축 | `CONFIRMED`, 축 `(1,2,0)` |
| `weak_marker` | `(1,0,2)` | 고유 마커 영수증 없음 | `UNDERPOWERED`, 계획 건너뜀 |
| `false_marker` | `(1,0,2)` | 새 GET에서 실패하는 추가 JSON assertion | `UNDERPOWERED`, 관측 실패 |
| `no_action` | `(1,0,2)` | 실행 계약 없음 | `UNDERPOWERED`, 개발 GET 없음 |
| `partial_boundary` | `(0,0,2)` | 마커 관측 후에도 경계 축이 0 | `UNDERPOWERED`, 민감도만 2로 상승 |

여섯 경우 모두 첫 실행은 Impact Development 포트 없이 수행해 `UNDERPOWERED` 기준 판정을 기록한다. 두 번째 실행은 같은 격리 DB를 재검증하며 실제 HTTP 재현과 Native Impact Development GET을 사용한다. `fixture` 평가 모드는 위 표의 최초 축을 고정하는 통제 입력이다. `fixture` 계획 모드는 고유 마커 조건에 따른 실행·건너뜀 결정을 고정한다. 두 모드는 Agent의 판단 품질을 입증하지 않는다. 실제 계획 판단을 보려면 `--planner-mode real`을 사용한다. `--assessment-mode real`은 최초 영향 축까지 실제 Blind Agent에 맡긴다. 그 경우 첫 판정이 `UNDERPOWERED`가 아니면 두 번째 실행을 시작하지 않고 그 사실을 기록한다.

현재 `minimal_threshold`와 `partial_boundary`는 **통제 fixture 전용**이다. 두 사례의 시작 축은 다른 네 사례와 다르지만, 준비된 공식 관찰·재현 계약·역할 조건은 같다. 준비기는 Impact 실행 전 Blind 입력과 Attack 출처 요청의 증거 해시를 `baseline_evidence_sha256`으로 기록한다. 동일한 시작 증거로 다른 축을 기대하는 두 사례에는 `real_axis_trial_ready=false`와 `shared_replay_evidence`를 남기고, 실행기는 실제 Blind 모드를 시작하기 전에 거부한다. 별도 공식 후보의 관찰값을 확보한 뒤에만 해당 모드를 열 수 있다. [정답지](../../resources/lab/validation-transition-answer-key.json)의 `real_agent_axis_trials`가 이 상태를 독립적으로 기록한다.

## 준비와 실행

기존 [로컬 기능 테스트 환경](LOCAL_FUNCTIONAL_LAB.md)의 두 앱을 실행한 뒤 저장소 루트에서 다음 명령을 사용한다. 준비기는 기존 출력 폴더를 덮어쓰지 않으며 `result/` 산출물은 Git에서 제외된다.

```bash
.venv/bin/python scripts/prepare_validation_transition_lab.py \
  --output result/test-runs/validation-candidates/validation-transition-next
.venv/bin/python scripts/run_validation_transition_lab.py \
  result/test-runs/validation-candidates/validation-transition-next verified_marker \
  --assessment-mode fixture --planner-mode real
.venv/bin/python scripts/score_validation_transition_lab.py \
  result/test-runs/validation-candidates/validation-transition-next verified_marker
```

다른 시나리오는 마지막 인자만 바꿔 **각각 한 번씩** 실행한다. `TransitionManifest.json`은 시나리오 선택과 통제 축을 담는다. 각 하위 폴더의 `Pipeline.db`, `TransitionTrace.json`, `TransitionScore.json`은 해당 경우의 재현 자료다. 재실행하려면 새 출력 이름으로 준비한다.

## 채점 기준과 현재 관측

채점기는 최초 단계의 Blind Assessment 증거와 정답지의 기준 축, 최신 DB 판정·영향 축·개발 가설 결과·현 단계 Native GET·새 증거 연결을 확인한다. 실행된 경우 계약 해시와 assertion별 성공·실패 원인도 검사한다. 로컬 HTTP 실행에서는 새 응답 해시가 준비 단계에서 확인한 응답 해시와 일치해야 한다. 테스트가 주입한 응답은 계약 assertion과 증거 연결을 검사한다. `DEVELOPING`은 최종 판정이 아닌 처리 단계이므로 실행 중 planner가 호출될 때의 `processing_phase`를 별도 스냅샷으로 기록한다. 현재 DB에는 재검증 전 최종 판정과 중간 처리 단계의 영구 상태 이력이 없으므로, 상태 전이의 시간 순서는 실행기의 스냅샷과 단계별 증거를 함께 읽어 판단한다.

`validation-transition-lab-v2` 통제 실행에서 두 양성 사례는 `UNDERPOWERED → CONFIRMED`, 네 부정 사례는 `UNDERPOWERED → UNDERPOWERED`였다. `verified_marker`, `minimal_threshold`, `false_marker`, `partial_boundary`는 계획 시점에 `processing_phase=blind_replay`가 관측됐다. 정답지는 이 네 사례를 `GAP_DEVELOPING_PHASE`로 표시한다. `weak_marker`와 `no_action`은 `PASS`였다. 이는 Impact Development가 실제 요청과 영향 보강은 수행하지만 현재 처리 단계에 `DEVELOPING`을 기록하지 않는다는 재현 가능한 차이를 드러낸다. 이 단계 전이를 구현·검증하는 작업은 별도로 남는다.

별도 `validation-transition-lab-real-smoke`의 `verified_marker`에서는 최초 축만 통제하고 Impact Development 계획은 실제 Agent가 만들었다. 결과는 `UNDERPOWERED → CONFIRMED`였으며, 정답지는 동일하게 `GAP_DEVELOPING_PHASE`를 기록했다. 다른 다섯 시나리오의 계획 판단은 위 통제 실행에서 고정된 입력으로 확인한 상태다.

이후 여섯 사례를 실제 Impact Agent 계획으로 실행하고, Blind Agent까지 실제로 실행한 여섯 사례를 별도로 재시험했다. 개발 전 Blind 평가를 기록해 최종 `CONFIRMED`의 인과성까지 구분한 결과는 [실험 보고서](../test-results/09.25/validation/VALIDATION_TRANSITION_EXPERIMENT.md)에 있다. 앞선 단일 smoke에는 이 개발 전 계측이 없어 인과적 성공 건수에 포함하지 않는다.

Impact 단계 기록·계획 인용 ID·동일 재현 결과의 Blind 점수 상승을 고친 뒤 새로 실행한 결과는 [리팩토링 후 재실험 보고서](../test-results/09.25/validation/VALIDATION_TRANSITION_REFACTOR.md)에 있다. 이전 실행 폴더의 저장된 점수는 당시 판정 기준을 기록한 것이므로 새 실행 결과와 섞어 집계하지 않는다.

### 증명 신호 후속 실습

현재 준비기는 여섯 양성 입력 DB에 비밀 값이 없는 `"password":` 필드 이름을 target 재현 assertion으로 사용한다. Impact 요청의 추가 assertion은 `ADMIN001`을 포함하므로 최초 증명과 개발 후 증명을 구분한다. 별도 `weak_source_signal` DB는 과거의 일반 문자열 `users` assertion을 보존하는 음성 대조군이며, Validation 실행 전에 `runtime_profile_semantics`로 거부되어야 한다. `TransitionManifest.json`의 `proof_negative_controls`와 [독립 정답지](../../resources/lab/validation-transition-answer-key.json)에 이 기대값이 있다.

`--assessment-mode real --planner-mode real`은 Blind와 Impact Agent를 실제로 실행한다. 이 모드에서도 실험 대상 밖인 Eligibility는 고정 fixture로 유지되며 선택값이 `TransitionTrace.json`에 기록된다. 로컬 서버가 없을 때 주입 HTTP 전송으로 계약과 단계 전이를 실험할 수 있지만, 이는 실시간 서버 연결 시험은 아니다. 실제 Blind Agent의 최초 축이 표의 통제 축과 다르면 채점기는 `BASELINE_AXIS_MISMATCH`로 기록한다. 상태 전이가 우연히 같아도 그 시나리오의 전제가 충족된 것으로 세지 않는다. 증명 신호 변경 후 결과는 [후속 보고서](../test-results/09.25/validation/VALIDATION_TRANSITION_REFACTOR.md#후속-작업-프로필-증명-신호와-실제-agent-재실험)에 있다.

`--assessment-mode real`은 현재 `verified_marker`, `weak_marker`, `false_marker`, `no_action` 네 사례에서만 준비돼 있다. `minimal_threshold`와 `partial_boundary`는 위의 증거 전제 검사 때문에 실제 Agent 모드에서 명시적인 오류를 반환한다. 이 제한은 과거 실행 결과를 다시 채점하거나 통제 fixture 실행을 막지 않는다.

### Development 진입 조건 (2026-09-25)

Impact Development는 Blind 평가가 재현 성공이며 영향이 `UNDERPOWERED`일 때만 검토한다. 선언된 사전 조건이 있는 경로는 신뢰된 검증기가 현재 후보의 실행 계약 해시, 경로, 모든 요구 조건, Attack 출처 요청 또는 현재 Validation 증거를 인용한 영수증을 생성해야 한다. 검증된 영수증을 현재 단계 증거로 저장하고 Agent 실행 계획이 해당 증거 ID를 인용해야 추가 요청을 보낸다. 영수증이 없거나 계약·인용이 맞지 않으면 계획과 요청을 건너뛰고 `UNDERPOWERED`를 유지한다. `weak_marker`는 이제 Agent 계획 전에 건너뛰는 음성 사례다.

현재 신뢰된 사전 조건 검증기는 VulnBank `/debug/users` 실습에만 연결돼 있다. 다른 Impact 경로에서 사전 조건을 선언했다면 전용 검증기를 구현·연결하기 전까지 새 개발 요청은 시작되지 않는다.

Blind 점수의 근거도 `hunt-source-leak`에 한해 검사한다. 양수 경계 축은 관측된 target과 효과가 없는 negative control을 모두 인용해야 하고, 양수 민감도·요구 조건 축은 관측된 target을 인용해야 한다. 부족한 축은 0으로 제한하며 Agent 원점수, 적용 점수, 제한 사유를 `blind_assessment_pre_impact`에 남긴다. 통제 fixture는 이 인용 조건을 만족하도록 구성했다. `minimal_threshold`와 `partial_boundary`의 서로 다른 시작 축은 여전히 동일한 재현 증거로 입증되지 않으므로 실제 Blind Agent 시험에는 사용하지 않는다.

`BLOCKED` 후보의 prerequisite Development는 이전 실행의 차단 유형, 액션 계약, Blind 입력, 현재 재현 응답, 범위, 정책, 출처 권한을 묶은 해시가 같으면 재시도하지 않는다. 이전 실행의 결과가 `outcome_unknown`이면 수동 검토가 필요한 `INCONCLUSIVE`로 끝낸다. 응답이나 계약 등 조건이 바뀌면 새 요청을 허용한다. 이 해시와 건너뜀 이유는 Validation DB에 남는다.

새 규칙의 실제 Impact Agent 양성·음성 실행은 [진입 조건 검증 기록](../test-results/09.25/validation/VALIDATION_TRANSITION_REFACTOR.md#development-진입-조건-강화-재검증)에 정리했다.
