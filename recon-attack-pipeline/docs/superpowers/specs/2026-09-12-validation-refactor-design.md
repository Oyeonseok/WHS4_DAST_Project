# Validation 재구조화 설계

- 상태: 승인됨
- 작성일: 2026-09-12
- 적용 대상: `recon-attack-pipeline`
- 기준 코드: `d3e4f70` (`origin/main`, native Attack/Chaining 통합 이후)
- 원안: `Validation_설계.pdf`

## 1. 문서 목적과 사용 순서

이 문서는 기존 오프라인 7 Question Gate를 실제 Blind 재현 기반 Validation 단계로 교체하기 위한 권위 있는 설계 명세다. 구현자는 다음 순서로 이 문서를 사용한다.

1. §2의 목표·비목표와 §3의 확정 결정을 구현 범위로 고정한다. 완료 조건은 기존 Validation.db나 정책 취약점 필터를 새 설계에 다시 도입하지 않는 것이다.
2. §4~§8의 계약에 맞춰 데이터 모델, 상태 머신, Blind 실행 경계를 구현한다. 완료 조건은 §13의 단위·통합 테스트가 각 불변식을 검증하는 것이다.
3. §9~§12의 Chaining, CLI, 복구, Report 연동을 구현한다. 완료 조건은 정상 파이프라인과 독립 Validation CLI가 같은 Coordinator를 사용하고, `CONFIRMED` 이외의 case에서 신규 보고서가 생성되지 않는 것이다.
4. 세부 작업 순서와 파일별 변경은 이 설계 승인 후 별도 implementation plan에서 정한다.

이 문서의 상태명과 판정 규칙이 유일한 정의다. Skill과 코드에서는 이 정의를 참조하며 별도의 상태 의미를 만들지 않는다.

## 2. 목표와 비목표

### 2.1 목표

- Attack이 생성한 Finding을 fresh 상태에서 재현하여 존재 여부와 실제 영향을 독립적으로 판단한다.
- 재현에 필요한 정보와 Attack의 해석을 분리하여 확증 편향을 줄인다.
- 단일 실패를 폐기하는 대신 실패 원인을 상태로 구분하고, 제한적으로 해결 가능한 전제조건만 보정한다.
- 기존 Attack Hunt Skill을 취약점 의미 지식으로 재사용하되 Validation의 실행 규칙은 코드가 강제한다.
- Recon, Attack, Chaining과 같은 `Pipeline.db`를 사용하면서 Validation의 쓰기 영역과 HTTP ledger를 분리한다.
- Finding과 demonstrated Chain을 검증하고 `CONFIRMED` 결과만 Report 입력으로 허용한다.
- `UNDERPOWERED` Finding은 부족한 영향 축과 후속 입증 방안을 구조화하되, 제안 자체를 검증 증거나 점수 상승으로 취급하지 않는다.
- 중단된 Validation stage를 기존 증거 손실 없이 재개할 수 있게 한다.

### 2.2 비목표

- Validation이 새로운 취약점, payload 계열 또는 chain을 탐색하지 않는다. 해당 책임은 Attack과 Chaining에 남는다.
- MVP에서는 취약점 클래스 제외 목록을 별도로 구조화하거나 Validation 전용 Policy Gate를 만들지 않는다.
- 상태 변경을 append-only event로 저장하지 않는다. 현재 case 상태만 유지하며 실제 attempt·evidence·request는 보존한다.
- 과거 별도 `Validation.db`를 shared DB로 자동 이관하거나 두 DB에 동시 기록하지 않는다.
- 다른 Pipeline.db 또는 다른 scan 사이에서 KNOWN을 검색하지 않는다.
- `CONTESTED`를 자동으로 반복 검증하거나 사람의 결정을 흉내 내지 않는다.
- 보고서를 외부 플랫폼에 자동 제출하지 않는다.

## 3. 원안에서 변경된 확정 결정

대화에서 승인된 다음 결정은 원안 PDF의 제안보다 우선한다.

1. 전용 Policy Precheck를 제거한다. Validation이 새 요청을 dispatch할 때 공통 Scope Guard를 적용하고, Candidate 단계에서는 출처 무결성과 KNOWN만 검사한다.
2. `OUT_OF_SCOPE`는 정상적인 1차 정책 필터 결과가 아니라 정책 변경, redirect, 개발 action 등 실제 Validation 요청이 현재 범위를 벗어날 때 사용하는 방어적 상태다.
3. `CONTESTED`는 단순한 Attack/Validation 불일치가 아니라 양쪽 모두 양성 근거가 있으면서 취약점 유형·권한 경계·민감한 영향의 해석이 충돌할 때만 사용한다.
4. `DEVELOPING`은 해결 가능한 blocker를 보정하는 비종결 상태다. UNDERPOWERED 증폭, 새 payload 탐색, 새 chain 생성에는 사용하지 않는다.
5. development cycle은 case당 한 번이며 action은 최대 2개다. 보정 후에는 기존 결과에 덧붙이지 않고 새 3회 배치를 시작한다.
6. 기존 Chaining 순서와 테이블은 변경하지 않는다. Validation은 Chaining 결과를 읽기만 하고 별도 Validation case로 재현한다.
7. Impact 축과 severity 구간은 §8의 승인된 기준을 사용한다. 이는 PDF의 잠정 점수표를 대체한다.
8. 신규 Validation과 Report는 shared `Pipeline.db` schema v9만 사용한다.
9. `UNDERPOWERED` Finding에는 제안 전용 ImpactGapAnalyzer를 실행한다. MVP는 영향 확장 가설을 저장할 뿐 추가 요청을 실행하거나 impact를 재평가하지 않는다.

## 4. 전체 아키텍처

### 4.1 파이프라인 순서

```text
Recon -> Attack -> Chaining -> Validation -> Report
```

Chaining이 `SKIPPED`여도 Attack Finding이 있으면 개별 Finding Validation은 실행한다. Attack에 검증 후보가 하나도 없을 때 Validation stage는 `skipped`로 종료한다.

### 4.2 Validation 데이터 흐름

```text
Attack/Chaining durable rows
        |
        v
CandidateIntegrityGate
        |
        v
KnownMatcher -----------------------> KNOWN
        |
        v
BlindCaseBuilder
        |
        v
Restricted Validation Agent
        |
        +--> target/control replay
        +--> evidence + blocker interpretation
        +--> bounded development request
        |
        v
Blind assessment frozen
        |
        v
AttackClaim reveal + semantic comparison
        |
        v
DecisionEngine + ImpactEvaluator
        |
        +--> UNDERPOWERED Finding: ImpactGapAnalyzer
             (analysis only, no dispatch)
        |
        v
validation_cases current snapshot
        |
        +--> CONFIRMED: Report eligible
        +--> CONTESTED: review bundle only
        +--> KNOWN: source case reference only
```

### 4.3 컴포넌트 책임

| 컴포넌트 | 단일 책임 | 의존성 |
|---|---|---|
| `ValidationCoordinator` | stage 시작·선택·재개, Agent 한도, case 격리, 최종 완료 검증 | Repository, Agent runner, DecisionEngine |
| `ValidationRepository` | Validation 테이블만 읽고 쓰는 트랜잭션 API | SQLite connection |
| `CandidateIntegrityGate` | Finding·attempt·Skill·reproduction spec 연결 검증 | shared DB 읽기 |
| `KnownMatcher` | 엄격한 2단계 KNOWN 판정 | confirmed validation cases |
| `BlindCaseBuilder` | 재현 입력과 숨길 Attack claim 분리·해시 | reproduction spec, credential refs |
| `SkillProfileResolver` | Attack Hunt Skill, Validation base Skill, machine profile 결합 | packaged skills/profiles |
| `ReproductionPort` | HTTP·browser·OOB 실행의 공통 추상화 | concrete adapters |
| `PrerequisiteResolverPort` | 승인된 development action을 실제 수행하고 결과를 구조화 | credential/state/transport/timing adapters |
| `ValidationRequestBroker` | 요청 scope·redirect·rate·credential 안전과 Validation ledger | shared request safety core |
| `Restricted Validation Agent` | 재현 수행, signal·blocker·impact 근거 제출 | staged BlindCase와 제한 helper |
| `DecisionEngine` | 횟수·control·blocker·상태 전이를 결정론적으로 판정 | structured observations |
| `ImpactEvaluator` | 증거에 묶인 세 축 점수와 severity 계산 | Skill profile, evidence IDs |
| `ImpactGapAnalyzer` | UNDERPOWERED Finding의 부족한 축과 후속 입증 가설을 구조화 | 현재 Validation evidence, Hunt Skill, machine profile |
| `ChainValidator` | 검증된 node를 전제로 demonstrated chain을 end-to-end 재현 | Chaining read model, ReproductionPort |

각 컴포넌트는 Protocol 또는 명시적 DTO 경계로 연결한다. Agent 응답, SQLite row, HTTP library 객체를 다른 계층에 직접 노출하지 않는다.

## 5. Attack에서 Validation으로 넘기는 계약

### 5.1 `finding_reproduction_specs`

Attack은 Finding을 확정하는 같은 트랜잭션 안에서 정확히 하나의 공식 reproduction spec을 생성한다. 필수 필드는 다음과 같다.

| 필드 | 요구사항 |
|---|---|
| `finding_id` | PK이자 `findings.finding_id` FK |
| `attack_skill_name` | 해당 Finding의 confirmed attempts에서 유일하게 결정된 Hunt Skill |
| `endpoint_id` | Finding과 같은 scan에 속한 endpoint |
| `method` | 정규화한 HTTP method |
| `endpoint_template` | path variable을 placeholder로 정규화한 endpoint |
| `injection_location` | `path`, `query`, `header`, `cookie`, `body` 중 하나 |
| `parameter_name` | 주입 대상의 안정적인 이름 |
| `payload_template_json` | 원래 기법을 보존하면서 runtime 값만 치환 가능한 template |
| `required_identity_roles_json` | 필요한 역할 이름. secret 값은 포함하지 않음 |
| `source_attempt_ids_json` | 같은 Finding에 연결된 confirmed attempt ID 목록 |
| `source_request_ids_json` | 위 attempts를 뒷받침하는 Attack request ID 목록 |
| `payload_structure_sha256` | 값 토큰을 제거한 payload 구조 해시 |
| `source_policy_sha256` | Attack 당시 승인된 TargetPolicy canonical digest |
| `runtime_contract_json` | 선택적인 target별 HTTP/browser/OOB 실행 계약. browser/OOB는 `runtime_kind`로 구분 |
| `runtime_contract_sha256` | 정규화된 runtime contract의 SHA-256. JSON과 함께 null이거나 함께 존재 |
| `spec_sha256` | canonical 필드 전체의 SHA-256 |
| `created_at` | 생성 시각 |

CandidateIntegrityGate는 아래 조건을 모두 확인한다.

- Attack stage와 해당 Finding이 durable하며 scan 관계가 일치한다.
- confirmed source attempt가 하나 이상 있고, 그 attempts에서 distinct `skill_name`이 정확히 하나다.
- `attack_skill_name`이 그 유일한 Skill과 일치하고 packaged AttackSkillLibrary에서 해시 검증을 통과한다.
- `source_request_ids_json`의 각 ID가 `attack_http_requests.request_id`를 가리키며 source attempt와 같은 task·fingerprint로 연결되고 endpoint·method가 spec과 모순되지 않는다.
- 모든 source Attack request의 `policy_sha256`이 reproduction spec의 `source_policy_sha256`과 일치한다. 현재 policy와 달라졌다는 사실만으로 기각하지 않고 실제 Validation 요청은 §10에서 현재 policy로 다시 검사한다.
- `spec_sha256`와 `payload_structure_sha256`이 현재 내용과 일치한다.
- runtime contract가 있으면 kind별 strict schema와 별도 SHA-256이 현재 내용과 일치한다.
- 필요한 역할을 현재 credential reference로 해석할 수 있다. 비밀값은 spec에 저장하지 않는다.

하나라도 실패하면 네트워크 요청을 보내지 않고 case를 `INCONCLUSIVE`로 종결하며 실패한 check 이름을 `decision_json`에 기록한다. 무결성 실패는 scope 판정이 아니므로 `OUT_OF_SCOPE`로 바꾸지 않는다.

HTTP contract는 기존 JSON 호환성을 위해 discriminator 없이 target/control의 request와
response assertion 구조로 저장한다. browser와 OOB 확장 contract는 각각
`runtime_kind='browser'`, `runtime_kind='oob'`를 필수로 둔다. browser observation은 선언한
selector, final URL, console marker와 browser request ledger ID만 반환한다. OOB contract는
attempt별 nonce를 trigger와 callback token에 함께 넣고 observer를 arm한 이후 발생한 동일
token·허용 protocol event만 인정한다.

### 5.2 Skill 구성

기존 `src/aidast/skills/attack/library/hunt-*/SKILL.md`는 수정하거나 복제하지 않고 취약점 의미·공격 메커니즘 참고자료로 로드한다. Validation Agent에는 다음 세 입력을 함께 제공한다.

1. 공통 Validation base Skill: Blind 규칙, evidence 인용, 출력 schema를 정의한다.
2. 연결된 Attack Hunt Skill: 취약점별 메커니즘과 관찰 의미를 제공한다.
3. `validation/profiles/<attack_skill_name>.json`: control, signal, timing baseline, impact mapping, 허용 development action과 영향 확장 경로를 기계 판독 형태로 정의한다.

profile 필수 키는 다음과 같다.

```json
{
  "schema_version": 1,
  "attack_skill_name": "hunt-example",
  "signal_types": ["response_diff"],
  "target_expected_signal": {},
  "control_positive": {
    "payload_template": {},
    "expected_signal": {},
    "signal_type": "response_diff"
  },
  "control_negative": {
    "payload_template": {},
    "expected_signal": {}
  },
  "baseline_samples": 3,
  "impact_rules": {},
  "allowed_development_actions": [],
  "impact_expansion_paths": []
}
```

`baseline_samples`는 timing 계열에서만 필수다. `impact_expansion_paths`의 각 항목은 stable `path_id`, 부족한 `gap_axis`, `hypothesis_kind`, 필요한 전제조건, 기대 signal, 권장 action, `execution_owner`를 정의한다. `execution_owner`는 `validation`, `chaining`, `manual` 중 하나이며 MVP에서는 분류 정보일 뿐 어느 경로도 자동 실행하지 않는다. 선택된 Hunt Skill의 profile이 없거나 이름·schema·해시가 맞지 않으면 해당 case는 `INCONCLUSIVE`다. 구현 완료 기준은 chain을 제외한 packaged Hunt Skill 각각에 정확히 하나의 유효 profile이 존재하는 것이다.

## 6. Blind 실행 경계

### 6.1 BlindCase에 보이는 정보

- endpoint와 method
- injection 위치와 parameter 이름
- payload template
- 필요한 identity 역할과 opaque credential reference
- profile이 허용한 signal과 control
- 선택된 Attack Hunt Skill과 Validation base Skill

실제 credential secret은 Agent에 노출하지 않는다. ValidationRequestBroker가 opaque reference를 현재 credential로 해석하고 dispatch 직전에 주입한다.

### 6.2 Blind assessment 전까지 숨기는 정보

- Attack verdict
- Attack claimed impact와 severity
- Attack 당시 캡처한 response 자체
- Attack Agent의 판정 설명

Coordinator는 숨길 `AttackClaim` DTO의 SHA-256을 replay 전에 case에 저장한다. Blind assessment가 schema 검증을 통과하고 `blind_assessment_sha256`으로 고정된 뒤에만 같은 Agent에게 claim 비교 단계가 열린다. Agent는 `aligned` 또는 `conflicting`과 evidence-bound 이유를 반환하며 최종 Validation 상태를 반환하지 않는다.

`AttackClaim`은 target kind와 ID, `vuln_class`, title, claimed impact description, claimed severity, 연결된 Attack evidence ID를 canonical object로 묶는다. Finding에서는 `findings`와 연결 evidence를, Chain에서는 `finding_chains`와 successful `chain_executions`를 사용한다. hash를 만든 뒤 원본 row가 달라지면 현재 실행을 계속하지 않고 concurrent state conflict로 stage를 실패시킨다.

### 6.3 제한 helper

Validation Agent는 shared DB 경로와 범용 SQL command를 받지 않는다. staged helper는 opaque case token을 사용하며 다음 명령만 제공한다.

- 현재 BlindCase 읽기
- target, positive control, negative control 실행
- 관찰과 evidence 제출
- blocker 진단 제출
- 허용된 development action 요청
- Blind assessment 확정
- claim 공개 이후 의미 비교 제출

각 명령은 현재 stage, case, batch, 횟수 한도를 다시 검증한다. 이 제한은 Agent prompt를 신뢰하기 위한 장치가 아니라 권한을 기술적으로 좁히기 위한 장치다.

### 6.4 Agent 출력 계약

Blind 단계의 `BlindAssessment`는 다음 정보만 포함한다.

- `case_id`, `blind_case_sha256`
- `reproduced`: `true`, `false`, `null`
- 관측한 `signal_types`, target/control attempt IDs, evidence IDs
- blocker 축과 evidence-bound 이유
- impact 세 축의 제안 점수, 각 축의 evidence IDs와 이유
- Blind 결론 설명

claim 공개 후의 `ClaimComparison`은 다음을 포함한다.

- `case_id`, `blind_assessment_sha256`, `attack_claim_sha256`
- `alignment`: `aligned` 또는 `conflicting`
- `conflict_axes`: `vuln_class`, `boundary`, `sensitivity`의 부분집합
- 양쪽 evidence ID에 묶인 이유

두 object 모두 extra field를 금지하며 Validation 최종 상태 field를 허용하지 않는다. Coordinator는 ID ownership, digest, enum, evidence 존재를 검증한 뒤 DecisionEngine에 전달한다.

## 7. shared Pipeline.db schema v9

기존 `stage_runs`에 `stage='validation'`을 사용한다. 별도 `validation_runs` 테이블은 만들지 않는다. 신규 테이블은 아래 일곱 개다.

기존 `attack_http_requests`에는 nullable `policy_sha256` column을 추가한다. v9에서 새로 실행되는 Attack request는 반드시 이 값을 기록하고, 새 reproduction spec은 모든 source request의 digest가 `source_policy_sha256`과 같은 경우에만 생성할 수 있다. migration 이전 request는 값이 null일 수 있지만 reproduction spec이 없으므로 새 Validation 입력으로 자동 승격하지 않는다. 최신 v9 계약은 Levenshtein 기반 KNOWN을 제거하며 이전 v9 DB의 `known_similarity` column도 case를 보존한 채 삭제한다.

### 7.1 `validation_cases`

Finding 또는 Chain 하나의 현재 Validation snapshot이다.

- `case_id` PK
- `scan_id` FK
- `target_kind`: `finding` 또는 `chain`
- `finding_id`, `chain_id`: 둘 중 정확히 하나만 non-null
- `latest_stage_run_id` FK
- `decision_stage_run_id` nullable FK: 현재 종결 snapshot을 생성한 stage
- `processing_phase`: `queued`, `blind_replay`, `developing`, `unblinding`, `completed`, `interrupted`
- `current_status`: 마지막으로 완료된 종결 상태 또는 null. 최초 판정 전까지만 null
- `state_version`: optimistic concurrency용 0 이상의 정수
- `attack_skill_name`, `skill_sha256`, `validation_profile_sha256`
- `source_policy_sha256`, `current_policy_sha256`
- `blind_case_sha256`, `blind_assessment_sha256`, `attack_claim_sha256`
- `known_source_case_id`
- `impact_boundary`, `impact_sensitivity`, `impact_actor_requirements`, `impact_score`, `severity`
- `decision_json`, `decision_sha256`: canonical JSON과 그 SHA-256
- `created_at`, `updated_at`

같은 scan의 같은 target에는 case가 하나만 존재한다. 재검증을 시작할 때 `latest_stage_run_id`와 `processing_phase='queued'`를 갱신하되, 새 판정이 완성될 때까지 직전 종결 snapshot은 유지한다. 이때 `decision_stage_run_id`는 직전 stage를 계속 가리킨다. CLI는 `current_status`, `processing_phase`, 두 stage ID를 함께 표시하여 직전 판정과 진행 중 재검증을 혼동하지 않게 한다. 새 판정은 한 transaction에서 current snapshot을 교체하고 `decision_stage_run_id=latest_stage_run_id`로 맞춘다. 이전 상태 전이와 decision snapshot은 복원하지 않지만 기존 attempts와 evidence는 삭제하지 않는다.

`decision_json`은 JSON-valid canonical object이고 `decision_sha256`은 저장 직전에 다시 계산한다. current snapshot을 바꾸는 update는 이전 `state_version`을 WHERE 조건에 포함해야 하며 영향받은 row가 정확히 하나가 아니면 concurrent state conflict로 처리한다.

### 7.2 `validation_attempts`

- `attempt_id` PK
- `case_id`, `stage_run_id` FK
- `batch_no`
- `attempt_kind`: `target`, `positive_control`, `negative_control`
- `ordinal`
- `signal_type`: §8.1의 enum
- `outcome`: `observed`, `not_observed`, `blocked`, `error`, `outcome_unknown`
- `signal_observed`
- `blocker_axis`: §8.3의 축 또는 null
- `observation_json`
- `started_at`, `finished_at`

`(case_id, stage_run_id, batch_no, attempt_kind, ordinal)`은 unique다. 완료된 attempt의 의미 필드는 불변이며 resume은 같은 unique key를 중복 실행하지 않는다.

### 7.3 `validation_evidence`

- `evidence_id` PK
- `case_id`, `stage_run_id` FK
- `attempt_id` nullable FK
- `development_action_id` nullable FK
- `evidence_kind`
- `details_json`: redacted·bounded evidence
- `content_sha256`, `content_length`
- `created_at`

실행 evidence는 `attempt_id` 또는 `development_action_id` 중 정확히 하나를 참조한다. Blind assessment나 claim comparison처럼 기존 evidence를 묶는 합성 record만 둘 다 null일 수 있으며 `evidence_kind`가 그 용도를 명시해야 한다. 모든 판정, blocker, impact 축은 같은 case와 현재 stage에서 생성된 evidence ID를 인용한다. 다른 case, Attack response 또는 존재하지 않는 ID를 인용하면 Coordinator가 거절한다.

### 7.4 `validation_development_actions`

- `action_id` PK
- `case_id`, `stage_run_id` FK
- `ordinal`: 1 또는 2
- `blocker_axis`
- `action_type`
- `status`: `planned`, `running`, `succeeded`, `failed`, `outcome_unknown`
- `details_json`
- `started_at`, `finished_at`

`(case_id, stage_run_id, ordinal)`은 unique다. 한 stage에서 action 2개를 초과하는 insert는 거절한다.

### 7.5 `validation_impact_hypotheses`

`UNDERPOWERED` Finding의 현재 증거에서 도출한 후속 입증 제안을 저장한다.

- `hypothesis_id` PK
- `case_id`, `stage_run_id` FK
- `ordinal`: case와 stage 안에서 1부터 시작하며 최대 3
- `gap_axis`: `boundary`, `sensitivity`, `actor_requirements`
- `path_id`, `hypothesis_kind`: 현재 Validation profile에 선언된 값
- `current_score`: 해당 축의 현재 검증 점수
- `reason_json`: 부족 판정의 evidence-bound 이유
- `required_preconditions_json`, `recommended_actions_json`
- `expected_signal_json`
- `supporting_evidence_ids_json`: 같은 case와 현재 stage의 Validation evidence만 허용
- `execution_owner`: `validation`, `chaining`, `manual`
- `feasibility`: `low`, `medium`, `high`
- `potential_impact_json`: 성공 시 예상 가능한 축 변화이며 비권위 정보
- `skill_sha256`, `validation_profile_sha256`
- `proposal_sha256`, `created_at`

`(case_id, stage_run_id, ordinal)`과 `(case_id, stage_run_id, path_id)`는 unique다. 가설은 Validation evidence가 아니며 `ImpactEvaluator`, `DecisionEngine`, Report eligibility의 입력으로 사용할 수 없다. `potential_impact_json`은 예상값일 뿐 현재 점수·severity·status를 변경하지 않는다. 가설 row와 advisory warning은 `decision_json` 및 `decision_sha256` 계산에서도 제외한다. JSON 내부 evidence ID와 profile path는 Coordinator가 저장 전에 검증한다.

### 7.6 `validation_http_requests`

기존 `attack_http_requests`와 같은 공통 safety 의미를 따르되 저장과 예산 계산은 Validation 전용이다.

- `request_id` PK
- `scan_id`, `stage_run_id`, `case_id`, nullable `attempt_id`, nullable `development_action_id` FK
- `policy_id`, `policy_sha256`
- `method`, `url`, `request_fingerprint`
- `status`: `reserved`, `running`, `completed`, `failed`, `outcome_unknown`
- `response_status`, `response_bytes`
- `result_json`, `error_message`
- `scheduled_at`, `dispatched_at`, `finished_at`, `created_at`

target/control 요청은 `attempt_id`, setup 등 보정 요청은 `development_action_id`를 참조하며 둘 중 정확히 하나만 non-null이다. header·cookie·token·민감 query value와 response 증거는 저장 전에 redaction한다. raw secret을 ledger나 Agent output에 넣지 않는다.

### 7.7 `finding_reproduction_specs`

§5.1의 Attack-to-Validation 계약을 저장한다. JSON 배열 내부 ID는 SQLite FK로 검증할 수 없으므로 CandidateIntegrityGate가 각 ID의 존재와 scan·finding 관계를 매 실행마다 확인한다.

### 7.8 상태 enum과 종결성

| 상태 | 종결 | 의미 |
|---|---:|---|
| `CONFIRMED` | 예 | 재현·control·impact·claim 비교 통과 |
| `DISPROVEN` | 예 | 비악용성이 명시적 증거로 입증됨 |
| `OUT_OF_SCOPE` | 예 | 실제 Validation 요청이 현재 policy 밖이라 dispatch하지 않음 |
| `KNOWN` | 예 | 엄격한 동일성 규칙으로 기존 confirmed case와 중복 |
| `UNDERPOWERED` | 예 | 신호는 재현됐지만 보안 영향이 보편 기준 미달 |
| `BLOCKED` | 예 | 해결 가능한 전제조건을 예산 내 해소하지 못함 |
| `INCONCLUSIVE` | 예 | 안정적이거나 충분한 증거를 얻지 못함 |
| `DEVELOPING` | 아니요 | `processing_phase='developing'`일 때 외부에 표시하는 effective status |
| `CONTESTED` | 예 | 양쪽 양성 근거의 핵심 의미가 충돌하여 사람 검토 필요 |

`DEVELOPING`은 terminal snapshot으로 저장하지 않고 processing phase에서 파생한다. Validation stage는 선택된 모든 case가 `processing_phase='completed'`, current status가 종결 상태, `decision_stage_run_id=latest_stage_run_id=현재 stage_run_id`일 때만 `completed`가 된다. 완료된 stage에 null·developing·이전 stage의 decision이 남아 있으면 lifecycle 검증이 완료를 거절한다.

## 8. 재현, control, 상태 판정

### 8.1 공통 signal enum

- `oob_callback`
- `response_diff`
- `error_signature`
- `timing`
- `dom_effect`
- `state_change`
- `authorization_boundary`

OOB는 가능한 signal 중 하나일 뿐 모든 취약점의 필수 조건이 아니다. profile이 선언한 signal만 해당 case의 양성 근거로 인정한다.

### 8.2 배치와 control 규칙

각 fresh batch는 target 3회와 profile이 정의한 positive·negative control로 구성한다. development 후 새 batch에서도 control을 다시 수행한다.

- positive control 실패: 탐지 채널 고장이므로 `INCONCLUSIVE`
- negative control에서 target과 같은 양성 signal: 오탐을 배제할 수 없으므로 `INCONCLUSIVE`
- timing signal: profile의 `baseline_samples`만큼 baseline을 측정하고 분산을 evidence로 남김
- target 3/3과 두 control 통과: impact와 claim 비교 경로 진입
- target 0/3: 명시적 반증, deterministic blocker, 원인 불명 순으로 분류
- target 1/3 또는 2/3: 결정적 blocker가 없으면 2회를 추가하며, 5회 결과가 혼재하면 `INCONCLUSIVE`

일반 불안정 경로의 target 상한은 5회다. 첫 3회에서 deterministic·resolvable blocker가 발견되면 추가 2회 대신 development cycle로 들어가며, 보정 후 독립된 새 3회 batch를 실행한다. 따라서 development를 사용한 case의 target 실행은 최대 6회이며 일반 5회 경로와 development 경로를 함께 사용하지 않는다.

`CONFIRMED` 경로는 최초 batch 또는 development 후 새 batch가 깨끗한 3/3일 때만 열린다. 3회 결과가 혼재한 뒤 추가한 5회 경로에서는 성공 개수가 많더라도 `CONFIRMED`하지 않는다.

### 8.3 BLOCKED와 DEVELOPING

| blocker 축 | 객관적 예시 | 허용되는 보정 |
|---|---|---|
| `identity_auth` | 401/403, 로그인 redirect, 만료 신호 | credential refresh |
| `state_setup` | 필요한 리소스 404, 빈 결과, no-op | 명세된 테스트 리소스 생성·초기화 |
| `encoding_transport` | 400/422, gateway 변형, 무해값과 동일 | profile이 허용한 encoding 변환과 payload-negation 확인 |
| `timing_concurrency` | rate-limit header, 세션 수명, 설명 가능한 간헐성 | profile이 허용한 간격·동시 실행 조정 |
| `environment_topology` | connection refused, 환경에서만 route 404 | 자동 변경 없음; `INCONCLUSIVE` |

Agent는 객관적 signal code와 evidence를 제출하고, blocker 축 판정은 허용 enum으로 제한한다. resolvable blocker가 발견되고 cycle을 아직 쓰지 않았다면 case는 `DEVELOPING`으로 전이한다.

- cycle은 case당 한 번이다.
- action은 최대 2개다.
- action은 profile allowlist 안에 있어야 한다.
- action 성공 후 새 3회 batch를 시작한다.
- 새 batch가 실패하거나 action 예산이 소진되면 `BLOCKED`다.
- topology 문제는 강행하지 않고 `INCONCLUSIVE`다.

### 8.4 DISPROVEN과 INCONCLUSIVE

`DISPROVEN`에는 sanitizer가 payload를 제거·무력화한 직접 관측, 요구한 권한 경계에서 일관된 401/403, 또는 target mechanism이 작동하지 않음을 보여주는 대조 evidence처럼 원인을 특정할 수 있는 반증이 필요하다. 단순 0/3, timeout, 5xx, 빈 응답, Agent 추측은 `INCONCLUSIVE`다.

### 8.5 CONTESTED

Blind 결과가 양성이고 Attack claim에도 양성 evidence가 있지만 아래 핵심 의미가 충돌할 때만 `CONTESTED`다.

- 실제 취약점 유형 또는 트리거 mechanism
- 넘은 권한·tenant·system 경계
- 민감 데이터 또는 상태 변화의 존재

숫자 점수나 severity band 차이만으로는 `CONTESTED`를 만들지 않는다. 현재 실행에서는 종결 상태이며 review bundle에 양쪽 claim과 evidence ID를 나란히 기록한다. 재검증은 사용자가 명시적으로 `validate run --finding-id`를 호출할 때 새 current snapshot으로 시작한다.

### 8.6 KNOWN

KNOWN 검색 범위는 같은 `Pipeline.db`와 같은 `scan_id`의 현재 `CONFIRMED` Finding case다.

1. `vuln_class`, normalized `endpoint_template`, HTTP method, `injection_location`, `parameter_name`, 정렬된 `required_identity_roles`, `attack_skill_name`이 모두 정확히 일치해야 한다.
2. 별도 `parameter_role` field가 없으므로 `(injection_location, parameter_name)` 조합을 parameter의 실행 역할로 사용한다.
3. source는 반드시 현재 `CONFIRMED`이며 `KNOWN`을 source로 연결하지 않는다.
4. source case에 저장된 Skill과 reproduction spec의 Skill이 일치해야 한다.
5. 여러 confirmed source가 통과하면 `case_id` lexical 순으로 하나를 선택하여 결과를 재현 가능하게 한다.

`signal_types`와 Validation profile hash는 중복 key에 포함하지 않는다. 이는 동일한 취약점을 어떤 관찰 채널과 control로 검증했는지를 나타내는 검증 방법의 속성이며, endpoint·trigger 위치·identity 조건으로 표현되는 대상의 정체성이 아니기 때문이다.

endpoint template은 Recon이 제공한 route parameter metadata만 placeholder로 치환한다. metadata가 없으면 normalized path를 그대로 사용하며 숫자·UUID처럼 보인다는 이유로 Validation이 path segment를 추측해 일반화하지 않는다.

payload canonicalization은 reproduction spec 무결성 검사를 위해 versioned `PayloadNormalizer`가 다음 순서로 수행한다.

1. `payload_template_json`을 key 정렬·최소 구분자의 canonical JSON으로 직렬화한다.
2. runtime placeholder를 타입을 보존하는 `<slot:type>` 토큰으로 치환한다.
3. 문자열 literal 내부는 보존하고 그 밖의 비의미 공백만 제거한 뒤 Unicode NFC로 정규화한다.
4. 결과 문자열과 UTF-8 bytes의 SHA-256을 저장한다.

canonical payload 문자열과 구조 hash는 KNOWN 판정에 사용하지 않는다. KNOWN이면 network replay를 생략하고 `known_source_case_id`, exact metadata `match_kind`, matcher version을 저장한다. payload의 semantic 동등성을 판단하는 LLM 단계는 이 변경 범위에 포함하지 않는다.

### 8.7 영향도와 UNDERPOWERED

각 축은 0~3이며 모든 축은 현재 Validation evidence ID를 인용한다.

| 축 | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Boundary | 경계 침해 없음 | 제한적 신뢰 경계 침해 | 사용자·역할 간 침해 | tenant·관리자·system 경계 침해 |
| Sensitivity | 보안상 의미 없음 | 낮은 민감도·경미한 효과 | 민감정보 또는 중요한 변경 | secret·계정 장악·코드 실행·대규모 영향 |
| Actor requirements | 비현실적 조건 또는 이미 높은 권한 | 특수 역할·복잡한 setup | 일반 저권한 계정 | 비인증 원격 공격자 |

```text
impact_score = boundary + sensitivity + actor_requirements
```

| 합계 | Severity |
|---:|---|
| 0~2 | `INFO` |
| 3~4 | `LOW` |
| 5~6 | `MEDIUM` |
| 7~8 | `HIGH` |
| 9 | `CRITICAL` |

신호가 재현됐더라도 다음 predicate 중 하나가 참이면 `UNDERPOWERED`다.

```text
boundary == 0 OR sensitivity == 0 OR impact_score < 3
```

Skill profile은 각 점수를 인정할 취약점별 evidence 기준을 정의한다. 코드는 enum, evidence ownership, 축 범위, 합계, severity 구간과 UNDERPOWERED predicate를 강제한다. Validation 점수가 Attack과 다르면 Validation evidence로 계산한 severity를 사용한다.

Finding이 `UNDERPOWERED` predicate를 만족하면 current snapshot을 종결하기 전에 `ImpactGapAnalyzer`를 한 번 실행한다. Analyzer는 현재 stage의 Validation evidence, 연결된 Hunt Skill, 검증된 profile의 `impact_expansion_paths`만 입력으로 받으며 Attack 당시 response 원문이나 범용 DB·요청 helper를 받지 않는다. 다음 규칙을 모두 적용한다.

1. 점수가 부족한 축마다 profile에 선언된 path만 후보로 만들며 case당 최대 3개로 제한한다.
2. 각 후보는 현재 점수가 부족한 evidence-bound 이유, 필요한 전제조건, 권장 action, 기대 signal과 실행 담당을 포함한다.
3. 같은 endpoint와 취약점 범위에서 향후 안전하게 입증할 수 있는 후보는 `validation`, 여러 Finding·단계의 결합이 필요한 후보는 `chaining`, 파괴적이거나 사람의 승인이 필요한 후보는 `manual`로 분류한다.
4. Agent가 profile 밖의 path, 존재하지 않는 evidence, 허용되지 않은 enum을 반환하면 해당 후보만 버린다. 유효 후보가 없어도 case 판정은 `UNDERPOWERED`로 정상 완료한다.
5. MVP에서 Analyzer는 네트워크 요청, credential 사용, development action, 새 payload 탐색을 수행하지 않는다.
6. 저장된 가설은 설명과 후속 작업 입력일 뿐 증거가 아니다. 가설 존재 여부와 예상 점수는 현재 impact, severity, `UNDERPOWERED` 판정을 바꾸지 않는다.

예를 들어 IDOR가 자신의 객체에 대한 반응 차이만 재현해 Boundary 0이라면, `cross_role_access` path는 보조 저권한 계정과 그 계정 소유 객체를 전제조건으로, 타 사용자 고유 데이터 반환을 기대 signal로 제안할 수 있다. 이 제안을 아직 실행하지 않았으므로 현재 점수는 그대로이며 case도 `UNDERPOWERED`다.

### 8.8 최종 판정 우선순위

DecisionEngine은 아래 순서를 고정하여 하나의 case가 여러 상태 조건을 동시에 만족하지 않게 한다.

1. Candidate 무결성 실패: `INCONCLUSIVE`
2. KNOWN 실행 메타데이터 exact match 통과: `KNOWN`
3. dispatch가 current policy에 거절됨: `OUT_OF_SCOPE`
4. control 실패 또는 모순: `INCONCLUSIVE`
5. 명시적 비악용 증거: `DISPROVEN`
6. topology 또는 원인 불명: `INCONCLUSIVE`
7. resolvable blocker: `DEVELOPING`을 거쳐 성공 시 새 batch 평가, 실패 시 `BLOCKED`
8. 불안정 5회 결과: `INCONCLUSIVE`
9. 깨끗한 3/3 이후 evidence-backed 핵심 claim 충돌: `CONTESTED`
10. 깨끗한 3/3 이후 UNDERPOWERED predicate 충족: Finding은 유효한 영향 확장 가설을 최대 3개 저장한 뒤 `UNDERPOWERED`; Chain은 바로 `UNDERPOWERED`
11. 깨끗한 3/3, control 통과, claim 정렬, 충분한 impact: `CONFIRMED`

9번은 Attack claim에도 연결된 양성 evidence가 있을 때만 적용한다. 단순 severity 숫자 차이는 9번 조건이 아니며 Validation severity를 채택하여 10번 또는 11번으로 진행한다.

## 9. Chaining 연동

기존 순서 `Attack -> Chaining`과 Chaining write model은 변경하지 않는다. Validation은 `finding_chains`, node, candidate, execution, binding, evidence를 읽기만 한다.

1. 개별 Finding case를 먼저 종결한다.
2. demonstrated chain의 모든 node가 `CONFIRMED` 또는 `KNOWN`일 때만 end-to-end Blind chain replay를 수행한다.
3. chain의 target signal은 마지막 단계에서 실제로 도달한 terminal impact다.
4. chain impact는 node 점수를 합산하지 않고 terminal effect를 §8.7의 세 축으로 새로 평가한다.
5. Validation 결과는 chain용 `validation_cases`와 Validation evidence 테이블에만 기록한다.

node gate에서 replay를 생략할 때 chain 상태는 다음과 같이 결정한다.

- node에 `DISPROVEN` 존재: `DISPROVEN`
- node에 `OUT_OF_SCOPE` 존재: `OUT_OF_SCOPE`
- node에 `BLOCKED` 존재: `BLOCKED`
- node에 `CONTESTED`, `UNDERPOWERED`, `INCONCLUSIVE` 존재: `INCONCLUSIVE`

Validation은 chain node, edge, binding 또는 기존 execution status를 수정하지 않는다. 이 불변식은 팀원이 완료한 Chaining 구현과의 독립성을 보장한다.

개별 Finding의 영향 확장 가설이 `execution_owner='chaining'`이어도 MVP Validation은 새 chain candidate를 생성하거나 기존 Chaining 테이블을 수정하지 않는다. 이 값은 후속 연동을 위한 분류이며 현재는 CLI status에서만 노출한다.

## 10. 요청 안전 경계

Attack과 Validation은 scope, redirect, method, rate, concurrency, credential 처리를 제공하는 공통 request safety core를 사용한다. stage별 차이는 adapter가 담당한다.

- Attack adapter는 `attack_http_requests`에 기록한다.
- Validation adapter는 `validation_http_requests`에 기록한다.

두 adapter는 실행에 사용한 canonical TargetPolicy SHA-256을 각 request row에 기록한다. reproduction spec의 source policy digest는 연결된 Attack request rows로 검증한다.

ValidationRequestBroker는 모든 최초 요청과 redirect를 dispatch 직전에 현재 TargetPolicy로 다시 검사한다. 거절된 요청은 전송하지 않고 case를 `OUT_OF_SCOPE`로 종결한다. 이는 별도 정책 판정 단계가 아니라 새 네트워크 행위에 대한 필수 실행 안전장치다.

Agent는 reproduction spec의 endpoint·method·injection location과 profile의 control/development 범위를 넓힐 수 없다. 요청 fingerprint, budget reservation, credential injection은 trusted broker가 수행한다.

## 11. Coordinator, CLI와 자동 실행

### 11.1 Agent topology

CandidateIntegrityGate와 KnownMatcher 이후 replay가 필요한 case가 하나 이상일 때 native custom Validation Agent를 정확히 하나 생성하고 해당 cases를 순차 처리한다. 모든 case가 network 전 단계에서 종결되면 Agent를 생성하지 않는다. Agent는 staged case만 보고 범용 DB 접근 권한을 받지 않는다. Coordinator는 case 사이에서 Blind 입력을 교체하고 각 case의 결과를 즉시 검증·저장한다.

Agent가 제출한 case object가 schema 검증에 실패하면 Coordinator는 오류 필드만 알려 한 번 수정 기회를 준다. 두 번째 제출도 실패하면 해당 case를 `INCONCLUSIVE`로 종결하고 다음 case를 계속한다. Agent 프로세스 자체가 종료되거나 이후 case를 처리할 수 없으면 §12.2의 stage 실패다.

유효한 BlindAssessment와 ClaimComparison이 이미 고정된 뒤 수행하는 ImpactGapAnalyzer는 비판정성 advisory pass다. 이 pass의 schema 오류, profile에 맞는 후보 부재 또는 생성 실패는 운영 log에 warning을 남기고 가설 없이 `UNDERPOWERED`를 확정한다. 기존 판정 입력이 완성됐으므로 advisory 실패만으로 case를 `INCONCLUSIVE`로 낮추거나 stage를 실패시키지 않는다.

Coordinator의 외부 결과 DTO는 `ValidationStageResult`이며 `stage='VALIDATION'`, `status`, `scan_id`, `db_path`, `stage_run_id`, 선택된 `case_ids`, `validation_agent_ids`, 요약을 포함한다. `validation_agent_ids`는 replay가 없으면 빈 배열, 있으면 정확히 한 항목이다. `status`와 case ID 목록은 Agent가 주장한 값이 아니라 durable DB를 다시 조회해 구성한다.

### 11.2 CLI 계약

정상 파이프라인과 독립 CLI는 같은 `ValidationCoordinator`를 호출한다.

```bash
aidast validate run Pipeline.db --scan-id <scan_id>
aidast validate run Pipeline.db --scan-id <scan_id> --finding-id <finding_id>
aidast validate run Pipeline.db --scan-id <scan_id> --chain-id <chain_id>
aidast validate resume Pipeline.db --stage-run-id <stage_run_id>
aidast validate status Pipeline.db --scan-id <scan_id>
aidast validate status Pipeline.db --case-id <case_id>
```

`--finding-id`와 `--chain-id`는 상호 배타적이다. 같은 scan에는 active Validation stage를 하나만 허용한다. 정상 pipeline 명령은 Chaining 종료 후 `run`과 같은 Coordinator API를 자동 호출한다.

`validate status --case-id`는 `UNDERPOWERED` Finding에서 현재 세 축 점수와 함께 영향 확장 가설을 ordinal 순서로 표시한다. 각 가설은 부족한 축, 전제조건, 기대 signal, 권장 action, 실행 담당과 예상 영향임을 명시하며 실제 검증 결과처럼 표현하지 않는다. scan 단위 status는 가설 개수와 실행 담당별 개수만 요약한다.

### 11.3 재검증

targeted run은 같은 target의 기존 `validation_cases` 행을 재사용한다. 실행 시작 시 `latest_stage_run_id`, `processing_phase`, `state_version`만 바꾸고 직전 종결 snapshot은 새 판정 commit까지 유지한다. 과거 attempts·evidence·request는 유지하지만 과거 최종 상태를 별도 history로 제공하지 않는다.

`CONFIRMED` source case의 재검증이 끝나 새 상태가 `CONFIRMED`가 아니면, 그 case를 가리키는 현재 `KNOWN` cases를 같은 transaction에서 `INCONCLUSIVE`로 바꾸고 이유를 `known_source_no_longer_confirmed`로 기록한다. source가 재검증 중일 때는 새 KNOWN 판정과 source 기반 Report 생성을 보류한다. 이 규칙으로 모든 완료 snapshot에서 `KNOWN -> CONFIRMED` 직접 참조 불변식을 유지한다.

## 12. 실패, resume과 Report

### 12.1 case 격리

입력 누락, control 실패, 증거 부족, blocker 등 도메인 실패는 해당 case의 종결 상태로 저장하고 다음 case를 계속 처리한다. 선택한 모든 case가 종결되면 결과에 `DISPROVEN`·`INCONCLUSIVE` 등이 포함되어도 stage는 `completed`다.

### 12.2 stage 실패

아래처럼 이후 case를 신뢰성 있게 실행할 수 없는 오류만 stage를 `failed`로 만든다.

- DB schema·transaction 오류
- Coordinator invariant 위반 또는 concurrent state conflict
- Validation Agent 프로세스 전체 중단
- Request Broker 고장

stage 실패 시 이미 종결된 case와 증거는 유지한다. `reserved` 또는 `running` 요청·action은 `outcome_unknown`, 처리 중 case는 `interrupted`로 정리하고 CLI는 non-zero로 종료한다. Recon·Attack·Chaining row는 수정하지 않는다.

`resume`은 Validation 전용 `resume_stage_run` lifecycle operation으로 원래 `failed` stage를 같은 `stage_run_id`의 `running` 상태로 되돌린다. 이 operation은 `stage='validation'`, 현재 `status='failed'`, 같은 scan에 다른 active Validation stage가 없음, 재개할 `queued` 또는 `interrupted` case가 존재함을 한 transaction에서 확인하고 audit event를 남긴다. `finished_at`과 active error field는 비우되 이전 실패 원인은 audit event에 보존한다.

재개 후에는 원래 stage의 selected cases에서 `queued` 또는 `interrupted`인 case만 계속하며, 완료된 attempt unique key를 다시 실행하지 않는다. Blind assessment가 이미 고정됐다면 replay하지 않고 unblind 단계부터 이어간다. 모든 selected cases가 종결된 뒤 같은 stage를 `completed`로 마친다.

### 12.3 Report 전환

기존 별도 `Validation.db`와 7 Question assessment reader를 제거하고 Report는 shared Pipeline.db의 case와 evidence를 읽는다.

```bash
aidast report run Pipeline.db --case-id <case_id> --platform <platform> [--output-dir <dir>]
```

- `CONFIRMED`: `processing_phase='completed'`이고 `decision_stage_run_id=latest_stage_run_id`일 때만 신규 보고서 생성 가능
- `KNOWN`: 신규 보고서를 만들지 않고 `known_source_case_id`를 반환. source report가 없으면 source case로 실행하도록 안내
- `CONTESTED`: 제출용 보고서 대신 Validation status의 review bundle만 제공
- 그 밖의 상태와 `DEVELOPING`: 보고서 생성 거절

confirmed demonstrated Chain case는 chain 전체를 하나의 보고서로 만들 수 있다. Report artifact와 기존 `Report.db`의 독립적인 출력·무결성 검증은 유지하되 source binding을 `validation_id` 대신 `scan_id`, `case_id`, `decision_sha256`, 정렬된 evidence hashes로 바꾼다.

Pipeline.db는 이후 재검증으로 변경될 수 있으므로 Report는 DB 파일 전체 hash나 WAL sidecar 부재를 요구하지 않는다. read-only snapshot transaction에서 schema, case 상태, decision hash, evidence ownership과 evidence hash를 검증한 뒤 source bundle을 Report.db에 복사한다. 이후 `report status`에서 Pipeline.db의 current decision hash가 달라졌다면 저장된 보고서 자체는 보존하되 `stale`로 표시하여 현재 검증 결과인 것처럼 사용하지 못하게 한다.

## 13. Migration, 테스트와 수용 기준

### 13.1 Migration

- `migrate_pipeline_schema`는 기존 row를 재구축하지 않고 `attack_http_requests.policy_sha256`과 Validation 테이블·index·trigger를 생성한 후 `user_version`이 8 이하일 때 9로 올린다.
- 미래 schema version은 기존 규칙대로 낮추지 않는다.
- 기존 Pipeline.db의 Recon, Attack, Chaining row와 FK가 migration 전후 동일해야 한다.
- 별도 Validation.db v1은 자동 import하지 않고 새 CLI 입력으로도 허용하지 않는다.
- 기존 `aidast.validation`의 7 Question model/store와 관련 package skill은 새 계약으로 교체한다.

### 13.2 필수 테스트

| 영역 | 검증해야 하는 관찰 가능한 결과 |
|---|---|
| Schema migration | v8 fixture가 v9가 되고 이전 v9의 `known_similarity`가 제거되며 기존 row·FK 보존과 재실행 idempotency 검증 |
| Reproduction spec | Finding과 atomic 생성되고 잘못된 scan·attempt·request·hash가 거절됨 |
| Skill binding | distinct confirmed Skill이 0개 또는 2개 이상이면 요청 없이 INCONCLUSIVE |
| Profile coverage | chain 제외 모든 packaged Hunt Skill에 유효 profile이 정확히 하나 존재 |
| Blind boundary | staged input과 Agent prompt에 숨김 필드·Attack response·DB path가 없음; replay가 없으면 Agent ID가 비어 있음 |
| Restricted helper | 허용하지 않은 command, target, method, 횟수, evidence ID가 거절됨 |
| KNOWN | 취약점·요청·identity·Hunt Skill exact match, current source 검증, deterministic tie-break 검증 |
| Controls | positive 실패와 negative false signal이 각각 INCONCLUSIVE |
| Retry | 3/3, 0/3, mixed->5, development->fresh 3의 모든 전이 검증 |
| Development | cycle 1회·action 2개 제한과 topology INCONCLUSIVE 검증 |
| Impact | evidence ownership, 점수 합계, severity 경계, UNDERPOWERED predicate 검증 |
| Impact gap | UNDERPOWERED Finding에서만 profile path·동일 stage evidence·최대 3개 제한을 검증하고, 후보 오류·부재가 판정과 점수를 바꾸지 않음 |
| CONTESTED | 단순 점수 차이는 제외하고 evidence-backed semantic conflict만 허용 |
| Request safety | 최초·redirect scope, rate/concurrency, credential redaction, 분리 ledger 검증 |
| Chain | node gate, read-only Chaining tables, terminal impact 재평가 검증 |
| Failure/resume | outcome_unknown 정리, 완료 시도 비중복, Validation-only failed->running 전이와 stage 복구 검증 |
| CLI/pipeline | 자동 실행과 run/resume/status/targeted run이 같은 Coordinator 사용 |
| Report | CONFIRMED만 신규 생성, KNOWN redirect, CONTESTED review-only, source snapshot 변경 시 stale 검증 |

외부 네트워크 없이 상태 머신 전체를 검증하도록 fake `ReproductionPort`, fake credential resolver, fake Agent runner를 제공한다. 실제 HTTP/browser/OOB adapter 테스트는 local test server와 deterministic callback fixture만 사용한다.

### 13.3 수용 기준

구현은 아래 조건을 모두 충족할 때 완료다.

1. `Recon -> Attack -> Chaining -> Validation`이 한 Pipeline.db에서 끝나고 Validation stage에 비종결 case가 남지 않는다.
2. Agent가 Attack claim이나 기존 response를 Blind assessment 고정 전에 얻는 경로가 테스트로 차단된다.
3. 같은 입력과 evidence에서 DecisionEngine, KnownMatcher, ImpactEvaluator가 항상 같은 결과를 만든다.
4. 모든 실제 Validation 요청이 current TargetPolicy 검사와 Validation ledger reservation을 통과한다.
5. 일반 재현은 target 최대 5회, development 경로는 1 cycle·2 actions·새 target 3회 한도를 넘지 않는다.
6. Validation이 Chaining write table을 수정하지 않는다.
7. stage crash 후 resume이 완료된 시도나 보고서를 중복 생성하지 않는다.
8. `CONFIRMED`가 아닌 case에서 신규 제출용 보고서 생성이 불가능하다.
9. 기존 Recon·Attack·Chaining 테스트와 신규 Validation·Report 테스트가 모두 통과한다.
10. `UNDERPOWERED` Finding의 유효한 영향 확장 가설이 status에서 조회되며, 어떤 가설도 요청을 dispatch하거나 current impact·severity·status·decision hash를 변경하지 않는다.

## 14. 구현 분할 원칙

상세 implementation plan은 다음 dependency 순서로 작업을 나눈다.

1. schema v9와 reproduction spec 계약
2. DTO, Repository, KnownMatcher, DecisionEngine, ImpactEvaluator, ImpactGapAnalyzer
3. 공통 request safety core 추출과 Validation ledger adapter
4. ReproductionPort와 fake/real adapters
5. Validation base Skill, per-Hunt profiles, restricted helper
6. native Agent staging과 ValidationCoordinator
7. demonstrated Chain validation
8. CLI 자동 실행·targeted run·resume·status
9. shared DB 기반 Report와 legacy Validation 제거
10. 전체 회귀·실패 복구·보안 경계 검증

각 단계는 해당 테스트가 먼저 실패하고 구현 후 통과하는 독립적인 vertical slice로 구성한다. 한 단계가 다음 단계의 공개 계약을 변경해야 한다면 코드보다 이 설계와 implementation plan을 먼저 갱신한다.
