# Validation 재구조화 구현 계획 — 데이터 무결성과 보고서 연동

- 작성일: 2026-09-12
- 상태: 실행 계층 1차 연결 진행 중
- 기준 명세: [Validation 재구조화 설계](../specs/2026-09-12-validation-refactor-design.md)
- 대상: `recon-attack-pipeline`
- 구현 여부: shared DB v9, DTO, 결정론적 판정, Repository, 복구, Report v2,
  status CLI에 이어 Candidate gate, profile resolver, injected Coordinator,
  ReproductionPort와 Validation request ledger의 1차 실행 경로, 완료 batch 및
  고정 BlindAssessment 이후의 실행 재개가 구현됐다.
  demonstrated Chain의 injected end-to-end Blind replay도 구현됐다.
  native 단일 Codex session도 tool-disabled lazy runner로 연결됐다.
  real 취약점별 adapter·pipeline 자동 실행은 미구현이다.

## 구현 진행 기록

현재 구현된 범위는 다음과 같다.

- `src/aidast/pipeline/schema.py`: shared Pipeline.db schema v9와 Validation 7개 테이블, active stage·target·ordinal·append-only 제약, Attack request policy digest.
- `src/aidast/validation/models.py`: BlindAssessment, ClaimComparison, case snapshot, stage result와 canonical digest 계약.
- `src/aidast/validation/{matching,impact,decision}.py`: 임베딩 없는 Levenshtein KNOWN 판정, 영향 점수와 우선순위 상태 판정.
- `src/aidast/validation/repository.py`: case·stage·evidence 소유권, 낙관적 동시성, snapshot commit과 KNOWN source 무효화.
- `src/aidast/pipeline/lifecycle.py`: Validation 실패 record 정리와 동일 stage 복구.
- `src/aidast/validation/evidence_policy.py`: 중첩 JSON의 민감 필드와 헤더 형태 문자열 제거, raw body/header 필드 제외, 깊이·컨테이너 크기·전체 노드 수·UTF-8 바이트 제한.
- `src/aidast/validation/source.py`: 기존 오프라인 reader에 연결. 안전한 형식이나 예산을 벗어나는 메타데이터는 원문 대신 생략 안내를 반환한다.
- `src/aidast/reporting/case_runtime.py`: 현재 CONFIRMED case의 read-only source snapshot, Report.db v2, KNOWN redirect, CONTESTED review-only, stale 판정.
- `src/aidast/validation/status.py`, `src/aidast/cli.py`: scan/case status와 `report run Pipeline.db --case-id`.
- `src/aidast/validation/{integrity,profiles}.py`: Attack reproduction spec의
  provenance gate와 packaged Hunt Skill 58개 profile coverage 검증.
- `src/aidast/validation/{coordinator,reproduction}.py`: injected 실행 포트 기반
  case 선택, control/target batch, 제한된 retry/development, Blind/unblind와 durable
  case 격리.
- `src/aidast/validation/{request_broker,http_adapter,policy}.py`: current policy를
  매 hop 재검사하는 Validation ledger 및 실제 transport adapter 계약.
- `src/aidast/validation/gaps.py`: profile과 현재 evidence에 제한된 비실행
  impact expansion proposal.
- `src/aidast/attack/db_cli.py`: native Finding과 reproduction spec의 원자적 producer.

패턴 기반 제거는 이름이나 문맥이 없는 임의의 비밀값을 식별한다고 보장하지 않는다. 기존 source에서 공개 context가 달라지면 기존 digest 검증이 이를 감지할 수 있으며, 저장된 과거 결과를 자동으로 재작성하지 않는다.

ReproductionPort, request broker/ledger, profile 파일 전체와 injected Coordinator는
구현됐다. completed node만 허용하는 demonstrated Chain replay도 같은 Coordinator에
연결됐다. native Validation runner는 `gpt-5.6-sol`의 동일 thread를 Blind/unblind
pass와 case 사이에 유지한다. 다만 profile 대부분은 보수적인 공통 초안이며
취약점별 real adapter와 pipeline 자동 실행은 아직 구현되지 않았다.
Blind claim 공개 시점은 Coordinator가 assessment digest를 먼저 고정하도록 연결됐다.

검증 명령은 macOS의 심볼릭 링크 임시 경로 문제를 피하도록 실제 경로를 지정한다.

```bash
TMPDIR=/private/tmp PYTHONPATH=src:tests .venv/bin/python -m unittest test_validation_evidence_policy test_validation_agent test_validation_store test_validation_report_cli -q
```

최종 관련 unittest 53개와 기존 pytest 보고서 테스트 31개가 통과했다. 전체 unittest는 330개를 실행했으며 코드 테스트는 통과했고 `.venv`에 pytest가 없어 `test_reporting_agent` import 한 건만 실패했다. 이후 추가한 두 migration/Blind 테스트는 관련 suite에서 통과했다. 시스템 pytest는 plugin autoload를 끄고 별도로 실행해 31개가 통과했다.

## 1. 범위와 완료의 의미

이 계획은 명세의 shared DB, 증거 무결성, 정보 접근 제한, 상태 보존, Report eligibility를 구현 가능한 작업으로 나눈다. 각 작업에는 수정 대상, 검증 방법, 완료 조건을 함께 둔다.

자율 취약점 재현을 가능하게 하는 취약점별 payload/control profile 작성, 실제 재현 adapter, native Agent 연결 및 영향 확장 기법 생성은 이 계획에 포함하지 않는다. 재시도·전제조건 보정과 end-to-end chain 상태 머신은 injected port 및 저장된 fixture까지 범위를 확장해 구현했다. 실제 transport 결과가 필요한 검증은 합성 DTO와 저장된 테스트 fixture로 수행한다. 따라서 이 계획을 모두 완료해도 원 명세 §13.3 전체가 구현됐다고 표시할 수 없다.

기준 명세의 상태와 계약은 그대로 참조한다. 범위에서 제외된 기능을 임의의 성공 반환이나 `CONFIRMED` 기본값으로 대체하지 않는다. 실제 실행이 연결되기 전에는 신규 실행 CLI와 자동 pipeline 연결을 완료 기능으로 공개하지 않는다.

## 2. 현재 코드와 변경 지점

아래 경로는 저장소 루트 기준이다. 신규 파일은 제안이며 기존 파일과 구분한다.

| 영역 | 현재 코드 | 계획상 변경 |
|---|---|---|
| 공유 DB | `src/aidast/pipeline/schema.py` | v9 저장 계약과 무결성 제약 |
| Stage lifecycle | `src/aidast/pipeline/lifecycle.py` | Validation 복구의 트랜잭션·감사 기록 |
| Validation DTO | `src/aidast/validation/models.py` | 기존 Question 기반 모델과 새 계약의 전환 준비 |
| Validation 저장소 | `src/aidast/validation/store.py` | 별도 DB 계약에서 shared DB repository로 전환 준비 |
| Source 검증 | `src/aidast/validation/source.py` | case·stage·evidence 소유권과 digest 검증 |
| Report | `src/aidast/reporting/{models,runtime,render}.py` | case 기반 source binding과 stale 표시 |
| CLI | `src/aidast/cli.py` | status와 case 기반 보고서 입력 |
| 기존 검증 | `tests/test_validation_*.py`, `tests/test_reporting_*.py` | 기존 보장 유지, 저장 계약 fixture 교체 |

현재 Validation 테스트는 별도 DB의 `validation_runs`, `validation_decisions`, 7개 question을 기대한다. Report runtime과 draft 모델은 `validation_id` 및 source DB 파일 hash에 의존한다. 단순히 DB 경로만 바꾸지 않고 모델·저장소·reader·CLI를 같은 계약으로 전환해야 한다.

## 3. 작업 순서

```text
Task 1 DTO와 fixture
  -> Task 2 schema v9
  -> Task 3 Repository와 증거 검증
  -> Task 4 정보 접근 및 판정 입력 제한
  -> Task 5 중단 상태·복구 무결성
  -> Task 6 Report source snapshot
  -> Task 7 status·전환 문서
  -> Task 8 회귀 검증
```

각 작업은 관찰 가능한 계약 테스트를 먼저 추가하고 구현 후 해당 테스트를 실행한다. 미완성 실행 계층에 의존하는 항목은 별도 의존성으로 남긴다.

## Task 1. 엄격한 DTO와 합성 fixture 정의

**명세:** §6.4, §7, §8.7, §11.1.

**파일:** `src/aidast/validation/models.py`, 신규 `tests/test_validation_contracts.py`, 신규 `tests/validation_fixtures.py`.

- [x] 현재 snapshot, evidence reference, BlindAssessment, ClaimComparison, ValidationStageResult의 DTO를 정의한다.
- [x] 입력 DTO는 extra field를 금지한다. Agent 제출 객체에 최종 상태를 넣으면 거절한다.
- [x] 종결 상태와 `processing_phase`를 분리하고 `DEVELOPING`을 종결 snapshot으로 저장하지 않는다.
- [x] canonical JSON과 digest 규칙을 한곳에 둔다. 기존 hash utility를 확인한 뒤 재사용 여부를 정한다.
- [x] 합성 fixture에 scan 두 개, case 두 개, stage 두 개를 넣어 잘못된 ownership을 검증할 수 있게 한다. 실제 credential이나 공격 payload를 포함하지 않는다.

**검증·완료:** 잘못된 enum, extra field, 점수 범위 위반, hash 불일치를 거절한다. 객체 key 순서만 다른 입력은 같은 canonical digest를 갖는다.

## Task 2. 비파괴 schema v9 migration

**명세:** §7, §13.1.

**파일:** `src/aidast/pipeline/schema.py`, `tests/test_pipeline_contract.py`, 신규 `tests/test_validation_schema.py`.

- [x] 명세 §7의 일곱 테이블과 nullable `attack_http_requests.policy_sha256`을 추가한다. 필드는 명세에서 직접 대조하며 이 문서에 중복 정의하지 않는다.
- [x] case target의 배타성, scan별 target 유일성, evidence 참조의 배타성, ordinal 범위와 unique key를 제약으로 표현한다.
- [x] JSON 내부 ID처럼 FK로 표현할 수 없는 제약은 Task 3의 repository 검증 목록으로 남긴다.
- [x] 기존 테이블을 재구축하거나 과거 request의 policy digest를 추정해 채우지 않는다.
- [x] 실제 v8 request table 형태의 fixture를 준비해 nullable policy digest와 기존 row 보존을 검증한다.
- [x] 미래 schema version을 낮추지 않으며 legacy Validation.db를 자동 import하지 않는다.

**검증·완료:** migration 전후 Recon·Attack·Chaining rows가 같고 `PRAGMA foreign_key_check`가 비어 있다. 두 번째 migration은 동일 결과를 만들며 v8이 v9로 올라간다.

## Task 3. Repository와 증거 소유권

**명세:** §7.1–§7.7, §11.3.

**파일:** 신규 `src/aidast/validation/repository.py`, `src/aidast/validation/source.py`, 신규 `tests/test_validation_repository.py`.

- [x] Validation 저장 작업을 transaction API로 감싸고 공유 source table 조회는 별도 read model로 구분한다.
- [x] evidence의 case, stage, attempt/action 관계와 decision 내부 reference를 저장 전에 검증한다.
- [x] snapshot 교체 시 이전 `state_version`을 조건으로 사용한다. 갱신 row가 정확히 하나가 아니면 rollback한다.
- [x] 재검증 시작 시 직전 decision snapshot을 보존하고 최신 실행 식별자와 진행 단계만 갱신한다.
- [x] 완료 attempt의 의미 필드와 기존 evidence를 변경·삭제하지 못하게 한다.
- [x] `KNOWN` source가 더 이상 `CONFIRMED`가 아니게 되는 snapshot 교체와 종속 case 무효화를 같은 transaction에 둔다.
- [x] digest는 저장 직전에 계산하고 읽을 때 재검증한다. 가설과 advisory warning은 decision hash 입력에서 제외한다.

**검증·완료:** 타 case·이전 stage의 evidence 참조, 중복 attempt key, stale version update, source 변조를 거절한다. 중간 실패 시 부분 snapshot이 남지 않고 Chaining rows는 변하지 않는다.

## Task 4. 정보 접근 제한과 판정 데이터 검증

**명세:** §6, §7.5, §8.7, §10의 정보 보호 요구사항.

**파일:** 신규 `src/aidast/validation/evidence_policy.py`, 신규 `tests/test_validation_evidence_policy.py`.

- [x] 공개 DTO는 allowlist로 직렬화하며 DB path, raw secret, Attack response, 숨겨야 하는 claim 필드를 포함하지 않는다.
- [x] Blind assessment가 검증·고정되기 전에는 claim reader가 자료를 반환하지 않도록 접근 제약을 둔다.
- [x] claim 원본 digest가 고정 이후 변경되면 동시 변경 오류로 처리한다.
- [x] 증거 길이 제한과 secret redaction을 저장 경계에서 검증한다. 합성 token으로 중첩 JSON과 오류 메시지 누출을 확인한다.
- [x] 영향 점수는 현재 stage evidence를 인용해야 하며 합계·severity 구간은 명세 §8.7과 일치해야 한다.
- [x] 후속 가설은 증거·현재 점수·Report eligibility에 사용할 수 없는 별도 데이터로 취급한다. 자동 가설 생성이나 실행은 추가하지 않는다.

**검증·완료:** 숨김 필드와 secret이 직렬화 결과에 없고 변조된 증거를 거절한다. 가설을 추가해도 current impact, severity, status, decision hash가 모두 같다.

## Task 5. 중단 상태와 복구의 저장 무결성

**명세:** §11.3, §12.1–§12.2.

**파일:** `src/aidast/pipeline/lifecycle.py`, 신규 `tests/test_validation_recovery.py`.

- [x] 동일 scan의 active Validation stage 유일성을 트랜잭션 경계에서 보장한다.
- [x] stage 실패 시 진행 중 record를 `outcome_unknown`으로, 처리 중 case를 `interrupted`로 정리한다. 완료된 case와 evidence는 유지한다.
- [x] Validation 전용 lifecycle 복구 연산은 failed 상태, 다른 active stage 부재, 재개 대상 존재를 한 transaction에서 확인한다.
- [x] 원래 stage ID를 유지하고 이전 실패 원인은 audit event에 보존한다.
- [x] 원래 selected case 집합은 `validation_cases.latest_stage_run_id`로 재구성하며 별도 테이블이 필요하지 않음을 확인한다.
- [x] 복구 테스트는 DB lifecycle까지만 다루며 네트워크 요청이나 Agent를 다시 실행하지 않는다.

**검증·완료:** 두 connection의 경합에서 하나만 성공한다. 부적합 stage의 복구는 거절하며 중단 전 완료 record가 바뀌지 않는다. 실행 재개 기능 전체의 완료로 간주하지 않는다.

## Task 6. Shared DB Report source snapshot

**명세:** §12.3.

**파일:** `src/aidast/reporting/models.py`, `src/aidast/reporting/runtime.py`, `src/aidast/reporting/render.py`, `tests/test_reporting_agent.py`, `tests/test_reporting_integration.py`.

- [x] read-only snapshot transaction에서 schema, case, decision hash와 evidence ownership을 함께 검증한다.
- [x] source binding을 `scan_id`, `case_id`, `decision_sha256`, 정렬된 evidence hashes로 교체하고 검증한 bundle을 Report.db에 복사한다.
- [x] `CONFIRMED`이며 completed이고 decision stage와 latest stage가 같은 case만 신규 보고서 입력으로 허용한다.
- [x] `KNOWN`은 source case reference만 반환한다. source가 재검증 중이면 source 기반 신규 보고서를 보류한다.
- [x] `CONTESTED`는 review 자료만 표시하며 다른 상태는 신규 제출용 보고서 생성을 거절한다.
- [x] Pipeline.db 전체 파일 hash 및 WAL 부재 의존성을 제거하되 Report artifact 자체의 무결성 검증은 유지한다.
- [x] 원본 decision 변경 시 기존 artifact는 보존하고 `stale`로 표시한다. source 접근 실패를 최신성 검증 성공으로 취급하지 않는다.
- [x] 기존 Report.db v1 읽기를 유지하고 shared case Report.db는 v2로 분리한다. 기존 파일을 암묵적으로 덮어쓰지 않는다.

**검증·완료:** 상태별 허용·거절, 재검증 중 생성 차단, evidence 변조, WAL 사용 DB의 일관된 읽기, decision 변경 후 stale 표시를 합성 fixture로 확인한다.

## Task 7. Status CLI와 전환 문서

**명세:** §11.2–§11.3, §12.3, §13.1.

**파일:** `src/aidast/cli.py`, `src/aidast/validation/__init__.py`, `src/aidast/reporting/__init__.py`, `tests/test_validation_report_cli.py`, `README.md`.

- [x] `validate status`에서 scan 또는 case를 선택하고 직전 종결 상태, 현재 처리 단계, 두 stage ID를 구분해 출력한다.
- [x] 가설 조회는 현재 snapshot에 대응하는 stage로 제한하며 case에서는 ordinal 순서, scan에서는 개수와 담당별 요약을 표시한다.
- [x] 가설의 예상 영향과 검증된 영향을 명확히 구분한다.
- [x] `report run Pipeline.db --case-id ...` 입력을 Task 6의 reader와 연결한다.
- [x] legacy Validation.db는 shared selector 입력으로 거절하고 자동 이관하지 않는다.
- [ ] 기존 7 Question API와 Skill의 제거는 모든 consumer가 전환된 뒤 진행한다. 실행 계층 미완성 상태에서 기존 경로부터 삭제하지 않는다.
- [x] shared `run`, `resume`과 finding/chain targeted selector를 injected Coordinator에 연결한다.
- [x] 정상 pipeline은 injected Coordinator가 있으면 Chaining 직후 같은 API를 자동 호출한다.
- [ ] native adapter를 기본 구성한 뒤 injection 없이도 자동 Validation을 활성화한다.

**검증·완료:** status가 DB를 변경하지 않으며 잘못된 ID·schema와 허용되지 않은 Report 상태는 명확한 오류 및 non-zero exit를 반환한다.

## Task 8. 회귀 검증과 인수 기록

**명세:** §13.2–§13.3 중 이 계획의 포함 범위.

- [x] 각 작업의 신규 테스트와 기존 Validation·Report 테스트를 실행한다.
- [x] 저장 계약 전환으로 바뀐 fixture와 기존에 보장하던 무결성 검증을 대조한다. 실패 테스트 삭제만으로 완료하지 않는다.
- [x] 전체 회귀는 저장소의 unittest 구성을 따라 실행한다.

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

- [x] 외부 서비스 없이 실행한 범위와 pytest 환경 차이를 진행 기록에 남겼다.
- [ ] migration, 경합, crash 정리, read-only Report snapshot 결과를 PR에 기록한다.
- [x] 실제 credential, 외부 대상 요청, 공격 실행 없이 포함 범위의 테스트가 완료되는지 확인한다.

## 4. 명세 대응과 남은 의존성

| 명세 영역 | 이 계획의 처리 | 전체 구현 완료를 위해 남는 부분 |
|---|---|---|
| §5 reproduction 계약 | 저장 schema와 provenance 제약 | Attack 확정 transaction의 실제 producer 연동 |
| §6 Blind 경계 | DTO, 공개 필드, hash, tool-disabled 단일 native session | Codex local persisted-thread 운영 정책 정리 |
| §7 shared DB | migration, repository, ownership | 실행 producer별 ledger 기록 통합 |
| §8 판정 | evidence·점수·가설의 데이터 검증 | 실제 관측을 만드는 재현 및 실행 상태 머신 |
| §9 Chain | node gate, injected end-to-end Blind replay, terminal impact 재평가, Chaining table 불변 검증 | 실제 transport adapter를 통한 다단계 binding 재실행 |
| §10 요청 안전 | redaction과 저장 경계 검증 | 공통 safety core와 실제 transport 통합 |
| §11 CLI | status, 보고서 입력, injected Coordinator 기반 run·resume·targeted 실행 | native adapter 기본 연결과 pipeline 자동 호출 |
| §12 복구·Report | lifecycle 저장 복구, 완료 batch·고정 assessment 재사용, snapshot·eligibility·stale | transport 완료와 local commit 사이의 outcome-unknown 운영 처리 |
| §13 테스트 | 합성 fixture 기반 포함 범위 회귀 | 실제 adapter 및 전체 pipeline 수용 검증 |

이 표의 남은 의존성이 해소되기 전에는 legacy 경로의 최종 제거와 새 Validation의 기본 활성화를 릴리스 완료 항목으로 처리하지 않는다.
