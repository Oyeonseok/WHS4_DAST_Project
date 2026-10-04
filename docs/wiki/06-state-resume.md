# 06. Stage 상태와 재개

**질문:** 완료·실패·확정은 어떻게 다르며, 저장된 실행은 어디서 이어가는가?

## 서로 다른 상태를 섞지 않기

| 기록 | 뜻 | 주요 저장소 |
| --- | --- | --- |
| Recon scan·도구 실행 기록 | 수집 실행의 상태와 Task에 연결된 도구 실행 결과 | `Recon.db`의 `scans`·`pipeline_runs`; Handoff 후 `Pipeline.db`에 복제 |
| `stage_runs` | 특정 단계의 실행 회차와 진행·종료 상태 | Native 후속 단계는 `Pipeline.db` |
| `attack_tasks`·Coverage | 배정된 조사 작업과 가설별 처리 결과 | `Pipeline.db` |
| `validation_cases` | 취약점 후보에 대한 현재 판정과 처리 단계 | `Pipeline.db` |
| Report draft 상태·해시 | 특정 case에 연결된 보고서 초안과 최신성 | case별 `Report.db`; 생성 단계 상태는 `Pipeline.db` |

근거: [Recon 스키마](../../src/aidast/recon/db.py), [후속 스키마](../../src/aidast/pipeline/schema.py), [공용 수명주기](../../src/aidast/pipeline/lifecycle.py), [Coverage](../../src/aidast/attack/coverage.py), [Validation 스키마](../../src/aidast/pipeline/live_schema.py), [Report 저장](../../src/aidast/reporting/case_runtime.py).

`completed`는 해당 단계 처리가 끝났다는 뜻이다. 취약점 확정은 Validation case의 `CONFIRMED` 판정이다. 모든 Task를 조사했다는 뜻도 아니다. 건너뜀·인증 부족·증거 부족처럼 사유가 기록된 종료 결과가 포함될 수 있다. [Attack 배치](../../src/aidast/orchestration/coverage_attack.py), [판정](../../src/aidast/validation/core/decision.py)

## 공통 수명주기 코드가 확인하는 것

`start_stage_run()`은 실행 회차를 `running`으로 만들고 감사 기록을 남긴다. `finish_stage_run()`의 종료 상태는 `completed`, `failed`, `cancelled`, `skipped`다. `completed`일 때 확인하는 Task는 **`attack_tasks` 테이블**이며, 모든 행이 `completed` 또는 `skipped`여야 한다. 이를 Recon Task 전체의 성공 검사로 일반화하지 않는다. [수명주기](../../src/aidast/pipeline/lifecycle.py)

Validation의 `completed` 처리에는 현재 stage에 속한 case의 처리 완료·판정 존재·결정 stage 일치 검사도 있다. case가 `INCONCLUSIVE`나 `OUT_OF_SCOPE`로 끝나도 해당 case의 처리는 완료될 수 있다. [수명주기](../../src/aidast/pipeline/lifecycle.py), [Validation coordinator](../../src/aidast/validation/orchestration/coordinator.py)

통합 CLI는 Recon 실패 Task가 있을 때 `scans.status='completed_with_errors'`로 저장하고 Recon stage를 마무리할 수 있지만, Handoff·Attack 호출은 중단한다. 따라서 **Recon stage의 completed만 보고 후속 조사 가능 여부를 판단하면 안 된다.** [CLI](../../src/aidast/cli.py), [Recon에서 Handoff로](03-recon-handoff.md)

## 재개는 검사와 실행으로 나뉜다

`inspect_resume()`은 파일·DB를 확인하고 **어느 단계부터 재개할지 계획만 반환**한다. `execute_resume()`이 그 계획을 받아 후속 coordinator를 호출한다. 검사 함수가 성공했다고 재개 실행의 모든 전제 조건까지 충족됐다는 뜻은 아니다. [재개 코드](../../src/aidast/pipeline/resume.py)

검사에서는 다음 연결을 확인한다.

1. 유효한 scan ID와 결과 루트 안의 기존 실행 폴더.
2. `Handoff.json`의 scan ID와 전달 파일의 크기·해시.
3. `Scope.json`·`Scope.md`와 `Approval.json`의 ID·해시 연결.
4. `TargetPolicy.json`이 같은 Scope ID를 참조하는지.
5. `Pipeline.db.pipeline_sources`의 Handoff·원본 DB 해시가 현재 파일과 맞는지.
6. Recon scan과 Recon stage의 완료 상태.

근거: [재개 검사](../../src/aidast/pipeline/resume.py), [Handoff 검증](../../src/aidast/pipeline/models.py). 이 검사는 기록된 원본과의 일치 여부를 확인한다. 원본 내용의 정확성이나 파일 작성자의 신원을 암호학적으로 증명하는 기능은 아니다.

## 어떤 단계가 선택되는가?

`attack → chaining → validation` 순서에서 가장 앞선 미완료 단계를 찾는다.

| 최신 stage 상태 | 검사 결과 |
| --- | --- |
| stage가 없음 | 해당 단계부터 시작 |
| `failed` | 해당 단계의 재개 경로 선택 |
| Attack이 `completed`지만 미완료 작업이 있음 | Attack부터 다시 선택 |
| Attack이 `completed`이고 작업이 끝남 | 다음 단계 검사 |
| Chaining·Validation이 `completed` 또는 `skipped` | 다음 단계 검사 |
| `pending`·`running`, 또는 그 밖의 허용되지 않은 상태 | 활성 실행 또는 재시도 불가로 거부 |
| 모든 후속 단계가 종료됨 | 재개할 단계가 없다는 오류 |

Attack 작업 잔여 여부는 Coverage에 비종료 항목이 있는지 확인한다. endpoint 검토 기록이 한 건 이상 있으면 검토 행 수가 포함된 endpoint 수보다 작은지도 비교한다. 이는 개별 누락 endpoint를 조회하는 검사는 아니다. **`blocked_auth`·`unsupported`·`error_terminal`은 자동으로 다시 실행할 미완료 항목과 다르다.** 현재 helper는 계획 진단의 `unresolved` 수 자체를 이 재개 조건에 포함하지 않는다. [재개 선택](../../src/aidast/pipeline/resume.py), [잔여 작업 검사](../../src/aidast/attack/coverage_snapshot.py), [Coverage 종료 상태](../../src/aidast/attack/coverage.py)

## 선택된 뒤 무엇을 이어 실행하는가?

| 시작 지점 | 실행 순서 |
| --- | --- |
| Attack | Attack → Chaining → Validation |
| Chaining | Chaining → Validation |
| Validation | 해당 failed stage의 Validation 재개; 새 실행이면 Validation 시작 |

같은 scan ID와 `Pipeline.db`, 전달 당시의 Scope·정책 파일을 사용한다. Attack·Chaining 재개는 해당 coordinator가 새 실행 회차를 만들 수 있고, failed Validation의 재개는 기존 stage 회차와 감사 기록을 이어 사용한다. 이 Validation 재개에는 같은 scan의 다른 `pending`·`running` Validation stage가 없어야 하고, 재개하려는 stage에 `queued`·`interrupted` case가 하나 이상 있어야 한다. `failed`라는 상태만으로 항상 실행 가능한 것은 아니다. [실행 분기](../../src/aidast/pipeline/resume.py), [Validation stage 재개 조건](../../src/aidast/pipeline/lifecycle.py), [Validation resume](../../src/aidast/validation/orchestration/coordinator.py)

현재 `execute_resume()`의 범위는 **Validation까지**다. Recon을 다시 수집하지 않고 Report도 자동 생성하지 않는다. 이미 생성된 보고서의 상태는 별도 `Report.db`와 현재 case 연결을 확인해야 한다. [재개](../../src/aidast/pipeline/resume.py), [보고서 최신성](../../src/aidast/reporting/case_runtime.py)

## 확인한 제한과 테스트 범위

`inspect_resume()`의 scan 검사는 `completed_with_errors`도 허용하지만, Native Attack 시작은 `completed`와 완료 시각을 요구한다. 일반 통합 CLI는 Recon 오류가 있으면 Handoff를 만들지 않으므로, 이 검사 차이를 Recon 오류를 자동 복구하는 기능으로 설명하지 않는다. [재개 검사](../../src/aidast/pipeline/resume.py), [Attack 시작 조건](../../src/aidast/orchestration/attack.py)

[재개 테스트](../../tests/test_scan_resume.py)는 가상 DB의 출처 검사, 경로 탐색과 가짜 coordinator 호출 순서를 검증한다. 이 페이지는 코드와 테스트 소스를 대조한 설명이며, 실제 대상 조사·모델 호출의 재개 성공률을 측정한 결과가 아니다.

## 확인할 질문

1. 단계의 `completed`와 case의 `CONFIRMED`는 무엇이 다른가?
2. 종료 상태인 Coverage와 실제 미완료 작업을 어떻게 구별하는가?
3. 왜 재개 검사 성공 뒤에도 실행 단계에서 추가 조건을 확인하는가?
4. 재개가 끝났을 때 Report 생성까지 수행됐다고 말할 수 있는가?
