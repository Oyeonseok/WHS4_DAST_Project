# 11. 테스트 사례로 파이프라인 따라가기

**질문:** 관측된 endpoint 하나가 후속 단계로 어떻게 이어지며, 각 테스트는 어디까지 입증하는가?

사례 A·B는 **실제 대상 스캔 기록이 아니라 저장소의 자동화 테스트**를 읽는 안내다. 가상 자산을 SQLite에 넣고 Agent·재현 포트를 가짜 객체로 대체하며 외부 대상 네트워크를 사용하지 않는다. Scope 페이지 수집과 Recon 프로그램 실행도 직접 수행하지 않는다. 아래의 별도 로컬 adapter 테스트·과거 실습 실험은 검증 범위를 구분해서 읽는다. 이번 위키 감사에서는 테스트·모델·실습 서버를 실행하지 않고 코드와 기존 기록을 대조했다. [통합 테스트 원본](../../tests/test_merged_pipeline_e2e.py)

## 사례 A: 관측은 있지만 확정 finding은 없는 흐름

[`test_recon_snapshot_drives_downstream_pipeline_without_mutation`](../../tests/test_merged_pipeline_e2e.py)은 아래 출발 데이터를 `Recon.db`에 직접 만든다.

| 데이터 | 테스트에 넣은 값 | 파이프라인에서의 뜻 |
| --- | --- | --- |
| scan | `scan`, 승인 Scope ID `scope`, 상태 `completed` | Attack이 요구하는 완료된 Recon 스캔 |
| asset·origin | `example.test`, `https://example.test` | 탐색 자산과 실제 웹 origin |
| endpoint | `GET /api/items` | Attack 가설을 연결할 관측 경로 |
| parameter | query의 `object_id`, `is_identifier=1` | 객체 ID로 보이는 입력 |
| observation·annotation | Playwright 출처, `data_role:identifier` | 해당 입력을 검토할 근거 |

입력 생성 코드는 [테스트](../../tests/test_merged_pipeline_e2e.py), 각 테이블의 의미는 [Recon DB 스키마](../../src/aidast/recon/db.py)에 있다.

| 순서 | 테스트에서 수행한 작업 | 확인되는 결과 |
| --- | --- | --- |
| 1. Handoff | `Recon.db`·`Scope.md`·`Approval.json`의 해시를 `Handoff.json`에 넣는다. | 어떤 원본을 전달하는지 고정한다. 이 테스트의 축약 Handoff는 실제 `aidast run` 산출물 전체 목록과 다르다. [테스트](../../tests/test_merged_pipeline_e2e.py), [실제 Handoff 작성](../../src/aidast/cli.py) |
| 2. DB 복제 | `materialize_pipeline()`으로 `Pipeline.db`를 만든다. | 후속 단계는 복제본을 쓰고 원본 `Recon.db`의 바이트·해시는 유지된다. [테스트 검증](../../tests/test_merged_pipeline_e2e.py), [복제 구현](../../src/aidast/pipeline/materialize.py) |
| 3. Attack 계획 | Handoff·DB 복제 이후, Attack에서 가짜 계획 AI가 `object_id`에 대한 IDOR 가설을 낸다. | Attack Task에 `hunt-idor`가 선택된다. **Recon의 가설 생성이나 실제 Codex의 추론을 검증하는 테스트는 아니다. 가설은 finding이 아니다.** [가짜 Agent와 결과 검사](../../tests/test_merged_pipeline_e2e.py), [계획 호출 순서](../../src/aidast/orchestration/attack.py) |
| 4. Attack 실행 | 가짜 Attack Agent가 소유·타인 객체를 비교할 인증 신원이 없다는 이유로 Task를 `skipped` 처리한다. | Attack stage는 완료되지만 근거 있는 finding은 생기지 않는다. [테스트의 `EmptyAttackAgent`](../../tests/test_merged_pipeline_e2e.py) |
| 5. Chaining | 증명된 Attack finding이 없어 실행 대상을 찾지 못한다. | Chaining stage는 `skipped`가 된다. [테스트 결과](../../tests/test_merged_pipeline_e2e.py), [입력 선택](../../src/aidast/orchestration/chaining.py) |
| 6. Validation | 선택할 finding·chain이 없다. | Validation stage는 `completed`이지만 `case_ids=()`이다. [테스트 결과](../../tests/test_merged_pipeline_e2e.py), [case 선택](../../src/aidast/validation/orchestration/coordinator.py) |

이 테스트의 핵심 검증 대상은 **endpoint 관측 → Attack 가설 → 가짜 실행 Agent의 인증 부족 처리 → 증거가 없으면 case 없음**이다. 실제 Agent가 인증 부족을 정확히 진단했거나 IDOR을 탐지했다는 증거는 아니다. Report는 호출하지 않는다. 실제 `aidast run`의 보고서 선택 조건은 [Report 자동 생성 코드](../../src/aidast/reporting/auto.py)에 있으며 완료된 현재 `CONFIRMED` case가 없다면 생성 대상이 없다.

마지막 SQL은 `attack`의 `completed` 행 두 개를 기대한다. 하나는 가설 계획 회차, 하나는 이 사례의 조사 batch 회차다. 일반 실행의 Attack stage 기록이 항상 두 개라는 뜻은 아니며 조사 batch 수에 따라 늘어난다. [테스트의 SQL 기대값](../../tests/test_merged_pipeline_e2e.py), [가설 계획 stage](../../src/aidast/orchestration/attack.py), [batch stage](../../src/aidast/orchestration/coverage_attack.py)

## 별도 사례 B: 확정 case가 있을 때

아래는 **사례 A의 이어지는 실행이 아니다.** [`test_approved_handoff_scope_controls_validation_and_report`](../../tests/test_merged_pipeline_e2e.py)은 finding 근거가 이미 준비된 별도 테스트 DB로 시작한다. 승인 Scope의 해시를 Handoff에 묶고 Pipeline DB로 복제한 다음 Validation을 수행한다.

| 테스트의 정책 판단 | Validation 결과 | Report 준비 |
| --- | --- | --- |
| `ELIGIBLE` | `CONFIRMED` | `CaseReportAgent`가 상태 `prepared`인 보고서 컨텍스트를 만든다. |
| `INELIGIBLE` | `OUT_OF_SCOPE` | 확정 case가 없어 보고서 준비를 거부한다. |
| `UNKNOWN` | `INCONCLUSIVE` | 확정 case가 없어 보고서 준비를 거부한다. |

이 사례는 가짜 Eligibility·Validation Agent와 재현 포트를 사용하고 보고서 **작성까지는 검증하지 않는다**. 또한 승인 원문을 복제한 뒤 외부 `Scope.md`를 변경해도 `Pipeline.db`의 바인딩된 스냅샷을 사용하는지 검사한다. 해시 검사와 스냅샷 유지가 실제 정책 해석의 정확도를 입증하는 것은 아니다. [사례 B](../../tests/test_merged_pipeline_e2e.py)

초안 파일 생성은 별도 [일반 보고서 테스트](../../tests/test_generic_reporting.py)에서 확인한다. 이 테스트도 미리 확정한 fixture case와 가짜 Writer를 사용한다. `CONFIRMED` case에 대해 `Report.db`·`Report.md`·`Report.json`을 만들고, 확정되지 않은 case에는 빈 결과를 반환하며, 기본 한국어·영어 분리와 stale 결정 차단 등의 기대값을 검사한다. **실제 AI 문안의 품질이나 취약점 탐지 성능을 평가하는 테스트는 아니다.** [Report fixture](../../tests/test_shared_validation_reporting.py), [자동 보고서 조건](../../src/aidast/reporting/auto.py)

## 테스트·실험별로 무엇을 말할 수 있나?

| 근거 | 구성과 확인 범위 | 이 근거만으로 말할 수 없는 것 |
| --- | --- | --- |
| 합성 통합 테스트 | DB fixture·가짜 Agent·가짜 재현 포트로 전달·상태·정책 분기·원본 유지 검사 | URL부터 시작한 발견율, 실제 Codex의 판단 정확도, 실제 요청 adapter의 성공 |
| Native 재현 acceptance 테스트 | 미리 입력한 finding·runtime contract, 로컬 서버, 가짜 평가 Agent로 Python 재현·대조군·ledger·최종 판정 연결 검사 | Attack이 스스로 finding을 발견하는 능력, 실제 평가 AI의 정확도 |
| Report 테스트 | 미리 만든 확정 case와 가짜 Writer로 별도 DB·파일·인용·최신성 검사 | 보고서 문장의 의미적 사실성, 실제 AI의 글쓰기 품질 |
| 2026-09-26 인증 전제 Validation 실험 기록 | 로컬 VulnBank, 사전에 준비된 두 테스트 사용자·소유 객체와 세 후보, 실제 Eligibility·Blind·Comparison 호출로 기대 판정 대조 | 일반 대상의 IDOR 탐지율, 계정·소유 객체의 자동 준비, 현재 코드 전체의 재실행 성공 |

근거: [합성 통합 테스트](../../tests/test_merged_pipeline_e2e.py), [로컬 acceptance 테스트](../../tests/test_validation_live_acceptance.py), [Report 테스트](../../tests/test_generic_reporting.py), [기존 인증 전제 실험 기록](../test-results/09.26/_archive/validation/AUTH_PREREQUISITE_ACCURACY.md).

기존 인증 전제 실험의 세 후보는 차단된 객체 접근 `DISPROVEN`, 타인 객체가 없는 목록 `DISPROVEN`, 타인의 보호된 목록이 반환된 사례 `CONFIRMED`로 기대 결과와 일치했다. 이 기록의 Attack `confirmed` 표시는 **Validation 시험을 위해 넣은 합성 주장**이다. 따라서 “세 IDOR을 자동으로 발견했다”나 “IDOR 탐지 정확도가 100%다”라고 발표하면 범위를 벗어난다. [실험 입력·결과·한계](../test-results/09.26/_archive/validation/AUTH_PREREQUISITE_ACCURACY.md)

현재 프로필별 의미 증거 규칙도 별도로 확인해야 한다. `test_idor_replay_signal_does_not_prove_owner_or_actor`는 양성 신호·assertion이 있어도 사용자·객체 소유권 증거가 자동 입증되지 않는 경계를 검사한다. 그 검사 결과는 `audit`이고, 부족한 의미 증거 자체가 확정을 차단하는 강제 게이트는 아니다. [의미 증거 테스트](../../tests/test_validation_profile_evidence.py), [audit 코드](../../src/aidast/validation/core/profile_evidence.py), [Validation 상세](05-validation-report.md)

**미확인:** 이 페이지의 근거만으로는 소스·정답지 단서를 주지 않은 URL 시작 전체 파이프라인의 일반적인 IDOR precision·recall을 산출할 수 없다. 별도 평가 설계에서는 다중 사용자 전제가 없으면 해당 사례를 `NOT_EVALUATED`로 구분하도록 정리돼 있다. [평가 설계](../test-plans/VULNBANK_JUICESHOP_EVALUATION_PLAN.md)

## 코드를 직접 따라 읽는 순서

1. [사례 A 테스트](../../tests/test_merged_pipeline_e2e.py)에서 `Recon.db`에 들어가는 자산·endpoint·annotation을 찾는다.
2. 바로 아래의 Handoff·`Pipeline.db` 생성과 `EmptyAttackAgent`의 Task 처리 결과를 연결한다.
3. 마지막 SQL 검사에서 `hunt-idor` Task와 `attack → chaining → validation` 상태를 확인한다.
4. [사례 B 테스트](../../tests/test_merged_pipeline_e2e.py)에서 정책 판단이 달라질 때 case와 보고서 준비 결과가 어떻게 바뀌는지 비교한다.

## 확인할 질문

1. `object_id`가 관측됐는데도 finding이 생기지 않은 이유는 무엇인가?
2. Attack stage의 `completed`와 Validation의 `CONFIRMED`는 왜 다른가?
3. 사례 B를 사례 A와 같은 스캔의 후속 결과라고 말하면 왜 틀리는가?
4. 실제 요청을 하는 로컬 adapter 테스트와 실제 AI의 탐지 성능 실험은 어떻게 다른가?
5. 사전에 준비한 후보 세 건의 기대 판정 일치를 전체 IDOR 탐지 정확도로 말할 수 없는 이유는 무엇인가?
