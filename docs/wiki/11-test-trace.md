# 11. 테스트 사례로 파이프라인 따라가기

**질문:** 관측된 endpoint 하나가 Attack·Chaining·Validation으로 어떻게 이어지는가?

이 페이지는 **실제 대상 스캔 기록이 아니라 저장소의 자동화 테스트**를 읽는 안내다. 테스트는 가상 자산을 SQLite에 넣고 Agent를 가짜 객체로 대체하므로 외부 네트워크를 사용하지 않는다. Scope 페이지 수집과 Recon 프로그램 실행도 이 테스트에서 직접 수행하지 않는다. [통합 테스트 원본](../../tests/test_merged_pipeline_e2e.py)

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
| 3. Attack 계획 | 가짜 계획 Agent가 `object_id`에 대한 IDOR 가설을 낸다. | Attack Task에 `hunt-idor`가 선택된다. **가설은 finding이 아니다.** [가짜 Agent와 결과 검사](../../tests/test_merged_pipeline_e2e.py) |
| 4. Attack 실행 | 가짜 Attack Agent가 소유·타인 객체를 비교할 인증 신원이 없다는 이유로 Task를 `skipped` 처리한다. | Attack stage는 완료되지만 근거 있는 finding은 생기지 않는다. [테스트의 `EmptyAttackAgent`](../../tests/test_merged_pipeline_e2e.py) |
| 5. Chaining | 증명된 Attack finding이 없어 실행 대상을 찾지 못한다. | Chaining stage는 `skipped`가 된다. [테스트 결과](../../tests/test_merged_pipeline_e2e.py), [입력 선택](../../src/aidast/orchestration/chaining.py) |
| 6. Validation | 선택할 finding·chain이 없다. | Validation stage는 `completed`이지만 `case_ids=()`이다. [테스트 결과](../../tests/test_merged_pipeline_e2e.py), [case 선택](../../src/aidast/validation/orchestration/coordinator.py) |

이 테스트가 검증하는 핵심은 **endpoint 관측 → Attack 가설 → 실행 가능성 검사 → 증거가 없으면 case 없음**이다. Report는 이 테스트에서 호출하지 않는다. 실제 `aidast run`의 보고서 선택 조건은 [Report 자동 생성 코드](../../src/aidast/reporting/auto.py)에 있으며, 완료된 `CONFIRMED` case가 없다면 생성 대상이 없다.

## 별도 사례 B: 확정 case가 있을 때

아래는 **사례 A의 이어지는 실행이 아니다.** [`test_approved_handoff_scope_controls_validation_and_report`](../../tests/test_merged_pipeline_e2e.py)은 finding 근거가 이미 준비된 별도 테스트 DB로 시작한다. 승인 Scope의 해시를 Handoff에 묶고 Pipeline DB로 복제한 다음 Validation을 수행한다.

| 테스트의 정책 판단 | Validation 결과 | Report 준비 |
| --- | --- | --- |
| `ELIGIBLE` | `CONFIRMED` | `CaseReportAgent`가 상태 `prepared`인 보고서 컨텍스트를 만든다. |
| `INELIGIBLE` | `OUT_OF_SCOPE` | 확정 case가 없어 보고서 준비를 거부한다. |
| `UNKNOWN` | `INCONCLUSIVE` | 확정 case가 없어 보고서 준비를 거부한다. |

이 사례는 가짜 Validation Agent·재현 포트를 사용하고, 보고서 **작성까지는 검증하지 않는다**. 실제 초안 파일 생성은 별도 [일반 보고서 테스트](../../tests/test_generic_reporting.py)의 `generate_scan_reports()` 검증에서 확인할 수 있다. 이 테스트는 `CONFIRMED` case에 대해 `Report.md`를 만들고, 확정되지 않은 case에는 빈 결과를 돌려준다. [자동 보고서 조건](../../src/aidast/reporting/auto.py)

## 코드를 직접 따라 읽는 순서

1. [사례 A 테스트](../../tests/test_merged_pipeline_e2e.py)에서 `Recon.db`에 들어가는 자산·endpoint·annotation을 찾는다.
2. 바로 아래의 Handoff·`Pipeline.db` 생성과 `EmptyAttackAgent`의 Task 처리 결과를 연결한다.
3. 마지막 SQL 검사에서 `hunt-idor` Task와 `attack → chaining → validation` 상태를 확인한다.
4. [사례 B 테스트](../../tests/test_merged_pipeline_e2e.py)에서 정책 판단이 달라질 때 case와 보고서 준비 결과가 어떻게 바뀌는지 비교한다.

## 확인할 질문

1. `object_id`가 관측됐는데도 finding이 생기지 않은 이유는 무엇인가?
2. Attack stage의 `completed`와 Validation의 `CONFIRMED`는 왜 다른가?
3. 사례 B를 사례 A와 같은 스캔의 후속 결과라고 말하면 왜 틀리는가?
