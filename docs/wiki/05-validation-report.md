# 05. Validation 판정에서 Report 초안까지

**질문:** Attack 후보 중 무엇이 최종 확인 사례와 보고서가 되는가?

## Case를 고르는 기준

기본 Validation 실행은 완료되거나 건너뛴 Chaining 단계를 확인한 뒤, 상태가 `unreviewed` 또는 `confirmed`인 finding과 `demonstrated` chain을 case로 만든다. 여기서 finding 선택 SQL에는 성공한 Attack attempt 조건이 없다. Chaining의 기본 입력 조건과 다르므로 둘을 같은 필터로 이해하면 안 된다. [Validation coordinator](../../src/aidast/validation/orchestration/coordinator.py), [Chaining coordinator](../../src/aidast/orchestration/chaining.py)

기존 case가 있으면 새 case를 무조건 만들지 않고 재검증 상태로 전환한다. 진행 중인 case는 중복 선택을 거부한다. [`_select_cases`](../../src/aidast/validation/orchestration/coordinator.py)

## 판정의 주체

Validation은 Scope와 정책을 결합하고 증거·재현·대조군·영향 정보를 모은다. 최종 `CONFIRMED` 등의 상태는 Agent의 문장 그대로 저장하는 것이 아니라 `DecisionEngine.decide()`가 구조화된 입력으로 결정한다. 무결성 실패, 정책 밖, 대조군 실패, 관측 부족, 영향 부족은 서로 다른 결과를 낸다. [Validation coordinator](../../src/aidast/validation/orchestration/coordinator.py), [DecisionEngine](../../src/aidast/validation/core/decision.py)

| 상태 예시 | 이 단계에서 뜻하는 것 |
| --- | --- |
| `CONFIRMED` | 필요한 관측과 대조군, 영향 조건을 통과한 현재 case 결정 |
| `OUT_OF_SCOPE` | 정책상 허용되지 않는 case |
| `INCONCLUSIVE` | 무결성·대조군·관측 등으로 결론을 내리기 어려운 case |
| `UNDERPOWERED` | 재현 신호는 있어도 영향 근거가 충분하지 않은 case |

이 표는 [판정 분기](../../src/aidast/validation/core/decision.py)를 간추린 것이며 모든 상태와 세부 기준은 코드에서 확인한다.

## Report의 문턱

`aidast run`은 Validation 단계가 완료됐을 때 Report 생성을 호출한다. `generate_scan_reports()`는 **현재 상태가 `CONFIRMED`이고 처리 완료이며 결정이 최신 stage run에 속한 case**만 조회한다. 해당 case가 없으면 빈 목록을 돌려준다. 초안을 만들기 전 case runtime은 결정 해시와 증거 참조를 검증한다. [CLI](../../src/aidast/cli.py), [자동 보고서 선택](../../src/aidast/reporting/auto.py), [case runtime](../../src/aidast/reporting/case_runtime.py)

따라서 Attack의 긍정 결과와 Report에 실리는 사례 사이에는 Validation의 독립 판정과 최신성 검사가 있다. Report 파일은 제출 완료가 아니라 로컬 초안이다. 출력 형태와 플랫폼별 절차는 [운영 상세](../OPERATIONS.md#case-기반-report)를 본다.

## 확인할 질문

1. finding 선택과 chain 선택 SQL은 어떻게 다른가?
2. 과거에 `CONFIRMED`였던 case라도 최신 결정이 아니라면 왜 보고서에서 빠지는가?
