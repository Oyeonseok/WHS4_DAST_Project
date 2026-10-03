# 04. Attack 후보와 Chaining의 경계

**질문:** 정찰 결과가 취약점 후보와 연결 후보가 되는 과정에서 무엇이 검증되는가?

## Attack의 입력과 작업

`AttackCoordinator.run()`은 `Pipeline.db`, 승인 Scope, TargetPolicy가 존재하고 Recon scan이 완료됐는지 확인한다. 그 뒤 Recon의 endpoint에서 가설을 계획하고 coverage manifest를 만든다. 실행할 가설이 없으면 빈 결과로 단계를 완료한다. 가설이 있으면 `ExhaustiveAttackCoordinator`가 제한된 배치로 작업을 수행한다. [AttackCoordinator](../../src/aidast/orchestration/attack.py), [가설 계획](../../src/aidast/attack/recon_hypotheses.py), [배치 실행](../../src/aidast/orchestration/coverage_attack.py)

배치 결과는 Agent의 응답만 믿고 완료하지 않는다. Coordinator가 DB에 기록된 finding·attempt와 응답을 대조하고, coverage 상태 및 Task의 종료 여부를 검사한다. [Attack 결과 검증](../../src/aidast/orchestration/attack.py), [coverage 배치](../../src/aidast/orchestration/coverage_attack.py)

`finding`은 **검증할 주장**이다. Attack의 matcher나 attempt가 긍정 신호를 남겨도 최종 판정은 [Validation](05-validation-report.md)의 case에서 이뤄진다. [README의 후보 설명](../../README.md#주요-기능), [Validation 대상 선택](../../src/aidast/validation/orchestration/coordinator.py)

## Chaining의 입력과 완료 조건

`ChainingCoordinator.run()`은 완료된 Attack stage를 요구한다. 기본 입력으로는 상태가 `unreviewed` 또는 `confirmed`인 finding 중, `attack_attempts.outcome='confirmed'`가 있는 것을 조회한다. 생성된 chain은 `demonstrated`로 기록되고 현재 단계의 성공적인 실행과 연결돼야 완료로 인정된다. [ChainingCoordinator](../../src/aidast/orchestration/chaining.py)

## 같은 “confirmed”라도 계층이 다르다

| 위치 | 의미 |
| --- | --- |
| Attack attempt의 `confirmed` | 해당 시도의 관측 결과 |
| finding 상태의 `confirmed` | Attack 저장소의 finding 상태 |
| Validation case의 `CONFIRMED` | 재현·대조군·영향 검사를 통과한 최종 case 판정 |

이 셋을 동일한 “확정 취약점”으로 합쳐 읽으면 파이프라인을 오해하게 된다. Chaining 입력의 attempt 조건은 [Chaining 코드](../../src/aidast/orchestration/chaining.py), Validation의 finding 선택 조건과 판정은 [Validation coordinator](../../src/aidast/validation/orchestration/coordinator.py)와 [DecisionEngine](../../src/aidast/validation/core/decision.py)에 있다.

`aidast attack`의 별도 승인형·Legacy 경로는 통합 `aidast run`의 Native Attack과 분리해 읽는다. 명령별 운영 방식은 [운영 상세](../OPERATIONS.md#legacy-attack-경로)를 참고한다.

## 확인할 질문

1. Attack 가설이 0개면 왜 Chaining과 Validation 호출이 여전히 이어질 수 있는가?
2. Chaining의 `demonstrated`와 Validation의 `CONFIRMED`는 무엇이 다른가?
