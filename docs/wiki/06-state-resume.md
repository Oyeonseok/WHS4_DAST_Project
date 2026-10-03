# 06. Stage 상태와 재개

**질문:** 재개 가능한 상태라면 어느 단계부터 다시 시작하며, 무엇을 먼저 검증하는가?

`Pipeline.db`의 `stage_runs`에는 단계별 실행과 상태가 기록된다. `start_stage_run()`과 `finish_stage_run()`은 상태 전이를 관리한다. 단계를 완료하려면 관련 Task가 완료 또는 건너뜀 상태여야 하며, Validation에는 현재 case 결정의 종료 조건도 적용된다. [DB 스키마](../../src/aidast/pipeline/schema.py), [수명주기 코드](../../src/aidast/pipeline/lifecycle.py)

`inspect_resume()`은 저장된 `Handoff.json`과 파일 해시, Scope·Approval 연결, TargetPolicy의 Scope ID, `pipeline_sources`의 원본 해시, 완료된 Recon을 검증한다. 그런 다음 `attack → chaining → validation` 순서로 시작하지 않았거나 재시도 가능한 첫 단계를 찾는다. `running`처럼 여전히 진행 중으로 기록된 단계는 임의로 다시 시작하지 않고 오류를 낸다. [재개 검사](../../src/aidast/pipeline/resume.py)

| 검사 결과 | 의미 |
| --- | --- |
| Handoff나 승인 근거 불일치 | 기존 실행의 출처를 신뢰할 수 없어 재개 거부 |
| Attack 작업이 남음 | Attack부터 다시 수행 |
| Chaining 또는 Validation 단계가 없거나 실패함 | 해당 단계부터 이어 수행 |
| 마지막 단계가 `pending` 또는 `running` 등 재시도 불가 상태 | 자동 재개 거부 |
| 세 단계 모두 완료 | 재개할 후속 작업 없음 |

`execute_resume()`은 선택된 단계부터 **Validation까지만** 실행한다. Recon을 다시 실행하거나 Report를 자동 생성하지 않는다. 이는 현재 구현의 범위다. [재개 실행](../../src/aidast/pipeline/resume.py)

사용자 명령의 옵션과 오류 안내는 [README](../../README.md)를 참고한다.

## 확인할 질문

1. `Handoff.json` 파일 자체와 `pipeline_sources`를 모두 확인하는 이유는 무엇인가?
2. 이미 완료된 단계와 실패한 단계를 어떻게 구별하는가?
