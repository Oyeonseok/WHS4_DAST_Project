# 07. Agent와 결정적 코드의 역할

**질문:** AI가 제안하는 부분과 코드가 허용·검증하는 부분은 어디서 갈리는가?

| 단계 | Agent의 역할 | 코드가 확인하는 것 |
| --- | --- | --- |
| Scope | 프로그램 문서 분석과 구조화 | 출처에 있는 자산·인용인지 검사하고 별도 승인을 요구 |
| Recon | 계획·태깅·검토 보조 | 승인 자산, Task 의존관계, `TargetPolicy`, 요청 예산 |
| Attack | 가설 조사와 결과 제안 | DB finding·attempt와 응답 대조, coverage와 Task 완료 검사 |
| Chaining | finding 연결 가설 제안 | 성공한 현재 replay에 연결된 `demonstrated` chain인지 확인 |
| Validation | 비교·재현 자료의 평가 보조 | 정책·증거·대조군을 모아 `DecisionEngine`으로 최종 판정 |
| Report | 검증된 case의 서술 초안 | 최신 `CONFIRMED` case와 증거 무결성 확인 |

근거: [Scope](../../src/aidast/orchestration/scope.py), [Recon executor](../../src/aidast/recon/executor.py), [요청 브로커](../../src/aidast/core/request_broker.py), [Attack](../../src/aidast/orchestration/attack.py), [Chaining](../../src/aidast/orchestration/chaining.py), [Validation 판정](../../src/aidast/validation/core/decision.py), [Report 선택](../../src/aidast/reporting/auto.py).

이 표는 각 구현의 **책임을 요약한 해석**이다. 특히 “Agent가 결과를 말했다”는 사실만으로 승인, 단계 완료, 취약점 확정이 되는 것은 아니다. 후속 단계는 파일·DB 상태와 정책을 다시 읽는다. [Handoff](../../src/aidast/pipeline/models.py), [stage 수명주기](../../src/aidast/pipeline/lifecycle.py)

각 Agent에게 주는 Skill과 실제 실행 프로그램·도우미는 [에이전트별 도구](09-agent-tools.md)에서 구분한다.

## 확인할 질문

1. Scope 분석 응답과 `Approval.json`은 각각 누가 만드는가?
2. Validation Agent의 의견이 `CONFIRMED`가 되려면 어떤 코드 조건을 더 통과해야 하는가?
