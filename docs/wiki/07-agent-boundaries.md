# 07. Agent와 결정적 코드의 역할

**질문:** AI가 선택·해석·제안하는 일과 Python이 실행·검증하는 일은 어디서 갈리는가?

## 역할 이름과 자율성은 구분한다

이 도구에서 “Agent”라는 이름은 AI가 맡는 작업 역할을 뜻할 때도 있다. 정해진 자료를 구조화하는 모델 호출과 관측에 따라 다음 도구 행동을 선택하는 실행 Agent를 같은 자율성으로 이해하면 안 된다. 전체 단계 순서·입력·저장·완료 조건은 Python Coordinator가 관리한다. [공통 AI](../../src/aidast/agents/main.py), [Native 실행 Agent](../../src/aidast/agents/native_pipeline.py), [단계 수명주기](../../src/aidast/pipeline/lifecycle.py)

| 단계 | Agent의 역할 | 코드가 확인하는 것 |
| --- | --- | --- |
| Scope | 프로그램 문서 분석과 구조화 | 원문 인용·응답을 검사하고 별도 승인을 요구. 인용 검사는 모든 해석의 의미적 정확성을 보장하지 않음 |
| Recon | 계획·태깅·검토 보조 | 승인 자산, Task 의존관계, `TargetPolicy`, 요청 예산 |
| Handoff | 이 단계 자체에는 조사 Agent가 없음 | 전달 파일 해시·Scope 승인 바인딩 검사와 `Recon.db` → `Pipeline.db` 복제 |
| Attack 가설 계획 | Handoff 뒤 저장된 Recon 관측으로 조사 가설 제안 | 구조·관측 참조 검사, 계획·Coverage·Task 저장. 이 호출은 실제 요청을 실행하지 않음 |
| Attack 실행 | 배정된 Task에서 도구 사용·관측 해석 선택, 조사 기록·후보 생성 | 도우미 broker·정책·요청 한도 적용, DB와 응답 대조, Coverage·Task 완료 검사 |
| Chaining | finding 연결 가설 제안 | 성공한 현재 replay에 연결된 `demonstrated` chain인지 확인 |
| Validation | Eligibility, 재현 계획 보완, Blind 평가, 주장 비교, 필요한 보완 계획 | Python 재현 실행·증거 참조·평가 동결, 구조화된 입력으로 `DecisionEngine` 판정 |
| Report | 검증된 case의 서술 초안 | 현재 `CONFIRMED`와 Scope eligibility·출처 바인딩 확인, 초안 형식·증거 ID 검사. 문장 의미의 자동 증명은 아님 |

근거: [Scope](../../src/aidast/orchestration/scope.py), [Recon executor](../../src/aidast/recon/executor.py), [요청 브로커](../../src/aidast/core/request_broker.py), [Handoff 복제](../../src/aidast/pipeline/materialize.py), [Attack 계획](../../src/aidast/attack/recon_hypotheses.py), [Attack 실행](../../src/aidast/orchestration/attack.py), [Chaining](../../src/aidast/orchestration/chaining.py), [Validation 실행·평가](../../src/aidast/validation/orchestration/coordinator.py), [Validation 판정](../../src/aidast/validation/core/decision.py), [Report 저장](../../src/aidast/reporting/case_runtime.py), [Report 초안 계약](../../src/aidast/reporting/models.py).

이 표는 각 구현의 **책임을 요약한 해석**이다. 특히 “Agent가 결과를 말했다”는 사실만으로 승인, 단계 완료, 취약점 확정이 되는 것은 아니다. 후속 단계는 파일·DB 상태와 정책을 다시 읽는다. [Handoff](../../src/aidast/pipeline/models.py), [stage 수명주기](../../src/aidast/pipeline/lifecycle.py)

## Attack 가설 계획과 실행 Agent는 다르다

기본 통합 경로는 **Recon → Handoff → Attack 가설 계획 → Python의 Coverage·배치 Task 준비 → 실행 Attack Agent**다. “Recon이 가설을 만들고 Handoff한다”라고 말하면 현재 기본 경로의 단계 경계와 다르다. 이미 source/benchmark 취약점 annotation이나 재사용할 계획이 있는 경우에는 새 가설 모델 호출을 생략할 수 있다. [CLI 순서](../../src/aidast/cli.py), [계획 재사용·대체](../../src/aidast/attack/recon_hypotheses.py), [Attack 준비](../../src/aidast/orchestration/attack.py)

가설 계획 AI는 “무엇을 조사할지”를 제안한다. 실행 Attack Agent는 Python이 준비한 작업을 받아 도우미를 사용한다. 배치마다 Codex 오케스트레이터가 실행 Agent 하나를 호출하도록 지시받으며, 취약점 유형마다 독립 Agent를 하나씩 만드는 구조는 아니다. Python 결과 검사는 Agent ID 목록과 DB 상태를 확인하며 전체 spawn 이력을 증명하는 검사는 아니다. [기본 호출·검증](../../src/aidast/orchestration/attack.py), [오케스트레이터 지시](../../src/aidast/agents/native_pipeline.py)

## Scope는 어느 의미에서 Agent인가?

Scope의 전체 순서인 수집·검증·초안·승인은 Python이 관리한다. 전용 Scope Agent 구현 클래스 대신 공통 `CodexMainAgent`가 AI 역할을 수행한다. `runtime-browser` 경로에서는 Reader가 화면을 관측하고 `choose_scope_view()`가 다음 화면 선택을 제안하며 Python이 조작한다. 수집한 원문을 `interpret_captured_scope()`로 구조화하는 호출은 정해진 입력을 해석하는 작업이다. [AI 메서드](../../src/aidast/agents/main.py), [화면 관측·조작](../../src/aidast/scope/reader.py), [전체 절차](../../src/aidast/orchestration/scope.py)

따라서 **Python이 관리하는 워크플로 안에 제한된 에이전트 동작이 있다**는 설명이 적절하다. 이는 구현의 책임을 설명하는 해석이며 클래스명만으로 자율성을 판단하지 않는다. 화면 선택·규칙 해석·참조 선택을 각각 독립 Agent라고 단정하지 않는다. [WebUI에서 같은 Agent 객체 연결](../../src/aidast/web/scope_workflow.py)

정책 참조가 미수집됐거나 해석이 모호하다는 이유만으로 모든 실행이 자동 중단되는 것은 아니다. 테스트 관련 advisory와 명시적 blocking requirement를 구분한다. 승인된 원문과 구버전 해석 보강 캐시의 역할도 다르다. [참조·보류 분류](../../src/aidast/scope/policy_references.py), [실행 보류 기준](../../src/aidast/scope/execution_rules.py), [Scope 상세](02-scope-recon.md)

## Python 판정에도 해석의 한계가 남는다

“Python이 최종 판정한다”는 말은 최종 분기를 코드로 적용한다는 뜻이다. Validation의 Blind 평가·영향 점수·주장 충돌 등의 값은 AI 평가와 실제 관측을 조합해 들어간다. 특히 프로필별 의미 증거 규칙은 현재 `audit` 모드여서 의미 증거 부족 자체가 자동 차단 조건은 아니다. Report도 허용된 증거 ID를 인용했는지 검사하지만 문장의 의미까지 검증하지는 않는다. [판정 입력 조립](../../src/aidast/validation/orchestration/coordinator.py), [의미 증거 audit](../../src/aidast/validation/core/profile_evidence.py), [Report 검증](../../src/aidast/reporting/models.py)

단계 완료는 취약점 확정·탐지 성능과 구분한다. Attack은 조사 항목을 인증 부족·미지원 등의 상태로 처리하고도 완료할 수 있고, Validation은 선택한 case가 없어도 완료할 수 있다. Recon의 성공·오류 조건은 공통 stage 상태와 별도로 확인해야 한다. [Attack Coverage](../../src/aidast/attack/coverage.py), [Validation 완료](../../src/aidast/validation/orchestration/coordinator.py), [Recon 통합 실행](../../src/aidast/cli.py), [상태·재개](06-state-resume.md)

각 Agent에게 주는 Skill과 실제 실행 프로그램·도우미는 [에이전트별 도구](09-agent-tools.md)에서 구분한다.

## 확인할 질문

1. Scope 분석 응답과 `Approval.json`은 각각 누가 만드는가?
2. Attack 가설 계획과 실행 Attack Agent는 입력·실행 권한이 어떻게 다른가?
3. 최종 분기가 Python이어도 의미적 오판 가능성이 남는 이유는 무엇인가?
