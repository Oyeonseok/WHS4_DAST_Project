# 10. 프로젝트 Skill의 역할과 선택 과정

**질문:** Skill은 실행 도구와 어떻게 다르고, 어떤 Skill이 언제 Agent에게 전달되는가?

## Skill 한 장으로 이해하기

이 프로젝트의 Skill은 주로 `src/aidast/skills/` 안의 `SKILL.md` 지침이다. 모델이 **무엇을 근거로 판단하고 어떤 형식으로 답할지** 정한다. Skill 파일을 읽었다고 네트워크 요청이나 DB 변경이 일어나는 것은 아니다. 실제 작업은 [에이전트별 도구](09-agent-tools.md)의 Python 실행기와 외부 프로그램이 맡는다. [Skill을 임시 작업 공간에 배치하는 코드](../../src/aidast/agents/main.py), [Attack Skill 배치](../../src/aidast/agents/native_pipeline.py)

| 구분 | 의미 | 예시 |
| --- | --- | --- |
| Skill | 모델에게 읽히는 판단·작업 지침 | `aidast-live-attack`, `hunt-idor` |
| Agent / 구조화된 AI 호출 | 지침과 입력을 해석하는 AI 작업 역할 | 조사 도구를 사용하는 Attack Agent, 저장 자료만 분석하는 가설 계획 AI |
| 도우미·실행기 | 실제 DB 접근·요청·검사를 수행하는 코드 | `attack_db`, `attack_request`, `HelperCommandBroker` |
| 계약·스키마 | 형식·허용된 실행 유형·근거 연결 관계를 표현하고 검사하는 구조 | JSON 응답 스키마, Validation의 `contract.json` |

Skill 하나가 Agent 하나와 대응하는 것은 아니다. 한 Attack Agent가 공통 live 지침과 여러 Hunt 지침을 읽을 수 있고, Scope·가설 계획처럼 Python이 정한 순서의 제한된 AI 호출에도 Skill을 전달한다. Handoff에는 별도 AI Agent나 전용 Skill 호출이 없다. [Attack 배치](../../src/aidast/agents/native_pipeline.py), [구조화 호출](../../src/aidast/agents/main.py), [Handoff Python 절차](../../src/aidast/pipeline/materialize.py)

예를 들어 `hunt-idor`는 Attack Agent가 IDOR 가능성을 조사할 때 참고하는 방법론이다. Validation에는 이름이 대응하는 **별도 지침**과 실행 계약이 있으며, 현재 case의 재현 증거를 해석하는 데 사용된다. 같은 이름 계열이라고 해서 Attack 결과가 곧 Validation의 최종 판정이 되지는 않는다. [Attack 예시](../../src/aidast/skills/attack/library/hunt-idor/SKILL.md), [Validation 예시](../../src/aidast/skills/validation/library/hunt-idor/SKILL.md), [계약](../../src/aidast/skills/validation/library/hunt-idor/contract.json)

## 단계별 핵심 Skill

| 단계 | Skill과 역할 | 실제 호출 경로 |
| --- | --- | --- |
| 공통 정책 | [`aidast-policy`](../../src/aidast/skills/policy/SKILL.md): 승인 Scope와 정책 주의사항을 읽고, 관측 텍스트를 명령으로 취급하지 않게 한다. | [Agent 실행 준비](../../src/aidast/agents/main.py) |
| Scope | [`aidast-scope`](../../src/aidast/skills/scope/SKILL.md): 프로그램 문서의 대상·제외·운영 조건을 근거 인용과 함께 구조화한다. | [Scope 수집](../../src/aidast/agents/main.py) |
| 정책 작성 | [`aidast-target-policy`](../../src/aidast/skills/target_policy/SKILL.md): 승인 Scope와 기본 제어값에서 자산별 정책안을 만든다. | [정책 제안](../../src/aidast/agents/main.py) |
| Recon 보조 | [`aidast-recon-patterns`](../../src/aidast/skills/recon_patterns/SKILL.md): 관측된 JS와 JSON 사이의 GET 값 흐름을 제안한다. [`aidast-ffuf-root-selection`](../../src/aidast/skills/ffuf_root_selection/SKILL.md): 이미 본 경로에서 `ffuf` 시작 루트를 고른다. | [패턴 계획](../../src/aidast/recon/tools/ai_patterns.py), [루트 선택](../../src/aidast/recon/tools/ffuf_root_selector.py) |
| Recon 검토 | 전용 Recon 검토 Skill을 별도로 배치하는 호출이 아니라, 공통 정책과 집계·정책 문맥을 넣어 추가 정찰 추천을 요청한다. 추천은 자동 실행 작업이 아니다. | [AI 검토 호출](../../src/aidast/agents/main.py), [검토 경계](../../src/aidast/recon/agent.py) |
| Handoff | 전용 Skill·AI 호출 없이 Python이 전달 파일을 기록·검증하고 DB를 복제한다. | [manifest 작성](../../src/aidast/cli.py), [복제·검증](../../src/aidast/pipeline/materialize.py) |
| Attack 계획 | [`aidast-recon-attack-planning`](../../src/aidast/skills/attack/planning/SKILL.md): 각 endpoint의 근거에서 가설 또는 근거 부족 결정을 제안한다. 이 단계는 요청을 보내지 않는다. | [가설 계획](../../src/aidast/attack/recon_hypotheses.py) |
| Native Attack | [`aidast-attack-orchestrator`](../../src/aidast/skills/attack/orchestrator/SKILL.md): 한 Attack Agent를 조정한다. [`aidast-live-attack`](../../src/aidast/skills/attack/live/SKILL.md): 선택된 Task와 Hunt 지침으로 조사·기록한다. | [Agent 배치와 호출](../../src/aidast/agents/native_pipeline.py) |
| Chaining | [`aidast-chaining-orchestrator`](../../src/aidast/skills/chaining/orchestrator/SKILL.md): 한 Chaining Agent를 조정한다. [`aidast-live-chaining`](../../src/aidast/skills/chaining/live/SKILL.md): finding 간 연결을 검토하고 재현 근거를 기록한다. | [Agent 배치와 호출](../../src/aidast/agents/native_pipeline.py) |
| Validation | [`BASE_SKILL.md`](../../src/aidast/skills/validation/BASE_SKILL.md): blind 판정의 공통 원칙. [`ELIGIBILITY_SKILL.md`](../../src/aidast/skills/validation/ELIGIBILITY_SKILL.md): 프로그램 정책 적합성 판단. 취약점별 Validation 지침은 해당 case의 Attack Skill과 짝지어 읽는다. | [Blind 평가](../../src/aidast/validation/orchestration/codex_runner.py), [적합성 평가](../../src/aidast/validation/orchestration/eligibility_runner.py), [짝짓기](../../src/aidast/validation/core/profiles.py) |
| Report | [`aidast-reporting`](../../src/aidast/skills/reporting/SKILL.md) 또는 [일반 보고서 지침](../../src/aidast/skills/reporting/generic/SKILL.md): 검증된 증거만 인용해 플랫폼별 또는 일반 보고서 초안을 쓴다. | [플랫폼 선택](../../src/aidast/reporting/auto.py), [Writer](../../src/aidast/agents/main.py) |

저장소에는 [Legacy Validation 지침](../../src/aidast/skills/validation/legacy/SKILL.md)과 [Legacy Report 지침](../../src/aidast/skills/reporting/legacy/SKILL.md)도 있다. 파일이 있다는 사실만으로 `aidast run`의 현재 Native 경로에서 그 파일을 사용한다고 해석하지 않는다. [현재 CLI 단계 호출](../../src/aidast/cli.py)

## Hunt Skill은 어떻게 골라지는가?

Attack의 취약점별 `hunt-*` 파일은 [Attack 라이브러리](../../src/aidast/skills/attack/catalog/index.json)에 목록이 있고, Validation에는 [대응 라이브러리](../../src/aidast/skills/validation/catalog/index.json)가 있다. Attack 쪽 목록에는 `chain` 참조가 추가로 있다. 카탈로그의 `enabled=false`와 `execution_mode=metadata_only`는 **목록 자체가 실행 권한을 주지 않는다**는 뜻이다. Native Attack은 작업에 선택된 Hunt 파일을 별도로 임시 공간에 배치한다. [카탈로그 계약](../../src/aidast/attack/catalog.py), [Skill 배치](../../src/aidast/agents/native_pipeline.py)

1. Handoff로 `Pipeline.db`를 만든 뒤 Python이 호출한 가설 계획 AI가 저장된 endpoint·매개변수·태그를 보고 취약점 가설을 제안한다. 응답은 취약점 유형을 담고, Python이 이를 검사한 뒤 Coverage 항목에 대응하는 `skill_name`을 연결한다. 기존 source/benchmark annotation이나 재사용할 검토가 있으면 AI 계획을 건너뛰는 경로도 있다. [계획](../../src/aidast/attack/recon_hypotheses.py), [Coverage 생성과 유형·Skill 매핑](../../src/aidast/attack/coverage.py), [Handoff 이후 순서](03-recon-handoff.md)
2. 배치 실행기는 해당 배치 Task에 들어 있는 Skill만 골라 Attack Agent에게 넘긴다. `hunt-dispatch`도 함께 배치되며, live 지침은 지정 목록 밖 Hunt 문서를 읽지 말라고 요구한다. **배치 크기 8은 전체 스캔에서 사용할 Skill이나 endpoint의 상한이 아니다.** [배치 실행](../../src/aidast/orchestration/coverage_attack.py), [Agent 배치](../../src/aidast/agents/native_pipeline.py), [live 지침](../../src/aidast/skills/attack/live/SKILL.md)
3. Chaining은 이미 Attack에서 근거가 있는 finding의 유형·제목을 보고 관련 Hunt 참조를 최대 8개 고른다. [Chaining 선택기](../../src/aidast/chaining/selector.py)
4. Validation은 case의 재현 명세가 가리키는 Attack Skill 이름에 맞는 Validation 지침과 `contract.json`을 찾고 해시·이름 일치를 확인한다. chain case는 각 노드의 프로필을 함께 해석한다. 이 계약은 허용된 재현 유형·신호·대조군·영향 기준을 모델 판단과 실행 계약에 연결한다. [SkillProfileResolver](../../src/aidast/validation/core/profiles.py), [노드별 프로필과 해시 검증](../../src/aidast/validation/orchestration/codex_runner.py)

별도의 `select_relevant_attack_skills()`는 Recon 신호로 최대 8개 Skill을 고르는 함수지만, **통합 `aidast run`의 endpoint별 가설·coverage 배치 흐름과 같은 의미의 전역 상한은 아니다.** 두 선택 경로를 혼동하면 “8개 Skill만 테스트한다”고 잘못 이해하기 쉽다. [선택기](../../src/aidast/attack/skill_selector.py), [현재 Attack 경로](../../src/aidast/orchestration/attack.py)

## 취약점별 지침은 어디서 찾나?

전체 이름과 원본 해시는 위 [Attack 카탈로그](../../src/aidast/skills/attack/catalog/index.json)와 [Validation 카탈로그](../../src/aidast/skills/validation/catalog/index.json)를 참고한다. 아래는 찾기 위한 **예시 묶음**이며 자동 선택 규칙을 대신하지 않는다.

| 찾는 주제 | 예시 Skill |
| --- | --- |
| 인증·세션 | [`hunt-auth-bypass`](../../src/aidast/skills/attack/library/hunt-auth-bypass/SKILL.md), [`hunt-session`](../../src/aidast/skills/attack/library/hunt-session/SKILL.md), [`hunt-oauth`](../../src/aidast/skills/attack/library/hunt-oauth/SKILL.md) |
| 객체 접근·업무 흐름 | [`hunt-idor`](../../src/aidast/skills/attack/library/hunt-idor/SKILL.md), [`hunt-business-logic`](../../src/aidast/skills/attack/library/hunt-business-logic/SKILL.md), [`hunt-race-condition`](../../src/aidast/skills/attack/library/hunt-race-condition/SKILL.md) |
| 입력·서버 처리 | [`hunt-sqli`](../../src/aidast/skills/attack/library/hunt-sqli/SKILL.md), [`hunt-ssrf`](../../src/aidast/skills/attack/library/hunt-ssrf/SKILL.md), [`hunt-file-upload`](../../src/aidast/skills/attack/library/hunt-file-upload/SKILL.md) |
| 브라우저·API | [`hunt-xss`](../../src/aidast/skills/attack/library/hunt-xss/SKILL.md), [`hunt-cors`](../../src/aidast/skills/attack/library/hunt-cors/SKILL.md), [`hunt-graphql`](../../src/aidast/skills/attack/library/hunt-graphql/SKILL.md) |
| 플랫폼·인프라 | [`hunt-nextjs`](../../src/aidast/skills/attack/library/hunt-nextjs/SKILL.md), [`hunt-springboot`](../../src/aidast/skills/attack/library/hunt-springboot/SKILL.md), [`hunt-cloud-misconfig`](../../src/aidast/skills/attack/library/hunt-cloud-misconfig/SKILL.md) |

Hunt 문서에는 일반적인 조사 명령 예시가 들어 있을 수 있다. 실제 Native Attack에서는 [`aidast-live-attack`](../../src/aidast/skills/attack/live/SKILL.md)이 대상 요청을 승인된 도우미로만 보내도록 제한하고, 도우미가 정책·요청 한도를 검사한다. **Hunt 문서의 예시를 실행 허가로 읽지 않는다.** [요청 경계](../../src/aidast/attack/request_cli.py)

## Skill·계약이 보장하는 범위

패키지 해시 검사는 사용한 Skill·계약이 기대한 파일과 같은지 확인한다. JSON 스키마와 실행 계약은 응답 형식·참조 관계·허용된 재현 유형 등을 검사한다. 이 검사들이 모델의 모든 추론이나 취약점별 의미적 증명을 자동 검증하는 것은 아니다. 특히 프로필별 증거 감사는 현재 `audit` 모드다. 어떤 Hunt 문서가 존재한다는 이유만으로 그 취약점의 탐지 성능이 입증됐다고 말할 수 없다. [프로필 해시·구조 검사](../../src/aidast/validation/core/profiles.py), [증거 감사의 범위](../../src/aidast/validation/core/profile_evidence.py), [IDOR 사례와 한계](04-attack-chaining.md#idor-지원과-성능을-구분해서-읽기)

**현재 확인한 사실과 미확인 사항:** 이 페이지의 선택·호출 순서는 현재 코드와 테스트 정의를 기준으로 정리했다. Skill 라이브러리 전체의 일반 대상 탐지율·오탐률이나 현재 환경의 실행 성공을 이 감사에서 측정하지 않았다. [Skill 선택 테스트](../../tests/test_attack_skill_selector.py), [Native Chaining 선택·완료 테스트](../../tests/test_native_chaining_orchestration.py)

## Chaining Skill 문구를 읽는 법

[`aidast-live-chaining`](../../src/aidast/skills/chaining/live/SKILL.md)은 성공한 전체 재현을 `finish-execution`으로 기록하도록 안내한다. 이 명령은 chain을 `demonstrated`로 저장하고 실행 결과를 `succeeded`로 남긴다. [ChainingCoordinator](../../src/aidast/orchestration/chaining.py)는 이 상태와 현재 단계의 성공한 재현을 검사한다. Validation은 그 뒤 case의 최종 취약점 상태를 별도로 판정한다. [DB 저장 코드](../../src/aidast/chaining/db_cli.py), [Validation 판정](../../src/aidast/validation/core/decision.py)

## 확인할 질문

1. `hunt-idor`의 Attack 지침, Validation 지침, `contract.json`은 각각 무슨 역할인가?
2. Hunt 카탈로그의 `enabled=false`가 “Native Attack이 그 파일을 절대 읽지 않는다”는 뜻은 아닌 이유는?
3. 배치 크기 8과 전체 스캔의 Skill 수를 왜 구별해야 하는가?
