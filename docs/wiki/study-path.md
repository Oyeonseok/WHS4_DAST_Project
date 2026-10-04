# 학습 순서

**질문:** 파이프라인의 실행 순서와 책임을 스스로 설명하려면 어떻게 읽으면 되는가?

먼저 [파이프라인 지도](pipeline-map.md)를 보고, 아래 01~11 페이지를 순서대로 읽는다. 각 설명을 **입력 → 주체 → 처리 → 저장 위치 → 다음 단계 조건**으로 정리하면 함수 이름을 외우는 것보다 데이터 이동을 이해하기 쉽다. 이는 학습을 위한 정리 방식이다.

| 순서 | 읽을 페이지 | 확인할 핵심 | 스스로 답할 질문 |
| --- | --- | --- | --- |
| 01 | [시작점](01-pipeline-entrypoints.md) | CLI 명령·후속 호출·기본 저장 경로 | URL 등록과 `run` 실행은 무엇이 다른가? |
| 02 | [Scope와 Recon](02-scope-recon.md) | 수집·정책 해석·승인·Recon 준비 | CLI와 WebUI의 Scope 수집 경로는 어떻게 다른가? |
| 03 | [Recon과 Handoff](03-recon-handoff.md) | 원본 전달·해시 검사·DB 복제 | `Handoff.json`과 `Pipeline.db`는 각각 무엇인가? |
| 04 | [Attack과 Chaining](04-attack-chaining.md) | 가설·Coverage·Task·Agent·후보 | Native 가설은 언제 만들고, finding과 무엇이 다른가? |
| 05 | [Validation과 Report](05-validation-report.md) | 정책 적합성·재현·판정·로컬 초안 | 어떤 case가 Report 대상이며 검사는 무엇을 보장하는가? |
| 06 | [상태와 재개](06-state-resume.md) | 실행 상태·case 판정·재개 범위 | `completed`와 `CONFIRMED`를 왜 구분해야 하는가? |
| 07 | [Agent의 경계](07-agent-boundaries.md) | AI 역할과 Python 책임 | 다음 행동을 선택하는 Agent와 고정된 해석 호출은 어떻게 다른가? |
| 08 | [대시보드](08-dashboard.md) | URL 등록·Scope 버전·CLI 실행·DB 투영 | 사용자 동작별로 어느 DB와 파일이 바뀌는가? |
| 09 | [에이전트별 도구](09-agent-tools.md) | 지침·도우미·실제 실행 프로그램 | AI가 판단하는 일과 Python 도우미가 실행하는 일을 설명할 수 있는가? |
| 10 | [Skill의 역할](10-skills.md) | Skill 선택과 계약·검증 범위 | Skill·Agent·실행 계약은 어떻게 연결되며 무엇을 보장하지 않는가? |
| 11 | [테스트 사례 추적](11-test-trace.md) | 가짜 Agent 테스트와 기존 로컬 실험의 범위 | 연결 테스트를 실제 취약점 발견 성능으로 설명하면 왜 틀리는가? |

각 페이지의 사실 근거는 해당 페이지 가까이에 있는 코드·테스트 링크로 확인한다. 구현 파일을 빠르게 찾으려면 [코드 길잡이](system-overview.md)를 사용한다.

## 발표를 준비할 때

발표에서는 역할이 구분되도록 다음 세 묶음으로 설명하면 된다. 아래는 발표 구성에 대한 제안이며, 실제 실행 조건은 각 원본 코드에서 확인한다.

1. **Scope:** 무엇을 검사할 수 있는지와 정책·승인.
2. **Recon·Handoff:** 무엇을 관측했고, 원본을 어떤 방식으로 전달하는지.
3. **Attack·Chaining·Validation·Report:** 관측에서 조사 가설을 만들고, 후보·판정·문서로 이어지는 과정.

Handoff 그림은 결과 기록·검증·복제까지만 설명하고, 다음 Attack 그림에서 가설 계획·배치·조사·완료 검사를 설명하면 내용이 덜 겹친다. [Handoff 설명](03-recon-handoff.md), [Attack 설명](04-attack-chaining.md)

## 복습할 때 확인할 경계

- **관측과 가설:** 관측된 사실과 아직 조사할 가능성을 구분한다.
- **가설과 finding:** 가설을 준비했다고 증거가 생긴 것은 아니다.
- **finding과 case 결정:** Attack의 후보와 Validation의 판정은 다르다.
- **완료와 성공:** 작업 종료와 취약점 확정은 다르다.
- **초안과 제출:** 로컬 Report 파일 생성이 외부 제출 완료를 뜻하지 않는다.

각 용어의 구현 근거는 [Attack 용어](04-attack-chaining.md), [Validation과 Report](05-validation-report.md), [상태와 재개](06-state-resume.md)에서 함께 확인한다.

## 확인할 질문

1. 다섯 항목인 입력·주체·처리·저장·조건으로 각 단계를 설명할 수 있는가?
2. 같은 AI 객체를 재사용해도 각 호출을 독립 Agent라고 단정하기 어려운 이유는 무엇인가?
3. 위키와 현재 구현이 충돌하면 어떤 원본을 다시 확인해야 하는가?
