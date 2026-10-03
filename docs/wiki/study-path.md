# 학습 순서

**질문:** 파이프라인을 직접 설명할 수 있으려면 어떤 순서로 읽으면 되는가?

각 페이지를 읽은 다음, 아래 질문에 **코드 위치를 짚으며** 답해 본다. 막히면 해당 페이지의 원본 링크로 돌아간다.

| 순서 | 읽을 페이지 | 스스로 답할 질문 |
| --- | --- | --- |
| 1 | [시작점](01-pipeline-entrypoints.md) | `run`이 `_run_recon`으로 들어가 후속 coordinator를 호출하는 순서는? |
| 2 | [Scope와 Recon](02-scope-recon.md) | AI가 읽은 범위와 승인된 범위는 어떻게 구별되는가? |
| 3 | [Recon과 Handoff](03-recon-handoff.md) | `Recon.db`를 직접 쓰지 않고 `Pipeline.db`를 만드는 이유는? |
| 4 | [Attack과 Chaining](04-attack-chaining.md) | 성공한 attempt와 최종 확정 case의 차이는? |
| 5 | [Validation과 Report](05-validation-report.md) | 보고서에 들어갈 case를 고르는 SQL 조건은? |
| 6 | [상태와 재개](06-state-resume.md) | `resume`이 검증하는 원본과 다시 실행하는 단계는? |
| 7 | [Agent의 경계](07-agent-boundaries.md) | 각 단계에서 Agent의 응답을 누가 검사하는가? |
| 8 | [대시보드](08-dashboard.md) | WebUI 실행 버튼과 CLI는 어떻게 연결되는가? |
| 9 | [에이전트별 도구](09-agent-tools.md) | `subfinder`·`katana`·`ffuf`와 Attack 도우미 중 실제 요청을 보내는 것은? |
| 10 | [Skill의 역할](10-skills.md) | `hunt-idor`의 Attack·Validation 지침과 실행 계약은 어떻게 연결되는가? |
| 11 | [테스트 사례 추적](11-test-trace.md) | 관측이 가설이 됐지만 finding은 없을 때 어떤 상태로 끝나는가? |

복습할 때는 [파이프라인 그림](pipeline-map.md)을 빈 종이에 다시 그리고, 각 화살표에 **입력 파일·검증 조건·출력 파일**을 적어 본다. 구현 위치는 [코드 길잡이](system-overview.md)를 사용한다.

## 확인할 질문

1. Scope 승인, Recon 완료, Validation 확정 중 무엇이 각 다음 단계의 문턱인가?
2. Pipeline.db의 상태와 Obsidian 위키의 설명이 충돌하면 어디를 다시 확인해야 하는가?
