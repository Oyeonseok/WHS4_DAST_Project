# AI DAST 파이프라인 학습 위키

이 위키는 우리 도구의 **실행 순서, 데이터 이동, 승인과 판정의 경계**를 코드와 연결해 설명한다. 명령 옵션과 설치 절차는 [README](../../README.md), 운영 규칙은 [OPERATIONS](../OPERATIONS.md)를 원본으로 본다.

## 처음 읽는 순서

1. [파이프라인 그림](pipeline-map.md)에서 전체 단계를 본다.
2. [학습 순서](study-path.md)를 따라 01~11 페이지를 읽는다.
3. 각 페이지의 코드 링크를 열어 실제 분기와 데이터 조건을 확인한다.

| 순서 | 페이지 | 답하는 질문 |
| --- | --- | --- |
| 01 | [시작점](01-pipeline-entrypoints.md) | `aidast run`은 어디서 시작하는가? |
| 02 | [Scope와 Recon](02-scope-recon.md) | 승인된 대상이 작업과 정책으로 어떻게 바뀌는가? |
| 03 | [Recon과 Handoff](03-recon-handoff.md) | 정찰 원본이 공용 DB로 어떻게 넘어가는가? |
| 04 | [Attack과 Chaining](04-attack-chaining.md) | finding과 chain은 어떤 조건으로 생성·검사되는가? |
| 05 | [Validation과 Report](05-validation-report.md) | 최종 확정 사례와 보고서 초안은 어떻게 정해지는가? |
| 06 | [상태와 재개](06-state-resume.md) | 중단된 실행을 어디서 이어가는가? |
| 07 | [Agent의 경계](07-agent-boundaries.md) | AI 제안과 코드 검증은 어떻게 나뉘는가? |
| 08 | [대시보드](08-dashboard.md) | WebUI는 CLI와 저장 데이터에 어떻게 연결되는가? |
| 09 | [에이전트별 도구](09-agent-tools.md) | 어떤 Agent가 무엇을 판단하고, 어떤 도구가 실제로 작업하는가? |
| 10 | [Skill의 역할](10-skills.md) | 단계별 Skill은 어떻게 선택되고 실행 도구와 어떻게 다른가? |
| 11 | [테스트 사례 추적](11-test-trace.md) | 관측 하나가 단계별 결과로 어떻게 이어지는가? |

[코드 길잡이](system-overview.md)는 단계별 구현 파일을 찾을 때 사용한다. 위키의 편집 원칙은 [AGENTS.md](AGENTS.md), 수정 이력은 [log.md](log.md)에 있다.

## Obsidian에서 보기

Windows의 Obsidian에서 **`C:\WHS4_DAST_Project` 폴더 전체**를 기존 보관함으로 연 뒤 `docs/wiki/index.md`를 연다. 코드 파일까지 탐색기에서 보려면 **설정 → 파일 및 링크 → 모든 파일 형식 표시**를 켠다. Obsidian 사용 방법은 [공식 도움말](https://obsidian.md/help/manage-vaults)을 참고한다.
