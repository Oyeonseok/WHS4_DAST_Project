# AI DAST 파이프라인 학습 위키

**이 위키가 답하는 질문: URL을 입력한 뒤 누가 무엇을 판단하고, 어떤 DB·파일을 만들며, 다음 단계로 넘어가는 조건은 무엇인가?**

전체 실행 순서와 데이터 이동을 현재 코드에 연결해 설명한다. 설치와 명령 옵션은 [README](../../README.md), 운영 절차는 [OPERATIONS](../OPERATIONS.md)를 참고한다. 문서와 구현이 다르면 코드·테스트 소스를 대조하고, 해석과 미확인 사항을 구분한다.

## 처음 읽는 순서

1. [파이프라인 그림](pipeline-map.md)에서 전체 흐름과 저장소를 본다.
2. [학습 순서](study-path.md)를 따라 01~11 페이지를 읽는다.
3. 각 단계에서 **입력 → AI와 Python의 역할 → 처리 → DB·파일 → 다음 단계 조건**을 확인한다.
4. 구현 파일을 찾을 때는 [코드 길잡이](system-overview.md)를 연다.

| 순서 | 페이지 | 답하는 질문 |
| --- | --- | --- |
| 01 | [시작점](01-pipeline-entrypoints.md) | `aidast run`은 어디서 시작하고 어떤 순서로 단계를 호출하는가? |
| 02 | [Scope와 Recon 시작 조건](02-scope-recon.md) | 프로그램 URL이 수집·Codex 해석·승인·네 가지 파일로 어떻게 이어지는가? |
| 03 | [Recon과 Handoff](03-recon-handoff.md) | 정찰·태깅·추가 정찰 제안은 어떻게 다르며, 원본을 공용 DB로 어떻게 전달하는가? |
| 04 | [Attack과 Chaining](04-attack-chaining.md) | Handoff 뒤 가설 계획·Task 준비·조사·검사를 누가 맡으며, candidate와 chain은 무엇인가? |
| 05 | [Validation과 Report](05-validation-report.md) | 최종 case 판정과 보고서 초안을 어떻게 만들고 무엇을 검사하는가? |
| 06 | [상태와 재개](06-state-resume.md) | `completed`는 무엇을 뜻하고, 중단된 실행을 어디서 이어갈 수 있는가? |
| 07 | [Agent의 경계](07-agent-boundaries.md) | AI 해석·행동 선택과 Python의 순서·검증·저장은 어떻게 나뉘는가? |
| 08 | [대시보드](08-dashboard.md) | URL 등록·Scope 수집·승인·실행·화면 표시는 어떤 DB와 파일을 사용하는가? |
| 09 | [에이전트별 도구](09-agent-tools.md) | 각 역할이 어떤 모델·Skill·Python 도구·외부 프로그램을 사용하는가? |
| 10 | [Skill의 역할](10-skills.md) | Skill은 어떻게 선택되며, 지침·실행 도구·재현 계약은 어떻게 다른가? |
| 11 | [테스트 사례 추적](11-test-trace.md) | 테스트 관측이 후속 단계로 어떻게 이어지고, 그 결과로 어디까지 말할 수 있는가? |

## 헷갈리기 쉬운 지점

| 질문 | 확인할 페이지 |
| --- | --- |
| 정책을 읽는 프로그램 URL과 검사 대상 URL은 같은가? Scope JSON에 원문은 어디에 있는가? | [Scope 입력·출력](02-scope-recon.md) |
| Recon도 가설을 제안하는가? Handoff 후 Native Attack 계획과 같은가? | [Recon review와 Handoff](03-recon-handoff.md), [Attack 계획](04-attack-chaining.md) |
| Python 코드가 순서를 정하면 Agent라고 부를 수 있는가? | [역할의 경계](07-agent-boundaries.md) |
| URL 등록 DB·정찰 DB·공용 DB·보고서 DB·로그 DB는 각각 무엇인가? | [저장소 지도](pipeline-map.md), [WebUI 저장소](08-dashboard.md) |
| Attack 완료·finding·chain·Validation 확정은 어떤 차이가 있는가? | [판정](05-validation-report.md), [상태](06-state-resume.md) |
| IDOR 후보 지원이나 테스트 통과가 실제 자동 탐지 성능을 증명하는가? | [Attack의 조건과 한계](04-attack-chaining.md), [테스트 해석](11-test-trace.md) |

## 검토 기준과 이력

2026-10-04에 위키 전체 17개 문서를 현재 작업 폴더의 코드·테스트 소스와 정적으로 대조했다. 실행 순서, 역할, DB·파일 경로, 승인·검증·판정의 범위와 구현 한계를 보강했다. 실제 모델 호출·대상 요청·테스트 실행은 이번 검토에 포함하지 않았다. 이후 원본이 바뀌면 관련 페이지를 다시 확인해야 한다.

편집 원칙은 [AGENTS.md](AGENTS.md), 변경 페이지와 근거는 [수정 이력](log.md)에 있다. 과거 이력의 설명은 당시 상태를 기록하므로 현재 학습에는 단계별 페이지를 우선한다.

## Obsidian에서 보기

Obsidian에서 **저장소 폴더 전체**를 기존 보관함으로 연 뒤 `docs/wiki/index.md`를 연다. 현재 Windows 작업 폴더는 `C:\WHS4_DAST_Project`다. [보관함 관리 도움말](https://obsidian.md/help/manage-vaults)

코드 파일까지 탐색기에서 보려면 **설정 → 파일 및 링크 → 모든 파일 형식 표시**를 켠다. [설정 도움말](https://obsidian.md/help/settings)

## 확인할 질문

- 지금 설명하는 것은 AI의 제안인가, Python이 실제로 검사·저장한 결과인가?
- 어떤 DB·파일을 근거로 다음 단계의 실행을 허용하는가?
- 문서에 적힌 확인 범위를 넘어 성능이나 안전성을 단정하고 있지는 않은가?
