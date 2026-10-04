# 위키 변경 기록

## [2026-10-04] audit | 전체 위키 코드 대조·설명 명확화

- 위키의 17개 Markdown을 모두 검토했다. 편집 규칙인 `AGENTS.md`는 유지하고, 01~11 학습 페이지·전체 지도·학습 순서·코드 길잡이·색인·변경 이력의 16개 문서를 갱신했다. 서로 다른 담당자의 페이지를 다시 교차검토했다.
- **전체 순서:** Handoff 이후 Native Attack 가설 계획을 지도와 시작점에 넣었다. 별도 Legacy 계획 경로, 통합 실행과 재개의 범위, Report 생성 조건을 구분했다. [시작점](01-pipeline-entrypoints.md), [지도](pipeline-map.md), [학습 순서](study-path.md), [코드 길잡이](system-overview.md)
- **Scope·WebUI:** 프로그램 정책 URL과 대상 URL, CLI·WebUI 브라우저 경로, 참조 정책 수집과 advisory·명시적 blocker, 승인 원본과 실행 규칙 캐시를 구분했다. 최종 파일은 `Scope.md`·`Scope.json`·`Manifest.json`·`Approval.json`이며 수집 원문은 `Scope.json`에 포함됨을 명시했다. URL 등록·수집 작업·이벤트·모델 호출·실행 DB와 선택한 승인 revision·대시보드 표시의 차이를 적었다. [Scope](02-scope-recon.md), [대시보드](08-dashboard.md)
- **Recon·Handoff·Attack·Skill:** Recon의 메모리 Plan·Task와 `Recon.db.pipeline_runs` 실행 이력을 구분했다. 오프라인 Recon review의 추가 정찰 추천은 Native 실행 가설 계획과 다르며 자동 재정찰을 뜻하지 않는다. Handoff의 파일·해시 검사와 DB 복사, AI 제안과 Python 검증·저장, 조사 중 finding 기록과 배치 종료 검사를 설명했다. Agent 반환 ID 검사와 실제 생성 이력의 증명, 지침과 도구·재현 계약, POSIX 브로커 제한을 구분했다. [Recon·Handoff](03-recon-handoff.md), [Attack·Chaining](04-attack-chaining.md), [역할](07-agent-boundaries.md), [도구](09-agent-tools.md), [Skill](10-skills.md)
- **판정·Report·재개·테스트:** stage의 `completed`와 case의 `CONFIRMED`, Attack 후보와 Chaining 근거, Validation 판정을 구분했다. IDOR 의미 증거의 audit 모드와 실제 탐지 성능의 미확인 범위를 명시했다. Report의 해시·참조·최신성 검사가 문안 전체의 의미적 사실성을 증명하지 않음을 적었다. 재개 상태와 failed Validation의 추가 조건, Validation까지만 이어 실행하는 범위를 설명했다. 합성 통합 테스트와 사전에 준비된 후보의 로컬 검증 결과를 실제 자동 탐지 성능으로 확대하지 않았다. [Validation·Report](05-validation-report.md), [상태·재개](06-state-resume.md), [테스트 해석](11-test-trace.md)
- 확인한 주요 원본: [CLI](../../src/aidast/cli.py), [결과 루트](../../src/aidast/paths.py), [Scope](../../src/aidast/orchestration/scope.py), [Codex 호출](../../src/aidast/agents/main.py), [Reader](../../src/aidast/scope/reader.py), [Recon](../../src/aidast/recon/executor.py), [Handoff](../../src/aidast/pipeline/materialize.py), [Native 계획](../../src/aidast/attack/recon_hypotheses.py), [Attack](../../src/aidast/orchestration/attack.py), [브로커](../../src/aidast/agents/helper_broker.py), [Chaining](../../src/aidast/orchestration/chaining.py), [Validation](../../src/aidast/validation/orchestration/coordinator.py), [Report](../../src/aidast/reporting/case_runtime.py), [자동 Report](../../src/aidast/reporting/auto.py), [재개](../../src/aidast/pipeline/resume.py), [lifecycle](../../src/aidast/pipeline/lifecycle.py), [WebUI launch](../../src/aidast/web/launch.py), [projection](../../src/aidast/web/projection.py), [통합 테스트](../../tests/test_merged_pipeline_e2e.py), [Report 테스트](../../tests/test_generic_reporting.py). 세부 근거는 각 페이지의 해당 주장 가까이에 연결했다.
- 점검: 전체 위키의 상대 파일 링크·Markdown 앵커·코드 fence·공백·색인 연결을 정적으로 검사했다. 누락 파일·앵커, 닫히지 않은 fence, trailing whitespace, 연결되지 않은 페이지가 없었다. 외부 URL 전체의 접근 가능성이나 Mermaid 렌더링은 검사하지 않았다.
- 확인 범위: 현재 코드·테스트 소스의 정적 대조와 문서 검사. 원본 코드·기존 문서를 수정하지 않았고, 실제 모델 호출·대상 요청·테스트 실행도 하지 않았다.

## [2026-10-03] correction | Native Attack 실행·그림 재검증

- `04-attack-chaining.md`에 AI 계획과 Python 저장, 배치 반복, 도우미 브로커, 조사 중 finding 저장, 이중 완료 검사와 종료 상태의 의미를 보강했다. `index.md` 안내도 갱신했다.
- 주요 근거 DB `Pipeline.db`와 별도 `events.db`·`CodexCalls.db`를 구분하고, 현재 POSIX 브로커 제한을 명시했다. PPT 그림은 `output/diagrams/attack-workflow-v3.png`에 저장했다.
- 확인한 원본: [AttackCoordinator](../../src/aidast/orchestration/attack.py), [계획](../../src/aidast/attack/recon_hypotheses.py), [배치](../../src/aidast/orchestration/coverage_attack.py), [Coverage](../../src/aidast/attack/coverage.py), [Native 실행](../../src/aidast/agents/native_pipeline.py), [브로커](../../src/aidast/agents/helper_broker.py), [DB 도우미](../../src/aidast/attack/db_cli.py), [템플릿](../../src/aidast/attack/template_cli.py), [계획 테스트](../../tests/test_recon_attack_hypotheses.py), [Coverage 테스트](../../tests/test_attack_coverage.py), [브로커 테스트](../../tests/test_native_helper_broker.py).
- 확인 범위: 코드·테스트 소스의 정적 대조. 실제 Codex Agent·대상 요청·테스트 실행은 하지 않았다.

## [2026-10-02] trace | Skill 상태 문구 수정과 테스트 사례

- `src/aidast/skills/chaining/live/SKILL.md`의 성공한 chain 상태를 구현과 같은 `demonstrated`로 바로잡았다.
- `11-test-trace.md`에 가상 `GET /api/items`와 `object_id` 매개변수 관측의 Handoff·Attack·Chaining·Validation 흐름과 별도 확정 case·보고서 테스트를 구분해 정리했다.
- `10-skills.md`의 오래된 불일치 안내를 현재 동작 설명으로 바꾸고 목차·학습 순서·코드 길잡이를 연결했다.
- 확인한 원본: [통합 테스트](../../tests/test_merged_pipeline_e2e.py), [Chaining DB](../../src/aidast/chaining/db_cli.py), [Chaining 검증](../../src/aidast/orchestration/chaining.py), [Report 테스트](../../tests/test_generic_reporting.py).
- 확인: Windows 저장소 코드로 통합·Chaining 대상 테스트 13개 통과.

## [2026-10-02] skills | 프로젝트 Skill 학습 페이지

- `10-skills.md`에 단계별 핵심 Skill, Hunt 지침 선택·배치, Attack과 Validation 지침·계약의 연결을 정리했다.
- Chaining Skill의 `proposed` 문구와 현재 구현의 `demonstrated` 저장 사이 차이를 기록했다.
- `index.md`, `study-path.md`, `system-overview.md`, `09-agent-tools.md`에서 연결했다.
- 확인한 원본: [Skill 파일](../../src/aidast/skills/policy/SKILL.md), [Attack 계획](../../src/aidast/attack/recon_hypotheses.py), [Attack 배치](../../src/aidast/orchestration/coverage_attack.py), [Validation Skill resolver](../../src/aidast/validation/core/profiles.py), [Chaining DB](../../src/aidast/chaining/db_cli.py).

## [2026-10-02] tools | 에이전트별 도구와 작업

- `09-agent-tools.md`에 Scope·Recon·Attack·Chaining·Validation·Report의 모델 호출, Skill, Python 실행기, 외부 프로그램을 구분해 정리했다.
- `index.md`, `study-path.md`, `system-overview.md`, `07-agent-boundaries.md`에서 새 페이지로 연결했다.
- 확인한 원본: [Main Agent](../../src/aidast/agents/main.py), [Native Agent](../../src/aidast/agents/native_pipeline.py), [Recon Executor](../../src/aidast/recon/executor.py), [Attack 도우미](../../src/aidast/attack/request_cli.py), [Validation 실행기](../../src/aidast/validation/orchestration/native.py), [Report Writer](../../src/aidast/reporting/runtime.py).

## [2026-10-02] correction | 코드 대조 결과 반영

- `01-pipeline-entrypoints.md`와 `pipeline-map.md`에 Handoff 뒤 오프라인 Legacy Attack 계획 저장 경로를 추가했다. 가상 자산의 데이터 이동 예시도 넣었다.
- `06-state-resume.md`에 `pending`·`running` 상태의 자동 재개 거부를 명시했다.
- `08-dashboard.md`의 DB 조회 설명을 `Pipeline.db`와 `Recon.db`를 포함한 실제 탐색 순서로 고쳤다.
- 확인한 원본: [통합 CLI](../../src/aidast/cli.py), [재개](../../src/aidast/pipeline/resume.py), [대시보드 projection](../../src/aidast/web/projection.py), [Recon DB](../../src/aidast/recon/db.py), [후속 DB](../../src/aidast/pipeline/schema.py).

## [2026-10-02] complete | 단계별 파이프라인 설명과 중복 정리

- `02~08` 페이지를 추가해 Scope 승인, Recon/Handoff, Attack/Chaining, Validation/Report, 재개, Agent 경계, 대시보드 연결을 코드 기준으로 정리했다.
- `index.md`, `study-path.md`, `system-overview.md`의 반복 설명을 탐색·학습·구현 파일 길잡이로 바꾸고 `resume`의 범위를 바로잡았다.
- 확인한 원본: [CLI](../../src/aidast/cli.py), [Scope](../../src/aidast/orchestration/scope.py), [Recon](../../src/aidast/recon/executor.py), [Handoff](../../src/aidast/pipeline/materialize.py), [Attack](../../src/aidast/orchestration/attack.py), [Chaining](../../src/aidast/orchestration/chaining.py), [Validation](../../src/aidast/validation/orchestration/coordinator.py), [Report](../../src/aidast/reporting/auto.py), [재개](../../src/aidast/pipeline/resume.py), [WebUI launch](../../src/aidast/web/launch.py).

## [2026-10-02] visualize | 통합 파이프라인 지도

- `pipeline-map.md`에 Obsidian에서 렌더링되는 Mermaid 흐름도를 추가했다.
- 확인한 원본: [CLI](../../src/aidast/cli.py), [파이프라인 생성](../../src/aidast/pipeline/materialize.py), [Report case 선택](../../src/aidast/reporting/auto.py), [README](../../README.md).

## [2026-10-02] ingest | 통합 파이프라인의 시작점

- `01-pipeline-entrypoints.md`를 추가하고 `index.md`, `study-path.md`에 연결했다.
- Windows 저장소의 2026-10-01 코드에서 `aidast run`의 분기, Recon 재사용, Handoff, Attack·Chaining·Validation·Report 호출을 확인했다.
- 확인한 원본: [CLI](../../src/aidast/cli.py), [파이프라인 생성](../../src/aidast/pipeline/materialize.py), [재개](../../src/aidast/pipeline/resume.py), [Attack 오케스트레이터](../../src/aidast/orchestration/attack.py), [Chaining 오케스트레이터](../../src/aidast/orchestration/chaining.py), [Report 생성](../../src/aidast/reporting/auto.py).

## [2026-10-01] correction | vault 경로 안내 수정

- `index.md`의 임의 로컬 경로를 제거하고, GitHub에서 내려받은 저장소 폴더를 선택하도록 수정했다.

## [2026-10-01] update | Obsidian 사용 안내

- `index.md`에 저장소 루트를 vault로 여는 절차와 코드 파일 표시, 탐색 제외 폴더를 추가했다.
- 근거: [Obsidian vault 관리](https://obsidian.md/help/manage-vaults), [Obsidian 설정](https://obsidian.md/help/settings).

## [2026-10-01] init | 학습 위키 시작

- `index.md`, `system-overview.md`, `study-path.md`, `AGENTS.md` 작성.
- 확인한 원본: [README](../../README.md), [운영 상세](../OPERATIONS.md), [CLI](../../src/aidast/cli.py), [프로젝트 설정](../../pyproject.toml).
- 현재 페이지는 전체 지도를 제공한다. 단계별 세부 동작은 원본 코드를 따라가며 보강한다.
## [2026-10-02] correction | Scope 입력·Agent 경계·저장소 대조

- `09-agent-tools.md`의 “Agent는 Codex 모델 호출” 정의를 역할 표현으로 수정하고, 모델 해석 호출과 행동 선택을 구분했다. `07-agent-boundaries.md`에 Python 워크플로 내부의 제한된 에이전트 동작이라는 해석을 명시했다.
- `02-scope-recon.md`에 `aidast scope`와 내부 `codex exec`, 표준입력 프롬프트·Skill·JSON Schema·임시 응답·최종 파일 흐름도를 추가했다. 승인 해시 검사와 웹페이지 최신성 검사를 구분했다.
- `08-dashboard.md`에 URL 등록과 수집 시작의 분리, runtime-browser 기본 경로, 접근 확인·검토·승인 흐름도, `programs.db`·`scope_jobs.db`와 파일 경로를 추가했다. `index.md`의 안내를 갱신했다.
- 확인한 원본: [CLI](../../src/aidast/cli.py), [Codex 호출·프롬프트](../../src/aidast/agents/main.py), [ScopeCoordinator](../../src/aidast/orchestration/scope.py), [Reader](../../src/aidast/scope/reader.py), [WebUI](../../WebUI/src/App.tsx), [요청 설정](../../WebUI/src/lib/scope.ts), [등록 저장소](../../src/aidast/web/programs.py), [작업 관리](../../src/aidast/web/scope_workflow.py), [API](../../src/aidast/web/server.py).
