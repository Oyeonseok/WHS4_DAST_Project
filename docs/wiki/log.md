# 위키 변경 기록

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
