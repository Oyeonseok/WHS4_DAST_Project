# AI DAST

AI DAST는 승인된 버그바운티 Scope 안에서 작동하는 멀티 Agent DAST CLI입니다.
Recon부터 Attack, Chaining, Validation, Report 초안까지 연결합니다.

```text
Scope 수집·승인
    ↓
AI-Dast Recon
    ↓
관측 태깅
    ↓
Handoff / Pipeline.db
    ↓
Native Attack
    ↓
Chaining
    ↓
Shared Validation
    ↓
플랫폼별 Report 초안
```

전체 단계 순서, 실행 gate, DB 상태 전이와 재개는 결정론적인 Python
오케스트레이터가 관리합니다. Codex CLI는 각 단계에서 제한된 구조화 판단과
Skill 실행만 담당합니다. 전체 파이프라인을 자율적으로 지휘하는 상위 Main Agent는
없으며, 실제 네트워크 요청은 Python 검증기와 정책 경계를 통과한 경우에만 실행합니다.

> 이 도구는 승인된 버그바운티 프로그램과 명시적으로 허가된 자산에서만 사용하세요.

## 바로가기

- [설치](#설치)
- [빠른 시작](#빠른-시작)
- [핵심 워크플로](#핵심-워크플로)
- [주요 명령](#주요-명령)
- [운영 상세](docs/OPERATIONS.md)

## 주요 기능

| 단계 | 역할 | 주요 결과 |
| --- | --- | --- |
| Scope | 프로그램 Scope 수집, 사용자 승인, 무결성 검증 | `Scope.json`, `Approval.json` |
| Recon | 자산·서비스·endpoint 수집과 관측 태깅 | `Recon.db`, `Surface.json` |
| Handoff | Recon 산출물의 해시와 역할 검증 | `Handoff.json`, `Pipeline.db` |
| Attack | 정책과 승인 경계 안에서 후보 조사 | finding, attempt, evidence |
| Chaining | 검증 가능한 finding 간 연결 분석 | chain candidate |
| Validation | 재현·대조군·증거 기반 최종 판정 | validation case |
| Report | 검증된 case의 플랫폼별 로컬 초안 생성 | `Report.md`, `Report.json` |

## 실행 전 확인

- 실제 요청은 승인된 Scope, `TargetPolicy`, 요청 예산을 모두 통과해야 합니다.
- 로그인 세션에는 쿠키·스토리지·토큰이 포함될 수 있으므로
  `result/.aidast_sessions/`와 브라우저 프로필을 공유하거나 커밋하지 않습니다.
- 정책 강제에 필요한 `mitmdump`를 시작하지 못하면 실행을 중단합니다.
- Report는 로컬 초안만 생성하며 플랫폼에 자동 제출하지 않습니다.

세부 정책, 요청 예산, 로그인 모드와 fail-closed 동작은
[안전 경계와 운영 원칙](docs/OPERATIONS.md)을 참고하세요.

## 설치

### 필수 환경

- Python 3.13 이상
- [uv](https://docs.astral.sh/uv/)
- [Codex CLI](https://github.com/openai/codex)
- Playwright Chromium

### GitHub에서 설치

```bash
OWNER="Oyeonseok"
REPO="WHS4_DAST_Project"
GITHUB="https://github.com"
uv tool install \
  "git+${GITHUB}/${OWNER}/${REPO}.git"

uvx --from playwright \
  playwright install chromium
```

### 팀 개발용 clone 설치

코드를 수정하고 PR을 만드는 팀원은 저장소를 clone한 뒤 editable tool로 연결합니다.

```bash
git clone https://github.com/Oyeonseok/WHS4_DAST_Project.git
cd WHS4_DAST_Project
uv sync --group dev
uv tool install --editable .
```

이후 어느 폴더에서든 `aidast`를 실행할 수 있으며, clone 폴더의 코드 수정이
재설치 없이 바로 반영됩니다.

### 설치 확인과 로그인

설치를 확인하고 Codex에 로그인합니다.

```bash
aidast --help
aidast login
```

`aidast login`은 Codex CLI 로그인 화면을 열고 완료 후 상태를 확인합니다.
인증 정보는 저장소나 AI DAST DB가 아니라 Codex CLI 사용자 설정에 저장됩니다.

### 업데이트

일반 사용자와 팀 개발자 모두 현재 설치를 삭제하지 않고 업데이트할 수 있습니다.

```bash
aidast update
```

GitHub에서 uv tool로 설치한 경우 패키지를 다시 내려받아 갱신합니다. editable
설치에서는 연결된 Git 저장소가 깨끗한지 확인한 뒤 현재 브랜치를
`git pull --ff-only`로 업데이트하고 tool 의존성을 새로 맞춥니다. 로컬 변경사항이
있으면 작업을 덮어쓰지 않고 중단하므로 먼저 commit하거나 stash해야 합니다.

### Recon 실행 도구

선택한 Recon 단계에 따라 다음 도구가 필요합니다.

```text
subfinder  dnsx  naabu  nmap
katana     ffuf  mitmdump
```

일부 선택 도구는 없으면 건너뜁니다. 단, wildcard 자산 발견에 필요한
Subfinder가 없거나 실패하면 해당 타깃을 실패 처리하고, 정책 강제에 필요한
`mitmdump`를 시작하지 못하면 Recon을 실행하지 않습니다.

## 빠른 시작

### 1. Scope 수집 및 승인

```bash
aidast scope "<PROGRAM_URL>"
```

생성된 임시 `Scope.md`를 원본 프로그램 페이지와 대조한 뒤 승인합니다.

로그인이 필요한 Intigriti researcher 페이지는 격리된 persistent Chromium을
열어 플랫폼 로그인과 MFA를 완료한 뒤 수집합니다.

```bash
aidast scope "<INTIGRITI_RESEARCHER_PROGRAM_URL>" \
  --login-mode runtime-browser \
  --identity "<ACCOUNT_LABEL>"
```

브라우저에서 정확한 프로그램 상세 페이지로 돌아와 Scope 화면을 연 다음
터미널에서 Enter를 누릅니다. 브라우저 프로필에는 인증정보가 포함되므로
공유하거나 Git에 추가하면 안 됩니다.

Adobe Public 프로그램을 `aidast`로만 운영하는 명령 허용 목록과 단계별 게이트는
[Intigriti Adobe Public aidast-only 가이드](docs/guides/INTIGRITI_ADOBE_PUBLIC_AIDAST_ONLY.md)를
참고하세요.

모든 기본 산출물을 저장소 밖의 한 디렉터리에 모으려면
`AIDAST_RESULT_ROOT`를 지정합니다.

Intigriti 프로그램에서 요청 식별 헤더를 요구하면 Recon 또는 통합 실행에
사용자명을 전달합니다.

```bash
aidast recon "<INTIGRITI_RESEARCHER_PROGRAM_URL>" \
  --all-targets \
  --intigriti-username "<INTIGRITI_USERNAME>" \
  --execute
```

```bash
export AIDAST_RESULT_ROOT="/path/to/dast_result"
```

이 설정은 기본 Scope, Recon DB/Surface, Runs, Attack, Validation, Report 경로에
적용됩니다. 명령에서 개별 출력 경로를 지정하면 해당 명령의 명시적 값이 우선합니다.

```text
이 Scope를 승인하고 저장할까요? [y/N]:
```

`y`만 승인으로 처리합니다. `n` 또는 Enter를 입력하면 임시 산출물을 폐기합니다.

```bash
aidast scope status "<PROGRAM_URL>"
```

### 2. 네트워크 요청 없이 정책 확인

```bash
aidast recon "<PROGRAM_URL>" --policy-only
```

Scope 해석, `TargetPolicy.json`, 도구 제어값만 확인하며 실제 타깃에는 요청하지 않습니다.

### 3. 승인된 전체 자산 실행

```bash
aidast run "<PROGRAM_URL>" --all-targets
```

일부 canonical 자산만 실행하려면 `--target`을 반복해서 지정합니다.

```bash
aidast run "<PROGRAM_URL>" \
  --target "example.com" \
  --target "api.example.com"
```

`aidast run`은 Recon, 태깅, Handoff, Native Attack, Chaining,
Shared Validation 순서로 실행합니다. Report는 검토할 Validation case를 선택한 뒤
별도 명령으로 생성합니다.

### 4. 검증된 case로 Report 초안 생성

```bash
aidast report run \
  result/AttackRuns/<scan_id>/Pipeline.db \
  --case-id <case_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>
```

지원 플랫폼은 `hackerone`, `intigriti`, `bugcrowd`입니다.
`CONFIRMED` case만 초안을 만들 수 있습니다.

## 핵심 워크플로

### Scope

Scope 산출물은 `result/Scope/<platform>/<program>/` 아래에 프로그램별로
분리합니다. 사용자 승인 뒤에는 `Scope.md`와 `Scope.json`의 무결성을 검사하며
기존 산출물을 자동으로 덮어쓰지 않습니다. 전체 파일 구성은
[Scope 수집과 정책](docs/OPERATIONS.md#scope-수집과-정책)을 참고하세요.

### Recon

```bash
aidast recon "<PROGRAM_URL>"
```

기본 명령은 승인된 Scope를 재사용하거나 새 Scope 승인을 받은 뒤 Recon Plan과
Task를 생성합니다. 실제 실행에는 `--execute`와 `--target` 또는 `--all-targets`가
필요합니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --target "example.com" \
  --start-url "https://example.com/app" \
  --max-rps 0.5 \
  --max-requests 100 \
  --execute
```

`--start-url`은 host, scheme, port, path 범위를 더 좁히며 형제 경로나 다른
타깃으로 일반화되지 않습니다. Scope에서 추출한 제한과 CLI 옵션의 적용 순서,
wildcard 배치, 브라우저 모드는 [Recon 실행 제어](docs/OPERATIONS.md#recon-실행-제어)를
참고하세요.

### 관측 태깅

미태깅 Recon 관측은 별도로 재개할 수 있습니다.

```bash
aidast tag result/Recon.db
```

같은 Recon 명령에서 태깅까지 이어가려면 `--tag-after`를 사용합니다.
태깅 worker는 실제 타깃에 접근하지 않으며 요청/응답 본문, 쿠키, 인증 헤더,
form 입력값을 LLM에 전달하지 않습니다.

### Handoff와 통합 DB

Recon 묶음은 `result/Runs/<scan_id>/`, 후속 단계가 공유하는 DB는
`result/AttackRuns/<scan_id>/Pipeline.db`에 저장합니다.

`Handoff.json`은 관련 artifact의 SHA-256, 크기, 역할과 scan ID를 기록합니다.
원본 `Recon.db`는 SQLite query-only 모드로 검증하고 backup으로 `Pipeline.db`를
만듭니다. 복제 전후 원본 해시가 달라지면 파이프라인을 중단합니다.
전체 산출물 구성은
[Handoff와 데이터 무결성](docs/OPERATIONS.md#통합-파이프라인과-데이터-무결성)을
참고하세요.

### Attack 실행 경계

`aidast.attack`에는 AI-DAST-ALL을 기준으로 병합한 로컬 승인 워크플로,
Ed25519 승인 검증, 요청 intent, 세션 바인딩, 정책 실행기와 내구성 있는 요청 예산
구현이 포함됩니다. 이 경로는 애플리케이션이 신뢰할 수 있는
`SkillAttackWorkflow` 또는 `SessionAttackLauncher`를 명시적으로 구성해 주입할
때만 네트워크 실행이 가능합니다.

일반 CLI의 `aidast attack approve`와 `aidast attack execute`는 명령행 입력만으로
신뢰 경계를 만들지 않습니다. 주입된 워크플로가 없으면 파일을 열거나 요청을
보내기 전에 실패합니다. 실행하려면 다음 항목이 모두 일치해야 합니다.

- Ed25519로 검증된 실행 승인과 현재 revocation generation
- 실행 계획에 결합된 정확한 요청 intent digest
- 승인된 Scope에서 파생된 `TargetPolicy`와 영속 요청 예산
- 타깃과 identity에 정확히 결합된 일반 파일 형태의 세션 상태

통합 `aidast run`의 Native Attack은 후속 Validation·Report와 같은
`Pipeline.db`를 사용합니다. 병합된 로컬 승인 워크플로의 thin Attack DB는 별도
호환 경로이며 Recon 원본을 읽기 전용으로 유지합니다.

### Validation

```bash
aidast validate status \
  result/AttackRuns/<scan_id>/Pipeline.db \
  --scan-id <scan_id>
```

최종 상태는 `CONFIRMED`, `DISPROVEN`, `OUT_OF_SCOPE`, `KNOWN`,
`UNDERPOWERED`, `BLOCKED`, `INCONCLUSIVE`, `CONTESTED` 중 하나입니다.
모델이 최종 상태를 직접 정하지 않습니다.

Shared Validation과 case 기반 Report는 현재 `Pipeline.db` schema v10 계약을
그대로 사용합니다. Attack finding의 runtime, development,
impact-development 재현 계약은 정규화된 해시와 함께 원자적으로 저장되며,
Report는 해당 Validation case가 허용한 evidence만 인용합니다. 생성 결과는 항상
로컬 초안이고 플랫폼에 자동 제출되지 않습니다.

## 주요 명령

| 명령 | 설명 |
| --- | --- |
| `aidast login` | Codex CLI 로그인 및 상태 확인 |
| `aidast update` | 설치 방식에 맞춰 AI DAST를 제자리에서 업데이트 |
| `aidast scope` | 프로그램 Scope 수집 또는 상태 확인 |
| `aidast recon` | Recon 계획, 정책 확인, 선택적 실행 |
| `aidast tag` | 저장된 Recon 관측 태깅 재개 |
| `aidast run` | Recon부터 Shared Validation까지 통합 실행 |
| `aidast attack` | 오프라인 계획·상태 관리와 주입된 신뢰 워크플로 실행 경계 |
| `aidast validate` | Shared 또는 Legacy Validation 실행·재개·조회 |
| `aidast report` | 로컬 Report 초안 생성 및 상태 확인 |

각 명령의 전체 옵션은 `aidast <command> --help`로 확인할 수 있습니다.
`Legacy`는 통합 `aidast run` 이전에 저장된 DB를 계속 사용할 수 있게 남겨 둔
호환 경로입니다. 자세한 차이는
[Legacy Attack 경로](docs/OPERATIONS.md#legacy-attack-경로)를 참고하세요.

## 결과 폴더

기본 산출물은 Git에서 제외되는 `result/` 아래에 저장됩니다.

- `Scope/<platform>/<program>/`: 프로그램별 Scope와 승인 정보
- `Runs/<scan_id>/`: Recon, Surface, Handoff 산출물
- `AttackRuns/<scan_id>/`: 통합 `Pipeline.db`
- `ReportRun/`: case 기반 Report 초안
- `AttackRun/`, `ValidationRun/`: Legacy 호환 데이터
- `.aidast_sessions/`: 로컬 로그인 세션

`--output-dir`, `--db-path`, `--surface-path`, `--run-root` 등으로 경로를
명시하면 해당 경로를 사용합니다.

## 프로젝트 구조

- `agents/`: 제한된 Codex 호출 adapter
- `orchestration/`: 단계 순서와 gate
- `scope/`, `recon/`: Scope 모델, Recon 실행과 관측
- `pipeline/`: Handoff와 `Pipeline.db`
- `attack/`, `chaining/`: 후보 조사와 finding 연결
- `validation/`, `reporting/`: 검증과 Report
- `skills/`: 단계별 로컬 Skill

## 개발

```bash
uv sync --group dev
uv run pytest -q
```

배포 의존성만 설치하려면 `uv sync --no-dev`를 사용합니다.
테스트 탐색 경로는 루트 `tests/`로 고정되어 있습니다.

## 상세 문서

- [운영 상세](docs/OPERATIONS.md): Recon 경계, 인증, 예산, 진단, Legacy 경로
- [병합 변경 이력](docs/changes/MERGE_CHANGES.md): 통합 전후 차이와 변경 이유
- [Attack Agent 병합 설계](docs/design/ATTACK_AGENT_MERGE_DESIGN.md)
- [외부 Claude-BugHunter 출처와 라이선스](docs/third-party/claude-bughunter/README.md)
