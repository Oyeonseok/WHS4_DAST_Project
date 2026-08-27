# AI DAST

멀티에이전트 AI DAST의 Scope 수집 CLI입니다. 로그인된 Codex CLI가 네이티브 Scope Skill을 읽고 프로그램 URL에 직접 접속해 정책을 해석한 뒤, 검토 가능한 `Scope.md`를 생성합니다.

## Requirements

- Python 3.13 이상
- [uv](https://docs.astral.sh/uv/)
- [Codex CLI](https://github.com/openai/codex)
- Playwright Chromium

## Install from GitHub

```bash
uv tool install git+https://github.com/<OWNER>/<REPOSITORY>.git
uvx --from playwright playwright install chromium
```

설치 확인과 최초 로그인:

```bash
aidast --help
aidast login
```

`aidast login`은 설치된 Codex CLI의 로그인 화면을 열고, 완료 후 로그인 상태를 자동 검증합니다. 인증 정보는 AI DAST나 저장소가 아니라 Codex CLI의 사용자 설정에 저장됩니다.

## Collect Scope

```bash
aidast scope "프로그램 URL"
```

산출물은 프로그램별로 구분됩니다.

```text
Scope/<platform>/<program>/
├── Scope.md
├── Scope.json
├── Manifest.json
└── Approval.json
```

기존 프로그램 산출물은 자동으로 덮어쓰지 않습니다.

## Review and Approve Scope

명령을 실행하면 임시 `Scope.md` 경로가 출력됩니다. 원본 프로그램 페이지와 임시 문서를 대조한 뒤 터미널에서 승인 여부를 입력합니다.

```text
이 Scope를 승인하고 저장할까요? [y/N]:
```

- `y`: 프로그램별 공식 경로에 Scope 산출물을 저장합니다.
- `n` 또는 Enter: 임시 산출물을 모두 폐기하고 종료합니다.

검토자 이름을 명시하려면 다음과 같이 실행합니다. 생략하면 현재 운영체제 사용자명이 기록됩니다.

```bash
aidast scope "<PROGRAM_URL>" --by "<REVIEWER>"
```

승인 상태와 파일 무결성을 확인합니다.

```bash
aidast scope status "<PROGRAM_URL>"
```

승인 후 `Scope.md` 또는 `Scope.json`이 변경되면 무결성 검사가 실패합니다.

## Create Recon Plan and Tasks

```bash
aidast recon "<PROGRAM_URL>"
```

동작 순서:

1. 승인된 기존 Scope가 있으면 무결성을 검증한 뒤 재사용합니다.
2. 기존 Scope가 없으면 Scope 수집과 대화형 승인을 먼저 수행합니다.
3. Main Agent가 승인된 `Scope.md`를 읽고 Recon Plan을 생성합니다.
4. Coordinator가 Plan의 단계들을 의존 관계가 있는 Recon Task로 변환합니다.

현재 Recon Plan과 Task는 같은 프로세스 안의 구조화된 객체로 전달되며 DB나 파일에 저장하지 않습니다. Recon Agent 실행은 아직 포함되지 않습니다.

## Skills

Scope 수집과 의미 해석은 Main Agent의 Codex 네이티브 Skill로 관리됩니다.

```text
src/aidast/skills/scope/SKILL.md
```

실행 시 Skill은 Codex 표준 경로인 `.agents/skills/aidast-scope/SKILL.md`에 임시 배치되고 `$aidast-scope`로 명시적으로 호출됩니다. Codex가 URL을 직접 열어 동적 Scope와 정책을 수집합니다.

HackerOne이나 Bugcrowd처럼 Codex 네이티브 브라우저가 JavaScript 페이지를 완전히 렌더링하지 못하면, 코드가 제한된 Playwright 브라우저로 같은 URL을 수집하고 Codex가 동일한 네이티브 Skill로 해당 캡처를 해석합니다. 사용자 승인, 원문 근거 검증, 무결성 검사와 공식 저장은 코드가 담당합니다.

## Development

```bash
uv sync
uv run python -m unittest discover -s tests -v
```

## Security Notes

- 페이지 내용은 신뢰할 수 없는 입력으로 처리합니다.
- Codex 로그인 정보는 저장소에 포함하지 않습니다.
- `Scope/`, `.env`, `.venv/`는 Git에 포함하지 않습니다.
- 로그인 전용 프로그램의 인증 세션 기능은 아직 구현되지 않았습니다.
