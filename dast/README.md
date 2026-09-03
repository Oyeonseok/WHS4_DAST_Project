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

## Run Policy-Gated Recon Tools

`aidast recon`은 승인된 `Scope.md`를 번들된 `aidast-recon-policy` Skill에
전달하고 같은 Scope 디렉터리에 schema 1.0 `recon-policy.json`을 먼저
생성합니다. 기존 승인 Scope의 정책만 다시 생성하려면 다음 명령을 사용합니다.

```bash
aidast policy-compile ./artifacts/<program>/scope.md \
  --output ./artifacts/<program>/recon/recon-policy.json
```

컴파일 단계는 프록시를 시작하거나 도구를 실행하지 않습니다. 생성된 정책에서
명시적으로
`execution_decision: allow`인 HTTP 도구만 실행할 수 있습니다. target과
`--tool`을 모두 생략하면 정책의 모든 구체적인 HTTP(S) 대상과 실행 가능한
등록 adapter를 자동으로 선택합니다.

```bash
aidast policy-run ./Scope/<platform>/<program>/recon-policy.json
```

실제 요청 없이 자동 생성된 계획만 확인할 수도 있습니다.

```bash
aidast policy-run ./Scope/<platform>/<program>/recon-policy.json --plan-only
```

```bash
aidast policy-run ./recon-policy.json https://app.example.com \
  --tool katana \
  --db ./recon-policy.sqlite3 \
  --header "X-Bug-Bounty:researcher-name"
```

특정 대상이나 도구만 제한하려면 positional target, 반복 가능한 `--target`,
`--tool`을 사용합니다. ffuf에는 워드리스트가 필요합니다.

```bash
aidast policy-run ./recon-policy.json https://app.example.com \
  --tool curl \
  --tool ffuf \
  --target https://api.example.com/v1 \
  --wordlist ./paths.txt
```

실행기는 다음 조건을 모두 만족해야 도구를 시작합니다.

- 정책과 대상 URL이 schema 1.0 검증을 통과해야 합니다.
- 도구의 `execution_decision`이 `allow`여야 합니다.
- blocking review item과 누락된 runtime input이 없어야 합니다.
- 도구가 target HTTP 트래픽용 안전한 adapter를 지원해야 합니다.
- 모든 요청이 로컬 mitmproxy addon을 지나야 합니다.

addon은 deny 규칙을 먼저 적용하고, scope 밖 요청과 제한 초과 요청에는
로컬 403/429 응답을 반환합니다. 내부 실행 식별 헤더는 대상 서버로 보내기
전에 제거합니다. 도구 결과와 redacted proxy flow는 각각
`tool_executions`, `proxy_flows` 테이블에 같은 execution ID로 저장됩니다.

현재 안전한 adapter는 `curl`, `httpx`, `katana`, `playwright`, `ffuf`, `nuclei`를
지원합니다. provider API로 나가는 `subfinder`와 HTTP 프록시가 전체 트래픽을
보장하지 못하는 `nmap`은 별도 목적지 정책이 생기기 전까지 차단됩니다.
wildcard host와 CIDR은 임의로 확장하지 않으며, 발견된 구체 URL을 `--target`으로
전달했을 때 전체 정책 검사를 통과한 경우에만 실행합니다.

구현 파일별 설명은 `docs/policy-runtime-implementation.md`에 정리되어 있습니다.
상황별 실행·차단 흐름은 `docs/policy-execution-scenarios.md`에서 확인할 수 있습니다.

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
