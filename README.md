# AI DAST

승인된 버그바운티 Scope를 정책으로 변환하고 Recon, 오프라인 Attack 계획,
Validation, Report 단계를 연결하는 멀티에이전트 AI DAST CLI입니다. 로그인된
Codex CLI가 네이티브 Skill을 사용해 범위와 수집 결과를 해석하고, 실제 네트워크
요청은 Python 검증기와 정책 경계를 통과한 경우에만 실행합니다.

## Requirements

- Python 3.13 이상
- [uv](https://docs.astral.sh/uv/)
- [Codex CLI](https://github.com/openai/codex)
- Playwright Chromium

실제 Recon 실행에는 선택한 단계에 따라 `subfinder`, `dnsx`, `naabu`, `nmap`,
`katana`, `ffuf`, `mitmdump`가 필요합니다. 설치되지 않은 선택 도구는 건너뛰지만,
정책 강제에 필요한 `mitmdump`를 시작하지 못하면 실행을 중단합니다.

## Result Directory

별도 옵션을 지정하지 않으면 실행 중 생성되는 모든 결과물과 타깃 세션은 Git에서
제외되는 `result/` 아래에 저장됩니다. 폴더가 없으면 각 명령이 필요한 상위 폴더까지
자동으로 생성합니다.

```text
result/
├── Scope/<platform>/<program>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Runs/<scan_id>/
├── AttackRuns/<scan_id>/
├── ValidationRun/
├── ReportRun/
└── .aidast_sessions/
```

`--output-dir`, `--db-path`, `--surface-path`, `--run-root` 등으로 경로를 직접
지정하면 해당 명시적 경로를 사용합니다.

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
result/Scope/<platform>/<program>/
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

Recon Plan과 Task는 같은 프로세스 안의 구조화된 객체로 전달됩니다. 기본 명령은
계획만 출력하며, 정책이 강제되는 실제 실행은 명시적으로 선택할 수 있습니다.

기본 `aidast recon`은 기존처럼 계획과 Task만 생성합니다. `--policy-only`는 선택
없이 전체 정책을 미리 볼 수 있지만, 실제 실행에는 승인된 `Scope.json`의 canonical
자산을 `--target`으로 지정하거나 `--all-targets`를 명시해야 합니다. `--target`은
여러 번 사용할 수 있으며 부분 문자열이나 유사 도메인은 허용하지 않습니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --target "example.com" \
  --start-url "https://example.com/owned/app" \
  --profile safe-recon \
  --max-rps 0.5 --max-requests 100 --execute \
  --db-path result/Recon.db --surface-path result/Surface.json \
  --ffuf-wordlist /path/to/wordlist.txt
```

`--max-rps`와 `--max-requests`는 Main Agent가 만든 정책보다 낮은 상한만 적용합니다.
더 큰 값을 전달해도 승인된 정책의 제한은 완화되지 않습니다.
`--start-url`은 단일 canonical `--target` 아래에서 운영자가 통제하는 실제 시작
URL을 선언하며, 호스트·scheme·port·path를 더 좁히는 실행 경계로 사용됩니다.
Python이 생성 모델의 출력과 무관하게 해당 타깃 정책을 이 정확한 host와 path subtree로
다시 제한하므로 다른 타깃이나 같은 호스트의 형제 경로로 일반화되지 않습니다.
이 경계 밖으로 이동하는 최상위 페이지와 Katana/ffuf 요청은 계속 차단합니다.
다만 승인된 페이지를 렌더링할 때 Playwright가 직접 발생시킨 읽기 전용 동일-origin
API 요청과 외부 정적 리소스 요청은 실행별 브라우저 표식을 검증한 뒤 로딩만
허용합니다. 동일-origin 지원 요청은 관측할 수 있지만 능동 도구의 실행 경계를
넓히지 않으며, SPA 렌더링에 필요한 동일-origin POST XHR/fetch도 수동 관측 대상으로
기록합니다. 외부 정적 리소스는 Recon endpoint나 HTTP 증거로 저장하지 않습니다.
Linux/macOS의 기본 `--login-mode runtime-browser`는 Endpoint Discovery의 Phase 1에서
프록시 없는 Chromium으로 로그인한 뒤 같은 영속 프로필을 프록시·Scope 적용 상태로
다시 엽니다.
브라우저 사이에 세션을 전달하지 않으므로 서버가 로그인 환경 변경을 거부하는 사이트에
적합합니다. 운영체제의 플랫폼 패스키가 필요하면 `--login-mode system-browser`를
사용합니다. 모든 운영체제의 기본값은 `runtime-browser`이며 Endpoint Discovery Phase 1에서
Playwright Chromium으로 로그인한 뒤 동일한 Chromium 프로필을 Phase 2 Recon에 재사용합니다.
로그인 직후 브라우저를 재시작하지 않고 동일한 Chromium 컨텍스트에 정책·관측 핸들러만
적용하므로 Shopify Admin처럼 브라우저 컨텍스트를 확인하는 서비스도 로그인 상태를 유지합니다.
Windows Chrome 세션을 명시적으로 사용하려면 `--login-mode system-browser`를 지정합니다.
Shopify Admin처럼 브라우저 컨텍스트에 세션을 묶는 서비스에서 전달된 세션이
권한 오류를 반환하면 Phase 2 Chromium 로그인 창이 자동으로 열립니다. 해당
Chromium에서 직접 로그인한 뒤 Enter를 누르면 세션을 저장하고 정책 적용 상태로
Endpoint Discovery를 재개합니다.
`--session-bundle`을 지정하면 두 모드 대신 기존 세션을
검증해 재사용합니다.
취소·저장·복귀 실패 시 자동 탐색으로 진행하지 않습니다. 재로그인에도 같은
전환을 적용합니다. 수동 로그인 중 Enter 입력은 최대 5분 대기하며, 입력이 없으면
현재 세션을 자동 저장합니다. 수동 로그인 중의 트래픽은 Recon에 수집되지 않으며,
외부 로그인 URL은 탐색 대상으로 추가하지 않습니다. 프록시 정책과 Recon의
기존 실행 상한은 유지됩니다.
Recon의 자동 form submission은 항상 비활성화됩니다. Scope의 out-of-scope 호스트는
`excluded_hosts`로 컴파일되며 wildcard 허용보다 우선하여 Python 요청 경계,
subdomain 승격, Playwright 및 mitmproxy에서 차단됩니다.
`--auth-host`와 `--auth-path`는 기존 CLI 호환용으로 남아 있지만, 수동 로그인에는
필요하지 않으며 자동 수집 단계의 Scope를 확장하지 않습니다.
`runtime-browser` 로그인 창은 설치된 Playwright Chromium과 실행별 전용 프로필을
사용하므로 평소 사용하는 Chrome과 동일한 환경은 아닙니다. 외부 서비스의 연결 검증이
계속되거나 프록시 전환 후 다시 요구될 수 있습니다.
선택한 Scope 자산 밖의 URL이거나 생성 정책이 해당 URL을 허용하지 않으면 실제
도구를 호출하기 전에 실행을 중단합니다.

실행 수치는 승인된 Scope에서 근거와 함께 추출한 정책을 우선합니다. 기본 실행에는
프로파일 상한을 추가하지 않습니다. Scope에 명시된 수치는 내부 기본값보다 커도
모델 스키마가 지원하는 범위 안에서 유지합니다. Scope에 수치가 없는 항목만 기존
애플리케이션 기본값(1 RPS, concurrency 3, depth 3, timeout 20초, 최대 2,000 요청)을
사용하며, 이를 Scope에서 추출한 제한으로 간주하지 않습니다.
`--profile safe-recon` 또는 `--profile focused-recon`은 사용자가 명시했을 때만
추가 상한으로 적용합니다. `--max-rps`, `--max-requests`, `--max-depth`,
`--max-concurrency`, `--timeout-seconds`도 명시한 경우에만 정책을 더 좁힙니다.

`max_requests`는 타깃별 HTTP 요청 한도입니다. HTTP probe에서 소비한 요청과 redirect
횟수를 먼저 차감하고, 남은 한도를 endpoint discovery의 공용 mitmproxy에 전달합니다.
따라서 Playwright, Katana, ffuf 및 API 2차 탐색은 각자 한도를 새로 시작하지 않고
남은 요청 예산을 함께 사용합니다. DNS 질의와 포트 스캔 패킷 수는 이 HTTP 요청
한도에 포함되지 않으며, 허용 포트와 각 도구의 속도·동시성 설정으로 별도 제한합니다.

Endpoint 후보는 브라우저 동일-origin API, document/redirect, form/API 후보, Katana,
ffuf, 정적 리소스 순으로 우선 처리합니다. 중복 요청은 예산에서 제외하고 정적
리소스는 별도 분류하며, 예산 초과로 차단된 후보는 `deferred_candidates`에 저장합니다.

실행 직전에 Main Agent가 승인된 `Scope.md`를 구조화된 `TargetPolicy.json`으로
변환합니다. Python 검증기가 Plan의 타깃과 정책의 타깃이 정확히 일치하는지,
서브도메인 허용이 명시적인 wildcard 자산에만 적용되는지 확인합니다. Katana와
ffuf에는 속도·동시성·깊이 제한을 전달하고, Playwright를 포함한 프록시 트래픽은
mitmproxy에서 scheme, host, port, path, method, 총 요청 수를 다시 검사합니다.
정책 강제 모드에서 mitmproxy를 시작할 수 없으면 Recon은 실행되지 않습니다.
실행 중 일반 오류뿐 아니라 `Ctrl-C` 같은 제어 종료가 발생해도 현재 scan과 stage를
`failed`로 마감하고 DB 연결을 닫은 뒤 종료 신호를 다시 전달합니다. 프로세스 강제
종료나 전원 손실처럼 정리 코드를 실행할 수 없는 경우에는 마지막 상태가 남을 수 있습니다.

### Temporary Recon diagnostics

도구별 결과가 지나치게 적거나 필터링 원인을 조사할 때만 `--diagnostic-logs`를
사용합니다.

```bash
aidast run "<PROGRAM_URL>" --target "<CANONICAL_ASSET>" --diagnostic-logs
```

로그는 `result/logs/<scan_id>/recon.jsonl`에 생성됩니다. 다음 내용을 단계별 JSONL로
기록합니다.

- 적용된 host, port, path, method와 남은 HTTP 요청 예산
- Katana 프로세스 종료 코드, 출력 행 수, 추출 form 수, parser 제거 수와 endpoint 목록
- ffuf root와 root별 종료 코드
- Playwright/Katana/ffuf/API 결과의 정책 필터 전후 개수
- primary/final deduplication 및 executor 정규화 전후 endpoint
- mitmproxy 허용·차단 요청 개수

인증 헤더·쿠키·요청/응답 본문·세션 파일 경로는 기록하지 않으며 URL query와 fragment도
제거합니다. 그래도 경로 자체에 계정 식별자가 들어갈 수 있으므로 로그는 로컬 진단 자료로
취급하고 외부에 그대로 공개하지 마세요. 이 옵션은 기본적으로 꺼져 있으며 원인 수정 후
플래그와 `aidast.recon.diagnostics` 연결부를 제거해도 Recon 실행 흐름에는 영향이 없습니다.

실제 타깃에 요청하지 않고 Scope 해석, 정책 JSON 및 도구 제어값만 검증하려면:

```bash
aidast recon "<PROGRAM_URL>" --policy-only
```

## Skills

Scope 수집과 의미 해석은 Main Agent의 Codex 네이티브 Skill로 관리됩니다.

```text
src/aidast/skills/scope/SKILL.md
```

실행 시 Skill은 Codex 표준 경로인 `.agents/skills/aidast-scope/SKILL.md`에 임시 배치되고 `$aidast-scope`로 명시적으로 호출됩니다. Codex가 URL을 직접 열어 동적 Scope와 정책을 수집합니다.

HackerOne이나 Bugcrowd처럼 Codex 네이티브 브라우저가 JavaScript 페이지를 완전히 렌더링하지 못하면, 코드가 제한된 Playwright 브라우저로 같은 URL을 수집하고 Codex가 동일한 네이티브 Skill로 해당 캡처를 해석합니다. 사용자 승인, 원문 근거 검증, 무결성 검사와 공식 저장은 코드가 담당합니다.

## Development

```bash
uv sync --group dev
uv run pytest -q
```

`pytest`는 개발 의존성 그룹에 포함되어 있습니다. 배포용 설치만 필요하면 기본
`uv sync --no-dev`를 사용할 수 있습니다.
테스트 탐색 경로는 루트의 `tests/`로 고정되어 있어, 작업 폴더 안에 보관된 이전
프로젝트 복사본의 동명 테스트를 중복 수집하지 않습니다.

## Security Notes

- 페이지 내용은 신뢰할 수 없는 입력으로 처리합니다.
- Codex 로그인 정보는 저장소에 포함하지 않습니다.
- `result/`, `.env`, `.venv/`는 Git에 포함하지 않습니다.
- 로그인 세션에는 쿠키·스토리지·토큰이 포함될 수 있으므로 `result/.aidast_sessions/`와
  브라우저 프로필을 공유하거나 Git에 커밋하지 않습니다.
- `runtime-browser`와 `system-browser` 세션 전달이 구현되어 있지만 서비스별 로그인
  성공이나 프록시 전환 후 세션 유효성을 범용적으로 보장하지는 않습니다.


## Recon observation annotations

실제 CLI Recon 실행은 LLM 호출로 멈추지 않고 관측 맥락을 먼저 저장합니다. 실행이
끝난 뒤 별도 worker를 실행해 최대 200개 관측씩 Codex로 기능 태깅합니다. 각 관측의
시각과 context를 함께 전달해 타임라인을 유지하며, 배치별 실패 상태를 기록합니다.
계획 및 `--policy-only`는 태깅을 실행하지 않습니다. 라이브러리에서
`ReconExecutor`를 직접 사용할 때도 기본적으로 관측만 저장합니다.

저장된 미태깅 관측은 다음처럼 재개·재시도할 수 있습니다(이미 태깅된 관측은 건너뜀).

```bash
.venv/bin/python -m aidast tag result/Recon.db
```

Recon과 같은 명령에서 이어서 태깅하려면 `--tag-after`를 추가합니다. 옵션을
생략하면 Recon은 관측 저장만 수행합니다.

- `discovery_contexts`: 페이지, 자동 클릭, 당시 인증 상태 및 세션 연결.
- `endpoint_observations`: 병합 전 발견 기록과 출처, 실제 HTTP 트랜잭션 근거.
- `annotation_runs`: 모델 선택 방식, 프롬프트/태그 목록 버전, 성공·실패 이력.
- `endpoint_annotations`: 관측별 기능/페이지/데이터 역할 태그와 판단 근거.

기존 Recon DB는 열 때 additive SQLite schema `user_version=4`로 마이그레이션됩니다. 기존 행은
보존하며, 출처를 알 수 없는 과거 트랜잭션이나 관측 맥락을 추측해 채우지 않습니다.
`Surface.json`은 기존 필드를 유지하며 `schema_version`, `endpoint_id`,
`observations`, `annotations`, `annotation_runs`를 추가합니다.

LLM에는 요청·응답 본문, 쿠키, 인증 헤더, 폼 입력값을 전달하지 않습니다. URL의
사용자정보·query·fragment를 제거하고 페이지 제목과 동작 설명을 제한합니다.
경로와 화면 설명에 포함된 임의의 민감정보까지 완전히 식별하는 필터는 아닙니다.
인증이 확인되지 않은 상태는 `unknown`으로 저장합니다. 수동 로그인 중 요청은
페이지 맥락으로, 자동 클릭 중 요청은 시간 구간 연관으로 기록하며 인과관계를
확정하지 않습니다. 프록시와 브라우저 요청은 URL만으로 동일 요청이라고 연결하지
않고 별도 관측으로 보존합니다. 모델 confidence는 검증된 확률이 아닙니다.
태깅 실패 시 수집 결과를 보존하고 실패 상태를 내보냅니다. 실패한 배치는 다음
`tag` 실행에서 다시 시도할 수 있으며, 태깅 worker는 실제 타깃에 접근하지 않습니다.

Recon 실행에서는 전체 HTTP 예산의 20%를 Endpoint/브라우저 관측용으로 예약합니다.
DNS·HTTP Probe·Origin 단계가 예산을 먼저 소진해 Headless/API 관측이 0건이 되는
상황을 방지하며, 예약분을 포함한 전역 예산은 mitmproxy에서 계속 공유됩니다.

GraphQL 능동 확인은 기본적으로 비활성화되어 있습니다. 승인된 타깃에서만
`TargetPolicy.json`의 `api_probe.graphql=true`와 구체적인 `allowed_paths`를
설정하며, 해당 경로에 한해서만 확인용 POST가 허용됩니다.

## Scope → Recon Agent → Attack Agent

승인된 canonical Scope 전체를 대상으로 통합 파이프라인을 실행하려면:

```bash
aidast run "<PROGRAM_URL>" --all-targets
```

일부 자산만 실행하려면 `--target`을 반복해서 지정합니다. `run`은 기존 Recon의
subdomain/DNS/port/HTTP/origin/Playwright/Katana/ffuf/API 수집을 그대로 실행하고,
저장 결과를 Recon Agent가 한 번 더 read-only로 검토합니다. 이후 scan을
`completed`로 닫고 다음 산출물을 `result/Runs/<scan_id>/`에 만듭니다.

```text
result/Runs/<scan_id>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Scope.json
├── Approval.json
├── TargetPolicy.json
└── Handoff.json
```

`Handoff.json`에는 각 파일의 SHA-256, 크기, 역할과 scan ID가 들어갑니다. Attack
단계는 이를 모두 검증하고 완료된 scan만 받아 `result/AttackRuns/<scan_id>/Attack.db`에
오프라인 계획을 저장하고 `review/`에 endpoint와 annotation 기반 검토 큐를
생성합니다. 기존 handoff만 다시 소비해 검토 큐를 생성할 수도 있습니다.

```bash
aidast attack result/Runs/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<scan_id>
```

기본 CLI는 오프라인 증거 검토/계획까지만 실행합니다. 동적 실행 코어는 별도로
구현되어 있지만, 검토된 고정 adapter의 HEAD/GET/OPTIONS 응답 메타데이터 관찰만
지원하며 신뢰된 승인 workflow와 `TargetPolicy` broker가 주입되지 않으면
fail-closed됩니다. 외부 Attack playbook 59개는 아직 실행 코드가 아닌 비활성
참고 카탈로그이므로 임의 payload나 shell 명령을 실행하지 않습니다.

따라서 현재 Attack 단계는 SQL injection, XSS, IDOR 같은 취약점을 능동적으로
검증하는 완성형 공격기가 아닙니다. 기본 CLI의 `approve`와 `execute`는 서명·만료·
철회·계획 바인딩을 검증하는 신뢰된 workflow가 애플리케이션에서 주입되지 않으면
항상 거부됩니다.

새로운 오프라인 실행 상태는 별도 `Attack.db`에 저장합니다. Recon handoff를
검증한 뒤 Attack 전용 DB에 계획과 작업만 기록하고, Recon 원본은 읽기 전용으로
참조합니다. DB를 열 때도 handoff와 원본 파일의 SHA-256을 다시 검증하므로
원본이 누락되거나 변경되면 열기를 거부합니다. SQLite의 `-wal`, `-journal`,
`-shm` 파일이 없는 완결된 Recon snapshot이 필요합니다.
기존 `aidast attack HANDOFF`는 계속 검토 큐만 생성합니다.

새 review config는 handoff 위치를 config 디렉터리 기준 상대 경로로,
Recon DB 위치를 handoff 디렉터리 기준 상대 경로로 기록합니다. 저장된 계획의
경로도 review 디렉터리 기준이므로 `result/Runs/`와 `result/AttackRuns/`의 상대 배치를
유지해 함께 이동하면 같은 계획을 재사용할 수 있습니다. CLI가 출력하는 DB와
검토 큐 경로는 현재 위치를 가리킵니다. 기존 절대 경로 review config는 원래
위치에서 계속 사용할 수 있으며, Recon을 복제한 구형 Attack DB는 새 출력
디렉터리에서 다시 `plan`을 생성해야 합니다.

```bash
aidast attack plan result/Runs/<scan_id>/Handoff.json --output-dir result/AttackRuns/<scan_id>
aidast attack status result/AttackRuns/<scan_id>/Attack.db
aidast attack revoke result/AttackRuns/<scan_id>/Attack.db --reason "검토 중단"
```

`plan`은 실행 ID, DB 경로, 작업 수와 검토 큐 경로를 JSON으로 출력합니다.
`status`와 `revoke`는 `--run-id`로 실행을 선택할 수 있으며, `revoke`는 저장된
실행의 승인 폐기 세대를 증가시킵니다. 카탈로그 항목은 비활성 메타데이터입니다.
기본 `revoke`는 로컬 AttackStore를 갱신합니다. 별도 broker 예산 ledger의
폐기 상태와는 구분되므로, 연결된 실행기는 매 요청마다 저장된 실행 상태와
폐기 세대도 검증해야 합니다. 워크플로가 주입되면 `revoke`도 해당 워크플로에
위임하며, 워크플로는 store와 ledger의 승인을 일관되게 폐기해야 합니다.

`approve`와 `execute` 명령은 신뢰된 애플리케이션이
`main(argv, attack_workflow=...)`로 검증 경계를 주입했을 때만 사용할 수 있습니다.
두 명령 모두 `--authorization FILE`이 필요하고, `approve`는 `--by REVIEWER`도
필요합니다. 기본 CLI에서는 명령을 거부하며, 파일 경로나 검토자 이름만으로
승인이 성립하지 않습니다. 주입된 워크플로가 서명·만료·폐기·계획 바인딩을
검증하고 안전한 Agent와 broker를 연결해야 합니다. CLI는 승인 키를 생성하지 않습니다.

### Validation Agent와 Report Agent

Attack 실행기가 저장한 finding은 프로젝트 내 `aidast-validation` Skill로 7-Question과
기존 PoC 증거를 검토합니다. Validation은 Recon/Attack DB를 수정하지 않고, 원본 DB
해시와 finding·evidence·request ID에 묶인 판정 이력을 별도 `Validation.db`에 저장합니다.

```bash
aidast validate run result/AttackRuns/<scan_id>/Attack.db \
  --finding-id <finding_id> \
  --output-dir result/ValidationRuns/<scan_id>
aidast validate status result/ValidationRuns/<scan_id>/Validation.db
```

최종 상태는 `confirmed`, `rejected`, `needs_evidence` 중 하나이며 모델이 직접 상태를
지정하지 않습니다. Python이 7개 답변, 존재하는 증거 ID, PoC request ID와 응답
hash/길이의 연결을 검사해 계산합니다. 기본 검토기는 증거가 부족하면 fail-closed하고,
CLI의 Codex 검토도 저장된 증거만 읽으며 PoC를 새로 실행하지 않습니다. 따라서
`confirmed`는 저장된 PoC 증거에 대한 오프라인 판정이며 새로운 재실행을 의미하지 않습니다.

Report Agent는 `confirmed`로 저장된 Validation만 받아 `aidast-reporting` Skill로 로컬
초안을 만듭니다. 지원 플랫폼은 HackerOne, Intigriti, Bugcrowd 세 가지이며 제출이나
플랫폼 접속은 하지 않습니다.

```bash
aidast report run result/ValidationRuns/<scan_id>/Validation.db \
  --validation-id <validation_id> \
  --platform hackerone \
  --output-dir result/ReportRuns/<scan_id>
aidast report status result/ReportRuns/<scan_id>/Report.db
```

결과 디렉터리에는 검증 가능한 `Report.db`, 구조화된 `Report.json`, 사람이 읽는
`Report.md`가 생성됩니다. 모든 사실 필드는 확인된 evidence ID를 인용해야 하며,
`--platform`은 `hackerone`, `intigriti`, `bugcrowd`만 허용합니다. 재현 가능한 팀 전달을
위해 Validation을 시작하기 전에 Attack DB 쓰기를 끝내야 합니다. 이후 Attack DB가
변경되면 기존 검증/보고서의 원본 확인은 실패하며 새 snapshot으로 다시 검증해야 합니다.

통합 전후 차이와 수정 이유는 `docs/changes/MERGE_CHANGES.md`에 누적합니다.

### 폴더 구성

핵심 단계는 `src/aidast/recon`, `attack`, `validation`, `reporting`으로 분리되어 있고,
각 Agent용 로컬 Skill은 `src/aidast/skills` 아래에 둡니다. 설계와 변경 이력은
`docs/design`, `docs/changes`, 외부 출처 보존 자료는 `docs/third-party`, 공용 wordlist는
`resources/wordlists`, 팀 전달용 ZIP은 `dist`에 둡니다. Scope, 세션, DB, JSON 등
실행 중 생성되는 자료는 모두 `result/` 아래에 두며 Git과 배포 ZIP에 포함하지 않습니다.


Katana는 Standard와 Headless 모두 JSONL 출력(`-j -or -ob -fx`)에서 발견 부모 URL,
HTML 태그/속성, 실제 HTTP 메서드, 응답 상태·종류·크기·리다이렉트를 추출합니다.
`-fx`의 form action/method도 별도 endpoint로 읽기 때문에 `<form method="post">`는
`POST`로 보존합니다. 이때 자동 입력·제출 옵션 `-aff`는 사용하지 않으며, POST를
수집하는 것과 실제 전송 권한을 분리합니다. 따라서 Recon 정책의 GET/HEAD/OPTIONS
제한과 프록시 차단은 그대로 유지됩니다. Headless에는 `-xhr`도 적용해 페이지에서
발생한 XHR/fetch의 URL과 POST 같은 실제 메서드를 JSONL에서 수집합니다. `-xhr` 자체는
요청을 새로 만들지 않습니다. 기존 URL 행 출력도 파싱할 수 있습니다.
ffuf는 탐색 루트, 관련 seed 경로(최대 10개), 응답 상태·종류,
크기·단어/줄 수와 리다이렉트를 남깁니다. 해당 필드가 없으면 추측하지 않습니다.
이 메타데이터는 `endpoint_observations.evidence_json`에 저장되며 Surface 2.1의
관측별 `evidence`와 LLM 입력에 함께 포함됩니다. 여러 루트에서 같은 경로를
발견해도 각 관측의 근거를 보존합니다. 추가 네트워크 요청은 발생시키지 않습니다.
프롬프트 버전 2는 soft-404 가능성과 부모 URL/탐색 루트의 의미를 구분하도록
지시합니다. 파서·저장·전달 경로는 테스트했으나 실제 모델 분류 정확도의 향상은
별도의 정답 데이터 평가가 필요합니다.
