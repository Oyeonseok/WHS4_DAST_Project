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
  --db-path Recon.db --surface-path Surface.json \
  --ffuf-wordlist /path/to/wordlist.txt
```

`--max-rps`와 `--max-requests`는 Main Agent가 만든 정책보다 낮은 상한만 적용합니다.
더 큰 값을 전달해도 승인된 정책의 제한은 완화되지 않습니다.
`--start-url`은 단일 canonical `--target` 아래에서 운영자가 통제하는 실제 시작
URL을 선언하며, 호스트·scheme·port·path를 더 좁히는 실행 경계로 사용됩니다.
선택한 Scope 자산 밖의 URL이거나 생성 정책이 해당 URL을 허용하지 않으면 실제
도구를 호출하기 전에 실행을 중단합니다.

실행 수치는 Codex가 아니라 Python 프로파일이 결정합니다. 기본 `safe-recon`은
0.5 RPS, depth 2, timeout 15초, 최대 500 요청이며 1 RPS 미만에서는 concurrency를
1로 낮춥니다. 명시적인 `--profile focused-recon`(기존 이름
`focused-discovery`도 호환)은 1 RPS, concurrency 3,
depth 3, timeout 20초, 최대 2,000 요청을 사용합니다. `--max-rps`,
`--max-requests`, `--max-depth`, `--max-concurrency`, `--timeout-seconds`는 선택한
프로파일과 Scope 근거 제한을 더 좁히는 방향으로만 적용됩니다.

실행 직전에 Main Agent가 승인된 `Scope.md`를 구조화된 `TargetPolicy.json`으로
변환합니다. Python 검증기가 Plan의 타깃과 정책의 타깃이 정확히 일치하는지,
서브도메인 허용이 명시적인 wildcard 자산에만 적용되는지 확인합니다. Katana와
ffuf에는 속도·동시성·깊이 제한을 전달하고, Playwright를 포함한 프록시 트래픽은
mitmproxy에서 scheme, host, port, path, method, 총 요청 수를 다시 검사합니다.
정책 강제 모드에서 mitmproxy를 시작할 수 없으면 Recon은 실행되지 않습니다.

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
uv sync
uv run python -m unittest discover -s tests -v
```

## Security Notes

- 페이지 내용은 신뢰할 수 없는 입력으로 처리합니다.
- Codex 로그인 정보는 저장소에 포함하지 않습니다.
- `Scope/`, `.env`, `.venv/`는 Git에 포함하지 않습니다.
- 로그인 전용 프로그램의 인증 세션 기능은 아직 구현되지 않았습니다.


## Recon observation annotations

실제 CLI Recon 실행은 기존 탐색 결과와 별도로 관측 맥락을 저장하고, 탐색 단계가
끝날 때 100개 관측씩 최대 3개의 독립 Codex 호출로 병렬 기능 태깅합니다. 완전히 같은
정제 입력은 한 번만 판정하고 결과를 각 관측에 연결합니다. 실패한 배치는 50개, 25개로
분할한 뒤 작은 배치를 한 번 더 재시도하며 진행률을 출력합니다. 계획 및
`--policy-only`는 태깅을 실행하지 않습니다. 라이브러리에서 `ReconExecutor`를 직접
사용할 때는 `annotation_agent`를 전달해야 LLM 태깅이 활성화됩니다.

중단되거나 반복 실패한 태깅은 Recon을 다시 실행하지 않고 shared DB에서 이어갈 수
있습니다.

```bash
aidast annotations status Runs/<scan_id>/Pipeline.db --scan-id <scan_id>
aidast annotations resume Runs/<scan_id>/Pipeline.db --scan-id <scan_id>
```

`resume`은 완료된 annotation이 없는 관측만 선택합니다. 기본값은
`--batch-size 100 --workers 3 --min-batch-size 25 --codex-timeout 300`이며 필요하면
더 낮춰 실행할 수 있습니다. 최종 실패가 남으면 종료 코드 1과 미완료 건수를 반환하고,
원본 관측은 계속 보존됩니다. 중단된 프로세스가 `running` row를 남겼다면 다른 태깅
프로세스가 없음을 확인한 뒤 `--recover-running`을 추가합니다.

- `discovery_contexts`: 페이지, 자동 클릭, 당시 인증 상태 및 세션 연결.
- `endpoint_observations`: 병합 전 발견 기록과 출처, 실제 HTTP 트랜잭션 근거.
- `annotation_runs`: 모델 선택 방식, 프롬프트/태그 목록 버전, 성공·실패 이력.
- `endpoint_annotations`: 관측별 기능/페이지/데이터 역할 태그와 판단 근거.

기존 DB는 열 때 SQLite `user_version=3`로 추가 마이그레이션됩니다. 기존 행은
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
태깅 실패 시 수집 결과를 보존하고 실패 상태를 내보냅니다. LLM 호출에 따른 실행
시간이 추가되며, 이 호출은 실제 타깃에 접근하지 않습니다.

## Scope → Recon Agent → Attack Agent

승인된 canonical Scope 전체를 대상으로 통합 파이프라인을 실행하려면:

```bash
aidast run "<PROGRAM_URL>" --all-targets
```

일부 자산만 실행하려면 `--target`을 반복해서 지정합니다. `run`은 기존 Recon의
subdomain/DNS/port/HTTP/origin/Playwright/Katana/ffuf/API 수집을 그대로 실행하고,
저장 결과를 Recon Agent가 한 번 더 read-only로 검토합니다. 이후 scan을
`completed`로 닫고 다음 산출물을 `Runs/<scan_id>/`에 만듭니다.

```text
Runs/<scan_id>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Scope.json
├── Approval.json
├── TargetPolicy.json
└── Handoff.json
```

`Handoff.json`에는 각 파일의 SHA-256, 크기, 역할과 scan ID가 들어갑니다. Attack
단계는 이를 모두 검증하고 완료된 scan만 받아 `AttackRuns/<scan_id>/Attack.db`에
오프라인 계획을 저장하고 `review/`에 endpoint와 annotation 기반 검토 큐를
생성합니다. 기존 handoff만 다시 소비해 검토 큐를 생성할 수도 있습니다.

```bash
aidast attack Runs/<scan_id>/Handoff.json \
  --output-dir AttackRuns/<scan_id>
```

기본 CLI는 오프라인 증거 검토/계획까지만 실행합니다. 동적 실행 코어는 별도로
구현되어 있지만, 검토된 고정 adapter의 HEAD/GET/OPTIONS 응답 메타데이터 관찰만
지원하며 신뢰된 승인 workflow와 `TargetPolicy` broker가 주입되지 않으면
fail-closed됩니다. 외부 Attack playbook 59개는 아직 실행 코드가 아닌 비활성
참고 카탈로그이므로 임의 payload나 shell 명령을 실행하지 않습니다.

새로운 오프라인 실행 상태는 별도 `Attack.db`에 저장합니다. Recon handoff를
검증한 뒤 Attack 전용 DB에 계획과 작업만 기록하고, Recon 원본은 읽기 전용으로
참조합니다. DB를 열 때도 handoff와 원본 파일의 SHA-256을 다시 검증하므로
원본이 누락되거나 변경되면 열기를 거부합니다. SQLite의 `-wal`, `-journal`,
`-shm` 파일이 없는 완결된 Recon snapshot이 필요합니다.
기존 `aidast attack HANDOFF`는 계속 검토 큐만 생성합니다.

새 review config는 handoff 위치를 config 디렉터리 기준 상대 경로로,
Recon DB 위치를 handoff 디렉터리 기준 상대 경로로 기록합니다. 저장된 계획의
경로도 review 디렉터리 기준이므로 `Runs/`와 `AttackRuns/`의 상대 배치를
유지해 함께 이동하면 같은 계획을 재사용할 수 있습니다. CLI가 출력하는 DB와
검토 큐 경로는 현재 위치를 가리킵니다. 기존 절대 경로 review config는 원래
위치에서 계속 사용할 수 있으며, Recon을 복제한 구형 Attack DB는 새 출력
디렉터리에서 다시 `plan`을 생성해야 합니다.

```bash
aidast attack plan Runs/<scan_id>/Handoff.json --output-dir AttackRuns/<scan_id>
aidast attack status AttackRuns/<scan_id>/Attack.db
aidast attack revoke AttackRuns/<scan_id>/Attack.db --reason "검토 중단"
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

Attack 실행기가 shared `Pipeline.db`에 저장한 finding과 demonstrated chain은
Validation Coordinator가 positive control, target 3회, negative control 순서로 fresh
replay합니다. Blind assessment를 먼저 고정한 뒤 Attack claim을 공개하며, 판정과 evidence는
같은 Pipeline DB의 case에 append-only로 연결됩니다.

```bash
aidast validate run Runs/<scan_id>/Pipeline.db \
  --scan-id <scan_id> \
  --finding-id <finding_id>
aidast validate status Runs/<scan_id>/Pipeline.db --scan-id <scan_id>
```

최종 상태는 `CONFIRMED`, `DISPROVEN`, `OUT_OF_SCOPE`, `KNOWN`, `UNDERPOWERED`,
`BLOCKED`, `INCONCLUSIVE`, `CONTESTED` 중 하나이며 모델이 직접 지정하지 않습니다.
Python이 candidate 무결성, control/target 관측, impact 세 축, 중복 key와 claim 충돌을
검사해 상태를 계산합니다.

Report Agent는 현재 `CONFIRMED`인 case만 받아 `aidast-reporting` Skill로 로컬 초안을
만듭니다. `KNOWN`은 source case를 안내하고 `CONTESTED`는 review-only bundle만 반환합니다.
지원 플랫폼은 HackerOne, Intigriti, Bugcrowd 세 가지이며 제출이나 플랫폼 접속은 하지 않습니다.

```bash
aidast report run Runs/<scan_id>/Pipeline.db \
  --case-id <case_id> \
  --platform hackerone \
  --output-dir ReportRuns/<scan_id>
aidast report status ReportRuns/<scan_id>/Report.db
```

결과 디렉터리에는 검증 가능한 `Report.db`, 구조화된 `Report.json`, 사람이 읽는
`Report.md`가 생성됩니다. 모든 사실 필드는 확인된 evidence ID를 인용해야 하며,
`--platform`은 `hackerone`, `intigriti`, `bugcrowd`만 허용합니다. 재현 가능한 팀 전달을
위해 report는 case의 decision hash와 정렬된 evidence hash에 묶입니다. 무관한 Pipeline
row 변경은 보고서를 무효화하지 않지만 case decision이 바뀌면 기존 보고서는 `stale`이 됩니다.

통합 전후 차이와 수정 이유는 `docs/changes/MERGE_CHANGES.md`에 누적합니다.

### 폴더 구성

핵심 단계는 `src/aidast/recon`, `attack`, `validation`, `reporting`으로 분리되어 있고,
각 Agent용 로컬 Skill은 `src/aidast/skills` 아래에 둡니다. 설계와 변경 이력은
`docs/design`, `docs/changes`, 외부 출처 보존 자료는 `docs/third-party`, 공용 wordlist는
`resources/wordlists`, 팀 전달용 ZIP은 `dist`에 둡니다. `Scope`, `.aidast_sessions`,
실행 중 생성되는 DB와 Surface 파일은 로컬 런타임 자료이므로 배포 ZIP에 포함하지 않습니다.


Katana는 JSONL 출력(`-j -or -ob`)에서 발견 부모 URL, HTML 태그/속성, 실제
HTTP 메서드, 응답 상태·종류·크기·리다이렉트를 추출합니다. 기존 URL 행 출력도
파싱할 수 있습니다. ffuf는 탐색 루트, 관련 seed 경로(최대 10개), 응답 상태·종류,
크기·단어/줄 수와 리다이렉트를 남깁니다. 해당 필드가 없으면 추측하지 않습니다.
이 메타데이터는 `endpoint_observations.evidence_json`에 저장되며 Surface 2.1의
관측별 `evidence`와 LLM 입력에 함께 포함됩니다. 여러 루트에서 같은 경로를
발견해도 각 관측의 근거를 보존합니다. 추가 네트워크 요청은 발생시키지 않습니다.
프롬프트 버전 2는 soft-404 가능성과 부모 URL/탐색 루트의 의미를 구분하도록
지시합니다. 파서·저장·전달 경로는 테스트했으나 실제 모델 분류 정확도의 향상은
별도의 정답 데이터 평가가 필요합니다.
