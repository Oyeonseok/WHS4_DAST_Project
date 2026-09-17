# AI DAST 운영 상세

이 문서는 AI DAST의 Recon 실행 경계, 인증 브라우저, 요청 예산, 진단,
관측 태깅, 통합 파이프라인과 Legacy 호환 경로를 설명합니다.
처음 설치하거나 일반적인 실행 흐름만 확인하려면 먼저
[README](../README.md)를 읽으세요.

## 목차

- [Scope 수집과 정책](#scope-수집과-정책)
- [운영 안전 원칙](#운영-안전-원칙)
- [Recon 실행 제어](#recon-실행-제어)
- [로그인과 브라우저 모드](#로그인과-브라우저-모드)
- [요청 예산과 프록시 경계](#요청-예산과-프록시-경계)
- [진단 로그](#진단-로그)
- [관측과 태깅](#관측과-태깅)
- [통합 파이프라인과 데이터 무결성](#통합-파이프라인과-데이터-무결성)
- [Legacy Attack 경로](#legacy-attack-경로)
- [Shared Validation](#shared-validation)
- [Case 기반 Report](#case-기반-report)
- [Legacy Validation과 Report](#legacy-validation과-report)
- [Skill 실행](#skill-실행)
- [결과 및 프로젝트 폴더](#결과-및-프로젝트-폴더)
- [Katana와 ffuf 증거 메타데이터](#katana와-ffuf-증거-메타데이터)

## 운영 안전 원칙

- 페이지 내용은 신뢰할 수 없는 입력으로 처리합니다.
- Recon의 자동 form submission은 항상 비활성화됩니다.
- Codex 로그인 정보는 저장소에 포함하지 않습니다.
- `result/`와 `.venv/`는 Git에서 제외합니다. `.env` 같은 비밀정보 파일도
  커밋하지 않습니다.
- 로그인 세션과 브라우저 프로필에는 쿠키, 스토리지, 토큰이 포함될 수 있으므로
  공유하거나 커밋하지 않습니다.
- 브라우저 세션 전달은 서비스별 로그인 성공이나 프록시 전환 후 유효성을
  범용적으로 보장하지 않습니다.
- Report는 로컬 초안만 생성하며 플랫폼에 자동 제출하지 않습니다.

## Scope 수집과 정책

### 수집과 승인

```bash
aidast scope "<PROGRAM_URL>"
```

임시 `Scope.md`가 만들어지면 원본 프로그램 페이지와 대조한 뒤 터미널에서
승인합니다.

```text
이 Scope를 승인하고 저장할까요? [y/N]:
```

- `y`: 프로그램별 공식 경로에 Scope 산출물을 저장합니다.
- `n` 또는 Enter: 임시 산출물을 모두 폐기합니다.

검토자 이름을 남기거나 저장된 Scope의 무결성을 확인할 수 있습니다.

```bash
aidast scope "<PROGRAM_URL>" \
  --by "<REVIEWER>"
aidast scope status "<PROGRAM_URL>"
```

승인 후 `Scope.md` 또는 `Scope.json`이 변경되면 무결성 검사가 실패합니다.
기존 프로그램 산출물은 자동으로 덮어쓰지 않습니다.

```text
result/Scope/<platform>/<program>/
├── Scope.md
├── Scope.json
├── Manifest.json
└── Approval.json
```

### Recon 계획과 정책 확인

```bash
aidast recon "<PROGRAM_URL>"
```

1. 승인된 Scope가 있으면 무결성을 확인하고 재사용합니다.
2. Scope가 없으면 수집과 대화형 승인을 먼저 수행합니다.
3. 제한된 Codex planning adapter가 `Scope.md`를 구조화된 Recon Plan으로 바꿉니다.
4. Coordinator가 Plan을 의존 관계가 있는 Recon Task로 변환합니다.

기본 `aidast recon`은 계획과 Task만 생성합니다. 실제 타깃에 요청하지 않고
Scope 해석, 정책 JSON과 도구 제어값만 확인하려면 다음 명령을 사용합니다.

```bash
aidast recon "<PROGRAM_URL>" --policy-only
```

실행 직전에는 승인된 `Scope.md`를 `TargetPolicy.json`으로 변환합니다.
Python 검증기는 Plan과 정책의 타깃이 정확히 일치하는지, 서브도메인 허용이
명시적인 wildcard 자산에만 적용되는지 확인합니다.

## Recon 실행 제어

실제 실행에는 승인된 `Scope.json`의 canonical 자산을 `--target`으로 지정하거나
`--all-targets`를 명시해야 합니다. `--target`은 반복해서 사용할 수 있으며 부분
문자열이나 유사 도메인은 허용하지 않습니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --target "example.com" \
  --start-url "<START_URL>" \
  --profile safe-recon \
  --max-rps 0.5 \
  --max-requests 100 \
  --execute \
  --db-path result/Recon.db \
  --surface-path result/Surface.json \
  --ffuf-wordlist /path/to/wordlist.txt
```

`--all-targets`는 선택 가능한 canonical 타깃을 모두 Plan에 포함합니다.
Exact web 타깃에는 DNS, HTTP Probe, Origin, Endpoint Discovery를 수행합니다.
Wildcard는 먼저 승인 범위에서 자산을 발견하고, 발견한 구체 호스트에 대해
Endpoint Discovery를 수행합니다.

Wildcard 후보는 Scope별
`result/Scope/<platform>/<program>/AssetDiscovery.db`에 보존됩니다.
기본적으로 wildcard당 한 실행에서 최대 25개 호스트를 처리합니다.
`--asset-discovery-batch-size`는 후보를 버리는 제한이 아니라 실행 회차의 크기입니다.

타깃 하나가 실패하면 해당 타깃에 의존하는 작업만 건너뛰고 독립 타깃은 계속
실행합니다. 일부 실패가 있어도 수집한 결과와 Surface를 저장하며 scan 상태는
`completed_with_errors`, CLI 종료 코드는 `2`입니다.

### 실행 수치 우선순위

승인된 Scope에서 근거와 함께 추출한 수치를 우선합니다. Scope에 수치가 없을 때만
기본값을 사용합니다.

| 설정 | 기본값 |
| --- | ---: |
| RPS | 1 |
| 동시성 | 3 |
| 깊이 | 3 |
| 타임아웃 | 20초 |
| 최대 요청 수 | 2,000 |

`--profile safe-recon`, `--profile focused-discovery`,
`--profile focused-recon`은 명시했을 때만 추가 상한으로 적용됩니다.
`--max-rps`, `--max-requests`, `--max-depth`, `--max-concurrency`,
`--timeout-seconds`도 정책을 더 좁힐 수만 있고 승인된 제한을 완화할 수 없습니다.

### 시작 URL 경계

`--start-url`은 단일 canonical `--target` 아래에서 운영자가 통제하는 실제 시작
URL을 선언합니다. Python이 모델 출력과 무관하게 host, scheme, port, path subtree를
검증하므로 다른 타깃이나 같은 호스트의 형제 경로로 일반화되지 않습니다.

이 경계 밖의 최상위 페이지와 Katana/ffuf 요청은 차단됩니다. 승인된 페이지 렌더링에
필요한 동일-origin API와 외부 정적 리소스는 실행별 브라우저 표식을 확인한 뒤
로딩만 허용합니다. 외부 정적 리소스는 Recon endpoint나 HTTP 증거로 저장하지 않습니다.

Scope의 out-of-scope 호스트는 `excluded_hosts`로 컴파일되며 wildcard 허용보다
우선합니다. Recon의 자동 form submission은 항상 비활성화됩니다.

### 종료 처리

일반 오류나 `Ctrl-C` 같은 제어 종료가 발생하면 현재 scan과 stage를 `failed`로
마감하고 DB 연결을 닫은 뒤 종료 신호를 다시 전달합니다. 프로세스 강제 종료나
전원 손실처럼 정리 코드를 실행할 수 없는 경우에는 마지막 상태가 남을 수 있습니다.

## 로그인과 브라우저 모드

기본 `runtime-browser` 모드는 Playwright Chromium과 실행별 전용 프로필을 사용합니다.
Endpoint Discovery의 Phase 1에서 프록시 없이 로그인하고, 같은 Chromium 컨텍스트에
정책과 관측 핸들러를 적용해 Phase 2 Recon을 이어갑니다.

운영체제의 플랫폼 패스키나 Windows Chrome 세션이 필요하면
`--login-mode system-browser`를 사용합니다. 전달한 세션이 권한 오류를 반환하면
Phase 2 Chromium 로그인 창을 다시 열어 직접 로그인할 수 있습니다.

`--session-bundle`을 지정하면 새 로그인 대신 기존 세션을 검증해 재사용합니다.
로그인 취소, 세션 저장 실패, 타깃 복귀 실패 시 자동 탐색을 시작하지 않습니다.
수동 로그인 중 Enter 입력은 최대 5분 대기하며, 입력이 없으면 현재 세션을
자동 저장합니다.

수동 로그인 트래픽은 Recon 관측에 포함하지 않으며 외부 로그인 URL을 탐색 대상으로
추가하지 않습니다. `--auth-host`와 `--auth-path`는 호환을 위해 남아 있지만 자동
수집 단계의 Scope를 확장하지 않습니다.

브라우저 모드와 세션 전달은 서비스별 로그인 성공이나 프록시 전환 후의 세션
유효성을 범용적으로 보장하지 않습니다.

## 요청 예산과 프록시 경계

`max_requests`는 타깃별 HTTP 요청 한도입니다. HTTP Probe와 redirect가 먼저 예산을
사용하고, 남은 예산을 Playwright, Katana, ffuf, API 2차 탐색이 공용 mitmproxy를
통해 공유합니다. DNS 질의와 포트 스캔 패킷은 이 HTTP 예산에 포함되지 않습니다.

전체 HTTP 예산의 20%는 Endpoint 및 브라우저 관측용으로 예약합니다.
mitmproxy는 다음 우선순위로 admission control을 수행합니다.

1. 브라우저 동일-origin API
2. HTML document와 redirect
3. 기타 API와 form 요청
4. Katana
5. ffuf
6. 정적 및 중복 요청

중복 요청은 예산에서 제외하고 정적 요청은 별도로 집계합니다. 예산 때문에 차단된
후보는 `deferred_candidates`에 저장합니다. 차단된 요청은 예산 사용량에 더하지 않습니다.

Katana와 ffuf에는 속도, 동시성, 깊이 제한을 전달합니다. Playwright를 포함한 프록시
트래픽은 scheme, host, port, path, method, 총 요청 수를 다시 검사합니다.
정책 강제 모드에서 `mitmdump`를 시작할 수 없으면 Recon은 실행되지 않습니다.

실행 순서는 인증된 브라우저/API 관측, Katana 경로 발견, 새 Katana 경로의
Playwright 상호작용 확장, ffuf 순서입니다. Playwright의 두 pass는 방문 URL과
페이지 상한을 공유합니다.

GraphQL 능동 확인은 기본적으로 비활성화됩니다. 승인된 타깃에서
`TargetPolicy.json`의 `api_probe.graphql=true`와 구체적인 `allowed_paths`를
설정한 경로에만 확인용 POST가 허용됩니다.

## 진단 로그

도구 결과가 지나치게 적거나 필터링 원인을 확인할 때만 사용합니다.

```bash
aidast run "<PROGRAM_URL>" \
  --target "<CANONICAL_ASSET>" \
  --diagnostic-logs
```

로그는 `result/logs/<scan_id>/recon.jsonl`에 생성되며 다음 정보를 단계별 JSONL로
기록합니다.

- 적용된 host, port, path, method와 남은 HTTP 요청 예산
- Katana 종료 코드, 출력 행 수, form 수, parser 제거 수와 endpoint 목록
- ffuf root와 root별 종료 코드
- Playwright, Katana, ffuf, API 결과의 정책 필터 전후 개수
- primary/final deduplication과 executor 정규화 전후 endpoint
- mitmproxy 허용 및 차단 요청 개수

인증 헤더, 쿠키, 요청/응답 본문, 세션 파일 경로는 기록하지 않습니다.
URL query와 fragment도 제거합니다. 경로 자체에 계정 식별자가 포함될 수 있으므로
로그는 로컬 진단 자료로 취급하고 외부에 그대로 공개하지 마세요.

## 관측과 태깅

Recon은 LLM 호출로 실행을 멈추지 않고 관측 맥락을 먼저 저장합니다.
실행이 끝난 뒤 별도 worker가 최대 200개 관측씩 Codex로 기능 태깅합니다.
계획 및 `--policy-only`는 태깅하지 않습니다.

```bash
aidast tag result/Recon.db
```

같은 Recon 명령에서 태깅까지 이어가려면 `--tag-after`를 추가합니다.
이미 태깅된 관측은 건너뜁니다.

- `discovery_contexts`: 페이지, 자동 클릭, 당시 인증 상태와 세션 연결
- `endpoint_observations`: 병합 전 발견 기록, 출처, HTTP 트랜잭션 근거
- `annotation_runs`: 모델 선택, 프롬프트/태그 버전, 성공 및 실패 이력
- `endpoint_annotations`: 기능, 페이지, 데이터 역할 태그와 판단 근거

기존 Recon DB는 additive SQLite schema `user_version=3`으로 마이그레이션됩니다.
기존 행은 보존하며 알 수 없는 과거 맥락을 추측해 채우지 않습니다.

LLM에는 요청/응답 본문, 쿠키, 인증 헤더, form 입력값을 전달하지 않습니다.
URL의 사용자정보, query, fragment를 제거합니다. 인증이 확인되지 않은 상태는
`unknown`으로 저장하고 모델 confidence를 검증된 확률로 취급하지 않습니다.
태깅 실패 시 수집 결과와 실패 상태를 보존하며 다음 `tag` 실행에서 재시도할 수 있습니다.
태깅 worker는 실제 타깃에 접근하지 않습니다.

## 통합 파이프라인과 데이터 무결성

```bash
aidast run "<PROGRAM_URL>" --all-targets
```

일부 자산만 실행하려면 `--target`을 반복해서 지정합니다.

```text
Scope → AI-Dast Recon → 태깅
      → Handoff → Pipeline.db
      → Native Attack → Chaining
      → Shared Validation
      → case 기반 Report
```

`Handoff.json`에는 `Recon.db`, Scope, 정책과 관련 artifact의 SHA-256, 크기,
역할과 scan ID가 들어갑니다. 원본 `Recon.db`는 query-only로 열고 SQLite backup으로
`Pipeline.db`를 만듭니다. Attack, Chaining, Validation schema는 복제본에만
추가합니다. 복제 전후 원본 해시가 달라지면 파이프라인을 중단합니다.

```text
result/Runs/<scan_id>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Scope.json
├── Approval.json
├── TargetPolicy.json
└── Handoff.json

result/AttackRuns/<scan_id>/
└── Pipeline.db
```

통합 `aidast run`의 종료 지점은 Shared Validation입니다. Report는 Validation case를
검토한 뒤 별도 명령으로 생성합니다. `CodexMainAgent`는 단계별 adapter 이름이며
전체 순서와 gate를 결정하는 상위 Agent가 아닙니다.

## Legacy Attack 경로

다음 경로는 persisted-data 호환을 위한 기존 오프라인 `Attack.db` 흐름입니다.
통합 `aidast run`의 Native Attack과 구분해야 합니다.

```bash
aidast attack review \
  result/Runs/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<scan_id>

aidast attack plan \
  result/Runs/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<scan_id>

aidast attack status \
  result/AttackRuns/<scan_id>/Attack.db

aidast attack revoke \
  result/AttackRuns/<scan_id>/Attack.db \
  --reason "검토 중단"
```

기본 CLI는 오프라인 증거 검토와 계획까지만 수행합니다. 동적 코어는 검토된 고정
adapter의 HEAD/GET/OPTIONS 응답 메타데이터만 관찰합니다. 신뢰된 승인 workflow와
`TargetPolicy` broker가 주입되지 않으면 fail-closed됩니다. 외부 Attack playbook
59개는 비활성 참고 카탈로그이며 payload나 shell 명령을 실행하지 않습니다.

Recon handoff와 원본 파일 SHA-256은 DB를 열 때마다 다시 확인합니다.
SQLite `-wal`, `-journal`, `-shm` 파일이 없는 완결된 Recon snapshot이 필요합니다.
Review config와 계획은 상대 경로를 사용하므로 `result/Runs/`와
`result/AttackRuns/`의 상대 배치를 유지하면 함께 이동할 수 있습니다.

`approve`와 `execute`는 신뢰된 애플리케이션이
`main(argv, attack_workflow=...)`로 검증 경계를 주입한 경우에만 사용할 수 있습니다.
두 명령 모두 `--authorization FILE`이 필요하고 `approve`는 `--by REVIEWER`도
필요합니다. 파일 경로나 검토자 이름만으로 승인이 성립하지 않습니다.

기본 `revoke`는 로컬 AttackStore를 갱신합니다. 별도 broker 예산 ledger의 폐기와는
다르므로 연결된 실행기는 매 요청마다 저장된 실행 상태와 폐기 세대도 검증해야 합니다.

## Shared Validation

기본 Validation은 별도 `Validation.db`를 만들지 않고 `Pipeline.db`에 case, attempt,
evidence, decision을 기록합니다. Chaining stage가 `completed` 또는 `skipped`일 때만
시작할 수 있습니다.

```bash
aidast validate run \
  <PIPELINE_DB> \
  --scan-id <scan_id> \
  --policy <TARGET_POLICY_JSON>

aidast validate run \
  <PIPELINE_DB> \
  --scan-id <scan_id> \
  --finding-id <finding_id> \
  --policy <TARGET_POLICY_JSON>

aidast validate resume \
  <PIPELINE_DB> \
  --stage-run-id <stage_run_id> \
  --policy <TARGET_POLICY_JSON>

aidast validate status \
  <PIPELINE_DB> \
  --scan-id <scan_id>
```

Validation은 HTTP, browser, OOB, chain adapter 뒤에서 positive/negative control과
반복 관측을 수행합니다. 최종 상태는 `CONFIRMED`, `DISPROVEN`, `OUT_OF_SCOPE`,
`KNOWN`, `UNDERPOWERED`, `BLOCKED`, `INCONCLUSIVE`, `CONTESTED` 중 하나입니다.
모델이 최종 상태를 직접 정하지 않습니다. 중단된 case는 같은 stage run과 audit
history를 유지해 재개합니다.

## Case 기반 Report

Report는 `Pipeline.db`의 Validation `case_id`를 선택해 로컬 초안을 만듭니다.
`CONFIRMED`만 draft 대상이고, `KNOWN`은 원본 case를 가리키며 `CONTESTED`는
review-only로 남습니다. HackerOne, Intigriti, Bugcrowd를 지원하며 자동 제출하지 않습니다.

```bash
aidast report run \
  <PIPELINE_DB> \
  --case-id <case_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>

aidast report status \
  result/ReportRun/<scan_id>/Report.db
```

`Report.db`, `Report.json`, `Report.md`는 Validation decision과 인용 evidence에
연결됩니다. Decision hash가 바뀌면 기존 Report는 stale로 판정됩니다.

## Legacy Validation과 Report

기존 `Attack.db → Validation.db → Report.db` 데이터는 삭제하거나 자동 변환하지
않습니다. `--run-id`와 `--validation-id`를 명시한 기존 명령을 계속 지원합니다.

```bash
aidast validate run \
  <LEGACY_ATTACK_DB> \
  --run-id <run_id> \
  --finding-id <finding_id> \
  --output-dir <VALIDATION_OUTPUT_DIR>

aidast report run \
  <LEGACY_VALIDATION_DB> \
  --validation-id <validation_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>
```

## Skill 실행

Scope 수집과 의미 해석은 제한된 Codex planning 호출과 네이티브 Skill로 관리됩니다.

```text
src/aidast/skills/scope/SKILL.md
```

실행 시 Skill은 Codex 표준 경로
`.agents/skills/aidast-scope/SKILL.md`에 임시 배치되고 `$aidast-scope`로
호출됩니다. Codex 네이티브 브라우저가 JavaScript 페이지를 충분히 렌더링하지
못하면 제한된 Playwright 브라우저로 같은 URL을 수집하고 Codex가 캡처를 해석합니다.
사용자 승인, 원문 근거, 무결성 검사와 공식 저장은 Python 코드가 담당합니다.

## 결과 및 프로젝트 폴더

기본 실행 산출물은 Git에서 제외되는 `result/` 아래에 저장됩니다.

```text
result/
├── Scope/<platform>/<program>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Runs/<scan_id>/
├── AttackRuns/<scan_id>/Pipeline.db
├── AttackRun/                     # legacy
├── ValidationRun/                 # legacy
├── ReportRun/
└── .aidast_sessions/
```

`--output-dir`, `--db-path`, `--surface-path`, `--run-root` 등으로 경로를 직접
지정하면 명시한 경로를 사용합니다.

핵심 코드는 `src/aidast/recon`, `pipeline`, `attack`, `chaining`, `validation`,
`reporting`으로 나뉩니다. Stage orchestration은 `src/aidast/orchestration`,
Codex adapter는 `src/aidast/agents`, 로컬 Skill은 `src/aidast/skills`에 있습니다.

설계와 변경 이력은 `docs/design`, `docs/changes`, 외부 출처 자료는
`docs/third-party`, 공용 wordlist는 `resources/wordlists`에 둡니다.

## Katana와 ffuf 증거 메타데이터

Katana Standard와 Headless는 JSONL 출력(`-j -or -ob -fx`)에서 발견 부모 URL,
HTML 태그와 속성, 실제 HTTP method, 응답 상태와 종류, 크기, redirect를 추출합니다.
`-fx`의 form action과 method도 별도 endpoint로 읽기 때문에
`<form method="post">`는 `POST`로 보존합니다.

자동 입력과 제출 옵션 `-aff`는 사용하지 않습니다. POST를 발견하는 것과 실제
전송 권한을 분리하며 Recon 정책의 GET/HEAD/OPTIONS 제한과 프록시 차단을 유지합니다.
Headless의 `-xhr`은 페이지에서 발생한 XHR/fetch URL과 실제 method를 수집할 뿐
추가 요청을 만들지 않습니다.

ffuf는 탐색 root, 관련 seed 경로(최대 10개), 응답 상태와 종류, 크기, 단어/줄 수,
redirect를 남깁니다. 없는 필드는 추측하지 않습니다. 메타데이터는
`endpoint_observations.evidence_json`과 Surface 2.1 관측별 `evidence`, LLM 입력에
전달됩니다. 여러 root에서 같은 경로를 발견해도 각 관측의 근거를 보존합니다.

파서, 저장, 전달 경로는 테스트했지만 실제 모델 분류 정확도 향상은 별도의
정답 데이터 평가가 필요합니다.
