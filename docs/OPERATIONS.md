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
- [로컬 웹 대시보드](#로컬-웹-대시보드)
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

모든 기본 결과를 하나의 저장소 밖 디렉터리에 모으려면 실행 셸에서 다음 환경변수를
설정합니다.

```bash
export AIDAST_RESULT_ROOT="/path/to/dast_result"
```

설정하지 않으면 clone한 저장소의 `result/`를 사용합니다. 따라서 어느 작업
디렉터리에서 `aidast`를 실행해도 CLI와 WebUI가 같은 결과를 읽습니다.
`--output-dir`, `--db-path`, `--surface-path`, `--run-root` 등 명시적 CLI 경로는
환경변수 기반 기본값보다 우선합니다.

## 로컬 웹 대시보드

`aidast dashboard --ui-dir <WebUI-dist>`는 clone한 저장소의 `result/`에 있는 persisted run을
읽기 전용으로 투영합니다. `/api/v1/scans`와 scan snapshot REST API, scan별
WebSocket replay stream을 제공하고 선택한 정적 WebUI도 같은 origin에서 제공합니다.

- `Recon.db`와 `Pipeline.db`는 SQLite read-only URI와 `query_only`로 엽니다.
- 로그에는 audit event type만 사용하며 `details_json`, HTTP body, cookie, token은
  전달하지 않습니다.
- durable WebSocket cursor는 파생 데이터인 `result/.webui/events.db`에 저장합니다.
- `Scope.json`과 `Approval.json`의 SHA-256이 일치해야 승인 상태가 표시됩니다.
- 인증이 구현되기 전까지 `127.0.0.1`, `::1`, `localhost` 이외의 bind는 거부합니다.
- 승인된 Scope로 새 스캔을 실행하고 중단·재개할 수 있습니다. 실행 전 정책 해석과
  필수 입력·확인 항목을 검증하며, 기존 승인 산출물은 수정하지 않습니다.

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

### 기존 승인 Scope 재수집과 새 스캔

대시보드의 프로그램 대기열에서 승인된 프로그램의 **View result**를 열고
**Collect again**을 누르면 현재 정책을 새로 수집합니다. 이 동작은
`POST /api/v1/programs/<id>/scope-collection`에 `refresh: true`를 보냅니다.
일반 수집 요청은 기본 `refresh: false`이며 기존 승인 Scope를 재사용합니다.
수집 중이거나 검토 대기 중인 작업이 있으면 두 요청 모두 새 작업을 만들지 않습니다.

새 초안에서 자산, 필수 요청 헤더, 실행 규칙과 참조 문서의 URL·수집 상태·
적용 분야·실패 이유를 원문 근거와 대조합니다. 기존의 검토자 이름과 전체 승인
확인으로 **Yes · Approve Scope** 또는 **No · Reject draft**를 선택합니다.
새 수집이 대기·실패·취소·거절되어도 이전에 승인된 Scope는 계속 사용할 수 있습니다.

기존 파일을 삭제하거나 수정할 필요가 없습니다. 최초 승인은 원래 프로그램 경로에
유지되고, 다시 승인한 버전은 다음 경로에 따로 게시됩니다.

```text
result/Scope/<platform>/<program>/revisions/<scopejob_id>/
├── Scope.md
├── Scope.json
├── Manifest.json
└── Approval.json
```

검증된 Scope 목록에는 원본과 새 승인 버전이 같은 프로그램으로 표시됩니다.
승인 결과의 **New scan with this Scope**를 누르면 방금 승인한 정확한 Scope ID가
선택됩니다. 목록에서 이전 버전도 선택할 수 있습니다. 대시보드가 실행하는
`aidast run`은 선택한 버전의 작업 ID를 `--scope-revision <scopejob_id>`로 전달하며,
CLI는 해당 프로그램의 이미 승인된 경로만 읽습니다. 잘못된 ID나 미승인 버전은
실패하며 원본으로 돌아가거나 새 정책을 수집하지 않습니다. 완성된 실행 규칙은
저장된 승인 근거에서 읽고 새 의미 해석 없이 적용합니다.

### 인증이 필요한 프로그램 페이지

Intigriti researcher URL처럼 플랫폼 로그인이 필요한 프로그램 페이지는
Scope 전용 runtime browser로 수집합니다.

```bash
aidast scope "<PROGRAM_URL>" \
  --login-mode runtime-browser \
  --identity "<ACCOUNT_LABEL>"
```

`aidast`가 저장소 밖의 격리된 persistent Chromium 프로필을 엽니다. 로그인과
MFA를 직접 완료하고, 명령에 입력한 정확한 프로그램 페이지로 돌아와 Scope
화면을 연 뒤 터미널에서 Enter를 누르세요. 다른 origin 또는 다른 path에 있는
탭은 캡처 대상으로 인정하지 않습니다.

프로필은 기본적으로
`~/.local/share/aidast/scope-sessions/<binding-hash>/browser-profile/`에
저장되어 같은 platform origin과 identity 조합에서 재사용됩니다. 실제 쿠키와
토큰이 포함되므로 공유·백업·커밋하지 마세요. Scope 캡처는 완전성 검사를 통과한
뒤에만 Codex가 해석하며, partial 또는 blocked 캡처는 승인 단계로 넘어가지
않습니다.

```text
result/Scope/<platform>/<program>/
├── Scope.md
├── Scope.json
├── Manifest.json
└── Approval.json
```

### 정책에서 자동 적용하는 실행 옵션

AI가 승인할 정책 원문에서 실행 제한과 사용자 의무를 구조화하고 정확한 근거
문장을 함께 남깁니다. 실행 코드는 지원하는 옵션의 타입·범위와 원문 근거를
검증하며, 정책 문구를 정규식으로 해석하지 않습니다.

| 정책 요구 | 자동 처리 | 사용자가 제공할 내용 |
| --- | --- | --- |
| 필수 식별 헤더 | 임의의 이름과 값 템플릿을 정책에 바인딩 | 선언된 사용자 이름 등 입력값 |
| 초당·분당·일당 요청 제한 | 횟수·기간·프로그램/대상 범위로 저장하고 전송 전 검사 | 더 낮은 실행 상한을 선택할 수 있음 |
| 총 요청 횟수 | 대상·단계가 공유하는 스캔 예산과 정책 총량을 검사 | 실행 예산; 정책 상한을 늘릴 수 없음 |
| 동시성·개별 타임아웃·깊이 | 기존 실행값과 정책 제한 중 더 작은 값을 적용 | 필요한 경우 더 낮은 상한 |
| 공유 요청 허가 시간 (`max_scan_seconds`) | 대기 시간을 포함한 기한 이후 새 전송을 차단하고 HTTP·명시적 전송의 남은 타임아웃을 줄임 | 별도 필수 입력 없음 |
| 허용 메서드·테스트 대상 | 기존 승인 범위와 교집합을 사용 | 승인된 대상 선택 |
| Playwright·Headless·ffuf·재귀·form 제출·MITM body 저장 | 정책에서 금지된 기능을 끔; 기존 권한을 확대하지 않음 | 별도 필수 입력 없음 |
| 테스트 계정 이메일·연구자 식별값 | 해당 대상의 필수 입력과 이메일 도메인을 검증 | 실제로 사용할 식별값 |
| 운영 환경 테스트 전 연락 등 수동 의무 | 해당 대상을 선택했을 때 확인 항목을 요구 | 실제 수행 후 확인 |
| 지원하지 않는 필수 실행 제어·해소되지 않은 모순 | 사유와 근거를 표시하고 해당 대상으로의 실행을 막음 | 정책 검토와 요구 해소 |

사전 연락, 외부 계정 생성과 사람의 판단이 필요한 의무는 코드가 대신 수행했다고
간주하지 않습니다. 입력·확인은 선택한 정확한 Scope 자산에 맞춰 검증합니다.
지원하지 않는 요구도 정확한 자산에 연결할 수 있습니다. 운영 환경에만 해당하는
차단 조건은 스테이징을 선택했을 때 적용하지 않으며, 대상이 없는 차단 조건은
전체 실행에 적용합니다.

기존 승인 Scope는 원본 JSON·Markdown·승인 파일을 유지하고, 저장된 원문을 AI가
해석한 결과를 별도 캐시에 보관합니다. 원문 내용이나 해석 버전이 달라지면 다시
해석하며 목록 조회는 모델을 호출하지 않습니다. 해석이 미완료이거나 실패하면
새 스캔을 실행할 수 없습니다. 새 요구는 Scope 승인 화면과 Markdown에서 확인합니다.

대시보드가 필요한 입력과 확인 항목을 표시합니다. CLI의 대응 옵션은 다음과 같습니다.

```bash
aidast run "<PROGRAM_URL>" --target "<APPROVED_ASSET>" \
  --header-input researcher_username="<HANDLE>" \
  --policy-input testing_email="<TESTING_EMAIL>" \
  --confirm-policy production_contact
```

키는 AI가 선언한 요구에 따라 달라지므로 화면이나 CLI 오류에 표시된 정확한 키를
사용합니다. 여러 입력·확인에는 옵션을 반복합니다. 관련 없는 대상의 확인이나
입력은 요구하지 않으며, 값을 입력했다는 것만으로 외부 계정의 실제 상태를
검증했다고 간주하지 않습니다.

새 스캔의 공유 요청 상태는 `result/.policy-budgets/`의 프로그램별 SQLite 파일에
저장합니다. Recon·Attack·Validation·다중 대상이 같은 스캔 예산을 소비하고,
프로그램/대상의 기간 제한은 새 스캔이나 단계 재시작으로 초기화되지 않습니다.
실패·전송 결과 불명인 예약은 보수적으로 계산하며 동시성 용량은 종료 또는
제한된 lease 만료로 해제합니다. 기록을 읽거나 쓸 수 없으면 전송을 차단합니다.
공유 제한은 새로 생성한 정책부터 적용하며 기존 스캔의 정책·DB는 변경하지 않습니다.
`max_scan_seconds`는 새 전송의 허가 기한입니다. 이미 시작한 브라우저·프록시
스트림을 그 시각에 강제 종료한다는 뜻은 아니며 해당 전송의 개별 제한을 따릅니다.
공유 제한이 있는 Validation 브라우저는 후속 요청을 전송 전에 검사할 수 없는
리다이렉트 응답을 차단합니다. 일반 HTTP 및 Recon 프록시 경로는 각 리다이렉트를
따로 검증하고 계산합니다. 기존 공유 제한이 없는 브라우저 정책은 유지합니다.

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

Intigriti 프로그램이 연구자 식별 헤더를 요구하면 사용자명을 명시합니다.
이 값은 HTTP Probe, Playwright, Katana, ffuf, API 2차 탐색의 승인된 타깃 요청에
동일하게 적용되며 외부 정적 리소스에는 전달되지 않습니다.

```bash
aidast recon "<PROGRAM_URL>" \
  --all-targets \
  --intigriti-username "<INTIGRITI_USERNAME>" \
  --execute
```

이 옵션은 `X-Intigriti-Username`과
`User-Agent: aidast-recon/0.1 <intigriti:USERNAME>`을 설정합니다. 저장되는 증거와
진단 데이터에서는 사용자명과 User-Agent 식별 접미사를 가립니다. 승인된 Scope가
해당 헤더를 요구하는 경우 능동 실행에서 옵션을 생략하면 fail-closed됩니다.

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
`--profile focused-recon`은 명시했을 때 실행 기본값과 상한으로 적용됩니다.
요청 속도는 승인된 Scope에 명시된 제한을 우선 사용하고, 없을 때만 프로필의
0.5/1 RPS를 사용합니다. 예를 들어 정책이 10회/초이면 두 프로필 모두 10 RPS가
기본값입니다. 별도 근거가 있는 더 낮은 대상별 제한과 사용자가 선택한 더 낮은
속도는 유지하며, 애플리케이션 상한은 50 RPS입니다.
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

별도 `--login-mode`를 지정하지 않으면 먼저 비로그인 Playwright Chromium으로
시작합니다. 404나 공개
페이지는 그대로 탐색하고, 비밀번호 입력창·폼·버튼·링크 같은 실제 로그인 UI가
확인될 때만 로그인 창을 엽니다. `--login-mode none`은 어떤 응답에서도 로그인 UI를
열지 않습니다. `--login-mode runtime-browser`를 지정하면 처음부터 Playwright
Chromium과 실행별 전용 프로필을 사용해 로그인한 뒤 같은 세션으로 Recon을 계속합니다.
기본 흐름으로 완료한 로그인은 같은 실행의 동일 origin 전체에서 재사용합니다. 경로가
달라지거나 이후 엔드포인트가 404를 반환해도 로그인 완료 입력을 다시 요구하지 않습니다.
Endpoint Discovery의 Phase 1에서 프록시 없이 로그인하고, 같은 Chromium 컨텍스트에
정책과 관측 핸들러를 적용해 Phase 2 Recon을 이어갑니다.

운영체제의 플랫폼 패스키나 Windows Chrome 세션이 필요하면
`--login-mode system-browser`를 사용합니다. 전달한 세션이 권한 오류를 반환하면
Phase 2 Chromium 로그인 창을 다시 열어 직접 로그인할 수 있습니다.

`--session-bundle`을 지정하면 새 로그인 대신 기존 세션을 검증해 재사용합니다.
로그인 취소, 세션 저장 실패, 타깃 복귀 실패 시 자동 탐색을 시작하지 않습니다.
수동 로그인 중 Enter 입력은 최대 5분 대기하며, 입력이 없으면 현재 세션을
자동 저장합니다.
대시보드에서 시작한 `runtime-browser` 스캔은 로그인 대기 안내에 **로그인 완료**
버튼을 표시합니다. 열린 Chromium에서 로그인과 초대 코드 등 가입 절차를 마치고
대상 사이트로 돌아온 뒤 버튼을 누릅니다. 브라우저가 살아 있고 대상 화면에
로그인 입력이나 명확한 접근 제한 안내가 남아 있지 않으면 같은 세션으로 Recon을
계속합니다. 제한 화면이 남아 있으면 해당 절차를 마친 뒤 다시 확인할 수 있습니다.
5분 안에 사용자 확인이 없으면 실패 처리하며 자동으로 수집을 시작하지 않습니다.

확인은 스캔 ID와 해당 로그인 요청 ID에 연결됩니다. 다른 스캔, 교체된 요청,
만료된 요청에는 적용되지 않습니다. 쿠키 인증도 지원하며 특정 인증 API의 성공
응답이나 `Authorization` 헤더를 요구하지 않습니다. 이후 API의 인증·권한 오류는
사용자 확인을 취소하거나 전체 로그인 흐름을 자동으로 다시 시작하는 근거로 쓰지
않습니다. 브라우저나 저장된 세션이 사라진 경우에는 기존 세션 복구 절차를 사용합니다.

확인 상태는 비밀정보 없는 `result/.webui/manual_login.db`에 저장하고, 감사 기록은
`recon.operator_login_confirmed` / `operator_confirmed`로 남깁니다. 이 기록은 사용자의
확인 사실이며 서버 인증 검증이나 모든 엔드포인트의 접근 권한을 보장하지 않습니다.

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
mitmproxy는 `pyproject.toml`과 `uv.lock`에 관리되는 필수 Python 의존성입니다.
프록시는 `sys.executable`로 mitmproxy의 `mitmdump` 진입점을 실행하므로 대시보드,
CLI, editable tool 설치 모두 자기 Python 환경을 사용합니다. 시스템 PATH의
별도 mitmdump 바이너리는 사용하지 않습니다. addon이 공유 요청 예산 기록을
읽고 쓰므로 해당 Python에는 표준 `sqlite3` 모듈이 필요합니다.
신규 설치는 `uv sync` 또는 `uv tool install --editable .`로 준비합니다.
기존 설치는 `uv sync --locked`와, editable tool을 사용한다면
`uv tool install --force --editable .`로 갱신한 뒤 대시보드를 재시작합니다.
프록시 포트 준비는 첫 실행의 모듈 초기화를 고려해 최대 30초 기다립니다.
준비 중 프로세스가 종료되면 대기 기한까지 기다리지 않고 실패를 감지합니다.

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
result/Runs/<platform>/<program>/<scan_id>/
├── Recon.db
├── Surface.json
├── ReconReview.json
├── Scope.json
├── Approval.json
├── TargetPolicy.json
└── Handoff.json

result/AttackRuns/<platform>/<program>/<scan_id>/
└── Pipeline.db
```

통합 `aidast run`은 Shared Validation 이후 현재 확정된 `CONFIRMED` case마다
Report 로컬 초안을 자동 생성합니다. 확정된 case가 없거나 지원하지 않는 플랫폼이면
Report 단계를 건너뜁니다. `CodexMainAgent`는 단계별 adapter 이름이며
전체 순서와 gate를 결정하는 상위 Agent가 아닙니다.

## Legacy Attack 경로

다음 경로는 persisted-data 호환을 위한 기존 오프라인 `Attack.db` 흐름입니다.
통합 `aidast run`의 Native Attack과 구분해야 합니다.

```bash
aidast attack review \
  result/Runs/<platform>/<program>/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<platform>/<program>/<scan_id>

aidast attack plan \
  result/Runs/<platform>/<program>/<scan_id>/Handoff.json \
  --output-dir result/AttackRuns/<platform>/<program>/<scan_id>

aidast attack status \
  result/AttackRuns/<platform>/<program>/<scan_id>/Attack.db

aidast attack revoke \
  result/AttackRuns/<platform>/<program>/<scan_id>/Attack.db \
  --reason "검토 중단"
```

기본 CLI는 오프라인 증거 검토와 계획까지만 수행합니다. 동적 코어는 검토된 고정
adapter의 HEAD/GET/OPTIONS 응답 메타데이터만 관찰합니다. 신뢰된 승인 workflow와
`TargetPolicy` broker가 주입되지 않으면 fail-closed됩니다. 외부 Attack playbook
59개는 비활성 참고 카탈로그이며 payload나 shell 명령을 실행하지 않습니다.

Recon handoff와 원본 파일 SHA-256은 DB를 열 때마다 다시 확인합니다.
SQLite `-wal`, `-journal`, `-shm` 파일이 없는 완결된 Recon snapshot이 필요합니다.
Review config와 계획은 상대 경로를 사용합니다. 통합 `Pipeline.db`의 원본 경로는
무결성 보호 대상이므로 완료된 평면 경로의 스캔을 직접 옮기지 마세요. 새 스캔은
처음부터 프로그램별 경로에 저장하며, 기존 평면 경로도 조회·재개할 수 있습니다.

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
통합 실행에서는 case별로 `result/ReportRun/<scan_id>/<case_id>/`에 자동 저장합니다.
`CONFIRMED`만 draft 대상이고, `KNOWN`은 원본 case를 가리키며 `CONTESTED`는
review-only로 남습니다. HackerOne, Intigriti, Bugcrowd는 플랫폼별 형식으로 생성하고,
플랫폼 미지정·미식별 대상은 기본 `generic` 형식을 사용합니다. 자동 제출하지 않습니다.

```bash
aidast report run \
  <PIPELINE_DB> \
  --case-id <case_id> \
  --platform hackerone \
  --output-dir result/ReportRun/<scan_id>/<case_id>

aidast report status \
  result/ReportRun/<scan_id>/<case_id>/Report.db
```

`Report.db`, `Report.json`, `Report.md`는 Validation decision과 인용 evidence에
연결됩니다. Decision hash가 바뀌면 기존 Report는 stale로 판정됩니다.

기존 스캔의 일반 보고서는 위 명령의 `--platform`을 `generic`으로 지정해 생성할 수 있습니다.
기본 형식은 대상·취약점·요약·재현 절차·관측 결과·영향·개선 권고를 포함합니다.
대시보드에서 일반 보고서의 Markdown과 마스킹된 ZIP을 다운로드할 때 플랫폼 제출 규칙을
입력할 필요는 없습니다. 추가로 설정한 필수 필드와 Validation·Scope·근거 무결성 검사는 유지됩니다.

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
├── Runs/<platform>/<program>/<scan_id>/
├── AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db
├── AttackRun/                     # legacy
├── ValidationRun/                 # legacy
├── ReportRun/<scan_id>/<case_id>/
└── .aidast_sessions/
```

`--run-root`와 `--attack-output-root`는 프로그램별 폴더를 만들 기준 경로입니다.
`--output-dir`, `--db-path`, `--surface-path`는 해당 명령의 출력 경로입니다.

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

## 일반 제외 조건과 실제 전송

정책 주의사항 검토를 마친 Scope(`policy_review_version >= 2`)에서는 모든 하위 조건이
`semantic` 또는 `unsupported`인 제외 규칙을 Agent가 준수할 지침으로 전달합니다.
원문 인용, 전체 조건식과 원래 자산 바인딩을 `TargetPolicy.policy_notes`와 실행 문맥에
보존하며, 캡처가 없는 첫 페이지 GET만으로 전체 스캔을 보류하지 않습니다.
Agent는 해당 조건에 맞거나 권한을 확정할 수 없는 개별 작업을 건너뛰고 이유를
기록해야 합니다. 이는 Agent의 판단에 의존하며 요청 경계의 결정적 차단을 뜻하지
않습니다. 대시보드의 **저장된 증거로 제외 조건 확인** 결과에서 전달된 지침을
확인할 수 있습니다. 기존 승인 Scope·승인 파일과 원래 실행 해석 캐시는 수정하지
않고 새 실행용 정책을 만들 때 적용합니다.

직접 조건이 하나라도 포함된 혼합 규칙, 직접 제외 규칙과 아직 검토하지 않은
Scope의 규칙은 아래 요청 경계 검사를 유지합니다. 명시적 필수 조건, 승인 대상,
메서드·식별 헤더·요청 제한도 계속 강제합니다.

Scope의 제외 문장은 AI가 제한된 조건식으로 해석합니다. 의미 범주 판단도 AI의 확률적 분류이며, 캡처 출처 검증이 그 판단의 의미적 정확성을 보장하지는 않습니다. 실제 요청 경계에서는 모델을 호출하지 않고 저장된 조건식을 결정적으로 평가합니다. 조건이 참이면 거절, 필요한 정보가 불명확하면 보류, 거짓이면 기존 호스트·경로·메서드·인증·예산 검사로 진행합니다. 지원하는 직접 조건은 정확한 호스트/메서드, 정확한 경로와 경로 구간 접두사, 쿼리 이름/값, JSON 포인터, URL 인코딩 폼 이름/값입니다. 중복 키, 모호한 경로, 지원하지 않는 인코딩/조건은 해당 조건에 필요한 경우 보류됩니다.

의미 분류 캐시는 승인된 Scope, 대상, 규칙, 검증된 캡처와 전체 요청 식별자에 묶입니다. URL·쿼리·메서드·헤더·본문·작업 문맥이 달라지면 기존 분류를 재사용하지 않습니다. 가장 오래된 근거 캡처로부터 최대 24시간 이내에 만료하며, 대기 후 실제 전송 직전에도 재평가합니다. 최초 검사에서 거절/보류된 요청은 전송 및 예약이 0건입니다. 이미 유효하게 예약한 뒤 대기 중 만료된 경우에는 전송을 막지만 기존의 보수적 예산 소비는 유지될 수 있습니다. 동시 요청 묶음은 모든 구성원을 예약 전에 검사하고, governor 대기 및 실제 DNS/TCP/TLS 연결 대기가 끝난 뒤 첫 요청 바이트를 보내기 직전에도 전체 묶음을 다시 검사합니다.

직접 HTTP는 자동 헤더까지 준비한 뒤 검사하며 환경 프록시를 자동 상속하지 않습니다. 프록시는 내부 제어 헤더를 제거한 후 실제 목적지·헤더·원시 본문을 검사합니다. 브라우저 지원 요청에도 실제 메서드를 사용합니다. 제외 조건이 있는 브라우저는 서비스 워커 및 주변 WebSocket 연결을 차단하고, 자동 리다이렉트/재시도 없는 한 홉 요청만 전달합니다. 브라우저 리다이렉트는 후속 전송 없이 중단됩니다. Playwright 세션 쿠키나 네이티브 프로토콜이 최종 헤더 신원을 완전히 확정하지 못하면 의미 조건은 보류하되, 알려진 직접 조건의 거짓 결과는 유지합니다.

새 캡처 영수증은 실제로 전달되어 완료된 교환의 원시 요청 본문과 정확히 DB에 저장될 응답 바이트에 연결됩니다. 프록시의 로컬 403, 후보/중복/정적 대체 기록, 중단·스트리밍·누락된 본문에는 사용할 수 있는 영수증을 발급하지 않습니다. 영수증이 없는 과거의 가공/비식별 캡처에 현재 자격 증명을 합쳐 의미 근거를 재구성하지 않습니다. 기존 DB·Scope·승인 파일은 준비 과정에서 읽기 전용으로 유지합니다.

현재 지원하지 않는 경계도 보류됩니다. 비관리 시스템 브라우저 로그인, 기존 CDP 브라우저 연결/복제, 정책 라우팅 해제, DNS/서브도메인 제공자/TCP 탐색은 적용 가능한 제외 조건이 있으면 시작하지 않습니다. WebSocket의 암묵적 pong/close 및 정리 프레임까지 완전하게 검사할 수 없어 해당 세션 전체를 연결 전에 보류합니다. gRPC는 실제 authority와 RPC 경로의 일치를 검사하며 알려진 직접 조건을 유지하지만, protobuf/framing 본문 조건과 불완전한 최종 신원에 의존하는 의미 조건은 보류합니다. DOM 클릭은 페이지 GET과 별도의 작업 문맥을 사용합니다. 현재 일반 버튼/폼/제어 요소 어댑터는 실제 동작 대상과 모든 로컬 효과를 확정하지 못하므로 호스트·경로·메서드·본문을 포함한 요청 조건을 미상으로 평가하고, 적용 가능한 제외 조건이 있으면 클릭을 보류합니다. 페이지 URL, href 또는 form action만으로 임의의 JavaScript 동작 전체가 관련 없다고 판정하지 않습니다. 따라서 잠재적으로 무해한 UI 탐색도 제한되며, 이 제한은 동작을 실행하지 않는 DOM/메타데이터 읽기과 구분됩니다. 실제 동작을 증명하는 별도 어댑터가 생기기 전까지 페이지 GET의 직접/의미 분류가 클릭을 허가하지 않습니다. 이후 발생한 모든 네트워크 요청은 다시 전송 경계를 통과해야 합니다.

알 수 없는 최초 seed를 조회해서 분류하는 예외는 없습니다. 기존에 확보한 검증 가능한 캡처로 명시적인 오프라인 준비를 수행해야 하며, 새로운/변경된 요청은 보류될 수 있습니다. 과거 정책의 누락된 guard는 기존 실행 동작을 유지하지만 새 실행의 Scope 해석은 명시적인 제외 조건 목록(`[]` 포함)이 필요합니다.


### Scope-time policy reference preparation

Fresh Scope collection now observes actual links on each primary browser view,
selects policy references with an offline model using observed IDs and exact parent
quotes, and captures the selected public documents before final analysis. Public,
authenticated browser and native collection use the same preparation step. The
native browser only observes external links; the application retrieves them in an
isolated HTTPS reader without browser sessions, authentication, cookies or proxy
inheritance. Every redirect receives public-address validation and a pinned TLS
connection preserving hostname verification.

The bounds are 128 observed links per primary view or reference page, at most 6
primary views, 8 fetched documents, depth 2, 3 redirects,
1 MiB per raw response, 120000 combined evidence characters and an absolute 15-second
request deadline. Unsupported, inaccessible or over-budget references remain
explicit unresolved records. Repeated links retain each selection's parent quote
and lifecycle phase while reusing captured content. Scope.json retains original
program text/digest; Scope.md displays reference provenance, bodies and failures.
The approval hashes cover the full evidence.

Primary captures persist `primary_views`, each with its URL, exact captured text
and observed links. The view text must occur verbatim in the original program
capture; it adds no asset authority. Candidate IDs are local to a view, link source
URLs must match that view, and each selected quote is checked against its own view.
Persisted primary reference edges retain and validate `primary_view_index`, including
different views sharing the same URL. Selection uses at most 14 offline calls
(6 primary views plus 8 captured references), with at most 8 choices per call and
112 selected-edge records. Each edge records its required, supporting or uncertain
relationship to testing, with an exact parent quote. Required references receive
retrieval priority; fragment variants share one document while distinct queries
remain separate. Later views retain their observations even when an earlier view
fills its 128-link allowance.
Fresh extraction retains a 64-blocker limit. Saved execution rules reserve up to
176 blockers for explicit extracted obligations and mandatory reference duties.
Missing supporting or uncertain context becomes a grounded advisory rather than
a blanket scan hold. An unavailable mandatory testing prerequisite still blocks
the affected target; preparation preserves its evidence and existing restrictions.

Legacy captures may omit `primary_views` and retain one flat `observed_links` list
of at most 128 entries, selected against the original aggregate primary text.
They cannot reconstruct missing per-view evidence and may require recollection.
Structured views and nonempty legacy flat observations cannot be mixed or selected
twice. Older approved files are read without rewriting their bytes or hashes.

Only primary program text authorizes assets and activities. Referenced evidence
can narrow execution rules or describe submission/reporting/public-disclosure
obligations. Later disclosure duties alone are not testing blockers. The model
distinguishes explicit prerequisites from uncertainty using captured evidence,
not title matching. Advisories are shown in the dashboard and bound to agent policy
context for Recon, Attack, chaining, validation and PoC reproduction. Explicit
headers, rate limits, exclusions and authorization checks remain enforced.
Fresh drafts and approval require explicit required_request_headers and
execution_rules.exclusions lists, including [] when reviewed and absent. Complete
approved rules are read directly at launch without additional policy retrieval or
interpretation. Existing request-context semantic resource checks still apply.
Historical approved artifacts remain unchanged. Their captured evidence can be
reinterpreted into a separate versioned execution-requirements cache; catalog reads
do not call a model. Missing mandatory evidence still requires collection/review.
For oversized repeated evidence, the Recon planner receives one lossless copy with
exact quote spans and digest; the approved Scope and downstream policy input remain
unchanged, and genuinely over-limit retained input fails explicitly.
