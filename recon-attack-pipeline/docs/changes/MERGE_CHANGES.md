# Recon → Attack 통합 변경 기록

이 문서는 `AI-Dast-main`의 Recon 기능을 유지하면서 `Scope 수집 → Recon Agent → Attack Agent` 단계 계약을 통합하는 작업의 전후 차이를 누적 기록한다.

## 2026-09-11: Playwright 수동 인증 브라우저 무한 로딩 수정

변경 전에는 Chromium을 `subprocess.Popen`으로 실행한 뒤
`connect_over_cdp()`로 다시 연결했다. 브라우저 창과 CDP endpoint는 살아 있어도
Playwright의 페이지 명령과 storage state 추출이 함께 멈추면서 대상 사이트가
무한 로딩되는 현상이 발생했다.

변경 후에는 Playwright가 화면이 보이는 Chromium을 처음부터 직접 관리한다.
새 Context/Page를 만들고 기존 프록시·TargetPolicy·service worker·WebSocket
경계를 유지했으며, Katana가 사용할 CDP endpoint도 계속 제공한다. 상세한 원인
분리, 전후 비교, 검증 결과는
[`PLAYWRIGHT_MANUAL_AUTH_LOADING_FIX.md`](PLAYWRIGHT_MANUAL_AUTH_LOADING_FIX.md)에
기록했다.

## 2026-09-09: Recon 기반 SKILL Attack 루프 연결

기존 Attack은 검토 plan과 응답 메타데이터 관찰까지만 연결되어 가설 생성,
SKILL 본문 사용, Finding 생성이 기본 실행 계약에 포함되지 않았다. 공급받은
controller 1개와 library SKILL 59개를 패키지에 포함하고, 해시 검증 후 Recon
annotation으로 선택하도록 변경했다.

`SkillAttackAgent`는 모델이 Recon 근거와 선택된 SKILL을 보고 가설을 만들게
하고, 신뢰된 executor가 노출한 승인 테스트 ID만 실행한다. 결과를 다시 모델이
평가하되, Python이 hypothesis/test/evidence 귀속을 검증하고 confirmed 결과만
`Attack.db`의 Finding과 request로 저장한다. 이 결과는 기존 Validation Agent가
추가 변환 없이 읽는다. 상세 설계와 통합 방법은 `SKILL_ATTACK_AGENT.md`에
기록했다.

## 2026-09-08: 통합 기반 및 안전 경계

### HTTP 요청 경계

문제/이유: redirect가 Scope 밖으로 이동하거나 정책 없는 요청이 실행되면 버그바운티 허용 범위를 벗어날 수 있었다. 모든 실제 HTTP 이동을 한 경계에서 검사하도록 수정했다.

| 변경 전 | 변경 후 |
|---|---|
| `http_probe`가 표준 `urlopen` 동작에 의존해 redirect 목적지를 정책으로 다시 검사하지 않음 | `RequestBroker`가 최초 URL과 각 redirect의 scheme, host, port, path, method를 `TargetPolicy`로 재검증 |
| 정책이 없어도 HTTP 요청 가능 | 정책이 없으면 네트워크 전송 전에 fail-closed |
| origin이 바뀌는 redirect에도 민감 헤더 전달 가능 | cross-origin redirect에서 인증·쿠키 등 민감 헤더 제거 |
| 요청 수가 probe 경계에서 제한되지 않음 | 정책의 `max_requests`와 redirect 횟수 적용 |
| 모델이 승인되지 않은 추가 host나 POST 같은 변경 메서드를 정책에 넣을 여지가 있음 | canonical host 밖의 값과 state-changing method를 Python 검증에서 거부 |

영향 파일:

- `src/aidast/core/request_broker.py`
- `src/aidast/core/http_safety.py`
- `src/aidast/recon/tools/http_probe.py`
- `src/aidast/recon/executor.py`

### 프록시 캡처와 민감정보

문제/이유: 기존 캡처에는 로그인 토큰, 쿠키, 요청·응답 본문이 그대로 남을 수 있었다. 다음 Agent에는 필요한 증거만 넘기고 비밀정보는 남기지 않도록 기본값을 바꿨다.

| 변경 전 | 변경 후 |
|---|---|
| mitm 캡처가 요청·응답 body를 항상 기록 | `mitm_capture_bodies`가 명시적으로 참인 경우에만 body 기록 |
| Authorization, Cookie 등 헤더 원문 저장 | 캡처와 DB 적재 양쪽에서 민감 헤더 마스킹 |
| 정책 파일 오류나 필수 프록시 시작 실패가 조용히 넘어갈 수 있음 | 정책 강제 모드에서는 설정·실행 실패를 오류로 처리 |

영향 파일:

- `src/aidast/recon/policy.py`
- `src/aidast/recon/tools/mitm_addon.py`
- `src/aidast/recon/tools/mitm_proxy.py`

### 브라우저 상호작용

문제/이유: form 안의 타입 없는 버튼은 실제로 제출 버튼인데 일반 버튼처럼 클릭할 수 있었다. 의도치 않은 데이터 생성·변경을 막기 위해 명시적 허용 없이는 건드리지 않는다.

| 변경 전 | 변경 후 |
|---|---|
| `<form>` 내부에서 `type`이 생략된 `<button>`을 일반 버튼처럼 누를 수 있음 | HTML 기본 submit 동작으로 판단하고 명시적 허용이 없으면 클릭하지 않음 |

영향 파일:

- `src/aidast/recon/tools/playwright_driver.py`
- `src/aidast/recon/tools/endpoint_discovery.py`

### Recon Agent 계층

문제/이유: 기존 Recon은 정해진 도구 순서를 잘 실행하지만, 수집 결과를 보고 다음 조사 방향을 조정하는 계층이 없었다. 기존 기능은 유지하고 근거 기반 제안 계층만 위에 추가했다.

| 변경 전 | 변경 후 |
|---|---|
| 고정된 Recon task 실행과 결과 저장만 존재 | 기존 실행기를 유지한 채, 저장된 근거를 읽어 다음 Recon 제안을 구조화하는 `OfflineReconReview` 추가 |
| 에이전트 제안의 반복·타깃 확장에 대한 별도 한도 없음 | canonical Scope/TargetPolicy 검증, 중복 제거, iteration/task budget 적용 |
| 제안과 네트워크 실행이 분리되지 않음 | review 계층은 read-only이며 자동 네트워크 실행 경로를 갖지 않음 |

영향 파일:

- `src/aidast/recon/agent.py`
- `tests/test_recon_agent.py`

### 통합 DB 및 handoff 계약

문제/이유: Recon과 Attack이 서로 다른 테이블과 완료 상태를 기대해 그대로는 연결할 수 없었다. 하나의 DB schema와 검증 가능한 handoff 파일을 두 단계의 공용 계약으로 만들었다.

| 변경 전 | 변경 후 |
|---|---|
| Recon DB와 외부 Attack SQL이 서로 다른 테이블·상태를 기대 | 기존 Recon 테이블을 보존하는 additive schema v4에 단계·Attack evidence 테이블 통합 |
| Recon 결과 소비자가 파일 경로와 완료 여부를 관례로 추측 | SHA-256/크기/상대 경로를 담는 `HandoffManifest`로 명시적 전달 |
| 단계 및 task 상태 전이·감사 로그가 통일되지 않음 | `stage_runs`, `attack_tasks`, append-only `audit_events`와 검증된 상태 전이 사용 |
| 세션/자격증명 저장 경계가 불명확 | 실제 secret 대신 `env://`, `keyring://`, `vault://` 참조만 저장 |

영향 파일:

- `src/aidast/pipeline/schema.py`
- `src/aidast/pipeline/models.py`
- `src/aidast/pipeline/lifecycle.py`
- `src/aidast/recon/db.py`

### 검증 현황

- HTTP broker/프록시 신규 오프라인 테스트: 통과
- Recon Agent 신규 오프라인 테스트: 통과
- DB/handoff 계약 신규 오프라인 테스트: 통과
- Attack handoff consumer 신규 오프라인 테스트: 통과
- 전체 테스트: 최종 통합 기준 141개 통과. `git diff --check`도 통과.

### 단일 실행 CLI와 Attack handoff consumer

문제/이유: 기존에는 Recon 결과를 만든 뒤 어떤 DB와 파일을 Attack 쪽에 넘길지 사람이 맞춰야 했고, scan도 계속 `running`으로 남았다. `aidast run`이 완료 상태와 해시를 확정한 뒤 검증된 검토 큐까지 자동으로 준비하게 했다.

| 변경 전 | 변경 후 |
|---|---|
| Scope와 Recon 명령만 존재 | `aidast run`으로 Scope → Recon → handoff → Attack review 준비 연결 |
| Recon 성공 후에도 `scans.status='running'` | 성공 시 `completed`/종료 시각, 실패 시 `failed`/종료 시각 기록 |
| Recon 산출물 위치·내용을 다음 단계가 신뢰 | DB, Surface, Scope, Approval, Policy, ReconReview를 SHA-256으로 검증 |
| 외부 Attack 폴더가 별도 DB 형태를 가정 | 설치 패키지 안의 offline consumer가 공용 v4 schema를 read-only로 소비 |
| 능동 Attack 실행 여부가 모호 | 현재는 evidence-review plan만 지원하고 active/network 요청은 명시적으로 거부 |

영향 파일:

- `src/aidast/cli.py`
- `src/aidast/agents/main.py`
- `src/aidast/attack/evidence.py`
- `src/aidast/attack/runtime.py`
- `src/aidast/skills/attack/controller.md`
- `src/aidast/skills/attack/manifest.json`
- `pyproject.toml`
- `README.md`

## 2026-09-09: 동적 Attack Agent 병합 설계

문제/이유: 외부 `attack` 폴더는 실제 Agent 실행 코드가 아니라 Markdown playbook과 SQL 조각이라 그대로 복사해도 동작하지 않고, 현재 immutable handoff·credential·정책 경계와도 충돌했다. 실행 주체와 데이터 계약을 분리한 단계별 병합 설계를 추가했다.

| 변경 전 | 변경 후 |
|---|---|
| 외부 controller가 한 Codex 세션과 writable Recon DB를 가정 | 새 AI 세션과 DB 기반 재개, immutable Recon DB와 writable Attack DB 분리 |
| playbook이 shell/network 동작을 직접 지시 | disabled catalog + 검토된 fixed adapter + 공용 broker 구조 |
| Scope 승인을 Attack 승인으로 오해할 수 있음 | plan/policy/catalog/task/budget/identity에 묶인 별도 `RunAuthorization` 설계 |
| process별 요청 수 제한 | restart 후에도 유지되는 전역 budget·lease·receipt 설계 |

설계 문서:

- `docs/design/ATTACK_AGENT_MERGE_DESIGN.md`

## 2026-09-09: 제한형 동적 Attack Agent 구현

문제/이유: 외부 Attack 폴더는 문서와 SQL뿐이라 직접 실행할 Agent, 승인 경계, 재시작 가능한 저장소가 없었다. 먼저 안전하게 검증 가능한 응답 메타데이터 관찰 범위로 실행 코어를 만들었다.

| 변경 전 | 변경 후 |
|---|---|
| 59개 playbook의 포함 범위와 출처를 런타임에서 확인할 수 없음 | 59개 library 항목과 controller를 해시 inventory로 보존하고 모두 비활성 메타데이터로 등록 |
| Recon DB를 Attack이 직접 수정할 위험 | handoff와 파일 hash를 재검증한 뒤 별도 writable `Attack.db`를 만들고 원본 hash를 보존 |
| v4에는 plan revision, 승인, lease, model iteration 저장 계약이 없음 | opt-in schema v5와 run/scan 경계를 검증하는 저장 API 추가 |
| 승인 파일의 진위·만료·정확한 task binding을 강제할 곳이 없음 | 서명된 `RunAuthorization`과 정확한 `RequestIntent` digest를 매 요청 검증 |
| 요청 budget이 process 재시작이나 여러 worker에서 초기화될 수 있음 | SQLite 원장에 전송 전 reservation/receipt를 기록하고 request/byte/time/rate/concurrency를 공유 |
| API 후보 요청, ffuf, Playwright 일부 경로가 공용 정책을 우회할 수 있음 | API broker 공유, ffuf proxy 전달, Playwright route guard/WebSocket 차단과 proxy 필수화 적용 |
| browser session이 host/port만으로 구분됨 | run/identity/target hash로 session 파일을 분리하고 executor가 scan ID를 전달 |
| 모델 결과가 URL·명령·임의 task를 실행 입력으로 만들 수 있음 | 모델은 기존 ID만 고르고 Python validator가 forged/duplicate/과대 결과를 거부 |
| Attack 실행 주체가 없음 | 재시작·철회·예산을 확인하는 `AttackAgent`와 고정 HEAD/GET/OPTIONS 메타데이터 adapter 추가 |
| CLI는 legacy offline review 한 가지뿐 | legacy 호환을 유지하며 `plan/status/revoke` 추가; `approve/execute`는 신뢰 workflow 없으면 거부 |

영향 파일:

- `src/aidast/attack/agent.py`, `planner.py`, `adapters.py`, `authorization.py`, `catalog.py`, `store.py`
- `src/aidast/core/policy_service.py`, `request_broker.py`
- `src/aidast/pipeline/schema.py`
- `src/aidast/recon/tools/api_secondary_discovery.py`, `endpoint_discovery.py`, `playwright_driver.py`
- `src/aidast/recon/executor.py`, `src/aidast/cli.py`, `pyproject.toml`, `README.md`
- `src/aidast/skills/attack/catalog/index.json`, `docs/third-party/claude-bughunter/`

현재 제한/이유: 실제 bug bounty target에서의 능동 exploit adapter는 안전성과 프로그램별 허용 범위를 별도로 검토해야 한다. 그래서 기본 CLI는 plan까지만 제공하고, 검증 workflow가 없는 `approve/execute`와 외부 playbook 실행은 fail-closed 상태로 남겼다.

검증: 외부 네트워크를 쓰지 않는 전체 219개 테스트와 `git diff --check`가 통과했다. wheel을 직접 빌드해 59개 비활성 catalog resource가 설치 결과에서도 로드되는 것을 확인했다.

## 2026-09-09: Attack 전용 thin DB 재설계

문제/이유: Attack 상태를 저장하려고 Recon 전체 DB를 복제해 데이터와 용량이 중복됐다. Recon은 읽기 전용 원본으로 두고 Attack 데이터만 별도 DB에 저장하도록 단순화했다.

| 변경 전 | 변경 후 |
|---|---|
| Recon.db 전체를 복사한 뒤 schema v5 적용 | 빈 thin schema v6 `Attack.db`를 만들고 Attack 테이블만 생성 |
| Attack DB 안의 복제된 endpoint를 FK/trigger로 확인 | 별도 read-only Recon 연결에서 `endpoint → origin → asset → scan` 귀속을 Python API가 확인 |
| Attack DB만 열면 오래된 Recon 사본도 계속 사용 가능 | 생성·재개마다 Handoff, Recon hash, 완료 scan, WAL/journal/SHM 부재를 재검증 |
| 원본 Handoff와 DB의 절대 경로 저장 | Attack/review 위치 기준 상대 locator를 저장해 두 묶음을 함께 이동 가능 |
| 저장 plan digest에 환경별 절대 출력 경로 포함 | portable plan에는 상대 config/queue locator만 포함 |
| `aidast run`이 review queue까지만 준비 | Recon 완료 후 thin `Attack.db`와 revision 1 plan까지 자동 생성 |
| 복제형 DB와 새 형식을 같은 v5로 오인할 가능성 | thin 형식은 v6로 구분하고 기존 복제형 v5는 새 출력 디렉터리 사용을 안내하며 거부 |

영향 파일:

- `src/aidast/attack/store.py`, `runtime.py`
- `src/aidast/pipeline/schema.py`
- `src/aidast/cli.py`, `README.md`
- `tests/test_attack_store.py`, `test_attack_runtime.py`, `test_attack_cli.py`, `test_pipeline_cli.py`

검증: 외부 네트워크 없이 전체 229개 테스트와 `git diff --check`가 통과했다. Attack DB에 Recon inventory 테이블이나 기존 Recon attempt가 복제되지 않고, 원본 변경·누락·다른 scan endpoint·sidecar·구형 v5가 모두 거부되는 것을 확인했다.

## 2026-09-09: Validation Agent 추가

변경 전: Attack 후보의 7문항·PoC 검증 결과를 분리해서 기록하는 단계가 없었다. 변경 후: 프로젝트 Skill로 기존 증거를 검토하고 원본 hash와 Finding/증거 ID를 별도 `Validation.db`에 저장한다.

이유: Attack의 발견 상태와 검증 판단이 섞이거나 근거가 부족한 후보가 확정되는 문제를 막기 위해 추가했다.

| 변경 전 | 변경 후 |
|---|---|
| 검증 규칙과 결과 저장 계약 없음 | `aidast-validation` Skill + Python 7Q/PoC 검증 + append-only `Validation.db` |
| 모델 설명만으로 확정될 가능성 | 7개 답변과 실제 evidence/request hash 연결이 모두 맞아야 `confirmed` |
| Attack DB에 검증 결과를 함께 기록 | Recon/Attack은 읽기 전용으로 두고 Validation 이력만 별도 저장 |

## 2026-09-09: 3개 플랫폼 Report Agent 추가

변경 전: 검증된 finding을 플랫폼 양식으로 옮기는 단계가 없었다. 변경 후: `confirmed` Validation만 HackerOne·Intigriti·Bugcrowd용 Skill로 작성해 별도 `Report.db/JSON/MD`에 저장한다.

이유: 확인되지 않은 내용이나 존재하지 않는 증거가 보고서에 섞이지 않도록, 모든 사실을 검증된 evidence ID에 묶고 자동 제출 기능은 제외했다.

| 변경 전 | 변경 후 |
|---|---|
| 수동으로 플랫폼별 보고서 작성 | `aidast report run --platform hackerone\|intigriti\|bugcrowd` |
| 보고서가 원본 검증 결과와 느슨하게 연결 | Validation DB·decision·context hash와 evidence ID를 강제 검증 |
| 생성과 제출 경계가 불명확 | 로컬 초안만 생성하며 네트워크 제출 기능 없음 |

검증: 전체 295개 테스트, 두 Skill 구조 검증, `git diff --check`, wheel 패키지 내 Skill·3개 플랫폼 reference 포함 확인이 모두 통과했다.

## 2026-09-09: 팀 전달용 폴더 재구성

변경 전: 설계·변경 문서, wordlist, 배포 ZIP이 프로젝트 루트에 섞여 있었다. 변경 후: 각각 `docs/design`, `docs/changes`, `resources/wordlists`, `dist`로 분리했다.

이유: 소스·문서·공용 자원·배포물과 Scope/세션/DB 같은 로컬 실행 산출물을 팀원이 바로 구분할 수 있게 하기 위해서다.

## 2026-09-09: GitHub main 루트 정리

변경 전: 루트 구버전과 `dast/` 구현, Scope·백업·디버그 파일이 새 통합 폴더와 중복됐다. 변경 후: 루트 안내 파일과 `recon-attack-pipeline/`만 남겼다.

이유: 사용자가 실행할 버전을 하나로 명확히 하고, 로컬 실행 산출물이나 오래된 구현을 실수로 사용하는 문제를 막기 위해서다.

## 2026-09-12: Recon → Native Attack Agent 자동 실행 및 공유 DB 통합

문제/이유: Recon 완료 후 Attack review plan과 전용 thin DB까지만 준비되고 실제 Attack Agent는 자동 생성되지 않았다. Recon·Attack 단계가 서로 다른 DB를 사용해 실행 상태와 Finding을 한 scan 흐름으로 조회하기도 어려웠다.

| 변경 전 | 변경 후 |
|---|---|
| Recon 완료 후 Attack plan 준비에서 실행 종료 | `aidast run`이 Recon 완료를 검증한 뒤 Native Attack Orchestrator를 호출하고 Attack Agent를 자동 생성 |
| Main Agent와 Attack Agent의 실행 계약이 불명확 | Main은 `gpt-5.6-sol` 기반 `aidast_attack` Agent를 정확히 한 개 생성하고, 실제 공격 판단과 실행은 자식 Agent가 담당 |
| Attack이 전체 Hunt Skill을 한 번에 읽거나 고정 관찰만 수행 | Recon annotation과 task의 취약점 유형을 기준으로 관련 Hunt Skill만 최대 8개 선택해 Agent에 제공 |
| 모델이 임의 URL·메서드·요청을 직접 실행할 위험 | Python 요청 helper가 scope, host, path, method, rate, concurrency, 전체 request budget을 요청마다 검사 |
| Recon DB와 별도 `Attack.db`에 실행 정보가 분산 | Native Attack 실행의 stage, task, attempt, HTTP request, fact, evidence, Finding을 동일한 `Pipeline.db`에 저장 |
| 응답 상태나 모델 설명만으로 Finding이 승격될 가능성 | 요청 증거와 assertion이 연결된 Attack attempt만 `confirmed`로 승격하고 나머지는 `lead` 또는 terminal 실패로 보존 |
| Attack Agent 완료 여부를 Main이 모델 응답만 보고 판단 | Main이 공유 DB의 stage run, agent 수, task/attempt/request terminal 상태와 반환 JSON을 교차 검증 |

기존 offline review용 thin schema v6 `Attack.db` 계약은 호환성을 위해 유지한다. 새 Native Attack 및 이후 Chaining 단계만 하나의 `Pipeline.db`를 사용하며, 공유 schema version은 v8로 확장했다.

영향 파일:

- `src/aidast/agents/main.py`
- `src/aidast/orchestration/attack.py`
- `src/aidast/attack/db_cli.py`, `models.py`, `request_cli.py`, `skill_selector.py`
- `src/aidast/attack/agent.py`
- `src/aidast/pipeline/schema.py`
- `src/aidast/recon/executor.py`
- `src/aidast/cli.py`, `pyproject.toml`
- `src/aidast/skills/attack/live/`, `src/aidast/skills/attack/orchestrator/`
- `tests/test_attack_request_guard.py`, `test_attack_skill_selector.py`, `test_native_attack_orchestration.py`

## 2026-09-12: Native Chaining Agent 및 전체 공격 흐름 재현 추가

문제/이유: Attack에서 여러 독립 취약점이 확인돼도 서로 연결 가능한지 판단하고, 실제 요청 흐름으로 최종 영향까지 재현하는 단계가 없었다. 단순히 취약점 이름을 조합한 시나리오가 성공한 체인으로 저장되는 것도 방지해야 했다.

| 변경 전 | 변경 후 |
|---|---|
| Attack 완료 후 후속 Agent 없음 | Main이 Attack 완료를 검증한 뒤 `gpt-5.6-sol` 기반 `aidast_chaining` Agent를 정확히 한 개 자동 생성 |
| 독립 Finding 사이의 연결 규칙 없음 | Finding 유형별 연관 Hunt Skill mapping으로 관련 Skill을 최대 8개 선택하고 2~4개 node의 chain candidate 생성 |
| 단일 취약점이나 다음 단계가 없어도 완성 체인처럼 보일 수 있음 | 검증된 다음 node가 없으면 예상 연결만 기록하고 candidate를 `inconclusive`로 종료 |
| 취약점 설명을 연결하는 것만으로 성공 판단 가능 | candidate마다 새로운 execution을 만들고 모든 node를 실제 HTTP 요청으로 순서대로 재현 |
| 앞 단계 결과가 다음 요청에 사용됐는지 확인 불가 | 응답에서 capture한 scalar 값의 hash를 저장하고, 다음 요청 URL·header·body에 실제 반영됐는지 binding으로 검증 |
| HTTP 200 응답만으로 최종 영향 판단 가능 | 마지막 node에서 `json_equals`, `header_equals`, `body_contains` 중 하나의 비상태 terminal assertion이 통과해야 성공 |
| 체이닝 결과 저장 계약 없음 | candidate, node, edge, execution, step, binding, evidence, proposed finding chain을 동일한 `Pipeline.db`에 저장 |
| 모델이 임의 성공 결과를 반환할 수 있음 | Main이 현재 stage에서 성공한 replay execution이 없는 신규 chain을 거부하고 DB의 모든 terminal 상태를 교차 검증 |

Chaining Agent는 Attack에서 실제로 확인된 Finding만 입력으로 사용한다. 실행 재현이 성공하면 `chain_executions.status='succeeded'`와 `finding_chains.status='proposed'`로 저장하며, 최종 `demonstrated` 승격은 추후 Validation 단계가 담당한다.

영향 파일:

- `src/aidast/agents/main.py`
- `src/aidast/orchestration/chaining.py`
- `src/aidast/chaining/models.py`, `selector.py`, `db_cli.py`
- `src/aidast/attack/request_cli.py`
- `src/aidast/pipeline/schema.py`
- `src/aidast/cli.py`, `pyproject.toml`
- `src/aidast/skills/chaining/live/`, `src/aidast/skills/chaining/orchestrator/`
- `tests/test_native_chaining_orchestration.py`
- `scripts/e2e_native_attack_smoke.py`

검증: 로컬 허가 대상 fixture에서 실제 Sol Chaining Agent가 CORS 응답의 `account_id`를 capture하고 이를 인증 없는 IDOR 요청에 binding한 뒤, private record terminal assertion까지 통과하는 2단계 체인을 재현했다. 성공 execution 1건, step 2건, binding 1건, evidence 2건과 proposed chain 1건이 공유 `Pipeline.db`에 저장되는 것을 확인했다. 반대로 terminal assertion이 거짓인 경우 HTTP 200이어도 chain을 생성하지 않는 fail-closed 동작도 확인했다.

관련 집중 테스트는 15개가 모두 통과했다. 전체 테스트는 297개 중 280개가 통과했으며, 나머지 17개는 기존 Windows symlink 권한, CP949 기본 decoding, Unix 실행 파일 가정, 경로 구분자 및 기존 Hunt Skill digest 불일치와 관련된 환경·선행 문제다. 신규 Native Attack/Chaining 테스트 실패는 없었다.
