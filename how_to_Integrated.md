# integrated/ 병합 과정 상세 기록

> **과거 병합 기록:** 이 문서의 2개 설치·수동 산출물 전달 절차는 초기 설계를 설명합니다. 현재 실행 방법은 `TEAM_GUIDE.md`와 `STATUS_REPORT.md`를 따르세요. 현재 `integrate/strix-recon-merge` 브랜치는 하나의 설치에서 Strix 정찰을 표준 Handoff·Attack·Validation·Report 파이프라인으로 연결하며 WebUI에서도 선택할 수 있습니다.

이 문서는 `attack/integrated/`가 어떻게 만들어졌는지, 왜 그렇게 결정했는지, 무엇을 바꿨고 무엇을 안 바꿨는지를 전부 기록합니다. 나중에 다시 봐도 재현/검증할 수 있도록 근거(코드 확인 결과)를 같이 남겼습니다.

---

## 0. 왜 이 작업을 했는가

팀에 세 가지 서로 다른 코드베이스가 있었습니다.

1. **`artex`** (팀 저장소 브랜치, commit `f6a1ef0`) — 가장 최신. 온라인 evidence graph, Coverage/Lead 듀얼 워크큐, precondition resolver, attack-time chain follow-up, 구조화된 외부 도구 어댑터, intent checkpoint, "실제 버그바운티 안전 실행 모드" 등을 추가하고 Wiki 기능은 제거한 버전.
2. **`benchmark`** (팀 저장소 브랜치, commit `314729e`) — artex의 바로 이전 베이스라인.
3. **`AI-Dast-main`**(로컬 작업 폴더, 이 세션 내내 테스트해온 것, 문서에서는 `ours`) — benchmark 계열의 더 오래된/부분적인 스냅샷. 로컬 전용 수정(체이닝 `demonstrated` 버그 수정 등)이 있었음.
4. **별도 Recon 저장소** — Strix 스타일 recon 엔진(실제 오픈소스 Strix를 쓰는 게 아니라 자체 구현)을 가진, 별도로 발전한 저장소. attack/chaining 코드는 자체적으로 갖고 있지만 **AI-Dast-main과 거의 동일한, 더 오래된 버전**이었음.

목표: artex의 더 발전된 attack/chaining 코드 위에, `recon/AI-Dast`의 Strix recon 엔진을 올리고, `ours`(AI-Dast-main)에만 있던 로컬 개선사항을 잃지 않고 포팅하는 것.

---

## 1. 비교 조사 (파일 단위 → 함수 단위)

### 1-1. `artex` vs `benchmark` vs `ours`

- `src/aidast/skills/chaining/`: **artex == benchmark, byte-identical** (tree hash 동일). 이 디렉터리는 둘 사이에 차이가 전혀 없음.
- `src/aidast/orchestration/chaining.py`: `ours` vs `artex` 간 26줄 차이. `artex`에만 있는 기능: 이전 Attack 단계가 새 finding을 추가하지 않았으면 체이닝을 `SKIPPED`로 건너뛰는 멱등성 체크. `ours`엔 없던 기능이라 이번엔 포팅하지 않음(선택 사항으로 남겨둠, 아래 "하지 않은 것" 참고).
- `src/aidast/attack/` 파일 목록 비교:
  - `ours`에만 있는 `.py` 파일: **0개** (`__pycache__` 제외). `ours`는 `artex`의 완전한 부분집합.
  - `benchmark`에만 있고 `ours`엔 없는 파일: `candidate_baseline.py`, `observed_objects.py`, `surface.py`, `wiki.py`, `wiki_cli.py`.
  - `artex`에만 있고 `ours`엔 없는 파일: `graph.py`, `work_queue.py`, `preconditions.py`, `external_tools.py`, `intent_checkpoint.py`, `online_chaining.py` (+ benchmark에서 이어지는 `observed_objects.py`, `surface.py`). `wiki.py`/`wiki_cli.py`는 artex에서 삭제됨(의도된 기능 제거).
- 함수 단위 비교(`grep "^def "`)를 `db_cli.py`, `store.py`, `coverage_snapshot.py`, `skill_selector.py`, `playwright_transport.py`, `recon_hypotheses.py`, `coverage.py`에 대해 전부 수행 → **`ours`만 가진 함수는 어디에도 없었음**. `coverage.py`는 artex가 `requeue_safe_session_binding_coverage`, `requeue_deterministic_engineio_coverage`, `requeue_orphaned_running_coverage`, `requeue_new_disposable_identity_coverage`, `requeue_auth_gated_negative_coverage`, `reclassify_explicit_auth_denial_coverage` 등을 추가로 가진 것 확인(1824줄 diff, 전부 artex가 더 많음).

**결론 1**: `benchmark`에서 따로 가져올 건 없음 — artex가 이미 benchmark의 상위집합.

### 1-2. `ours`에만 있던 예외 두 가지 (실제로 포팅 대상이 된 것)

파일/함수 목록 비교로는 못 찾고, 핵심 경로를 직접 읽어서 발견:

1. **`chaining/db_cli.py`의 `demonstrated` 상태 버그.**
   - `ours`: `INSERT INTO finding_chains (...) VALUES (?,?,?,?,?,'proposed')` 로 넣고, 체인의 모든 노드가 confirmed 처리된 뒤 `UPDATE finding_chains SET status='demonstrated' WHERE chain_id=?`로 승격.
   - `artex`/`benchmark` 둘 다: `INSERT INTO finding_chains (...) VALUES (?,?,?,?,?,'demonstrated')` — **INSERT 시점에 바로 demonstrated를 박아넣는 원래 버그가 그대로 남아있었음.** (`grep -n "demonstrated"`로 두 파일 다 직접 확인)
   - 왜 버그인가: 체인 실행이 중간에 실패해도 이미 `demonstrated`로 기록된 상태라, "증명됨"이라는 상태의 의미가 깨짐.

2. **`attack/request_cli.py`의 `guarded_replay` (IDOR replay) 기능 전체가 artex엔 없음.**
   - `ours`: `identity_role="identity_b"` + Playwright `session_state` 파일로 두 번째 계정의 요청을 처리.
   - `artex`: 인증 모델을 완전히 바꿔서 `credential_reference_id` + `PipelineCredentialResolver`(`aidast.validation.execution.credentials`)로 자격증명을 해석. `identity_role`/`session_state` 개념 자체가 제거됨.
   - `guarded_replay`(Account A가 관측한 read-only 요청을 Account B 자격증명으로 재생해서 IDOR을 비교하는 기능)는 `artex`에 **아예 없음**. 단순 복붙이 불가능하고, artex의 새 인증 모델에 맞춰 재구현해야 했음.

**결론 2**: 포팅할 건 이 두 가지뿐.

---

## 2. `merged/` (1차 시도, 지금은 `integrated/`로 대체됨)

처음엔 attack/chaining/skills만 뽑아서 `artex` 위에 위 두 가지를 패치한 `merged/` 폴더를 만들었습니다. 패치 내용:

- `chaining/db_cli.py`: INSERT를 `'proposed'`로 바꾸고, 체인 노드 confirm 루프 뒤에 `UPDATE ... SET status='demonstrated'` 추가.
- `attack/request_cli.py`:
  - 상수 추가: `_SENSITIVE_AUTH_HEADER`, `_REPLAY_OMIT_HEADERS`, `_SENSITIVE_QUERY_NAME` (헤더/쿼리에서 자격증명 성격의 값을 걸러내기 위함, `ours`에서 그대로 가져옴).
  - `_origin_key()` 함수 추가 (origin 정규화·비교용, `ours`에서 가져옴).
  - `guarded_replay()` 함수를 artex의 새 모델에 맞춰 재구현 (아래 3장에서 상세 설명).
  - CLI에 `replay-observed` 서브커맨드 + `--source-request-id`/`--target-origin`/`--credential-reference-id` 옵션 복원.

`py_compile`로 문법 검증만 하고, 이 단계에서는 실행 테스트를 하지 않았습니다.

### `merged/`가 왜 최종본이 아닌가

`merged/`를 그대로 `recon/AI-Dast`에 끼워 넣으려 했는데, 다음을 확인하고 중단했습니다:

- `recon/AI-Dast`의 `attack/request_cli.py`는 `ours`(AI-Dast-main)와 **byte-identical**이었음(`diff -q` 결과 0). 즉 `recon/AI-Dast`는 자체적으로 AI-Dast-main과 거의 같은 (더 오래된) attack 코드를 갖고 있었습니다.
- artex의 최신 attack 코드(`request_cli.py` 등)는 `recon/AI-Dast`에는 없는 지원 모듈들에 의존:
  - `aidast.core.capture_receipt` (MISSING)
  - `aidast.core.request_governor` (MISSING)
  - `aidast.pipeline.request_profiles` (MISSING)
  - `aidast.pipeline.browser_credentials` (MISSING)
  - `aidast.attack.surface` (MISSING)
  - (`aidast.core.http_safety`, `aidast.validation.execution.credentials`는 있었음)

즉 "조각만 뽑은 patch를 recon/AI-Dast 위에 얹기"는 import 에러가 날 수밖에 없는 구조였습니다. 그래서 방향을 바꿨습니다.

---

## 3. `integrated/` — 실제 최종본

### 3-1. 만든 방법

```bash
# artex 전체를 통째로 추출 (968개 파일)
git archive artex | tar -x -C integrated/

# recon/ 디렉터리만 Strix 엔진으로 교체 (삭제는 막혀 있어서 덮어쓰기+추가만 함)
cp -rf recon--AI-Dast/src/aidast/recon/. integrated/src/aidast/recon/
```

- **베이스는 artex 전체**(968개 파일: `core/`, `pipeline/`, `validation/`, `scope/`, `agents/`, `auth/`, `web/`, `WebUI/` 등 전부 포함). artex 쪽은 거의 그대로 둠.
- **`src/aidast/recon/` 디렉터리만** `recon/AI-Dast`의 것으로 교체:
  - 겹치는 파일명(`__init__.py`, `activity.py`, `agent.py`, `annotations.py`, `db.py`, `judgment.py`, `models.py`, `policy.py`, `profiles.py`, `surface.py`, `tools/`)은 **Strix 쪽 내용으로 덮어씀**.
  - Strix 전용으로 새로 추가된 파일: `api_spec_ingestion.py`, `strix_bridge.py`, `strix_engine/`(디렉터리 전체, root/child 에이전트, 동적 스킬 로더, Docker 샌드박스 연동 등).
  - artex에만 있던 (결정론적 recon 전용) 파일은 **지우지 못함**(연결 폴더의 삭제 제한 때문) — `diagnostics.py`, `executor.py`, `origin.py`, `source_import.py`, `tagging_progress.py`, `ui_synthesis.py`, `verification.py`가 그대로 남아있음. **이 파일들은 죽은 코드입니다** — 아래 3-3에서 설명하듯 `integrated`의 `cli.py`를 통해 recon을 실행하지 않기 때문에 실제로 쓰이지 않습니다. 신경 쓰지 않아도 되지만, 나중에 레포를 정식으로 정리할 때 삭제 대상입니다.
- 그 위에 `merged/`에서 만든 두 패치(`chaining/db_cli.py`, `attack/request_cli.py`)를 다시 적용.
- 추가 파일: `scripts/register_strix_credentials.py` (아래 3-4).

### 3-2. 호환성을 어떻게 확인했나 (이게 이 통합이 성립하는 핵심 근거)

- `recon/AI-Dast`의 `src/aidast/pipeline/schema.py`를 `artex`의 것과 `diff`로 비교 → **완전히 동일 (0줄 차이)**. `credential_references`, `sessions`, `attack_tasks`, `attack_http_requests` 등 artex의 attack 코드가 기대하는 테이블이 전부 `recon/AI-Dast`에도 같은 구조로 존재.
- `recon/AI-Dast`의 `recon/db.py`도 `from aidast.pipeline.schema import migrate_pipeline_schema`를 호출해서 **같은 통합 Pipeline.db에 스키마를 적용**(artex의 `recon/db.py`와 동일한 패턴). 즉 Strix 엔진은 원래부터 팀의 공유 파이프라인 스키마를 염두에 두고 만들어져 있었음.
- `sessions` 테이블 컬럼(`session_id, origin_id, target, auth_state, isolation_scope, created_at, expires_at`)이 양쪽에서 동일.
- `request_cli.py`의 정책(JSON) 읽기 코드(`_policy_allows`)는 artex 전용 신규 필드(`execution_allowed_methods`, `excluded_hosts`)를 `policy.get(...)`로 읽어서, 없으면 허용 쪽으로 기본값 처리 — 즉 `recon/AI-Dast`가 만드는 조금 더 오래된 형식의 `TargetPolicy.json`도 문제없이 읽힘.

### 3-3. 왜 `cli.py`는 합치지 않았나 — "두 설치본" 아키텍처

artex의 `cli.py`에 있는 `recon` 명령은 `ReconExecutor`(결정론적 크롤러) 전용으로 깊게 짜여 있음(`_run_recon` 함수가 스코프 검증, TargetPolicy 생성, 실행, 태깅까지 한 흐름으로 묶여 있고, 수백 줄 단위). `recon/AI-Dast`의 `_run_strix_recon`(약 400줄)을 여기 억지로 꽂아 넣으려면 두 명령의 로직을 줄 단위로 재설계해야 해서 위험 부담이 컸고, 테스트도 어려운 환경이라 섣불리 손대지 않기로 했습니다.

대신 택한 방식: **recon과 attack을 서로 다른 두 개의 설치본(venv)으로 돌리고, 같은 DB 파일을 공유**.

```
[recon/AI-Dast 설치]              [integrated 설치]
    aidast recon ...        →         Recon.db (= Pipeline.db)
  (Strix 엔진, 이미 검증됨)              ↓  같은 파일 경로를 --db로 넘김
                                   aidast attack ...
                                   aidast chain ...
```

이게 가능한 이유는 3-2에서 확인한 스키마 동일성 때문입니다. `integrated`의 `recon/` 디렉터리를 Strix로 바꿔둔 건 사실 이 "두 설치본" 방식에서는 **직접 쓰이지 않습니다** — recon 실행 자체는 원래 쓰던 `recon/AI-Dast` 설치로 하기 때문입니다. `integrated` 안의 `recon/` 교체는 향후 `cli.py`까지 완전히 합치는 작업을 할 때를 위한 준비 단계로 남겨둔 것입니다.

### 3-4. 자격증명(Identity B) 연결 — `register_strix_credentials.py`

artex는 이미 이 문제를 풀어둔 함수가 있었습니다: `src/aidast/pipeline/browser_credentials.py`의 `register_browser_session_credentials()`. artex 자신도 recon이 끝나면 `cli.py`에서 이 함수를 호출해서 `credential_references`를 채웁니다(`executor.auth_session_files`라는, 결정론적 recon이 실행 중 쌓아두는 세션 목록을 넘겨줌).

`recon/AI-Dast`는 별도 프로세스라 이 자동 호출 지점이 없습니다. 그런데 `recon/AI-Dast`의 `src/aidast/recon/tools/agent_browser.py`가 로그인/계정생성 시 저장하는 세션 파일이 Playwright `storage_state` 형식이고, 이게 `register_browser_session_credentials()`가 내부적으로 쓰는 `PlaywrightDriver`/`ManualSessionConfig(session_file=...)`가 읽는 바로 그 형식이라는 걸 확인했습니다. 그래서 새 로직을 만들 필요 없이, **기존 함수를 그대로 호출하는 작은 브리지 스크립트**만 추가했습니다 (`integrated/scripts/register_strix_credentials.py`, 기존 파일은 전혀 수정하지 않음).

이 함수는 이미 `identity_b` 같은 복수 계정 역할을 네이티브로 지원합니다(`sessions` 파라미터가 3-튜플이면 기본 `authenticated` 역할, 4-튜플이면 임의의 `identity_role` 문자열 — 원래부터 우리의 dual-identity IDOR 테스트를 위해 설계된 것처럼 맞아떨어졌습니다).

### 3-5. `guarded_replay` 재구현 상세

`merged/`에서 만든 것과 동일하지만, 최종본(`integrated/src/aidast/attack/request_cli.py`)에 있는 버전을 기준으로 정리:

- **입력 검증** (ours와 동일한 기준 유지):
  - source request가 이 scan의 `http_transactions`에 실제로 있는지, 해당 endpoint가 `is_excluded=0`인지.
  - method가 `SAFE_METHODS`(GET/HEAD/OPTIONS)인지 — mutation 재생은 금지.
  - URL 쿼리에 자격증명성 파라미터(`_SENSITIVE_QUERY_NAME`: access_token, password, session_id 등)가 없는지.
  - body가 없는지(읽기 전용만 재생 허용).
  - `target_origin`이 source request의 origin과 일치하는지(`_origin_key` 비교) — 크로스 오리진 재생 방지.
  - endpoint가 인증 필요로 태깅돼 있거나, 해당 origin에 인증된 세션이 있는지.
  - endpoint에 식별자 파라미터(`parameters.is_identifier=1`)가 있는지 — IDOR 비교 대상이 될 자격이 있는 요청인지.
  - source 응답이 2xx였는지(Account A 기준선이 성공적이었는지).
- **헤더 처리**: source request의 헤더에서 자격증명/세션 관련 헤더(`SENSITIVE_HEADERS`, `_SENSITIVE_AUTH_HEADER`, `_REPLAY_OMIT_HEADERS`)를 제거한 "안전한" 헤더만 남김.
- **인증 전환**: 제거한 자격증명 대신 `credential_reference_id`를 payload에 넣어서 `guarded_request()`에 넘김. `guarded_request()`의 기존 `_credential_headers()`가 이 reference를 해석해서 Account B의 헤더를 주입 — 즉 artex의 기존 보안 검증(해당 task에 이 credential_reference가 허용돼 있는지, origin이 맞는지, identity_role이 호환되는지)을 **전부 그대로 통과**해야만 재생이 성립합니다. 우리가 검증을 우회한 게 아니라 artex의 기존 체크 위에 얹은 것입니다.
- **CLI**: `replay-observed` 서브커맨드, 인자는 `--source-request-id`, `--target-origin`, `--credential-reference-id`.

---

## 4. 검증 상태 (지금까지 한 것 / 안 한 것)

**한 것:**
- `py_compile`로 수정/추가된 모든 파일의 문법 검증 완료 (`request_cli.py`, `chaining/db_cli.py`, `register_strix_credentials.py`, 교체된 `recon/` 파일들, `orchestration/chaining.py`).
- `request_cli.py`가 import하는 artex 전용 지원 모듈(`core/capture_receipt.py`, `core/request_governor.py`, `pipeline/request_profiles.py`, `pipeline/browser_credentials.py`, `attack/surface.py`, `validation/execution/credentials.py`)이 전부 `integrated/` 트리에 실제로 존재하는지 확인.
- 스키마 동일성(`pipeline/schema.py` diff 0, `sessions` 테이블 컬럼 동일) 확인.
- `recon/AI-Dast`·`AI-Dast-main` 원본은 전혀 수정하지 않았음을 `git status`/수정시각으로 재확인 (이번 통합 작업은 전부 `attack/` 폴더 안의 사본에서만 진행).

**안 한 것 (실행 환경 제약):**
- 실제 `aidast recon`/`aidast attack`/`aidast chain` 명령 실행 — 이 작업 환경엔 Docker/네트워크가 없어서 WSL에서 직접 해봐야 함.
- 유닛 테스트 스위트 실행.
- `guarded_replay`를 실제 Juice Shop/VulnBank 대상으로 돌려서 자격증명 해석·IDOR 비교가 끝까지 동작하는지 확인.

실제 테스트 순서와 각 단계에서 확인해야 할 SQL/명령어는 대화 중 안내된 절차를 따르면 됩니다 (Juice Shop → VulnBank → 승인된 실제 타깃 순서, 각 단계에서 `credential_references` 등록 여부·`guarded_replay` 응답 코드 비교·`finding_chains.status` 승격 여부를 확인).

---

## 4-1. 실행 중 발견된 문제: `pyproject.toml`에 `recon-engine` extra가 없었음

`integrated/`는 artex의 `pyproject.toml`을 그대로 가져왔는데, artex는 Strix 엔진을 모르니 `[project.optional-dependencies]` 테이블 자체가 없었습니다. `recon/AI-Dast`의 `pyproject.toml`에서 `recon-engine` extra(`openai-agents[litellm]`, `litellm`, `docker`, `pydantic-settings`, `rich`, `requests`, `cvss`, `markdown-it-py`, `reportlab`, `pypdf`)와 `aidast.recon.strix_engine` 패키지 데이터 항목을 그대로 가져와서 추가했습니다.

**아직 확인 못 한 잠재적 충돌**: 두 `pyproject.toml`의 기본 의존성 버전이 다릅니다 — artex는 `cryptography>=41,<46` / `websockets>=17.1,<18`, `recon/AI-Dast`는 `cryptography>=48.0.1,<49` / `websockets>=15,<17`를 요구합니다. `integrated/`는 artex 쪽 범위를 그대로 쓰고 있어서, `recon-engine` extra의 패키지들이 더 신버전 `cryptography`를 강제로 요구하면 `uv sync` 단계에서 의존성 해석 충돌이 날 수 있습니다. 지금은 TOML 문법 오류만 고쳤고, 이 버전 충돌은 실제로 `uv sync --extra recon-engine`을 돌려봐야 나타나는지 확인 가능합니다 — 에러 나면 그대로 알려주세요.

## 4-3. 실제 recon 실행에서 발견한 버그: Material 커스텀 드롭다운은 클릭이 안 먹힘

`import 수정 끝내고 `uv run aidast --help`가 성공한 뒤, 실제로 `recon/AI-Dast` 설치본으로 Juice Shop(`juice-shop-open`) recon을 돌렸습니다 (`--allow-lab-account-creation`, 두 번째 계정=Identity B 생성 시도).

**결과**: 태깅은 14/14 배치 전부 0건 실패로 완벽했지만(배치 크기 20 수정이 유효함을 재확인), **가입(signup)이 끝까지 안 가서 `finish_recon`이 두 번 거부**됐고, 결국 미인증 상태로 123개 엔드포인트만 남기고 종료됨. agents.db의 전체 대화 기록을 직접 조회해서 원인을 추적했습니다.

**지난번 쿠키 배너 버그와는 다른, 새로운 버그였습니다.** 쿠키 배너는 이번엔 매번 정상적으로 닫혔습니다(그 수정은 계속 유효). 문제는 가입 폼의 "보안 질문" 선택란 — 네이티브 `<select>`가 아니라 Angular Material의 `mat-select`(ARIA `combobox`+`listbox`+`option` 패턴, 옵션이 별도 overlay에 렌더링됨)였습니다.

**직접 재현해서 원인을 확정했습니다** (추측이 아니라 WSL에서 `agent-browser`를 npm으로 직접 설치해서 Juice Shop 가입 폼을 한 동작씩 분리해서 테스트):
1. `click @e20`(콤보박스 트리거)로 드롭다운을 열면 — 옵션들이 `@e23`~`@e36` 식으로 정상적으로 개별 ref가 붙어서 나타남 (agent-browser의 접근성 트리 인식 자체는 문제없음).
2. **`click @e34`(특정 옵션 직접 클릭) → "✓ Done"으로 보고되지만, 재스냅샷해보면 드롭다운이 여전히 열려있고 아무것도 선택 안 됨.** 이게 recon 실행에서 가입이 끝까지 안 간 진짜 원인 — 클릭이 "성공"으로 보고되는데 Angular Material 컴포넌트의 내부 상태가 반응을 안 함.
3. **`focus @e20` → `press ArrowDown` → `press Enter` → 성공.** 재스냅샷하면 `expanded=false`로 닫히고, 콤보박스 값에 선택한 옵션 텍스트가 실제로 반영됨.

**수정한 파일**: `recon/AI-Dast`와 `integrated` 양쪽의 `src/aidast/recon/strix_engine/skills/tooling/agent_browser.md` (두 파일이 동일해야 해서 둘 다 수정) — "커스텀 콤보박스의 옵션은 클릭하지 말고 키보드(focus→ArrowDown/Up→Enter)로 선택하라, 재스냅샷으로 `expanded=false`와 선택된 텍스트를 확인하기 전엔 성공으로 가정하지 말라"는 지침을 "Dismiss cookie/consent banners" 단락 바로 뒤에 추가.

**일반화 근거**: Angular Material뿐 아니라 MUI, Ant Design, Radix/Headless UI 등 ARIA `combobox`+`listbox` 패턴을 쓰는 커스텀 드롭다운 전반에 적용되는 문제로 보입니다(동일한 접근성 패턴이라 동일한 synthetic-click 처리 방식을 쓸 가능성이 높음). Juice Shop 전용 우회가 아니라, 이 패턴을 쓰는 어떤 타깃에도 적용되는 범용 수정입니다. 다만 "모든 프레임워크에서 100% 이렇다"까지 검증한 건 아니고, Angular Material에서 직접 재현해서 확정한 사실이라는 점은 명확히 구분해둡니다.

**아직 안 한 것**: 이 수정을 반영한 재실행(두 번째 계정 가입이 실제로 끝까지 가는지)은 아직 안 해봤습니다. 다음 recon 실행에서 확인 필요.

## 5. 하지 않은 것 / 남겨둔 것 (의도적으로 손대지 않음)

- `orchestration/chaining.py`의 artex 전용 멱등성 스킵 기능(새 finding 없으면 체이닝을 SKIPPED 처리) — `ours`엔 없던 기능이라 이번 포팅 범위에 넣지 않음. artex 원본 그대로 유지.
- `integrated/src/aidast/recon/`에 남아있는 구버전 결정론적 recon 전용 파일들(`diagnostics.py`, `executor.py`, `origin.py`, `source_import.py`, `tagging_progress.py`, `ui_synthesis.py`, `verification.py`) — 연결 폴더 삭제 제한 때문에 못 지웠고, 지금 방식(두 설치본)에서는 쓰이지 않는 죽은 코드. 정식 레포로 옮길 때 정리 권장.
- `cli.py` 자체의 recon 명령 통합 — 아직 artex 원본 그대로. Strix recon은 `recon/AI-Dast` 설치본으로 별도 실행.
- WebUI — `integrated/WebUI`에는 artex가 가진 일반적인 공격 관련 화면(수동 로그인 안내, 리포트 제출, 공격 커버리지 대시보드)만 그대로 들어있고, `guarded_replay`를 위한 화면은 없음. 필요하면 추가 작업.
