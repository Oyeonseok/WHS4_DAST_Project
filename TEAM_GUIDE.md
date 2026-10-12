# TEAM_GUIDE — 역할별 안내

이 문서는 `integrate/strix-recon-merge` 브랜치에서 작업할 팀원 각자가 "내 역할에서 뭘 어떻게 돌리면 되는지"만 보면 되게 정리한 것입니다. 병합 과정 전체(왜 이렇게 구조를 짰는지, 어떤 버그를 고쳤는지)는 `how_to_Integrated.md`를 보세요. 여긴 현재 사용법 위주입니다.

## 공통: 하나의 통합 설치를 사용합니다

- 설치: `uv sync --locked --extra recon-engine --group dev`
- 전체 실행: `uv run python -m aidast run <scope-url> --target <승인 자산> --recon-engine integrated ...`
- `integrated`는 Strix를 먼저 실행하고, Strix 런타임이 막히거나 인스코프 엔드포인트가 없을 때 같은 승인 정책으로 기본 정찰을 이어서 실행합니다.
- 공용 `Recon.db`에서 `Surface.json`과 `Handoff.json`을 만든 뒤 Attack, Chaining, Validation, Report가 자동으로 이어집니다.

---

## WebUI 담당

- 실행: `uv run python -m aidast dashboard --result-root <결과 폴더> --ui-dir WebUI/dist`. 기본 포트 8000, `127.0.0.1`에만 바인딩됩니다.
- 새 스캔 화면에서 `Strix 통합 · 기본 정찰 자동 대체` 또는 `기본 정찰 엔진`을 선택할 수 있습니다. 기본값은 통합 Strix입니다.
- `로그인 방식`을 `런타임 브라우저`로 선택하면 동일한 사람 로그인 세션을 유지하기 위해 기본 정찰 엔진으로 자동 전환됩니다.
- `--ui-dir`로 빌드된 WebUI dist 폴더를 지정하면 그걸 `/`에서 서빙합니다. 커스텀 화면을 만들고 있다면 여기로 꽂으면 됩니다.
- WebUI는 정찰 엔진 선택과 통합 실행 인자를 지원합니다. `guarded_replay`(IDOR 크로스 계정 테스트) 전용 화면은 아직 없으므로 해당 기능은 CLI에서 실행합니다.

## 공격(Attack) 검토/수정 담당

- 핵심 파일: `src/aidast/attack/*`(특히 `coverage.py`, `graph.py`, `surface.py`, `request_cli.py`), `src/aidast/orchestration/attack.py`(`AttackCoordinator`), `src/aidast/orchestration/coverage_attack.py`(`ExhaustiveAttackCoordinator`).
- 통합 실행은 `Handoff.json`을 만들기 때문에 후속 단계 실패 시 `aidast resume <scan_id>`을 사용할 수 있습니다. Attack만 따로 점검하려면:
  ```bash
  uv run python -m aidast.cli attack coverage-plan <Recon.db> --scan-id <scan_id>
  uv run python scripts/run_attack_coordinator.py \
    --db <Recon.db> --scan-id <scan_id> \
    --scope <Scope.md 경로> --policy <TargetPolicy.json 경로>
  ```
  `run_attack_coordinator.py`는 `AttackCoordinator`를 Handoff 없이 직접 부르는 스크립트입니다(recon/attack 본체 코드는 수정 안 함).
- **credential_reference_id 모델**: 이번 artex 버전은 `identity_role`/`session_state` 파일 대신 `credential_references` 테이블 + `credential_reference_id`로 인증을 다룹니다. 교차 계정(IDOR 등) 테스트용 두 번째 계정은 `scripts/register_strix_credentials.py`로 등록합니다.
- **알고 있어야 할 스키마 차이**: recon/AI-Dast의 `endpoints` 테이블에 원래 `verification_status` 컬럼이 없어서 `coverage-plan`이 깨졌습니다 — `recon/db.py`/`pipeline/live_schema.py`에 이미 고쳐 넣었으니, 이 `integrated/`를 그대로 쓰면 신경 안 써도 됩니다. 혹시 recon 쪽을 더 건드리면서 비슷한 "no such column" 오류가 또 나오면, 같은 패턴(`PRAGMA table_info`로 확인 후 `ALTER TABLE ... ADD COLUMN`)으로 고치면 됩니다 — recon/AI-Dast와 artex의 테이블 스키마가 100% 동일하지 않을 수 있다는 걸 염두에 두세요.

## 실타깃 버그바운티 담당

- 실타깃은 `--allow-lab-account-creation` 대신 **`--allow-authorized-account-registration`**을 씁니다 (사람의 명시적 승인/HITL 전제). `--allow-lab-account-creation`은 랩 전용이니 실타깃에 쓰지 마세요.
- **계정 가입 자동화가 비결정적입니다.** Angular Material 같은 커스텀 드롭다운/버튼에서 `agent-browser`의 `click`이 "성공"으로 찍혀도 실제로는 안 눌린 경우가 있습니다 — `src/aidast/recon/strix_engine/skills/tooling/agent_browser.md`에 일반화된 가이드(클릭 후 반드시 재검증, 안 되면 `focus`+keyboard로 재시도)를 넣었지만, LLM 에이전트가 매번 그대로 따르진 않습니다(확인됨, 4번 중 1번만 가이드대로 시도).
- **그래서 자동 가입이 안 되면**: 수동으로 직접 가입/로그인(agent-browser로 직접) → `scripts/register_strix_credentials.py`로 세션을 credential_reference로 등록 — 이 경로는 랩/실타깃 무관하게 항상 됩니다. 실제로 승인된 테스트 계정이 타깃 쪽에서 이미 제공된 경우엔 애초에 자동 가입 자체가 필요 없고 이 수동 경로만 쓰면 됩니다.
- Account A(관찰 대상)의 인증된 read-only 요청 하나를 DB에 넣어야 `guarded_replay`(교차 계정 IDOR)를 테스트할 수 있는데, 실제 recon 프록시를 다시 띄우는 대신 `scripts/capture_identity_a_request.py`로 쿠키 기반 요청 하나를 직접 캡처 포맷으로 넣을 수 있습니다.
- 안전 문구: recon/attack 어느 쪽 코드도 Scope 승인 없이는 요청을 보내지 않습니다(mitmproxy가 fail-closed). 승인된 Scope 밖으로 나가는 요청은 자동으로 차단/기록됩니다.

## 태깅

- 명령어: `uv run python -m aidast.cli tag <Recon.db> --scan-id <scan_id> [--batch-size 200]`
- 내부적으로 `aidast.recon.annotations.tag_pending_observations`를 씁니다 — recon이 끝난 뒤 쌓인 미분류 observation을 배치로 분류합니다. 배치 크기 관련 버그는 이전에 이미 고쳐서 반영돼 있습니다.
- 태깅은 recon의 캡처 산출물(`coverage_diagnostics.json`, `agent_action_diagnostics.jsonl` 등)이 이미 완성된 뒤에 돌리는 **완전히 별도의 후속 단계**입니다. recon이 끝났는지는 이 파일들이 생겼는지로 확인 가능하고, 태깅까지 기다릴 필요 없이 recon 완료 즉시 attack coverage-plan 등을 시작해도 됩니다.

---

## 알려진 제약 (전원 참고)

- WebUI 통합 Strix 실행은 `aidast resume` 가능한 표준 Handoff를 생성합니다.
- 계정 가입 자동화는 본질적으로 100% 결정론적이지 않습니다 — 실패하면 재시도하거나 수동 경로(위 스크립트들)로 전환하세요.
- 로컬 변경은 `integrate/strix-recon-merge` 작업 트리에 있으며, 별도 요청 전에는 push하지 않습니다.
