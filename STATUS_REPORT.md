# artex + Strix Recon 통합 현황 (2026-10-12 보완)

## 현재 실행 방식

Strix Recon이 이제 artex의 `aidast run`과 WebUI 실행 경로에 직접 연결됩니다. WebUI의 새 스캔 화면에서 기본값인 **`Strix 통합 · 기본 정찰 자동 대체`**를 선택하면 다음 한 흐름으로 실행됩니다.

`Scope → Strix Recon → Recon.db/Surface.json/Handoff.json → Attack → Chaining → Validation → Report`

Strix가 Docker·모델 공급자·샌드박스 문제로 시작하지 못하거나 인스코프 엔드포인트를 하나도 만들지 못하면, 스캔을 오류로 끝내지 않고 같은 승인 Scope와 TargetPolicy를 사용해 기본 정찰 엔진이 이어서 실행합니다. 사람이 직접 로그인하는 `runtime-browser` 모드는 동일 Chromium 세션을 유지해야 하므로 처음부터 기본 정찰 엔진을 사용합니다.

WebUI에서 선택한 정찰 모델은 `chatgpt/<선택한 모델>` 형태로 Strix에 전달됩니다. 별도의 `STRIX_LLM` 환경 변수가 없어도 대시보드 모델 선택이 적용됩니다. Strix가 관찰한 트래픽은 승인된 호스트·스킴·포트·경로·메서드, 요청 예산, 속도 제한, 필수 헤더를 적용한 MITM 경계를 통과한 뒤 공용 `Recon.db`에 정규화됩니다. Docker 내부의 `host.docker.internal` 관찰은 승인된 루프백 주소로 되돌려 저장됩니다.

## 요약

artex의 공격·체이닝·검증 본체와 기존 정찰 공용 계약을 유지하면서, 통합된 Strix 기반 엔진을 선택 가능한 정찰 실행기로 연결했습니다. 초기의 두 개 독립 설치 방식은 사용하지 않습니다. 하나의 설치와 하나의 `aidast run` 프로세스가 Strix 결과를 공용 DB 계약으로 변환한 뒤 후속 단계를 실행합니다.

지금까지 한 일은 (1) 비교 분석, (2) 통합 빌드 제작, (3) 실제 Juice Shop 대상 recon→attack 연결까지 실전 테스트입니다. 아래는 그 과정에서 **확실히 잘 작동하는 것**과 **아직 해결이 필요하거나 알고 있어야 할 것**을 나눈 것입니다.

## 잘 작동하는 것

**recon 자체는 안정적입니다.** Juice Shop을 상대로 여러 번 돌려봤고, 매번 70~100개 이상의 엔드포인트를 수집하고, Scope 경계(mitmproxy fail-closed)도 정확히 지켜졌습니다. recon이 도중에 깨지거나 Scope 밖으로 나간 적은 한 번도 없었습니다.

**병합 중 생긴 진짜 호환성 버그 5건을 찾아서 고쳤습니다.** `pyproject.toml`의 의존성 누락(recon-engine extra, websockets 버전 충돌), `recon/policy.py`가 Strix 버전으로 통째로 바뀌면서 cli.py가 필요로 하던 함수들이 없어진 것, `auth/browser.py`도 마찬가지로 Strix가 필요로 하는 함수가 빠진 것, `mitm_proxy.py`에 레거시 코드가 참조하는 함수가 없던 것, 그리고 가장 최근에 찾은 `endpoints` 테이블에 artex의 attack 쪽 코드가 요구하는 `verification_status` 컬럼이 recon/AI-Dast 스키마에 없던 것. 전부 원인을 정확히 찾아서 고쳤고, 마지막에는 `attack/orchestration/pipeline` 전체 SQL을 실제 DB 스키마와 자동으로 대조하는 검사를 돌려서 **더 이상 같은 종류의 숨은 버그가 없는지까지 확인**했습니다.

**recon→attack 핸드오프가 실제로 작동하는 걸 확인했습니다.** 이게 가장 중요한 결과입니다 — recon이 끝난 DB를 가지고 artex의 실제 `AttackCoordinator`(진짜 Codex 모델 호출, 목이나 시뮬레이션 아님)를 돌려서, 공격 가설(annotation) 4192개가 실제로 생성됐고, 공격 배치가 여러 번 완료됐고, finding도 1건 이미 나왔습니다. 즉 recon 산출물이 attack 쪽에서 실제로 읽히고 쓰인다는 것이 증명됐습니다.

**크로스 계정 인증(credential_reference_id) 모델도 연결 확인했습니다.** artex의 새 인증 모델(옛 identity_role/session_state 방식 대신 credential_references 테이블 기반)에 맞춰 두 번째 계정(Identity B)을 수동 가입 후 등록하는 데 성공했고, IDOR 교차 계정 테스트(guarded_replay)에 쓸 수 있는 상태까지 만들었습니다.

## 아직 해결이 필요하거나, 알고 있어야 하는 것

**계정 가입 자동화가 비결정적입니다.** Juice Shop의 Angular Material 드롭다운/제출 버튼에서, recon 에이전트가 쓰는 `agent-browser`의 클릭이 "성공"으로 보고돼도 실제로는 눌리지 않는 경우가 있습니다. 직접 재현해서 원인을 확인했고(클릭 대신 키보드 입력을 쓰면 확실히 됨), 이 가이드를 recon의 skill 문서에 일반화된 형태로 추가했습니다. **다만 이건 "고쳤다"고 할 수 있는 종류의 문제가 아닙니다** — LLM 에이전트가 매번 그 가이드를 그대로 따르진 않아서(4번 시도 중 1번만 가이드대로 함), 여전히 실패할 수 있습니다. 중요한 건 이게 **우리가 만든 문제가 아니라는 것**입니다 — 병합 전, 저희가 코드를 하나도 안 건드렸던 10/10 시점의 원본 recon/AI-Dast에서도 3번 중 2번은 실패했던 걸 로그로 확인했습니다. 대응책은 자동 재시도와, 실패 시 수동 가입 후 세션을 등록하는 경로(스크립트로 준비됨) 두 가지입니다.

**`aidast resume`과 자동 후속 단계가 연결되었습니다.** Strix 결과도 `aidast run` 내부에서 공용 `Recon.db`, `Surface.json`, `ReconReview.json`, `Handoff.json`을 만들기 때문에 Attack 이후 단계가 실패하더라도 기존 resume 경로를 사용할 수 있습니다.

**공용 계약 회귀 검사를 완료했습니다.** 정찰·대시보드 중심 Python 검사 883개와 실제 Chromium 검사 7개, WebSocket 검증 검사 73개, WebUI 검사 150개가 통과했습니다. 전체 Python 검사에서는 3,156개가 통과했습니다. 남은 21개 실패는 현재의 target-only Validation 계약과 과거 control 기반 실습 스크립트가 서로 다른 계약을 가정하는 기존 테스트이며, 라이브 `aidast run` 경로와는 분리되어 있습니다.

**브랜치 기준점은 팀 repo에 있습니다.** 기존 통합 기준점은 `integrate/strix-recon-merge`에 push되어 있습니다. 이 문서의 2026-10-12 보완 내용과 현재 실행 어댑터 수정은 로컬 작업 트리에 있으며 별도 push는 수행하지 않았습니다.

**속도가 느립니다.** 공격 단계가 엔드포인트 하나당 실제 모델 호출을 거치기 때문에, 112개 커버리지 항목을 전부 처리하는 데 꽤 오래 걸립니다(현재도 진행 중). 실타깃처럼 범위가 넓어지면 더 오래 걸릴 수 있다는 걸 감안해야 합니다.

**WebUI에 정찰 엔진 선택이 추가되었습니다.** 통합 Strix와 기본 정찰 엔진을 선택할 수 있고, 통합 모드의 자동 대체 동작과 사람 로그인 시 기본 정찰을 사용하는 이유가 화면에 표시됩니다. guarded_replay 전용 상세 화면은 아직 별도 구현이 필요합니다.
