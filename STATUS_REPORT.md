# artex + Strix recon 통합 현황 (2026-10-12 기준)

## 요약

artex(공격/체이닝/검증 본체)를 기준으로, benchmark의 필요한 부분과 우리 로컬 수정본(ours)의 고유 기능 두 가지를 얹고, recon 엔진은 민석의 Strix 기반 엔진(`recon/AI-Dast`)으로 교체하는 통합을 진행했습니다. recon과 attack을 억지로 하나로 합치지 않고, "같은 DB 파일을 공유하는 두 개의 독립 설치"로 구성했습니다 — recon/AI-Dast의 recon 구현과 artex의 recon 구현이 이미 너무 많이 갈라져 있어서, 억지로 합치는 것보다 이 방식이 훨씬 안전하다고 판단했습니다.

지금까지 한 일은 (1) 비교 분석, (2) 통합 빌드 제작, (3) 실제 Juice Shop 대상 recon→attack 연결까지 실전 테스트입니다. 아래는 그 과정에서 **확실히 잘 작동하는 것**과 **아직 해결이 필요하거나 알고 있어야 할 것**을 나눈 것입니다.

## 잘 작동하는 것

**recon 자체는 안정적입니다.** Juice Shop을 상대로 여러 번 돌려봤고, 매번 70~100개 이상의 엔드포인트를 수집하고, Scope 경계(mitmproxy fail-closed)도 정확히 지켜졌습니다. recon이 도중에 깨지거나 Scope 밖으로 나간 적은 한 번도 없었습니다.

**병합 중 생긴 진짜 호환성 버그 5건을 찾아서 고쳤습니다.** `pyproject.toml`의 의존성 누락(recon-engine extra, websockets 버전 충돌), `recon/policy.py`가 Strix 버전으로 통째로 바뀌면서 cli.py가 필요로 하던 함수들이 없어진 것, `auth/browser.py`도 마찬가지로 Strix가 필요로 하는 함수가 빠진 것, `mitm_proxy.py`에 레거시 코드가 참조하는 함수가 없던 것, 그리고 가장 최근에 찾은 `endpoints` 테이블에 artex의 attack 쪽 코드가 요구하는 `verification_status` 컬럼이 recon/AI-Dast 스키마에 없던 것. 전부 원인을 정확히 찾아서 고쳤고, 마지막에는 `attack/orchestration/pipeline` 전체 SQL을 실제 DB 스키마와 자동으로 대조하는 검사를 돌려서 **더 이상 같은 종류의 숨은 버그가 없는지까지 확인**했습니다.

**recon→attack 핸드오프가 실제로 작동하는 걸 확인했습니다.** 이게 가장 중요한 결과입니다 — recon이 끝난 DB를 가지고 artex의 실제 `AttackCoordinator`(진짜 Codex 모델 호출, 목이나 시뮬레이션 아님)를 돌려서, 공격 가설(annotation) 4192개가 실제로 생성됐고, 공격 배치가 여러 번 완료됐고, finding도 1건 이미 나왔습니다. 즉 recon 산출물이 attack 쪽에서 실제로 읽히고 쓰인다는 것이 증명됐습니다.

**크로스 계정 인증(credential_reference_id) 모델도 연결 확인했습니다.** artex의 새 인증 모델(옛 identity_role/session_state 방식 대신 credential_references 테이블 기반)에 맞춰 두 번째 계정(Identity B)을 수동 가입 후 등록하는 데 성공했고, IDOR 교차 계정 테스트(guarded_replay)에 쓸 수 있는 상태까지 만들었습니다.

## 아직 해결이 필요하거나, 알고 있어야 하는 것

**계정 가입 자동화가 비결정적입니다.** Juice Shop의 Angular Material 드롭다운/제출 버튼에서, recon 에이전트가 쓰는 `agent-browser`의 클릭이 "성공"으로 보고돼도 실제로는 눌리지 않는 경우가 있습니다. 직접 재현해서 원인을 확인했고(클릭 대신 키보드 입력을 쓰면 확실히 됨), 이 가이드를 recon의 skill 문서에 일반화된 형태로 추가했습니다. **다만 이건 "고쳤다"고 할 수 있는 종류의 문제가 아닙니다** — LLM 에이전트가 매번 그 가이드를 그대로 따르진 않아서(4번 시도 중 1번만 가이드대로 함), 여전히 실패할 수 있습니다. 중요한 건 이게 **우리가 만든 문제가 아니라는 것**입니다 — 병합 전, 저희가 코드를 하나도 안 건드렸던 10/10 시점의 원본 recon/AI-Dast에서도 3번 중 2번은 실패했던 걸 로그로 확인했습니다. 대응책은 자동 재시도와, 실패 시 수동 가입 후 세션을 등록하는 경로(스크립트로 준비됨) 두 가지입니다.

**`aidast resume`(이어서 진행하기)을 못 씁니다.** 이건 artex 자체 recon(`aidast run`)만 만드는 `Handoff.json`이라는 인수인계 파일이 있어야 쓸 수 있는 명령어인데, Strix 브릿지로 recon을 돌리면 이 파일이 생기지 않습니다. 두 설치를 분리하기로 한 설계의 당연한 결과이고, 실타깃이든 랩이든 Strix로 recon을 돌리면 항상 그렇습니다. 대신 `AttackCoordinator`를 직접 호출하는 스크립트를 만들어서 우회했고, 이건 랩/실타깃 구분 없이 똑같이 작동합니다.

**attack 다음 단계(chaining → validation → report)가 자동으로 이어지는지는 아직 검증 전입니다.** 지금까지는 recon→attack만 확인했고, attack 배치가 끝나는 대로 chaining부터 이어서 확인할 계획입니다.

**아직 git 저장소가 아닙니다.** `attack/integrated` 폴더는 지금 로컬 실험 상태이고, 팀 repo에 올리려면 테스트가 끝난 뒤 git 저장소로 만들고 커밋/푸시하는 절차가 따로 필요합니다.

**속도가 느립니다.** 공격 단계가 엔드포인트 하나당 실제 모델 호출을 거치기 때문에, 112개 커버리지 항목을 전부 처리하는 데 꽤 오래 걸립니다(현재도 진행 중). 실타깃처럼 범위가 넓어지면 더 오래 걸릴 수 있다는 걸 감안해야 합니다.

**WebUI는 artex 기본 화면뿐입니다.** guarded_replay(교차 계정 IDOR) 결과를 보여주는 전용 화면 같은 건 없고, 기존 artex 대시보드가 보여주는 정도만 됩니다. 필요하면 WebUI 쪽에서 추가 작업이 필요합니다.
