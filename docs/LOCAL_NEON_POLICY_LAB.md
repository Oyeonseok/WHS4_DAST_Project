# Juice Shop · VulnBank의 Neon 공통 제한 실험

로컬 앱 두 개에 Neon의 명확한 요청 제한과 식별 헤더만 옮긴 별도 실험용 Scope다. 현재 로컬 Scope는 이 두 최신 정의를 사용하며, Neon 승인본은 별도로 보존한다. 실제 Neon 자산을 테스트하도록 허가하는 문서가 아니다.

| 설정 | 적용 값 | 근거 |
| --- | --- | --- |
| 요청 상한 | 프로그램 기준 1초당 10회 이하 | 캡처된 Neon 원문 |
| 필수 식별 헤더 | `X-Bug-Bounty: <HackerOne username>` | 캡처된 Neon 원문 |
| 스캔 전체 요청 예산 | 최대 500회 | 로컬 실험 설정 |
| 동시성 | 1 | 로컬 실험 설정 |
| 요청 timeout · 탐색 depth | 15초 · 2 | 로컬 실험 설정 |

총 요청 예산은 Recon·Attack·Validation 전체에서 같은 스캔 원장으로 계산한다. 두 앱은 각각 독립 프로그램으로 등록되어 앱별 스캔 예산을 사용한다. 실제 사용 속도는 선택한 실행 프로필이나 더 낮은 사용자 설정으로 좁혀질 수 있다. 공유 원장은 rolling 1초 quota를 초과하는 예약을 전송 전에 거부한다. quota는 단순히 평균 속도를 의미하지 않으며 창이 만료되기 전의 추가 예약은 차단될 수 있다.

Prism의 권고 헤더, Neon 전용 이메일 도메인, production 사전 연락, 특정 Neon 폼 제외 조건은 이 공통 제한 실험에 옮기지 않는다. 로그인용 Cookie·Bearer 인증은 앱별로 유지한다. 기존 로컬 권한의 외부 접근·파괴 행위 금지와 GET/HEAD/OPTIONS/POST 경계도 유지한다.

## 생성

```bash
PYTHONPATH=src .venv/bin/python scripts/prepare_local_lab_scopes.py \
  --policy-profile neon-common \
  --policy-source result/Scope/hackerone/neon_bbp/Scope.json \
  --hackerone-username YOUR_HACKERONE_USERNAME
```

캡처 내용의 SHA-256, 공식 Neon URL, 정확한 두 원문 인용을 확인한다. 승인 파일이 함께 있으면 Scope 승인 해시도 확인한다. 헤더 값을 검증한 뒤 기존 게시 방식으로 `Scope.json`, `Scope.md`, `Manifest.json`, `Approval.json`과 실행 가능한 `TargetPolicy.json`, 출처 설명 `LabPolicyProvenance.json`을 생성한다. 원문이 다르거나 기존 실험 파일의 신원·정책이 다르면 덮어쓰지 않는다.

산출물:

- `result/Scope/lab-aidast-invalid/neon-policy-juice-shop/`
- `result/Scope/lab-aidast-invalid/neon-policy-vuln-bank/`

Scope 이름은 **Local Lab — Neon policy — juice-shop**, **Local Lab — Neon policy — vuln-bank**다. 대시보드에서 해당 Scope를 선택하고 필수 HackerOne username을 입력한다. 등록된 대상은 각각 `http://127.0.0.1:3001/`, `http://127.0.0.1:5001/`이다.

이 두 Scope는 실행 규칙과 필수 헤더를 생성 시 구조화하므로 선택 시 AI 정책 재해석을 기다리지 않는다. 정책 코드 변경 전에 시작한 대시보드 서버는 새 산출물을 목록에서 누락할 수 있다. 해당 경우 진행 중인 스캔을 확인한 뒤 서버를 최신 코드로 재시작하고 화면을 새로고침한다. 이전 `AI DAST Local Lab` 정의는 정리했으며, 대시보드에서는 위 두 최신 로컬 Scope를 선택한다.

## 새 통합 실험 시작

```bash
aidast run https://lab.aidast.invalid/neon-policy-juice-shop \
  --target http://127.0.0.1:3001/ \
  --hackerone-username YOUR_HACKERONE_USERNAME \
  --profile focused-recon --max-requests 500 --max-concurrency 1

aidast run https://lab.aidast.invalid/neon-policy-vuln-bank \
  --target http://127.0.0.1:5001/ \
  --hackerone-username YOUR_HACKERONE_USERNAME \
  --profile focused-recon --max-requests 500 --max-concurrency 1
```

이 명령은 새 전체 실험을 시작한다. 생성 자체에는 외부 모델 호출이나 대상 요청이 없다. 앱 로그인 정보는 정상 로그인 또는 각 앱의 session bundle로 공급한다.

Scope의 `TargetPolicy.json`에는 특정 스캔 ID를 고정하지 않는다. 통합 실행 시 `bind_execution_policies`가 스캔별 공유 governor를 연결하고, 후속 단계에는 해당 실행의 정책 스냅샷을 전달한다. 이전 스캔에 새 Scope를 소급 적용하지 않는다.

## 검증

```bash
.venv/bin/python -m pytest tests/test_local_neon_policy_lab.py \
  tests/test_request_governor.py tests/test_required_identity_headers.py \
  tests/test_scope_execution_rules.py tests/test_governor_transports.py -q
```

신규 테스트는 두 대상의 정확한 포트·메서드 경계, 원문·해시 검증, 단일 Neon 헤더, 앱 인증 보존, rolling quota, 공유 요청 예산 500회, 동시성 1과 재생성 시 원본 보존을 검사한다. 500회 예산 검사는 가상 시계와 통제 전송을 사용하므로 앱에 500회 요청을 보내지 않는다.
