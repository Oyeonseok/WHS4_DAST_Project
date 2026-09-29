# Neon 공통 제한을 적용한 로컬 Scope — 2026-09-29

사용자가 승인한 구성에 따라 Juice Shop과 VulnBank에 `X-Bug-Bounty` 하나만 사용하고 Neon의 1초당 10회 상한을 적용한 별도 Scope를 생성했다. 총 요청 예산 500회, 동시성 1, timeout 15초, depth 2는 로컬 실험 설정이며 공식 Neon 요구사항으로 표시하지 않는다.

## 출처와 적용

- 원문: `result/Scope/hackerone/neon_bbp/Scope.json`. 공식 프로그램 URL, 캡처 내용 해시, 승인 파일 및 정확한 헤더·요청 제한 인용을 확인했다.
- 새 Scope: `result/Scope/lab-aidast-invalid/neon-policy-juice-shop/`, `neon-policy-vuln-bank/`.
- 헤더 값은 기존 Neon 정책에 저장된 사용자 식별값을 사용했다. 앱 로그인용 Cookie/Bearer와는 별도다.
- `ApprovedScopeCatalog`에서 두 Scope 모두 `ready`, 상한 10, 필수 헤더 `X-Bug-Bounty`로 조회됨을 확인했다.
- 신규 정책의 원장은 정상 스캔 실행 시 연결된다. 로컬 송신 검증에는 별도 스캔 ID의 정책 스냅샷과 원장을 사용했다.

## 테스트 결과

```bash
.venv/bin/python -m pytest tests/test_local_neon_policy_lab.py \
  tests/test_request_governor.py tests/test_required_identity_headers.py \
  tests/test_scope_execution_rules.py tests/test_governor_transports.py -q
```

**74 passed, 21.07초.** 신규 11개 테스트를 구현 전에 실행해 기능 부재로 실패하는 것을 확인했다. 구현 후 전체 집중 검사가 통과했다.

검사 범위는 원문·해시 불일치 거부, 두 loopback 포트의 메서드 경계, 단일 식별 헤더 주입과 앱 인증 보존, 1초 rolling quota 차단, 서로 다른 broker 인스턴스 사이의 스캔 전체 500회 예산, 공유 동시성 1, 동일 설정 재실행의 바이트 보존이다. 기존 전송 검사에서 Attack·Validation HTTP/browser/transport·Recon proxy의 공유 governor 연동도 확인했다.

500회 예산 검사는 가상 시계와 통제 HTTP 응답을 사용한다. 실제 앱에 500회를 보내거나 취약점을 공격한 실험이 아니다.

## 실제 로컬 송신 확인

| 대상 | 요청 | 결과 | 송신 헤더 검사 |
| --- | --- | --- | --- |
| Juice Shop `http://127.0.0.1:3001/` | 루트 GET 3회 | HTTP 200, 3/3 | `X-Bug-Bounty` 일치, `X-HackerOne` 없음 |
| VulnBank `http://127.0.0.1:5001/` | 루트 GET 3회 | HTTP 200, 3/3 | `X-Bug-Bounty` 일치, `X-HackerOne` 없음 |

첫 네트워크 시도는 샌드박스의 loopback 접근 제한으로 중단됐다. 허용된 로컬 접속으로 다시 실행해 위 결과를 얻었다. 응답 본문과 인증 비밀값은 저장하지 않았다. 헤더 확인은 클라이언트의 실제 전송 경계에서 수행했으며 서버의 수신 로그를 확보한 것은 아니다.

실시간 검사는 소량 요청이므로 상한을 채운 부하 실험이 아니다. quota·총량 차단은 위 통제 테스트 결과로 구분한다. 공유 governor는 quota를 초과하는 예약을 즉시 거부하며, 최대 속도의 지속적인 전송을 보장하는 큐가 아니다.

실행 원본: `result/test-runs/09.29/neon-common-policy/live-smoke.json`, `verify_live.py`, `catalog.json`, 앱별 `TargetPolicy.json`, `.policy-budgets/`.

## 원본 보존

기존 Juice Shop·VulnBank·Neon Scope 디렉터리의 일반 파일 18개를 생성 전후 SHA-256으로 대조해 변경이 없음을 확인했다. 기준 해시는 `result/test-runs/09.29/neon-common-policy/original-artifact-hashes.json`에 보관했다.

사용법은 [Neon 공통 제한 실험 안내](../../LOCAL_NEON_POLICY_LAB.md)에 있다. 새 Scope를 선택해 시작하는 이후 스캔에 적용되며, 기존 스캔의 정책과 판정을 소급 변경하지 않는다.
