# Exhaustive Attack Coverage 구현 및 검증

작성일: 2026-09-24

## 결론

Recon DB의 소스 취약점 주석을 Attack 실행 단위로 변환하고, 모든 단위가 명시적인
종결 상태에 도달해야만 exhaustive 실행이 끝나도록 구현했다. 최신 loopback benchmark
실행에서는 VulnBank의 108개 주석이 108개의 coverage item으로 만들어졌고 누락 없이
모두 처리됐다. 12개 finding을 전부 독립 Validation했으며, 3개가 `CONFIRMED`되어
evidence-bound 로컬 Report 3개가 생성됐다.

이 결과는 **108개의 실제 취약점을 모두 확인했다**는 뜻이 아니다. 108은 소스에서
수집한 취약점 신호의 수이며, 최종 결과는 확인 3개, 검증 불충분 9개, 동적 finding으로
이어지지 않은 항목 96개다. 확인되지 않은 항목에는 보고서를 만들지 않고 명시적인
`WITHHELD` 결과를 남긴다.

## 구조 변경

### 1. DB coverage ledger

`attack_coverage_items`와 append-only `attack_coverage_events`를 Pipeline DB schema
version 12에 추가했다. 각 item은 endpoint, annotation, vulnerability class, 선택된 입력
지점, 필요한 identity와 현재 처리 상태를 보존한다.

### 2. 결정적 manifest

`aidast.attack.coverage.ensure_coverage_manifest`가 완료된 Recon DB의
`source_vulnerability` annotation만 읽어 안정적인 SHA-256 coverage key를 만든다.
재실행은 `INSERT OR IGNORE`를 사용하므로 같은 item을 중복 생성하지 않는다.

### 3. 전 취약점 분류의 Skill 매핑

현재 source importer가 생성하는 14개 분류를 모두 Hunt Skill에 매핑했다. 매핑되지 않은
분류도 삭제하지 않고 `hunt-misc` 실행 단위로 남긴다.

### 4. bounded exhaustive coordinator

`ExhaustiveAttackCoordinator`가 기본 10개 단위로 batch를 만들고, 각 item에 정확히 한
개의 Attack task를 연결한다. 한 batch가 끝나면 request/attempt/finding ledger를 검사해
item을 `tested_negative`, `candidate`, `blocked_auth`, `policy_excluded`, `unsupported` 또는
오류 상태로 전이한다. 열린 item이 남아 있으면 전체 실행을 완료로 반환하지 않는다.

### 5. Attack Agent 계약

coverage task에는 정확한 endpoint, HTTP method, vulnerability class, 입력 위치와
parameter가 전달된다. Agent는 다른 endpoint로 넓힐 수 없으며, applicability를 먼저
판단해야 한다. 증거가 없으면 finding을 만들지 않고 명시적인 skip 사유를 기록한다.

### 6. 기존 우선순위 모드와 분리

일반 Attack의 최대 8개 Skill 제한은 유지했다. DB 전체 coverage 실행에서만 해당 제한을
해제해, 기존 빠른 실행의 동작을 바꾸지 않았다.

### 7. Validation authoritative 동기화

`candidate -> confirmed`는 완료된 Validation case가 `CONFIRMED`일 때만 허용한다.
재검증 결과가 바뀌면 `confirmed -> candidate` 이벤트를 남겨 오래된 확정 상태가
커버리지 숫자에 남지 않도록 했다.

### 8. post-Attack stage 재실행

완료된 Chaining이 있더라도 그보다 새로운 완료 Attack stage가 있으면 Chaining을 다시
실행할 수 있다. 새 Attack이 없는데 같은 Chaining을 중복 실행하는 것은 계속 거부한다.
최신 stage 선택에는 초 단위 timestamp 대신 SQLite `rowid` 순서를 사용한다.

### 9. CLI

다음 명령을 추가했다.

```text
aidast attack coverage-plan PIPELINE --scan-id SCAN
aidast attack coverage-status PIPELINE --scan-id SCAN
aidast attack exhaustive PIPELINE --scan-id SCAN --scope SCOPE --policy POLICY
```

Scope와 TargetPolicy는 실행 권한 경계이므로 제거하지 않았다. 공격 후보, endpoint,
parameter, vulnerability annotation과 재현 결과는 Recon/Pipeline DB에서만 읽으며 원본
소스 저장소를 Attack, Validation 또는 Report 단계에서 다시 분석하지 않는다.

## VulnBank 검증 결과

### 입력 DB

- method-route endpoint: 81
- parameter: 84
- source vulnerability annotation: 108
- vulnerability class: 14

### Attack coverage

| 상태 | 수 |
|---|---:|
| `tested_negative` | 18 |
| `candidate` | 15 |
| `confirmed` | 1 |
| `blocked_auth` | 63 |
| `policy_excluded` | 5 |
| `unsupported` | 5 |
| `error_terminal` | 1 |
| 합계 | 108 |

- 고유 `endpoint_id:annotation_id`: 108
- 미완료 item: 0
- disposition coverage: 100%
- 실행 가능 item: 34
- 실행 가능 item 처리율: 100%
- candidate 중 Validation 확정률: 1/16 (6.25%)

`blocked_auth`, `policy_excluded`, `unsupported`, `error_terminal`은 시험 성공이나 음성
판정이 아니다. 특히 인증된 기능 63개를 동적으로 검증하려면 DB에 비밀값 자체가 아니라
안전한 credential reference와 테스트 identity 역할 정보가 추가로 필요하다.

### Chaining

16개 finding을 모두 입력으로 사용했다. 16개 chain candidate를 검토했으나 응답에서
다음 단계로 전달할 재현 가능한 값이 없어 모두 `inconclusive`였고, demonstrated chain은
0개였다.

### Validation

| 판정 | 수 |
|---|---:|
| `CONFIRMED` | 1 |
| `UNDERPOWERED` | 3 |
| `INCONCLUSIVE` | 12 |

확정된 finding은 `POST /api/v1/forgot-password`의 unauthenticated error-based SQL
injection이다. Validation은 정상 control, inert control, target 요청을 DB의 immutable
runtime contract에서 읽어 독립 재현했다.

### Report

확정 case 한 건만 로컬 HackerOne 형식 초안으로 생성했다. Report status 검증 결과는
`drafted`, `stale=false`였으며 context SHA-256과 각 evidence SHA-256이 Report DB에
결속돼 있다. 외부 제출은 수행하지 않았다.

## 무결성 검증

- `PRAGMA integrity_check`: `ok`
- `PRAGMA foreign_key_check`: 위반 0
- coverage item/event: 108 / 229
- Pipeline finding: 16
- 열린 coverage item: 0
- Report source binding: stale 아님
- 변경 범위 회귀 테스트: 171 passed, 209 subtests passed
- 권한 있는 loopback adapter 테스트: 138 passed, 206 subtests passed
- 추가 lifecycle/coverage 테스트: 11 passed
- Python bytecode compile 및 `git diff --check`: 통과

초기 sandbox 실행에서는 loopback bind 제한과 macOS `/var`·`/private/var` 별칭으로
실패가 발생했다. loopback 권한을 허용하고 경로의 표시형·canonical 보안 검사를
분리한 뒤 전체 suite는 `1068 passed, 6 skipped, 642 subtests passed`로 통과했다.
Ruff는 개발 환경에 설치되어 있지 않아 실행하지 못했다.

## 해석과 남은 한계

이번 구조 변경은 “검사하지 않은 후보”를 숨기지 않는 문제를 해결했다. 그러나 DB에
테스트 identity, seed object, protocol adapter 또는 허용 정책이 없으면 그 정보를
추측하거나 우회하지 않는다. 따라서 108/108은 처리 상태 커버리지이고, 실제 취약점
발견률 100%를 의미하지 않는다.

## 2026-09-25 인증·소유 객체 및 개별 Validation 보강

- 자격증명은 `env://`, `keyring://`, `vault://` 형태의 불투명 참조만 DB에 저장하고,
  실제 헤더는 신뢰된 request broker가 전송 직전에만 해석한다.
- coverage task는 해당 scan과 task에 허용된 자격증명 ID만 사용할 수 있다. 토큰 원문은
  request 결과, finding, evidence 및 report에 저장하지 않는다.
- IDOR task는 서로 다른 두 identity를 요구하며, 테스트 계정과 소유 객체의 관계는
  비밀이 아닌 `owned_test_object` fact로 공급할 수 있다.
- `candidate` finding에 immutable runtime contract가 없으면 완료된 것으로 재사용하지
  않는다. 중복 요청 금지로 재구성할 수 없는 항목은 `unsupported`로 명확히 남긴다.
- `unauthenticated` 문자열 안의 `auth` 때문에 `blocked_auth`로 오분류되던 substring
  판정을 제거하고 명시적인 인증 차단 사유만 분류한다.
- 성공한 chain replay는 `proposed`가 아니라 `demonstrated`로 저장한다.
- 명시적인 `finding_id` Validation은 완료된 Attack만 요구한다. 최신 Chaining이 실패해도
  독립 finding 검증은 실행되며, 전체 scan/chain Validation은 계속 완료 또는 skipped
  Chaining을 요구한다.
- AIDAST가 생성한 명시적 loopback 실습 Scope는 loopback 주소, exact eligible origin,
  intentionally-vulnerable 문구, 허용 메서드, 모호성 없음이 모두 일치할 때만 정책
  적격성을 결정론적으로 판정한다. 원격 Scope에는 적용되지 않는다.

인증 실행 후 108개 coverage item의 최종 상태는 candidate 17, confirmed 1,
tested-negative 30, unsupported 42, policy-excluded 14, error-terminal 4이며 unfinished는
0이다. 두 merchant 테스트 identity와 관리자 계정 객체로 `GET
/check_balance/{account_number}`의 cross-role IDOR 후보가 추가됐다. 독립 Validation은
positive control 1회, inert negative control 1회, target 3회를 실행해 모든 target에서
authorization-boundary 신호를 재현했다. 다만 Attack claim은 username과 balance 노출을
주장한 반면 runtime assertion은 username만 명시적으로 봉인했기 때문에 최종 상태는
`CONTESTED`다. 이는 취약 동작 미재현이 아니라 민감도 과장 방지 판정이며, confirmed
report로 자동 승격하지 않았다.

관련 회귀 묶음은 `122 passed, 109 subtests passed`, Pipeline DB는
`PRAGMA integrity_check=ok`, foreign-key 위반 0이었다.

### macOS 및 교차 플랫폼 경로 보강

- CLI와 handoff API는 사용자가 입력한 absolute path 표기를 결과에 보존한다.
- artifact containment, symlink 탈출 방지, 실제 파일 검증은 계속 canonical path로
  수행한다.
- Attack DB 내부의 상대 source locator는 display path가 아니라 canonical source와
  output을 기준으로 계산해 `/var`와 `/private/var`가 섞여도 `/private/private` 같은
  잘못된 경로가 생기지 않는다.
- 경로 동일성 테스트는 양쪽을 canonicalize한 뒤 비교한다. Windows의 서로 다른 path
  표기와 macOS의 OS 관리 alias에서도 같은 원칙을 사용한다.

## 2026-09-25 최종 loopback benchmark

### 추가 구현

- `aidast import-recon --lab-benchmark`는 명시적으로 허가된 loopback 실습 대상에만
  bounded 상태 변경 메서드와 작은 동시성 한도를 허용한다. 원격 대상에는 적용되지
  않는다.
- `aidast attack benchmark-vulnbank`는 테스트 사용자 2개와 merchant 2개를 만들고,
  실제 토큰은 프로세스 환경에만 두며 Pipeline DB에는 `env://` 참조 4개와 소유 객체
  fact 6개만 저장한다. 재실행 시 같은 label/role 참조를 재사용한다.
- `aidast attack coverage-export`는 108개 각 항목에 Attack, Validation, Report 결과를
  한 행씩 내보낸다. `CONFIRMED`가 아닌 항목의 Report 결과는 `WITHHELD`다.
- 중단 시 `KeyboardInterrupt`를 포함한 종료 상태를 `error_retryable`과 failed stage로
  먼저 저장하므로 다음 실행에서 안전하게 재개할 수 있다.
- 생성 Scope에는 표 형식과 deny-wins 검사기가 읽는 bullet 형식을 함께 기록하고,
  승인과 hash는 이 최종 내용에 대해 수행한다.

### 실제 실행 결과

Scan ID: `scan_cecffb09e31c4c4cb5897161bb199092`

| Attack 결과 | 수 |
|---|---:|
| `candidate` | 10 |
| `tested_negative` | 28 |
| `unsupported` | 62 |
| `error_terminal` | 7 |
| `policy_excluded` | 1 |
| 합계 | 108 |

- unfinished: 0
- disposition coverage: 100%
- executable coverage: 100%
- 생성 finding: 12
- 개별 Validation: `CONFIRMED` 3, `INCONCLUSIVE` 9
- coverage-level Validation: `CONFIRMED` 3, `INCONCLUSIVE` 9,
  `NOT_APPLICABLE` 96
- Report: `DRAFTED` 3, `WITHHELD` 105
- 외부 제출: 수행하지 않음

확정된 세 건은 다음과 같다.

1. unauthenticated username SQL injection을 통한 administrator login
2. merchant login email SQL injection을 통한 authentication token 발급
3. authenticated low-privilege 사용자의 `check_balance` boolean SQL injection을 통한
   administrator row 조회

SSRF, debug/source disclosure, AI configuration 노출 등 나머지 9개 finding은 Attack
관측만으로는 만들어졌지만 독립 Validation의 확인 기준을 충족하지 못해
`INCONCLUSIVE`로 유지했다. 이를 취약점으로 확정하거나 report로 승격하지 않았다.

### 최종 검증

- `PRAGMA integrity_check`: `ok`
- `PRAGMA foreign_key_check`: 위반 0
- plaintext bearer token 검사: 결과 디렉터리 및 Pipeline DB 모두 0건
- credential reference: `env://` 4개, plaintext token 저장 0건
- 변경 집중 테스트: `121 passed, 109 subtests passed`
- 전체 회귀 테스트: `1074 passed, 6 skipped, 642 subtests passed`
