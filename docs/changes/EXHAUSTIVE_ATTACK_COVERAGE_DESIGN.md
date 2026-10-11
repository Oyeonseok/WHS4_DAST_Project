# Exhaustive Attack Coverage 구조 변경 설계

작성일: 2026-09-24

## 1. 배경

현재 AIDAST의 소스 기반 Recon Import는 VulnBank에서 다음 데이터를 정상적으로
수집했다.

- 81개 method-route endpoint
- 84개 입력 파라미터
- 108개 endpoint 취약점 표식
- 14개 취약점 분류

그러나 기존 Attack 단계는 Recon 표식 전체를 실행 단위로 만들지 않는다. Recon
전체에서 점수가 높은 최대 8개 Hunt Skill만 선택하고, Agent가 그중 일부 endpoint를
시험한다. 실제 VulnBank 실행에서는 HTTP 요청이 12회만 발생했고, 전체 endpoint와
표식 중 극히 일부만 검사됐다.

따라서 현재 결과의 의미는 다음과 같다.

> 108개 후보를 모두 검사해 한 건만 확인한 것이 아니라, 일부 후보만 검사해 두 건의
> Attack finding을 만들었고 그중 한 건을 Validation으로 확인했다.

이 문서는 AIDAST가 모든 Recon 후보의 처리 여부를 증명할 수 있도록 Attack 구조를
변경하기 위한 구현 명세다.

## 2. 목표

1. Recon의 모든 `endpoint × 취약점 분류 × 입력 지점` 조합을 영속적인 coverage
   item으로 만든다.
2. 모든 item이 명시적인 종결 상태에 도달할 때까지 batch 실행과 resume을 반복한다.
3. 검사하지 않은 후보와 검사 결과가 음성인 후보를 구분한다.
4. 정책상 실행할 수 없는 후보도 누락하지 않고 차단 사유를 기록한다.
5. Attack finding은 실제 요청·응답 증거와 재현 계약이 있을 때만 생성한다.
6. Validation과 Report의 기존 증거 무결성 요구사항을 약화하지 않는다.

## 3. 비목표

- 소스의 취약점 주석을 곧바로 finding으로 승격하지 않는다.
- 공개 버그바운티 프로그램의 rate limit이나 금지 항목을 우회하지 않는다.
- 모든 취약점 유형을 동일한 payload나 동일한 요청 수로 검사하지 않는다.
- 인증정보, 소스의 비밀값 또는 실제 사용자 데이터를 Recon DB에 복사하지 않는다.
- `coverage=100%`를 `모든 후보가 안전함` 또는 `모든 취약점을 발견함`으로 표현하지
  않는다.

## 4. Coverage 단위

기본 coverage key는 다음 필드로 구성한다.

```text
scan_id
endpoint_id
HTTP method
normalized path
annotation_id
vulnerability class
injection location
parameter name
required identity role
```

동일 endpoint에 취약점 분류가 두 개 있으면 coverage item도 두 개다. 동일 분류가
서로 다른 파라미터에 적용되면 파라미터별 item을 만든다.

파라미터를 특정할 수 없는 함수 단위 표식은 다음 값으로 유지한다.

```text
injection_location = endpoint
parameter_name = NULL
```

예시:

```text
coverage_001 | POST | /api/login                    | sqli | json | username
coverage_002 | POST | /api/login                    | sqli | json | password
coverage_003 | GET  | /transactions/{account_id}    | sqli | path | account_id
coverage_004 | GET  | /api/v3/user/{id}             | idor | path | id
coverage_005 | POST | /upload_profile_picture_url   | ssrf | json | url
```

## 5. 신규 DB 테이블

### 5.1 attack_coverage_items

```sql
CREATE TABLE attack_coverage_items (
    coverage_id TEXT PRIMARY KEY NOT NULL,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id),
    annotation_id TEXT NOT NULL REFERENCES endpoint_annotations(annotation_id),
    vuln_class TEXT NOT NULL,
    skill_name TEXT NOT NULL,
    injection_location TEXT,
    parameter_name TEXT,
    required_identity_role TEXT NOT NULL DEFAULT 'unauthenticated',
    status TEXT NOT NULL CHECK(status IN (
        'pending',
        'running',
        'tested_negative',
        'candidate',
        'confirmed',
        'blocked_auth',
        'policy_excluded',
        'unsupported',
        'error_retryable',
        'error_terminal'
    )),
    disposition_reason TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
    last_stage_run_id TEXT REFERENCES stage_runs(stage_run_id),
    finding_id TEXT REFERENCES findings(finding_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(
        scan_id, endpoint_id, annotation_id, vuln_class,
        injection_location, parameter_name, required_identity_role
    )
);

CREATE INDEX idx_attack_coverage_status
    ON attack_coverage_items(scan_id, status, vuln_class);

CREATE INDEX idx_attack_coverage_endpoint
    ON attack_coverage_items(scan_id, endpoint_id);
```

SQLite에서 nullable column이 포함된 `UNIQUE` 제약은 NULL을 서로 다른 값으로 취급할
수 있으므로 실제 migration에서는 `COALESCE` 기반 unique expression index 또는 빈
문자열로 정규화한 별도 key column을 사용해야 한다.

### 5.2 attack_coverage_events

상태 변경의 감사 가능성을 위해 append-only event를 저장한다.

```sql
CREATE TABLE attack_coverage_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    coverage_id TEXT NOT NULL REFERENCES attack_coverage_items(coverage_id),
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    stage_run_id TEXT REFERENCES stage_runs(stage_run_id),
    previous_status TEXT,
    next_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    attempt_id TEXT REFERENCES attack_attempts(attempt_id),
    request_id TEXT REFERENCES attack_http_requests(request_id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_attack_coverage_events_item
    ON attack_coverage_events(coverage_id, created_at);
```

## 6. 상태 정의

| 상태 | 의미 | 종결 상태 |
|---|---|---:|
| `pending` | 아직 실행하지 않음 | 아니오 |
| `running` | 현재 worker가 처리 중 | 아니오 |
| `tested_negative` | 필수 대조군과 target 시험이 완료됐으나 신호 없음 | 예 |
| `candidate` | 반복 가능한 신호가 있어 finding/Validation 후보 생성 | 예 |
| `confirmed` | Validation에서 독립 재현 완료 | 예 |
| `blocked_auth` | 필요한 테스트 계정 또는 role이 없음 | 예 |
| `policy_excluded` | Scope/TargetPolicy에서 해당 시험을 금지 | 예 |
| `unsupported` | 필요한 실행 adapter 또는 안전한 시험 계약이 없음 | 예 |
| `error_retryable` | 일시적 오류로 재시도 가능 | 아니오 |
| `error_terminal` | 재시도 불가능한 구조적 오류 | 예 |

허용 상태 전이 예시:

```text
pending -> running
running -> tested_negative
running -> candidate
running -> blocked_auth
running -> policy_excluded
running -> unsupported
running -> error_retryable
running -> error_terminal
error_retryable -> running
candidate -> confirmed
```

`running` 상태로 프로세스가 비정상 종료되면 resume 시 자동으로 성공 처리하지 않는다.
해당 stage와 request ledger를 검사한 뒤 `error_retryable` 또는 기존의 증명 가능한
종결 상태로 복구한다.

## 7. 취약점 분류와 Skill 매핑

소스 기반 Recon이 현재 생성하는 분류는 모두 매핑해야 한다.

| Recon 분류 | Attack Skill |
|---|---|
| `sqli` | `hunt-sqli` |
| `idor` | `hunt-idor` |
| `auth_bypass` | `hunt-auth-bypass` |
| `ssrf` | `hunt-ssrf` |
| `xss` | `hunt-xss` |
| `file_upload` | `hunt-file-upload` |
| `lfi` | `hunt-lfi` |
| `jwt_crypto` | `hunt-jwt-crypto` |
| `api_misconfig` | `hunt-api-misconfig` |
| `source_leak` | `hunt-source-leak` |
| `brute_force` | `hunt-brute-force` |
| `csrf` | `hunt-csrf` |
| `llm_ai` | `hunt-llm-ai` |
| `race_condition` | `hunt-race-condition` |

매핑이 없는 분류를 조용히 버리면 안 된다. coverage item을 `unsupported`로 종결하고
누락된 mapping 이름을 `disposition_reason`에 기록한다.

## 8. 기존 Skill 선택 제한 변경

현재 `MAX_RELEVANT_HUNT_SKILLS = 8`은 일반적인 우선순위 실행 모드에서는 유지한다.
전체 coverage 모드에서는 이 제한을 사용하지 않는다.

권장 모드:

```text
prioritized  기존 방식. 높은 우선순위 skill을 제한적으로 실행
exhaustive   coverage manifest의 모든 item을 batch로 실행
```

Exhaustive 모드도 모든 skill 문서를 한 번에 Agent context에 넣지 않는다. 현재 batch에
필요한 skill만 읽어 context 크기를 제한한다.

## 9. Coverage Manifest 생성 절차

1. 완료된 Recon scan인지 확인한다.
2. 제외되지 않은 endpoint만 읽는다.
3. 완료된 annotation run의 `source_vulnerability` annotation을 읽는다.
4. annotation과 endpoint parameter를 결합한다.
5. 분류별 parameter relevance rule을 적용한다.
6. 안정적인 canonical JSON에서 `coverage_id`를 계산한다.
7. `INSERT OR IGNORE`로 재실행 안전성을 확보한다.
8. 생성 수, 중복 수, 제외 수와 사유를 manifest summary로 저장한다.

Coverage ID 예시:

```text
coverage_ + sha256({
  scan_id,
  endpoint_id,
  annotation_id,
  vuln_class,
  injection_location,
  parameter_name,
  required_identity_role
})
```

## 10. Batch 실행

108개 item을 한 번에 Agent에게 전달하지 않는다.

기본값:

```text
batch size: 10
동일 host concurrency: 1
기본 rate: 0.5 requests/second
동일 coverage item 최대 요청: 분류별 profile에서 결정
```

선택 순서:

1. `error_retryable`이면서 backoff 시간이 지난 item
2. `pending` item
3. severity 우선순위
4. endpoint와 vuln class의 안정적인 정렬

Batch 처리 중 한 item이 실패해도 나머지 item의 결과를 폐기하지 않는다. item별 transaction과
request ledger를 사용한다.

## 11. 최소 테스트 계약

`tested_negative` 또는 `candidate`가 되려면 다음 자료가 필요하다.

1. 정상 동작을 확인하는 positive/baseline control
2. 공격 신호를 만들지 않는 inert negative control
3. 제한된 target test
4. 요청·응답 status와 body signature
5. 사용한 TargetPolicy hash
6. endpoint, parameter와 request의 provenance 연결
7. terminal attack attempt

다음 조건에서는 `tested_negative`로 처리하면 안 된다.

- WAF/edge에서 모든 요청이 동일한 403
- 인증이 없어 실제 기능에 도달하지 못함
- 대상 기능의 필수 seed data가 없음
- adapter가 해당 protocol을 실행하지 못함
- timeout 또는 connection error
- 응답이 rate limit 상태

이 경우 각각 `blocked_auth`, `unsupported`, `error_retryable` 등의 상태를 사용한다.

## 12. 분류별 실행 고려사항

### SQL Injection

- 파라미터별 baseline, inert control, target 차이를 비교한다.
- 오류 발생만으로 finding을 생성하지 않는다.
- boolean, error, time 또는 UNION 신호 중 최소 하나를 대조군과 분리해 입증한다.

### IDOR

- 최소 두 개의 본인 소유 테스트 identity가 필요하다.
- 동일 객체에 대한 owner/non-owner 차이를 비교한다.
- 두 번째 identity가 없으면 `blocked_auth`다.

### Auth Bypass

- unauthenticated와 정상 authenticated 요청을 비교한다.
- 로그인 페이지 또는 공통 200 응답만으로 확인하지 않는다.

### SSRF

- 공개 대상에서는 프로그램이 허용한 callback만 사용한다.
- 로컬 격리 환경에서는 전용 loopback canary를 사용할 수 있다.
- 외부 OOB가 금지되면 `policy_excluded` 또는 안전한 in-band 시험만 수행한다.

### XSS

- 단순 문자열 reflection과 실행 가능한 browser sink를 구분한다.
- Browser runtime contract가 없으면 confirmed로 승격하지 않는다.

### File Upload 및 LFI

- 무해한 fixture만 사용한다.
- 실행 파일, web shell, 시스템 파일 읽기를 기본 시험으로 사용하지 않는다.

### JWT/Crypto

- 테스트 계정에서 발급된 토큰만 사용한다.
- 서명 검증 우회와 단순 JWT decoding을 구분한다.

### Brute Force

- 공개 대상에서는 정책상 허용된 낮은 횟수만 실행한다.
- 대량 시도 없이 rate-limit 존재 여부를 판단할 수 없으면 `policy_excluded` 또는
  `underpowered` 성격의 terminal reason을 기록한다.

### Race Condition

- 동시 요청 adapter와 테스트 전용 객체가 필요하다.
- 운영 데이터에 재정적·외부 부작용이 발생할 수 있으면 실행하지 않는다.

## 13. 요청 예산 계산

고정된 전역 `max_requests=100`만 사용하면 전체 coverage를 보장할 수 없다. manifest
생성 후 분류별 최소 예산을 합산한다.

기본 계산식:

```text
required_budget = Σ(coverage item별 positive + negative + target + 허용 재시도)
```

VulnBank의 단순 최솟값:

```text
108 items × 3 requests = 324 requests
```

인증 비교, race condition, browser XSS와 재시도를 고려하면 로컬 실습 환경에서는
약 500~800회의 상한이 현실적이다. 이는 공개 프로그램의 권장값이 아니다. 실제
버그바운티 대상은 프로그램별 rate limit과 금지 항목을 먼저 적용해야 한다.

예산이 부족하면 stage를 `completed`로 만들지 않는다. coverage item을 보존하고
`paused: request_budget_exhausted`로 중단해야 한다.

## 14. Resume 규칙

Resume은 다음 item만 다시 queue한다.

```text
pending
error_retryable
증명되지 않은 stale running
```

다음 item은 재실행하지 않는다.

```text
tested_negative
candidate
confirmed
blocked_auth
policy_excluded
unsupported
error_terminal
```

단, Scope, TargetPolicy, source commit, endpoint signature 또는 test profile hash가 바뀌면
기존 종결 상태를 stale로 표시하고 재검사 여부를 명시적으로 결정한다.

## 15. Attack 완료 조건

Agent의 완료 응답만으로 stage를 완료하지 않는다.

```sql
SELECT COUNT(*)
FROM attack_coverage_items
WHERE scan_id = ?
  AND status IN ('pending', 'running', 'error_retryable');
```

결과가 0일 때만 exhaustive Attack stage를 `completed`로 만들 수 있다.

각 item의 `candidate` finding은 다음 조건도 만족해야 한다.

- atomic reproduction spec 존재
- confirmed attack attempt 존재
- 모든 source request가 terminal 상태
- completed Attack stage 또는 완료된 resume 계보에 귀속
- finding과 endpoint가 같은 scan에 속함

## 16. Coverage 지표

한 개의 percentage만 표시하면 안 된다.

### Disposition coverage

모든 후보 중 명시적인 종결 상태가 있는 비율이다.

```text
terminal items / total items
```

### Executable coverage

정책과 준비 조건상 실행 가능한 후보 중 실제 target 시험을 완료한 비율이다.

```text
(tested_negative + candidate + confirmed) /
(total - blocked_auth - policy_excluded - unsupported)
```

### Validation coverage

생성된 candidate 중 Validation 결정을 받은 비율이다.

```text
validation-terminal candidates / candidates
```

### Confirmed rate

실제 실행한 후보 중 confirmed 비율이다. 이는 제품의 취약점 탐지율과 같지 않다.

## 17. CLI 제안

아래 명령은 설계안이며 아직 구현된 인터페이스가 아니다.

### Manifest 생성

```bash
aidast attack coverage-plan "$PIPELINE_DB" \
  --scan-id "$SCAN_ID" \
  --mode exhaustive
```

### 실행

```bash
aidast attack run "$PIPELINE_DB" \
  --scan-id "$SCAN_ID" \
  --coverage exhaustive \
  --batch-size 10 \
  --max-requests-per-item 6 \
  --max-total-requests 800 \
  --max-rps 0.5 \
  --max-concurrency 1 \
  --codex-timeout 86400
```

### Resume

```bash
aidast attack resume "$PIPELINE_DB" \
  --scan-id "$SCAN_ID" \
  --coverage exhaustive \
  --retry pending,error_retryable \
  --codex-timeout 86400
```

### 상태 확인

```bash
aidast attack coverage "$PIPELINE_DB" \
  --scan-id "$SCAN_ID" \
  --format table
```

출력 예시:

```text
Total coverage items: 108
Tested negative:       72
Candidates:             8
Confirmed:              3
Blocked by auth:       10
Policy excluded:        5
Unsupported:            4
Pending:                6

Disposition coverage: 94.4%
Executable coverage:  91.2%
Validation coverage: 100.0%
```

## 18. 구현 단계

### Phase 1: DB 및 Manifest

- Pipeline schema version 증가
- `attack_coverage_items`, `attack_coverage_events` 추가
- Recon annotation에서 deterministic manifest 생성
- 중복과 nullable key 테스트
- read-only coverage status 명령 추가

### Phase 2: Deterministic Scheduler

- pending item batch selector 구현
- item별 lease와 상태 전이 구현
- request/attempt와 coverage item 연결
- budget exhaustion을 pause로 처리
- stale `running` 복구 구현

### Phase 3: Skill Execution Contract

- 14개 분류별 실행 profile 정의
- parameter relevance rule 구현
- 최소 control contract 적용
- unsupported/blocked/policy-excluded 판정기 구현

### Phase 4: Resume와 Stage 완료

- terminal coverage 검사 후에만 Attack 완료
- retryable item만 resume
- policy/profile/source hash 변경 시 stale 처리
- 기존 prioritized 모드와 하위 호환 유지

### Phase 5: Validation 및 Report 연결

- candidate/confirmed item과 finding 연결
- runtime reproduction contract 누락을 coverage 결과에 표시
- confirmed Validation case만 report 대상으로 전달

## 19. 테스트 요구사항

### Unit tests

- 동일 Recon 입력에서 동일 coverage ID 생성
- endpoint와 annotation 누락 방지
- 분류별 skill mapping 검증
- 허용되지 않은 상태 전이 거부
- nullable parameter 중복 방지
- request budget 계산 검증
- policy-excluded item이 HTTP 요청을 생성하지 않는지 검증

### Integration tests

- 108개 manifest item 생성 확인
- batch 크기를 넘어도 모든 item이 처리되는지 확인
- 중간 timeout 후 pending/retryable item만 resume되는지 확인
- 이미 terminal인 item을 다시 실행하지 않는지 확인
- 모든 item이 terminal이 되기 전에 stage 완료를 거부하는지 확인
- finding이 없는 tested-negative 결과도 coverage에 남는지 확인
- WAF의 동일 403을 tested-negative로 판정하지 않는지 확인

### End-to-end acceptance criteria

VulnBank 로컬 격리 환경에서:

1. Recon의 모든 source vulnerability annotation이 coverage item으로 연결된다.
2. manifest count와 DB coverage item count가 일치한다.
3. 누락된 endpoint-annotation pair가 0이다.
4. `pending`, `running`, `error_retryable`이 0이 되기 전에는 Attack이 완료되지 않는다.
5. 모든 HTTP 요청이 TargetPolicy와 request ledger를 통과한다.
6. 모든 candidate는 reproduction spec을 가진다.
7. 모든 confirmed finding은 독립 Validation을 통과한다.
8. `PRAGMA integrity_check`가 `ok`이고 foreign-key 오류가 없다.
9. coverage summary의 각 합계가 total item 수와 일치한다.

## 20. 결과 해석 규칙

다음 표현은 금지한다.

```text
108개를 모두 검사했으며 취약점은 한 개뿐이다.
```

실제 coverage 상태에 맞춰 다음처럼 표현한다.

```text
108개 후보 중 90개는 실제 시험 완료, 8개는 candidate,
6개는 인증 부족, 4개는 adapter 미지원이며 미처리 후보는 0개다.
확인된 취약점은 독립 Validation을 통과한 3개다.
```

소스 표식은 가설이며, coverage item의 종결은 해당 시험 계약 범위에서의 판단이다.
특정 입력과 검사를 통과했다고 해서 해당 endpoint에 같은 분류의 다른 변형이 존재하지
않는다고 보장할 수는 없다.
