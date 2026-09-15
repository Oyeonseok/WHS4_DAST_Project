# Attack 상태 변경 요청 권한 일반화

- 변경일: 2026-09-15
- 대상 단계: TargetPolicy 생성, native Attack HTTP transport
- 대상 코드: `src/aidast/recon/policy.py`, `src/aidast/agents/main.py`,
  `src/aidast/attack/request_cli.py`, `src/aidast/pipeline/schema.py`

## 목적

Juice Shop의 특정 POST 경로를 예외로 추가하지 않고, 승인된 어떤 웹 대상에서도
Attack Agent가 필요한 상태 변경 요청을 안전하게 보낼 수 있게 한다. 동시에 Recon이
발견하지 못한 사용자 상호작용 경로도 테스트 후보에서 사라지지 않게 한다.

## 이전 구현

`TargetPolicy.allowed_methods`는 Recon과 Attack이 함께 사용했다. 안전 메서드만
허용하면 Attack의 POST/PUT/PATCH/DELETE가 전부 차단되고, 상태 변경 메서드를
추가하면 Recon crawler에도 같은 권한이 열릴 수 있었다. 또한 endpoint가 DB에
존재하는지만으로 실행 권한을 판단하면 정적 분석에서 추출된 후보와 실제 네트워크
관측을 구분할 수 없었다.

## 현재 구현

### 1. Scope에서 단계별 활동 권한 분리

- `allowed_methods`: Recon 전용이며 GET/HEAD/OPTIONS만 가능하다.
- `attack_allowed_methods`: Attack이 사용할 수 있는 메서드다.
- `attack_authorization_mode=active_non_destructive`는 Scope의 `Allowed activities`가
  능동 보안·침투·취약점 테스트를 허용할 때만 사용할 수 있다. 근거 원문은
  `attack_authorization_evidence`에 보존한다.
- 활동 권한이 있으면 인용문이 HTTP method를 열거하지 않아도 일반적인
  POST/PUT/PATCH/DELETE를 사용할 수 있다. 단, Prohibited activities가 명시적으로
  금지한 method는 추가할 수 없다.
- 로그인이나 수동 인증만 허용한다는 문구는 Attack 권한으로 승격되지 않는다.
- 읽기 전용 테스트 문구도 능동 Attack 권한으로 승격되지 않는다.
- 인용이 없거나 모호하면 정책 생성 단계에서 fail-closed한다.

### 2. 런타임의 하이브리드 provenance 판정

Scope가 능동 테스트를 허용한 뒤 request helper는 endpoint 관측 여부를 권한이 아닌
provenance로 기록한다.

| 요청 종류 | 처리 |
|---|---|
| GET/HEAD/OPTIONS | 기존 Scope·예산 검사 후 실행 |
| 일반 POST/PUT/PATCH | 관측 여부와 무관하게 제한 내 자동 실행 |
| task가 생성하고 capture-binding한 테스트 리소스 DELETE | 제한 내 자동 실행 |
| 외부 부작용 또는 고위험 path | 사용자 승인 envelope 생성 |
| 소유권을 증명하지 못한 DELETE | 사용자 승인 envelope 생성 |
| 파괴적·대량 작업 | 승인 후보 없이 차단 |

따라서 SPA의 클릭·폼 제출처럼 Recon이 놓친 경로도 Attack Agent가 제안할 수 있지만,
Scope 경계, task capability, 위험 분류와 요청 예산을 우회할 수 없다.

모든 상태 변경 요청에는 `risk_class`가 필요하다. 일반 변경, 테스트 리소스 생성,
테스트 리소스 삭제, 외부 부작용, 파괴적·대량 작업을 구분하며 마지막 분류는 항상
차단한다. 같은 task와 정규화 path의 mutation은 최대 10회로 제한한다.

### 3. 승인 envelope

승인은 다음 경계에 묶인다.

- 현재 Attack task
- 정확한 HTTP method
- origin과 정규화된 path
- 최대 10회 요청(더 작은 TargetPolicy 전체 예산이 있으면 그 값을 적용)
- request body 최대 16 KiB
- 승인 후 15분
- redirect 금지

Main Agent의 승인 broker만 터미널 입력을 소유한다. helper는 DB에 `pending` envelope를
만들고 기다리며, 사용자는 한 번만 `y/N`을 입력한다. `y` 이외의 입력, EOF 또는
인터럽트는 거부다. 거부된 같은 task/method/path는 다시 묻지 않고 계속 차단한다.
승인된 요청은 전송 전에 사용 횟수를 원자적으로 소비한다.

### 4. 감사 및 추적

- `attack_authorization_envelopes`가 요청 근거, 결정, TTL, 최대·사용 횟수를 보존한다.
- `attack_http_requests.authorization_source`는 `scope_safe_method`,
  `scope_active_mutation`, `approved_envelope` 중 하나다.
- `endpoint_provenance`는 `network_observed`, `recon_candidate`,
  `agent_proposed`를 별도로 기록한다. 관측 여부가 권한으로 오인되지 않게 한다.
- `risk_class`, Scope policy 또는 envelope ID, endpoint reference를 요청 ledger에
  함께 저장한다.
- 승인·거부 결정은 append-only `audit_events`에도 기록한다.

## 수동 인증 capability와의 차이

Recon의 수동 인증 capability는 브라우저가 만든 정확한 POST 한 건을 짧은 HMAC
capability로 허용하며 TTL은 20초다. 이번 Attack envelope는 취약점 검증 task가
생성한 동일 method·정규화 path의 제한된 요청 묶음을 최대 15분 동안 허용한다.
두 기능 모두 제품별 endpoint 하드코딩은 하지 않지만, 권한 주체와 수명 및 반복
횟수가 다르므로 서로의 승인을 재사용하지 않는다.

## 남는 경계

- Scope가 능동 비파괴 보안 테스트를 허용하지 않으면 상태 변경 요청이나 envelope
  후보를 만들지 않는다.
- 정규화는 숫자 또는 긴 16진 path segment만 `:id`로 치환한다. query 값은 승인
  화면과 ledger URL에서 노출하지 않는다.
- 승인은 취약점 존재를 의미하지 않는다. Finding은 각 Hunt Skill의 별도 확인 조건과
  재현 evidence를 충족해야 한다.
