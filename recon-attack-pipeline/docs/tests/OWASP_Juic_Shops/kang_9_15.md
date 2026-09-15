# OWASP Juice Shop 통합 파이프라인 테스트 결과

## 1. 실행 개요

| 항목 | 값 |
|---|---|
| 대상 | `http://127.0.0.1:3000` |
| Scan ID | `scan_2ef64e612230473cb11b3000340a5352` |
| 실행 결과 | Recon, Attack, Chaining, Validation 모두 정상 완료 |
| Pipeline DB | `Runs/scan_2ef64e612230473cb11b3000340a5352/Pipeline.db` |
| Surface | `Runs/scan_2ef64e612230473cb11b3000340a5352/Surface.json` |
| Recon Review | `Runs/scan_2ef64e612230473cb11b3000340a5352/ReconReview.json` |

이번 실행에서는 SQL Injection finding 1건이 생성됐고 재검증에서도 동일한 동작이 반복 재현됐다. 다만 민감정보 노출이나 권한 경계 침해가 입증되지 않아 Validation 최종 상태는 `UNDERPOWERED`로 결정됐다.

## 2. 단계별 결과

| 단계 | 상태 | 소요 시간(약) | 결과 |
|---|---|---:|---|
| Recon | `completed` | 4분 15초 | 엔드포인트 23개 저장, 15개 분석 대상으로 유지 |
| Attack | `completed` | 9분 47초 | SQL Injection finding 1건 생성 |
| Chaining | `completed` | 2분 52초 | 후보 1건 검토, 실행 0건, 확정 chain 0건 |
| Validation | `completed` | 54초 | 5회 재검증 후 `UNDERPOWERED` 판정 |

`completed`는 각 단계가 오류 없이 종료됐다는 의미다. 취약점의 최종 확정 여부는 `validation_cases.current_status`로 판단해야 한다.

## 3. Playwright 세션과 Recon 분석

Playwright는 다음 런타임 세션 파일을 저장했다.

```text
.aidast_sessions/8e95f27b28d8910da0347e69/36bde66f289a35683683b041/
├── 127.0.0.1_3000_c51203df6e75a968.json
└── 127.0.0.1_3000_c51203df6e75a968.json.sessionstorage.json
```

첫 번째 파일에는 브라우저의 cookie와 localStorage 기반 `storage_state`가, 두 번째 파일에는 sessionStorage가 저장된다. 이 상태는 후속 인증 기반 탐색에서 재사용할 수 있다. 단, 파일 저장 메시지만으로 로그인 성공이 보장되는 것은 아니며 인증 전용 페이지 접근 결과를 함께 확인해야 한다.

### 네트워크 수집

```text
mitmproxy 허용 및 적재: 458건
mitmproxy 정책 차단:   129건
별도 HTTP probe:         1건
DB HTTP 트랜잭션 합계: 459건
```

허용된 mitmproxy 요청 458건은 모두 `http_transactions`에 저장됐다. 총 459건과의 차이 1건은 초기 `http_probe` 요청이다.

이번 `TargetPolicy`의 주요 실행 제한은 다음과 같다.

- `http://127.0.0.1:3000`만 허용
- 기본 허용 메서드는 `GET`, `HEAD`, `OPTIONS`
- `POST`는 수동 로그인 구간의 동일 origin 요청에만 임시 허용
- 다른 호스트와 `PUT`, `PATCH`, `DELETE` 요청 차단
- 최대 1 RPS, concurrency 3, depth 3, 요청 2,000건

정책 차단 129건은 정책 강제가 실제로 동작했음을 보여준다. 다만 차단된 개별 URL과 사유는 현재 공유 DB에 저장되지 않아 이 결과만으로 세부 차단 원인을 분류할 수 없다.

### 엔드포인트와 관측

| 데이터 | 건수 |
|---|---:|
| 전체 엔드포인트 | 23 |
| 분석 대상 엔드포인트 | 15 |
| 제외 엔드포인트 | 8 |
| endpoint observations | 357 |
| endpoint annotations | 154 |
| annotation runs | 5 (`completed`) |

관측 출처는 다음과 같다.

| 출처 | 건수 |
|---|---:|
| mitmproxy | 249 |
| katana 인증 headless | 66 |
| Playwright 로그인 | 32 |
| Playwright runtime | 5 |
| katana 인증 standard | 5 |

제외된 엔드포인트 8개는 `/main.js`, `/polyfills.js`, `/scripts.js`, `/styles.css`, `/chunk-*.js`와 같은 정적 JS/CSS 파일이다. 따라서 `발견 15건 (제외 8건)`은 정상적인 탐색 결과다.

### Recon Review 집계 불일치

`ReconReview.json`에는 `observations: 0`으로 기록됐지만 실제 DB의 `endpoint_observations`에는 357건이 있다. `OfflineReconReview.summarize()`가 새 `endpoint_observations` 대신 기존 `observations` 테이블을 집계하기 때문에 발생한다.

수집 데이터가 유실된 것은 아니지만 Recon Review가 현재 관측 데이터를 요약하지 못한 상태이므로 집계 대상을 수정할 필요가 있다.

## 4. Attack 분석

Attack 단계에서는 다음 Skill 작업이 선택됐다.

| Skill | 작업 상태 | 결과 |
|---|---|---|
| `hunt-auth-bypass` | completed | 유효 신호 없음 |
| `hunt-idor` | skipped | 실행 대상 없음 |
| `hunt-websocket` | completed | 유효 신호 없음 |
| `hunt-cors` | completed | 유효 신호 없음 |
| `hunt-api-misconfig` | completed | 유효 신호 없음 |
| `hunt-sqli` | completed | finding 1건 생성 |
| `hunt-xss` | completed | 유효 신호 없음 |

Attack HTTP 요청은 총 7건이며 모두 정책 broker를 통과해 완료됐다. SQL Injection Skill은 비교 요청 1건과 성공 요청 1건을 수행했고 성공 요청을 finding으로 승격했다.

### 생성된 finding

| 항목 | 값 |
|---|---|
| Finding ID | `finding_af7ea77d8ebe461383d37dcc366bc193` |
| 유형 | SQL Injection |
| CWE | CWE-89 |
| Endpoint | `GET /rest/products/search` |
| 입력 | Query parameter `q` |
| Attack severity | HIGH |
| CVSS | 8.2 |
| Finding 상태 | `unreviewed` |

Attack Agent는 조작된 검색 입력이 기존의 빈 결과를 전체 상품 데이터로 변경했고 soft-deleted 상품도 포함했다고 판단했다. 비교 응답은 30 bytes, 성공 응답은 21,581 bytes였다.

## 5. Chaining 분석

Chaining 단계 결과는 다음과 같다.

```text
candidates:       1
executions:       0
proposed chains:  0
candidate status: inconclusive
```

Chaining Agent는 SQL Injection을 통해 password-reset token 또는 credential을 얻고 인증 우회와 계정 접근으로 연결할 수 있는지 검토했다. 그러나 Attack 단계에서 실제 입증된 내용은 삭제된 상품 레코드 조회뿐이었다.

- password-reset token 획득 근거 없음
- credential 획득 근거 없음
- 인증 우회를 입증한 finding 없음
- 다음 단계로 전달할 검증된 값과 binding 없음

따라서 실행 가능한 Chain Runtime Contract를 만들 수 없었으며, 네트워크 chain 실행 없이 후보를 `inconclusive`로 종료했다. Chaining 단계의 `completed`와 chain 결과 0건은 서로 모순되지 않는다.

## 6. Validation 재검증

Validation은 SQL Injection finding을 HTTP 어댑터로 재검증했다. 요청 ledger에는 5건이 모두 `completed`로 기록됐고 정책 위반이나 환경 blocker는 없었다.

| 시도 | 결과 | HTTP 상태 | 응답 크기 |
|---|---|---:|---:|
| Positive control | `observed` | 200 | 30 bytes |
| Negative control | `not_observed` | 200 | 30 bytes |
| Target 1 | `observed` | 200 | 21,581 bytes |
| Target 2 | `observed` | 200 | 21,581 bytes |
| Target 3 | `observed` | 200 | 21,581 bytes |

Negative control에서는 목표 상품 레코드가 나타나지 않았지만 동일한 target 요청 3회에서는 모두 목표 레코드와 큰 상품 응답이 반환됐다. 따라서 다음 동작은 반복 재현된 것으로 볼 수 있다.

- 인증 없이 `q` 파라미터를 통한 검색 쿼리 결과 조작
- inert 입력과 target 입력 사이의 명확한 응답 차이
- target 입력에서 특정 상품 레코드 반환
- 3회의 target 시도에서 동일한 결과

Blind assessment와 Attack 주장의 비교 결과는 `aligned`이며 의미 충돌은 없었다.

### 영향도와 최종 판정

| 영향 축 | 점수 | 근거 |
|---|---:|---|
| Boundary | 1 | 검색 필터 우회는 확인했지만 권한 경계 침해는 입증하지 못함 |
| Sensitivity | 0 | credential, PII, 비공개 기록, 파일, 코드 실행 등의 근거 없음 |
| Actor requirements | 3 | 인증 없이 GET query parameter로 재현 가능 |
| 합계 | 4 | Validation severity `LOW` |

최종 Validation 결과는 다음과 같다.

```text
reproduced:     true
alignment:      aligned
impact score:   4
severity:       LOW
current status: UNDERPOWERED
```

`UNDERPOWERED`는 SQL Injection 동작이 재현되지 않았다는 의미가 아니다. 현재 결정 규칙은 `sensitivity == 0`이면 충분한 보안 영향이 입증되지 않은 것으로 판단한다. 이번 실행에서는 쿼리 조작은 확인했지만 민감 데이터 접근이나 권한 경계 침해를 증명하지 못했다.

Attack의 `HIGH`는 최초 주장에 대한 평가이고 Validation의 `LOW / UNDERPOWERED`는 통제된 재검증 증거에 기반한 최종 평가다. 보고서 작성 자격은 후자를 기준으로 한다.

## 7. 결론 및 후속 확인 항목

파이프라인은 Scope 정책 강제, Recon 수집, Attack finding 생성, 독립 Validation까지 정상적으로 동작했다. 현재 결과만으로 확정할 수 있는 것은 인증 없는 상품 검색 쿼리 조작이다. 정식 보고 대상인 `CONFIRMED`에 도달하려면 허용된 테스트 범위 안에서 다음과 같은 실질적 영향을 추가로 입증해야 한다.

- 일반 검색으로 접근할 수 없는 비공개 데이터 조회
- 사용자·인증 관련 민감정보 노출
- 권한 경계 우회
- 민감한 데이터베이스 객체에 대한 접근 영향

코드 측 후속 작업으로는 Recon Review가 `endpoint_observations` 357건을 정확하게 집계하도록 수정하는 것이 필요하다. 또한 mitmproxy 정책 차단을 운영 관점에서 분석하려면 차단된 요청의 안전한 메타데이터와 사유를 별도 집계하는 기능이 필요하다.

현재 case는 `UNDERPOWERED`이므로 `CONFIRMED` case만 허용하는 Report Agent의 정식 보고서 생성 대상은 아니다.
