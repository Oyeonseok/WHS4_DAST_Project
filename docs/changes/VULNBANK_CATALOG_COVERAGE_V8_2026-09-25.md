# VulnBank catalog coverage V8 (2026-09-25)

## 목적

VulnBank의 공식 README에 적힌 취약점 목록과 AIDAST가 Flask route 주석에서 만든
동적 Attack 단위를 같은 숫자로 취급하지 않도록 분리한다. 공식 목록은 completeness
denominator이고, finding은 독립적인 HTTP 증거와 Validation이 있어야만 확정된다.

## 기준 소스

- 저장소: `Commando-X/vuln-bank`
- 고정 commit: `4bb7cd5f46921959f034455e5615782481966177`
- 공식 README `Implemented Vulnerabilities`: **80개**, 11개 카테고리
- route/method별 source vulnerability annotation: **78개**

80과 78은 서로 다른 단위다. README 항목에는 JWT 설정, 브라우저 localStorage,
GraphQL resolver, 여러 endpoint에 공통인 설계 결함과 서로 중복되는 설명이 포함된다.
78개 annotation은 HTTP method와 route에 결합된 Attack 작업 단위다. 따라서 80개를
그대로 80개의 고유 동적 finding으로 계산하면 안 된다.

## 변경 사항

### Recon DB catalog

- Recon schema를 9로 올렸다.
- `benchmark_catalog_items` 테이블을 추가했다.
- 각 README 항목의 ordinal, category, title, source path/line, source ref 및 README
  SHA-256을 저장한다.
- 최초 상태는 `declared_unassessed`다. 소스 프로젝트의 주장만으로 `confirmed`를
  생성하지 않는다.
- `(scan_id, ordinal)` 및 `(scan_id, category, title)` uniqueness로 누락과 중복을
  탐지한다.

### Source import와 handoff

- `--lab-benchmark` source import에서 `Implemented Vulnerabilities` section을
  결정적으로 파싱한다.
- `BenchmarkCatalog.json`을 생성하고 Handoff의 `benchmark-catalog` artifact로
  SHA-256 고정한다.
- Recon.db를 SQLite backup으로 materialize하므로 동일한 80개가 Pipeline.db에도
  보존된다.
- CLI, SourceInventory, ReconReview, Handoff count에 catalog item 수를 노출한다.

### Attack coverage와 export

- JWT coverage는 공개 login route에 붙은 annotation이라도 발급된 opaque 인증
  token을 baseline으로 요구한다. 토큰 없이 JWT 검사를 시도해 `blocked_auth`가 되는
  잘못된 경로를 제거한다.
- CoverageResults JSON/Markdown에 upstream catalog 총계와 assessment status를 함께
  출력한다.
- catalog claim과 route Attack item은 별도 배열과 별도 상태로 유지한다.

## 실제 V8 import 검증

- Scan: `scan_a22f3b7021094ea0896350bef599475d`
- endpoints: 81
- parameters: 84
- route vulnerability signals: 78
- benchmark catalog items: 80
- category count: 11
- Recon.db: `PRAGMA integrity_check = ok`, foreign-key 오류 0
- Pipeline.db: `PRAGMA integrity_check = ok`, foreign-key 오류 0
- 두 DB 모두 ordinal `1..80`, status `declared_unassessed`

카테고리별 항목 수는 다음과 같다.

| Category | Count |
|---|---:|
| Authentication & Authorization | 9 |
| Data Security | 6 |
| Transaction Vulnerabilities | 6 |
| File Operations | 7 |
| Session Management | 4 |
| Client and Server-Side Flaws | 4 |
| Virtual Card Vulnerabilities | 11 |
| Bill Payment Vulnerabilities | 9 |
| Merchant Payment API Vulnerabilities | 8 |
| AI Customer Support Vulnerabilities | 10 |
| GraphQL Vulnerabilities | 6 |
| Total | 80 |

## 결과 해석 규칙

다음 숫자를 분리해서 보고한다.

1. 공식 catalog coverage: README 80개를 DB에 손실 없이 보존했는가.
2. executable coverage: route/method annotation 78개에 terminal disposition이 있는가.
3. Attack candidates: 독립 Validation 전의 증거 결합 후보 수.
4. confirmed cases: fresh control/target replay로 확인된 Validation case 수.
5. unique root causes: 동일 원인의 중복 보고서를 통합한 보수적 수.

`declared_unassessed`, `unsupported`, `tested_negative`를 finding으로 세지 않는다.
동일 root cause가 README 여러 bullet 또는 route 여러 개에 나타나도 자동으로 고유
취약점 수를 늘리지 않는다.

## 테스트

- catalog parser와 Recon/Pipeline DB 보존 회귀 테스트
- catalog를 finding으로 자동 확정하지 않는 상태 테스트
- CoverageResults catalog projection 테스트
- JWT authenticated baseline 선택 테스트
- schema future-version downgrade 방지 테스트를 현재 schema 상대값으로 변경
- 전체 suite 최초 실행: 1084 passed, 6 skipped, 642 subtests passed, schema version
  expectation 2건 실패
- expectation 수정 후 해당 회귀 테스트 2건 통과

## V8 동적 실행 중간 상태

Attack Agent를 5개 batch에서 시작한 뒤 20개 batch로 전환해 실행했다. task-bound
승인은 모두 disposable loopback fixture에만 적용했고 redirect 금지, task별 최대 10회,
16 KiB body 제한을 유지했다.

Codex 사용량 한도가 발생한 시점의 보존 상태는 다음과 같다.

| Attack disposition | Count |
|---|---:|
| candidate | 14 |
| tested_negative | 15 |
| unsupported | 32 |
| error_retryable | 14 |
| error_terminal | 1 |
| pending | 2 |
| Total | 78 |

- findings: 15
- attempts: 81 (`confirmed 19`, `negative 43`, `inconclusive 18`, `rejected 1`)
- HTTP requests: 91 completed
- Pipeline DB integrity: `ok`, foreign-key 오류 0
- 제한 해제 안내 시각: 2026-09-26 17:09
- 중간 export: `AIDASTLabBenchmarkV8/InterimCoverage/CoverageResults.{json,md}`

이 수치는 최종 Validation 결과가 아니다. `candidate` 14개는 Validation 전이고,
`error_retryable` 및 `pending` 16개는 사용량 한도 해제 후 같은 Pipeline.db에서 다시
실행해야 한다. 공식 80개 catalog가 저장됐다는 사실도 80개 취약점이 동적으로
확인됐다는 뜻이 아니다.
