# Recon DB 기반 Attack → Validation → Report V11

## 목적

VulnBank 소스 인벤토리를 고정된 로컬 벤치마크로 사용하되, 실행 코어는
특정 애플리케이션 이름이 아니라 완성된 `Recon.db`/`Pipeline.db`의 endpoint,
parameter, annotation, credential reference, owned-object fact를 입력으로 사용한다.
소스 주석이나 카탈로그 항목은 공격 가설일 뿐 finding으로 간주하지 않으며,
실제 HTTP 증거와 독립 Validation을 통과한 항목만 보고서가 된다.

## 구조 변경

1. 모든 Recon parameter를 Attack task의 `parameter_candidates`로 전달하고 한 개의
   deterministic preference만 표시한다. 첫 번째 parameter가 실제 sink가 아니어도
   같은 DB endpoint의 다른 후보를 검사할 수 있다.
2. 현재 annotation과 관련 source annotation을 `source_context`로 전달한다. 이는
   untrusted hypothesis context이며 증거를 대신하지 않는다.
3. `business_logic`, `graphql`, `session`을 일반 vulnerability-to-skill 매핑에 추가하고
   source importer의 취약점 분류 범위를 넓혔다.
4. `coverage-requeue`를 추가해 기존 request, attempt, finding, event를 삭제하지 않고
   명시적으로 terminal coverage를 다시 열 수 있게 했다.
5. 실패/취소된 과거 Attack stage의 미승격 lead는 다음 재개 시 `inconclusive`로
   보존 종결한다. 현재 batch 검증은 현재 batch가 새로 만든 lead만 검사하므로 과거
   중단 상태가 이후 batch를 영구 차단하지 않는다.
6. 한 native batch가 정책상 증명 불가 또는 terminal failure로 끝나도 해당 batch를
   DB에 reconcile한 뒤 관계없는 다음 coverage를 계속 실행한다. 사용자 중단과
   예상하지 못한 구현 오류는 계속 전파한다.
7. exhaustive coverage finding은 immutable `runtime_contract` 없이는 commit할 수 없다.
   따라서 Attack Agent 메모리에만 존재하고 Validation에서 재현할 수 없는 finding이
   새로 생성되지 않는다.
8. report writer가 준비된 context hash를 잘못 복사한 경우, 동일한 immutable context로
   해당 case만 최대 3회 재시도한다. 다른 validation/report 오류는 숨기지 않는다.
9. benchmark catalog는 pinned VulnBank README SHA와 정확히 일치할 때만 활성화된다.
   80개 카탈로그 항목을 executable endpoint hypothesis에 각각 연결하며, 이 adapter는
   일반 Recon DB execution core와 분리되어 있다.
10. coverage export는 catalog item → annotation → endpoint → coverage → finding →
    validation → report 연결을 함께 출력한다.
11. 최신 `main`에서 제거된 Recon DB convenience helper에 의존하지 않도록 source
    vulnerability observation과 surface signal을 현재 스키마 트랜잭션 안에서 직접
    기록한다.

## 인증 및 IDOR fixture

로컬 벤치마크 helper는 실행 시 disposable identity 다섯 개(`user-a`, `user-b`,
`admin-a`, `merchant-a`, `merchant-b`)를 생성한다. DB에는 bearer token이나 비밀번호를
저장하지 않고 opaque `env://` reference만 기록한다. 두 사용자에게 각각 소유된
`user_id`, `account_number`, `card_id`를 기록하므로 IDOR은 A→A positive control,
A→B target, 존재하지 않는 object negative control을 구성할 수 있다.

`env://` credential은 프로세스 수명에 묶인다. 중단 후 재개할 때는 benchmark bootstrap을
같은 프로세스에서 다시 실행해야 하며, 일반 target에서는 호출자가 동일 reference를
해석할 환경 변수 또는 keyring backend를 제공해야 한다.

## V11 실행 결과

- Scan: `scan_cc1b1669e70547aa9326e274cfe0bbd1`
- Recon endpoints: 81
- Recon parameters: 84
- Source vulnerability signals: 92
- Pinned catalog mappings: 80/80
- Attack coverage: 172/172 terminal, unfinished 0
- Attack coverage dispositions:
  - confirmed: 20
  - candidate: 35
  - tested negative: 72
  - unsupported: 32
  - error terminal: 12
  - policy excluded: 1
- Evidence-bound findings: 48
- Validation cases: 48/48 completed
  - confirmed: 16
  - known duplicate: 4
  - contested: 1
  - inconclusive: 27
- Confirmed report drafts: 16/16 valid and non-stale
- Attack HTTP requests with unknown outcome: 0
- Open Attack leads: 0
- Pipeline SQLite integrity: `ok`
- Foreign-key violations: 0
- Latest `main` integration test suite: 1,170 passed, 15 skipped, 645 subtests passed

한 finding이 여러 source/catalog 가설을 동시에 충족할 수 있으므로 coverage confirmed
20과 독립 confirmed Validation/report 16은 같은 수가 아니다.

## 카탈로그 결과와 해석

80개 pinned catalog 항목의 최종 상태는 다음과 같다.

- confirmed: 8
- not reproduced: 29
- unsupported by the current safe contract: 22
- mapped runtime hypothesis: 21

따라서 이번 결과를 “80개 취약점을 모두 찾았다”고 해석하면 안 된다. 80은 README에서
가져온 기대 카탈로그 수이고, 독립 Validation에서 재현된 보고 가능 finding은 16개다.
특히 stored XSS처럼 write endpoint와 별도 read/browser endpoint가 필요한 흐름,
외부 OOB callback이 필요한 SSRF, 실제 동시성 보장이 필요한 race condition은 단일
endpoint HTTP runtime contract만으로 완전하게 증명되지 않을 수 있다. 이 항목들은
거짓 finding으로 승격하지 않고 terminal/inconclusive로 보존했다.

## 일반 Recon DB에 대한 보장 범위

다음 동작은 VulnBank 전용 코드가 아니라 모든 완성된 Recon/Pipeline DB에 적용된다.

- DB의 모든 parameter와 source context를 task에 전달
- opaque credential reference와 owned-object fact 전달
- 중단된 stage/lead 복구
- failed batch 격리와 다음 coverage 계속 실행
- Validation-ready runtime contract 강제
- 전체 coverage outcome export
- confirmed case만 report 생성 및 report hash 재시도

VulnBank 전용인 부분은 pinned README catalog mapping과 disposable fixture bootstrap뿐이다.
다른 애플리케이션에서 같은 결과 품질을 얻으려면 Recon DB에 정확한 method/path/parameter,
인증 reference, 소유 객체 및 필요한 다단계 workflow 관계가 들어 있어야 한다.

## 결과 위치

개인 경로를 문서에 고정하지 않는다. 실행 시 지정한 `<RESULT_ROOT>` 아래에서 확인한다.

- Pipeline DB: `<RESULT_ROOT>/AttackRuns/<SCAN_ID>/Pipeline.db`
- 전체 coverage JSON: `<RESULT_ROOT>/FinalResults/CoverageOutcome/CoverageResults.json`
- 전체 coverage Markdown: `<RESULT_ROOT>/FinalResults/CoverageOutcome/CoverageResults.md`
- confirmed reports: `<RESULT_ROOT>/FinalResults/Reports/<CASE_ID>/Report.md`
- report provenance: `<RESULT_ROOT>/FinalResults/Reports/<CASE_ID>/Report.context.json`
- report database: `<RESULT_ROOT>/FinalResults/Reports/<CASE_ID>/Report.db`
