# Validation 재구조화 변경 기록

이 문서는 Validation 재구조화 구현 변경을 누적 기록한다. 관련 구현을 완료할 때마다 최신 날짜의 항목을 문서 상단에 추가한다.

## 2026-09-12: shared Validation 기반 구현

- Pipeline.db를 schema v9로 올리고 Validation case, attempt, evidence, development action, impact hypothesis, HTTP ledger, reproduction spec 테이블을 추가했다.
- Blind 입력과 Attack claim을 분리하고 Blind assessment가 고정된 뒤에만 claim을 공개하도록 제한했다.
- KNOWN 판정은 임베딩 없이 exact key와 정규화된 Levenshtein 유사도 `0.85` 기준으로 구현했다.

  이유: 이 방식은 원 설계 §8.6과 같다. 먼저 취약점 유형, endpoint template, parameter 이름이 모두 같은 후보만 비교하므로 의미 검색이 필요하지 않다. 이후 payload 구조의 작은 차이만 결정론적으로 계산하면 된다. 임베딩은 모델·버전·실행 환경에 따라 결과가 변할 수 있고 동일 입력의 재현성, 오프라인 실행, 임계값 설명 가능성을 약화하므로 KNOWN 자동 판정에 사용하지 않았다. 현재 `0.85`는 동일 취약점 확률이 아니라 정규화된 문자열 편집 유사도다.

- Boundary, Sensitivity, Actor requirements의 세 축 영향 점수와 `UNDERPOWERED`, 상태 판정 우선순위를 결정론적으로 구현했다.

  참고: 이 점수는 원 설계의 보편적인 기술 영향 기준이다. 설치 수나 개별 버그바운티의 접수·보상 규칙은 포함하지 않으며, 이후 별도의 프로그램 eligibility 판단으로 분리해야 한다.

- Repository에 case·stage·evidence 소유권 검증, decision hash, optimistic concurrency와 KNOWN source 무효화를 추가했다.
- Validation stage 실패 시 진행 중 record를 `outcome_unknown`/`interrupted`로 정리하고 동일 stage ID로 재개할 수 있게 했다.
- 증거 메타데이터에서 secret, 민감 헤더, raw body를 제거하고 깊이·항목·바이트 제한을 적용했다.
- CONFIRMED case를 읽는 Report.db v2를 추가했다. KNOWN은 source case를 반환하고 CONTESTED는 review-only이며, decision 변경 시 기존 보고서를 `stale`로 표시한다.

  설계와 다른 점 및 이유: 원 설계는 기존 `validation_id` 기반 Report binding을 새 case binding으로 교체하도록 요구한다. 현재는 기존 Report.db v1 reader를 제거하지 않고 case 기반 v2와 병행한다. 새 Validation 실행 경로가 아직 완성되지 않은 상태에서 v1을 즉시 제거하면 기존 보고서와 회귀 테스트를 읽을 방법이 없어지므로, 전환 완료 전까지 읽기 호환성을 유지했다. 새 case 보고서는 설계대로 DB 전체 hash 대신 `scan_id`, `case_id`, decision hash와 정렬된 evidence hash에 묶인다.

- `validate status --scan-id/--case-id`와 `report run Pipeline.db --case-id`를 추가했다.

  설계와 다른 점 및 이유: 원 설계는 `validate run`, targeted run, `resume`과 pipeline 자동 실행까지 새 Coordinator에 연결한다. 현재 Coordinator와 ReproductionPort가 없으므로 실행 명령을 성공한 것처럼 노출하지 않고, 완성된 shared DB 기능인 status와 Report만 새 계약에 연결했다. 기존 `validate run`은 전환 중 호환성을 위해 아직 7 Question Validation.db 경로를 사용한다.

- 새 Attack HTTP request에 canonical TargetPolicy SHA-256을 기록한다. 기존 request의 digest는 추정해 채우지 않는다.

검증:

- 관련 unittest 53개 통과
- 기존 Reporting pytest 31개 통과
- 전체 unittest 330개에서 코드 테스트 통과. `.venv`의 pytest 미설치로 pytest 기반 모듈 import 1건은 별도 시스템 pytest로 검증
- 소스 compileall 및 `git diff --check` 통과

남은 작업:

- reproduction spec producer와 CandidateIntegrityGate
- Validation profile 전체 및 Skill binding
- ReproductionPort, Validation request broker와 실제 adapter
- restricted helper, native Validation Agent와 Coordinator
- retry/development 실행 연결과 ImpactGapAnalyzer
- demonstrated Chain Validation
- `validate run/resume`, targeted run과 pipeline 자동 실행
- 새 실행 경로 전환 후 기존 7 Question Validation.db 제거

상세 구현 상태와 작업별 수용 조건은 [implementation plan](../superpowers/plans/2026-09-12-validation-refactor-implementation.md)을 따른다.
