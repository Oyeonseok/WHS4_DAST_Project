# Phase별 로컬 테스트 결과 문서 작성 정책

## 적용 범위와 파일 배치

`docs/test-plans/`의 단계별 테스트를 실행할 때 결과 세트마다 `docs/test-results/<결과 세트>/README.md`와 `PHASE_A.md`부터 `PHASE_F.md`까지 작성한다. `<결과 세트>`는 실행 날짜 또는 브랜치·목적을 식별할 수 있는 이름으로 정한다. 실행하지 않은 단계도 `PHASE_<문자>.md`를 만들고 `NOT RUN` 사유와 재개 조건을 기록한다. 이 문서는 결과 문서의 **기록 형식**을 정하며, 각 단계의 통과 조건은 해당 테스트 계획을 따른다.

`README.md`에는 단계별 문서 링크, 판정, 핵심 수치, 채택한 scan ID와 남은 제한사항을 한 표로 요약한다. 세부 수치와 판단 근거는 각 `PHASE_*.md`에 둔다. 같은 지표를 여러 단계에서 비교할 때는 별도 비교 문서를 둘 수 있지만, 해당 지표의 단계별 값과 링크를 각 Phase 문서에도 남긴다. Recon 수집률에는 [전용 기록 형식](RECON_COVERAGE_TEMPLATE.md)을 사용한다.

## 공통 판정과 수치 표기

| 표기 | 의미 |
| --- | --- |
| `PASS` | 계획에 명시된 해당 단계의 필수 확인 항목과 중단 조건을 검증해 통과했다. 수집률이나 탐지율이 높다는 뜻은 아니다. |
| `PARTIAL` | 실행과 일부 판정은 끝났지만 계획의 필수 항목 중 미판정 또는 미완료 항목이 있다. 완료한 항목과 남은 항목을 분리한다. |
| `FAIL` | 실행 또는 검증이 계획의 중단·실패 조건에 걸렸다. 원인, 영향을 받은 scan과 후속 조치를 기록한다. |
| `NOT RUN` | 해당 단계의 평가 실행을 시작하지 않았다. 선행 gate와 미충족 조건을 기록한다. |

- 위 **문서 판정**과 DB의 `completed`, `failed`, `skipped`, `INCONCLUSIVE` 같은 **stage·case 상태**를 혼용하지 않는다. `skipped`가 정당한 조건인지, `INCONCLUSIVE`가 어떤 gate에서 발생했는지 설명한다.
- 측정하지 못한 값은 `NOT_MEASURED`, 적용 대상이 아닌 값은 `N/A`로 쓴다. 실제로 확인한 0건과 구분한다. 퍼센트에는 `분자/분모(소수점 첫째 자리%)`를 함께 적고, 분모·집계 단위를 바로 옆에 정의한다.
- 사람이 확인한 사실, 자동 도구 출력, 해석·추론을 구분한다. 부분 실행 수치를 완료 실행의 성능 결과에 합치지 않는다. 대상·인증 상태·시작 경로·코드/정책 버전이 다른 수치를 합칠 때는 집합 계산 규칙과 포함한 scan을 명시한다.
- `TP`, `FP`, `FN`, `UNSUPPORTED`, `UNRESOLVED`와 Validation decision은 별도 열로 기록한다. 전체 `ELIGIBLE` ground truth가 없으면 recall·F1을 임의 계산하지 않는다.

## 모든 `PHASE_*.md`의 본문 순서

아래 제목과 순서를 기본으로 사용한다. 해당 단계에 적용되지 않는 항목은 생략하는 대신 `N/A`와 이유를 한 줄로 남긴다. 긴 분석은 하위 제목으로 분리하되 공통 제목은 유지한다.

1. **판정** — `PASS`/`PARTIAL`/`FAIL`/`NOT RUN`, 한 문장 근거, 해당 단계의 gate 충족 여부.
2. **실행 기준** — KST 날짜·시간 범위, AI DAST commit과 미커밋 소스 변경 여부, 대상 image/source 버전, Scope·Policy, 인증 identity 역할, 시작 URL, 모델·도구 및 요청 제한. 민감한 값은 적지 않는다.
3. **실행 이력** — 시도별 대상, scan ID, 명령 또는 재현 가능한 옵션, exit code, DB stage 상태, 채택·제외 여부와 이유. 재시도 전후를 별도 행으로 둔다.
4. **단계 결과** — 해당 Phase의 필수 결과를 아래 표준 항목에 맞춰 표로 기록한다. 대상별 결과와 여러 실행의 합집합·집계값을 분리한다.
5. **지표와 검증 근거** — 분자·분모, 원본 DB/JSON/log 경로, 필요한 경우 hash·SQL/명령, 수동 대조 근거. 숫자만 적지 않고 어떤 원본에서 얻었는지 연결한다.
6. **실패·제외·재시도** — 중단 조건, 미완료 scan, 원인 조사 결과, 수정 버전과 재검증. 직접 확인하지 못한 원인은 가설로 표시한다.
7. **제한사항과 다음 게이트** — 미평가 범위, 수치의 해석 한계, 다음 단계로 넘어갈 조건.
8. **원본 산출물** — 채택한 scan별 `Recon.db`, `Surface.json`, `ReconReview.json`, `Handoff.json`, `Pipeline.db`, Report와 로그의 실제 경로 중 해당하는 것. 없는 산출물은 사유를 적는다.

복사해서 시작할 최소 골격은 다음과 같다.

```markdown
# Phase <A-F> — <단계명> (<YYYY-MM-DD HH:mm~HH:mm KST>)

## 판정

**<PASS/PARTIAL/FAIL/NOT RUN> — <한 문장 근거>.** <계획의 gate 충족 여부>

## 실행 기준

| 항목 | 값 |
| --- | --- |
| 코드·대상 버전 | <commit, image digest/source commit, 미커밋 변경> |
| Scope·Policy | <artifact 경로/해시, host·method·요청 한도> |
| 인증·시작 URL | <public/primary/secondary, 시작 URL> |
| 도구·모델 | <버전/식별자 또는 N/A> |

## 실행 이력

| 대상·시도 | scan ID | 명령/옵션 근거 | exit code | stage 상태 | 채택 여부·사유 |
| --- | --- | --- | ---: | --- | --- |
| <대상·1차> | <scan_id 또는 N/A> | <명령·로그 경로> | <값/N/A> | <상태> | <채택/제외·사유> |

## 단계 결과

<해당 Phase의 필수 표와 관측 사실>

## 지표와 검증 근거

<분자/분모·원본 경로·수동 대조>

## 실패·제외·재시도

<없으면 '확인된 실패 없음'; 미실행이면 사유>

## 제한사항과 다음 게이트

<미평가 범위·다음 단계 조건>

## 원본 산출물

- <실제 원본 경로 또는 N/A 사유>
```

## Phase별 필수 결과

| Phase | `단계 결과`에 반드시 포함할 내용 | 핵심 근거 |
| --- | --- | --- |
| A — 사전 점검 | 대상·DB health, 도구 준비 상태, 승인 Scope 무결성, policy-only의 정확한 host·port·scheme·method·요청 제한, 중단 조건 확인 | Docker/health 출력, Scope·Approval·TargetPolicy 경로와 hash, 명령 exit code |
| B — 공개 Recon | 대상별 Recon stage, endpoint·observation·HTTP transaction, annotation 성공/실패, Surface·Review 생성 여부, 허용·차단·범위 밖 요청, 고정 GET route 수집률 | 채택한 `Recon.db`, 프록시 집계·로그, [수집률 형식](RECON_COVERAGE_TEMPLATE.md) |
| C — 인증 Recon | identity별 session 검증, 시작 URL별 Recon 상태, 인증 화면·API의 성공 응답, 인증/공개 수집의 구분, 비밀값 노출 검사, 고정 GET route 수집률 | session bundle 무결성·권한 결과, `Recon.db`·Surface·HTTP 거래, 비밀값 대조 결과 |
| D — 통합 실행 | scan별 Recon→Attack→Chaining→Validation stage와 소요 시간, Recon 수집률, task·attempt·request ledger, finding·reproduction spec·chain, Validation case·decision·evidence, 미종결 요청과 DB 무결성 | `Recon.db`·Handoff hash·`Pipeline.db`, stage/ledger/foreign-key 조회 |
| E — 판정·Report | finding별 ground truth와 증거 대조, TP/FP/duplicate/unsupported/unresolved, Validation 적격성·재현 결과, 계산 가능한 precision/recall/F1 또는 `NOT_MEASURED`, Report 인용·stale 검사 | finding/spec/case/evidence ID, 대조군·재현 요청, 로컬 Report 원본과 status |
| F — 반복 평가 | 대상별 3회 실행의 동일 baseline 복원 검증, 고정 코드·모델·정책·계정, 실행별 상태·요청·시간·모델 사용량, 중앙값과 최소·최대, 중단·제외 회차 | 초기 상태 snapshot/복원 검증, 각 scan DB·로그, 계산식 |

Phase B·C·D의 Recon 수집률은 **실행별 표**와 **단계 내 대상별 중복 제거 합집합 표**를 모두 쓴다. 전체 application GET route 분모, 인증별 접근 가능 범위, 취약점 탐지율은 서로 다른 지표다. 계산과 표 열은 [Recon 수집률 기록 형식](RECON_COVERAGE_TEMPLATE.md)을 따른다.

## 기록과 검증 규칙

- 코드·대상·Scope·모델 또는 데이터 baseline이 바뀐 재시도는 새 실행 행과 scan ID로 기록한다. 실패 이력을 덮어쓰지 않는다. 최종 판정의 분자에는 **채택한 완료 실행만** 넣고 제외 사유를 남긴다.
- `result/`의 원본은 그대로 보존한다. 문서에는 검증 가능한 경로를 쓰고, git에 넣지 않는 로컬 파일이면 그 사실을 명시한다. 로그가 없거나 에러 세부 메시지가 저장되지 않았다면 원인을 단정하지 않는다.
- 계정 비밀번호, cookie, token, 세션 파일 내용, 비밀 payload 원문은 결과 문서에 복사하지 않는다. 필요하면 권한·hash·비노출 검사 결과와 로컬 경로만 기록한다.
- 문서를 완료하기 전에 표의 산술, 링크와 원본 경로, scan ID ↔ 산출물 대응, 판정과 stage 상태의 일치 여부를 확인한다. 문서만 변경했다면 코드 테스트 대신 이 검증을 기록한다.
