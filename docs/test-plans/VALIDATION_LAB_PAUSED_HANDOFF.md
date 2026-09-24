# Validation lab 작업 재개 기록 (2026-09-24)

사용자가 중단한 Validation 준비를 재개해 실행 입력과 채점 도구를 완성했고, 2026-09-24에 실제 `aidast validate run`으로 7건을 실행했다. 상세 결과는 [첫 실행 보고서](../test-results/09.24/validation/VALIDATION_LAB_FIRST_RUN.md)에 있다.

## 현재 산출물

- `result/test-runs/validation-candidates/CandidateInventory.db`: 공식 자료 기반 후보 237개(Juice Shop 120, VulnBank 117).
- `CandidateAnswerKey.db`: 별도 정답 10개(비취약 8, 취약 2), 목표 Validation 상태·증거 조건·준비 상태 포함.
- `LocalControlObservations.json`: 고정 Docker 이미지와 VulnBank 소스 신원을 확인한 읽기 전용 GET 7건의 상태·본문 해시·길이. 7건 모두 정답지의 HTTP 상태와 일치했다.
- `validation-lab/Pipeline.db`, `TargetPolicy.json`, `CandidateFindingMap.json`: 격리된 합성 Attack 주장 7건. 앱별 `GET`과 필요한 경로로 제한하고, 생성 직전에 실행 신원과 7개 응답을 다시 대조했다. `CandidateIntegrityGate` 7/7 통과, SQLite 무결성 `ok`.
- `validation-lab/ValidationScore.json`: 실제 실행 후 `PASS` 1건, `UNRESOLVED` 6건, 두 merchant 신원이 필요한 `NEEDS_PREREQUISITES` 3건.

채점기는 정답과 같은 상태라도 현재 단계의 대조군, target 시도, 인용 증거, 명시적 비취약 근거 또는 영향 점수가 없으면 `UNSUPPORTED_DECISION`으로 처리한다. 관련 테스트는 165개와 subtest 144개가 통과했다. 이 산출물은 모두 로컬에 있으며 commit하지 않았다.

## 다음 작업

부정 증거를 범위가 한정된 재현 계약으로 표현하고, 명시적 비취약 증거가 충족된 경우의 판정 경로를 리팩토링한다. 현재 기본 HTTP 재생 어댑터는 `explicit_non_exploit`을 자동 산출하지 않아 비취약 6건이 `DISPROVEN`에 도달하지 못했다. 두 merchant 신원과 소유 객체를 준비한 뒤 보류된 3건을 실행한다.

다른 사용자 수정 파일은 건드리지 않았다.
