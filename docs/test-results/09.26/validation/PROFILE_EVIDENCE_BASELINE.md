# Validation 프로필 증거 기준선 (2026-09-26)

## 실행 범위

공식 정답지의 `GET_REPLAY_READY` 7건을 새 격리 번들 `result/test-runs/validation-candidates/validation-profile-evidence-v3`에 준비했다. 준비기는 실행 중인 로컬 Juice Shop `127.0.0.1:3001`과 VulnBank `127.0.0.1:5001`의 GET 상태·본문 해시·길이를 기존 고정 관찰값과 재대조했다. Validation 재생도 같은 로컬 앱에 실제 GET을 보냈다. 과거 실험 DB와 공식 정답지는 수정하지 않았다.

실제 Codex Agent 재실행은 Eligibility subprocess가 응답하지 않아 재생 전에 중단했다. 따라서 이 기준선은 명시적인 **통제 평가기**를 사용했다. 평가기는 완료된 target 신호가 모두 참이면 `reproduced=true`, 모두 거짓이면 `false`로 기록한다. 축은 양성 `(1,0,2)`, 음성 `(0,0,0)`으로 고정한다. Eligibility는 고정 로컬 Scope의 허용 상태만 반환한다. 이 방법은 재생·증거·감사 저장 경로를 측정하며, Blind/Eligibility Agent의 판단 정확도를 측정하지 않는다. 재실행 명령은 `scripts/run_validation_profile_audit_lab.py`에 보존했다.

## 관측 결과

| 항목 | 결과 |
| --- | ---: |
| 새 격리 Validation 후보 | 7 |
| 현재 단계 감사 기록 및 내부 결합 확인 | 7/7 |
| 공식 음성 후보의 출처·대조군 포함 독립 채점 `PASS` | 6/6 |
| 공식 양성 `/debug/users` | `UNDERPOWERED`, 정답 대비 `UNRESOLVED` |
| 완전한 양성 재생의 구조적 사실 | `assertion_differential` 1, `json_value_differential` 1 |
| 프로필별 독립 B/S/A 정답 라벨 | 0 |
| SQLite 무결성 | `ok` |

`/debug/users` 계약은 기존 `"password":` 필드 이름 검사에 `users[0].password`의 비어 있지 않은 문자열 검사를 추가했다. Native HTTP 평가 결과에는 실제 문자열이 없고 참/거짓의 해시만 남는다. 감사 영수증은 JSON 경로와 전체 검사 조건의 해시, target 3회·음성 대조군의 증거 ID를 기록한다. 이 구조적 사실은 보호 데이터의 분류, 누가 접근했는지, 사용자 소유권을 독립적으로 증명하지 않는다. 그래서 현재 생산 규칙은 민감도 0 제한을 유지했고, 통제 양성 사례는 `UNDERPOWERED`로 끝났다.

음성 6건의 감사 상태는 `target_inconsistent`이고 사실 영수증은 없다. 독립 [Validation 채점기](../../../../scripts/score_validation_lab.py)는 실행 중인 로컬 앱의 결과, 원본 라우트 코드, 대조군 해시, 최종 결정의 증거 인용을 확인해 6건을 `PASS`로 판정했다. [보정 보고서](PROFILE_EVIDENCE_BASELINE.json)는 감사 축을 같은 단계의 봉인된 Blind 평가와 대조하며, `evidence_backed_status_matches=6`은 독립 채점 결과를 의미한다. `independent_axis_labels=0`이므로 합성 전이 축 6건의 임계값 일치는 생산 점수 규칙의 보정 근거가 아니다. 외부에서 제공한 축 라벨은 출처 검증 전까지 참고 비교에만 사용한다.

## 다음 검증 경계

1. 실제 Agent 실행 환경의 Eligibility subprocess 지연 원인을 분리해 같은 격리 후보를 다시 실행한다. 통제 평가기 결과는 실제 Agent 성능 집계에 포함하지 않는다.
2. 값 존재 영수증에 더해 보호 내용의 분류와 접근 주체를 검증하는 독립 관찰·정답 라벨을 확보한 뒤 `hunt-source-leak` 민감도 제한을 조정한다.
3. 두 merchant 신원처럼 별도 전제 조건이 필요한 후보는 현재 7건 기준선과 분리해 준비한다.
