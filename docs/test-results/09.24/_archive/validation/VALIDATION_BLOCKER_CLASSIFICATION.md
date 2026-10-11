# Validation 장애 분류: 첫 실행 후속 점검 (2026-09-24)

이 문서는 리팩토링 전 첫 실행의 분류 기록이다. 최종 구현과 재실행 결과는 [후속 실행 보고서](VALIDATION_LAB_FOLLOWUP.md)를 따른다.

## 분류 기준

| 분류 | 판단 근거 | 현재 판정 경로 |
| --- | --- | --- |
| 프로필 연결 오류 | 후보가 시험하는 경계와 Validation 프로필의 성공 조건이 다름 | 준비 데이터를 수정하고 새 격리 DB에서 재실행 |
| 해결 가능한 실행 장애 | 관찰된 장애가 시험 대상 바깥에 있고, 같은 범위에서 실행 가능한 Development 계약이 있음 | `DEVELOPING`으로 진입해 조치·재생 후 판정 |
| 원인 미확정·증거 부족 | 신호 부재 또는 401·404만 관찰되며, 원인을 증명할 독립 대조군·신뢰 가능한 계약이 부족함 | `INCONCLUSIVE`; `DISPROVEN`으로 확정하지 않음 |
| 범위가 한정된 부정 증거 | 신뢰 가능한 경계·라우트 제약과 대상·대조군의 신선한 응답으로 해당 재현 계약의 효과가 불가능함을 명시적으로 입증 | 이후 `explicit_non_exploit` 판정 경로의 입력 후보 |

`BLOCKED`는 단순히 target이 거부됐다는 뜻으로 사용하지 않는다. 현재 구현은 모델이 허용된 `blocker_axis`를 지정하면 `DEVELOPING`에 진입하지만, 실행 가능한 Development 계약의 존재를 먼저 확인하지 않는다. `development_contract_missing`으로 조치가 실패해도 `development_used=True`여서 최종 `BLOCKED`가 된다. 따라서 현재의 `BLOCKED`와 위 표의 “해결 가능한 실행 장애”는 동의어가 아니다.

## 7건의 원인 분류

| 대상 | 첫 실행 | 분류 | 근거·처리 |
| --- | --- | --- | --- |
| Juice Shop `/api/Complaints`, `/api/Feedbacks/1`, `/api/PrivacyRequests` | `BLOCKED identity_auth` | 프로필 연결 오류 | 무인증 노출 가설에 타인 객체 접근용 `hunt-idor`가 연결됐다. `hunt-auth-bypass`로 수정한 새 격리 입력에서 재실행했다. |
| Juice Shop `/api/Users` | `INCONCLUSIVE` | 원인 미확정·증거 부족 | target 401 × 3, 양성 대조군도 401. 인증된 데이터 채널을 확인하지 않아 부정 증거를 확정할 수 없다. 새 프로필로도 재실행했다. |
| VulnBank `/api/billers/by-category/<int:category_id>` | `BLOCKED encoding_transport` | 라우트 제약 증거 누락 및 Development 계약 부재 | 고정한 앱 소스는 정수 경로 변환기를 사용한다. 문자열 SQLi target과 잘못된 정수 음성 대조군은 404, 정상 정수 양성 대조군은 200. BlindCase에는 신뢰 가능한 변환기 증거가 없다. 시도한 encoding 조치는 `development_contract_missing`으로 실패했다. |
| VulnBank `/api/virtual-cards/<int:card_id>/transactions` | `BLOCKED encoding_transport` | 라우트 제약 증거 누락 및 Development 계약 부재 | 같은 정수 경로 변환기와 404 target/음성 대조군. 정상 정수 양성 대조군은 401이므로 인증 전송만 확인했다. encoding 조치는 `development_contract_missing`으로 실패했다. |
| VulnBank `/debug/users` | `CONFIRMED` | 정상 양성 사례 | 독립 대조군과 target 반복 재생, 영향 점수로 첫 실행에서 정답과 일치했다. |

원래 실행 DB는 `result/test-runs/validation-candidates/validation-lab/Pipeline.db`에 보존했다. 프로필 수정은 `scripts/prepare_validation_lab.py`에 적용하고 새 입력을 `result/test-runs/validation-candidates/validation-lab-classification-v2/`에 만들었다. 수정한 입력에는 기존 정답지가 포함되지 않는다.

새 입력에서 Juice Shop 네 건을 모두 다시 실행한 결과는 **`INCONCLUSIVE` 4건**, `blocker_axis=null` 4건, Development 동작 0건이었다. 네 건 모두 정답지의 `DISPROVEN`에는 아직 도달하지 못해 `UNRESOLVED`다. 나머지 실행 가능 사례 3건은 새 입력에서 실행하지 않았으므로 `PENDING`이며, 신원 준비가 필요한 3건은 `NEEDS_PREREQUISITES`다. 세부 채점은 새 입력의 `ValidationScore.json`에 있다. 새 DB의 SQLite 무결성 검사는 `ok`, 준비·채점 관련 테스트는 `18 passed`였다.

## 이번 수정 범위와 다음 단계

이번 수정은 Juice Shop 무인증 가설의 프로필 연결만 변경한다. 이 변경으로 401을 잘못된 `identity_auth` 장애로 해석한 원인을 제거할 수 있는지 재실행으로 확인한다. 401만으로 `DISPROVEN`이 되는 것은 아니다.

VulnBank 두 건은 라우터의 정수 변환 제약을 신뢰 가능한 재현 계약으로 전달하고, 해당 계약과 새 HTTP 응답을 함께 평가해야 한다. 그 전에는 404만으로 `DISPROVEN`을 만들거나 `encoding_transport`를 해결 가능한 장애로 단정할 수 없다. Development 가능 여부도 허용 액션 목록뿐 아니라 **실행 가능한 계약의 존재**로 확인하는 설계가 필요하다. 두 작업은 판정 계약과 공통 코디네이터 경계를 바꾸므로 별도 리팩토링 범위로 둔다.
