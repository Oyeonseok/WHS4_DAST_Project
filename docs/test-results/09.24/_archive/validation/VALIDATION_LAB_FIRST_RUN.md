# Validation 실습 첫 실행 결과 (2026-09-24)

이 문서는 리팩토링 전 첫 실행의 결과 기록이다. 최신 판정과 채점은 [후속 실행 보고서](VALIDATION_LAB_FOLLOWUP.md)에 있다.

## 범위와 입력

- 대상: 고정 버전의 로컬 OWASP Juice Shop(`127.0.0.1:3001`)과 VulnBank(`127.0.0.1:5001`). 승인된 로컬 Scope와 `GET` 전용 TargetPolicy를 사용했다.
- 실행 입력: `result/test-runs/validation-candidates/validation-lab/Pipeline.db`의 **합성 Attack 주장** 7건. 이는 실제 공격 성공을 뜻하지 않는다. 정답은 별도 `CandidateAnswerKey.db`에만 있다.
- 실행 전 원본: 같은 디렉터리의 `Pipeline.before-validation.db`. 현재 DB에는 최신 Validation 판정과 과거 재검증 단계가 함께 남아 있다.
- 요청: 최신 단계마다 양성 대조군 1회, 음성 대조군 1회, target 3회. 7건에서 총 35회의 로컬 HTTP GET이 기록됐다.

## 최신 단계 결과

| 앱 | 후보 | 목표 상태 | 실제 상태 | 최신 target 응답 | 채점 |
| --- | --- | --- | --- | --- | --- |
| Juice Shop | `GET /api/Complaints` 무인증 노출 가설 | `DISPROVEN` | `BLOCKED` (`identity_auth`) | 401 × 3 | `UNRESOLVED` |
| Juice Shop | `GET /api/Feedbacks/1` 무인증 노출 가설 | `DISPROVEN` | `BLOCKED` (`identity_auth`) | 401 × 3 | `UNRESOLVED` |
| Juice Shop | `GET /api/PrivacyRequests` 무인증 노출 가설 | `DISPROVEN` | `BLOCKED` (`identity_auth`) | 401 × 3 | `UNRESOLVED` |
| Juice Shop | `GET /api/Users` 무인증 노출 가설 | `DISPROVEN` | `INCONCLUSIVE` | 401 × 3 | `UNRESOLVED` |
| VulnBank | `GET /api/billers/by-category/<int:category_id>` SQLi 가설 | `DISPROVEN` | `BLOCKED` (`encoding_transport`) | 404 × 3 | `UNRESOLVED` |
| VulnBank | `GET /api/virtual-cards/<int:card_id>/transactions` SQLi 가설 | `DISPROVEN` | `BLOCKED` (`encoding_transport`) | 404 × 3 | `UNRESOLVED` |
| VulnBank | `GET /debug/users` 데이터 노출 | `CONFIRMED` | `CONFIRMED` | 200 × 3 | `PASS` |

양성 `/debug/users`는 양성 대조군 200, 음성 대조군 404, target 200 × 3, 인용된 시도 증거와 충분한 영향 점수로 `PASS`를 받았다. VulnBank 정수 경로 두 건은 target 404 × 3이 음성 대조군 404와 같았고, 정상 경로 양성 대조군은 각각 200·401이었다. Juice Shop 네 건은 target 401 × 3이었고 양성 대조군도 401이었다. 모든 최신 사례의 적격성은 `ELIGIBLE`이며 SQLite 무결성 검사는 `ok`다.

별도 정답지의 merchant 신원·소유 객체가 필요한 3건은 실행 입력에 포함하지 않아 `NEEDS_PREREQUISITES`다. 최종 채점 요약은 **`PASS` 1, `UNRESOLVED` 6, `NEEDS_PREREQUISITES` 3**이다. 반대쪽 확정 상태로 판정한 사례는 없다. 237개 전체 후보의 성능 지표로 해석하지 않는다.

## 실행 중 확인하고 수정한 문제

1. 최초 실행은 준비 DB에 승인 Scope 연결이 없어 `scope_binding_missing`으로 요청 전에 중단됐다. 준비 스크립트가 승인 `Scope.md`를 스캔에 묶고 TargetPolicy 제한을 Scope 이하로 낮추도록 수정했다.
2. 초기 적격성 에이전트는 Scope의 떨어진 두 문장을 하나의 `scope_quote`로 결합해 여러 사례가 `UNKNOWN`에서 멈췄다. 원문에서 연속된 한 구절만 인용하도록 프롬프트와 근거 오류 재시도 안내를 수정했다. 수정 후 최신 7건은 모두 적격성을 통과하고 재생됐다. 원문 인용의 일치 검사는 유지했다.
3. 기본 HTTP 재생은 target 신호가 없을 때 `explicit_non_exploit`을 자동 산출하지 않는다. 따라서 범위가 좁은 비취약 가설도 `DISPROVEN`에 도달하지 못했다. 모델은 인증 거부를 `identity_auth`, 정수 라우트의 문자열 거부를 `encoding_transport`로 분류해 5건을 `BLOCKED`로 처리했다. 이 상태를 잘못된 확정 판정으로 세지 않되, 정답 목표에 도달하지 못한 기능 공백으로 기록한다.

## 다음 리팩토링 초점

- 비취약 판정에는 단순한 신호 부재보다 강한 **명시적이고 범위가 한정된 부정 증거**를 정의한다. 예를 들어 정수 라우트의 매개변수 타입 제한과 실제 404/대조군 일치, 무인증 라우트의 401과 응답 내 민감 데이터 부재를 각각 검증 가능한 계약으로 표현한다.
- 그 증거가 충족되면 더 실행해서 해결할 수 없는 인증·라우팅 거부를 일반 `BLOCKED`로 남기지 않도록 판정 경로를 분리한다. 보호된 데이터 채널의 건강성을 요구하는 경우, 현재 401만 확인하는 Juice Shop 양성 대조군도 개선해야 한다.
- 두 merchant 신원과 서로 다른 소유 결제 객체를 준비한 뒤 보류된 3건을 별도로 실행한다.

## 검증

관련 후보·채점·Validation 적격성·코디네이터·경계 테스트: `165 passed, 144 subtests passed`. 로컬 서버를 여는 테스트는 허용된 네트워크 환경에서 실행했다. 채점 파일은 `result/test-runs/validation-candidates/validation-lab/ValidationScore.json`이다.
