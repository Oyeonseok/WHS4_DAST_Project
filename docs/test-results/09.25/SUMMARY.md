# 09.25 실험 요약 — Validation 상태 전이의 인과성과 증거 계약

**추가 Impact 관측 때문에 `UNDERPOWERED → DEVELOPING → CONFIRMED`로 바뀌는 경로를 검증했다.** 초기 실제 Agent 실험에서는 인과적 양성 전이를 입증하지 못했지만, 증거 ID 분리·단계 기록·Blind 점수 보존·프로필 신호 강화를 거쳐 실제 Blind·Impact Agent 양성 전이 1건을 정답지 기준으로 확인했다.

## 범위와 실험 조건

- 기록 범위: `validation/`의 초기 실험, 리팩토링·후속 재실험 문서, 프로필 보정 JSON. 원본 문서 표기는 **2026-09-25**이며 후속 절에 별도 실행 시각이 없는 항목도 있다.
- 대상 경로: VulnBank `GET /debug/users` 한 경로를 6개 시나리오로 변형한 실습. Attack의 confirmed 주장은 합성 입력이고 정답지는 Agent에게 제공하지 않았다.
- 상태 전이의 성공은 최종 CONFIRMED만으로 세지 않는다. 개발 전 UNDERPOWERED, DEVELOPING 단계의 유효한 계획, 추가 GET, assertion 성공, 새 증거 인용이 모두 필요하다.
- B/S/A는 경계·민감도·행위자 요구 축이다. 시나리오 채점 PASS와 일반적인 취약점 판정 정확도는 다른 지표다.
- 초기 실험의 두 번째 단계는 로컬 앱에 실제 GET을 보냈다. **리팩토링 직후 및 다수 후속 실험은 저장 관찰값을 주입한 HTTP 응답**을 사용했다. 아래 표에서 통제 조건을 구분한다.

## 어떤 실험을 했고 결과는 어땠나

| 실험 | Agent·응답 조건 | 정답지 결과 | 해석 |
| --- | --- | --- | --- |
| 초기 A | Blind 축 통제, Impact Agent 실제; 로컬 GET | PASS 2/6 (33.3%), EXECUTION_ERROR 3, GAP_DEVELOPING_PHASE 1 | 계획이 Attack 요청 ID를 Validation 증거 ID로 인용해 3건 중단. 음성 일부는 과잉 확정하지 않음 |
| 초기 B | Blind·Impact Agent 실제; 로컬 GET | 시작 조건 불충족 3, NON_CAUSAL_BASELINE 2, UNRESOLVED 1 | 인과적으로 입증된 양성 전이 0건. 개발 전 재평가만으로 충분해진 2건을 성공에서 제외 |
| 리팩토링 통제 모드 | Blind 축·Impact 계획 통제, 응답 주입 | PASS 6/6 (100.0%) | 전이 판정식·실행 계약 검증 |
| 리팩토링 Impact Agent 모드 | Blind 축 통제, Impact Agent 실제, 응답 주입 | PASS 6/6 (100.0%) | 양성 2건 CONFIRMED, 음성 4건 UNDERPOWERED 유지 |
| 리팩토링 전체 Agent 모드 | Blind·Impact Agent 실제, 응답 주입 | PASS 2/6 (33.3%), BASELINE_NOT_UNDERPOWERED 4 | 양성 2건이 시작 조건에 못 들어가 인과적 양성 전이는 여전히 0건 |
| 프로필 증명 신호 강화 후 전체 Agent | Eligibility 통제, Blind·Impact Agent 실제, 응답 주입 | PASS 4/6 (66.7%), BASELINE_AXIS_MISMATCH 2 | `verified_marker` 양성 전이 1건 PASS; 음성 3건 유지. 특수 축 시나리오 2건은 전제 불충족 |
| 특수 축 경계 재검증 | 시작 축 fixture, 로컬 Native GET | PASS 2/2 (100.0%) | minimal_threshold는 CONFIRMED, partial_boundary는 UNDERPOWERED. 실제 Blind의 축 판단 성과가 아님 |
| Development 진입 영수증 강화 | Blind·Eligibility fixture, Impact Agent 실제, 응답 주입 | PASS 2/2 (100.0%) | 영수증 인용 후 양성 전이, 거짓 마커는 UNDERPOWERED 유지 |
| 축별 인용 강화 후 양성 재검증 | Blind·Impact Agent 실제, Eligibility·응답 통제 | PASS 1/1 (100.0%), SQLite `ok` | 적용 축 (1,0,2) → (1,2,2), 인용 규칙 위반 없이 CONFIRMED |

각 행은 별도 번들·변경 시점의 결과다. 통제 수준과 준비 증거가 달라 PASS를 합산한 하나의 정확도나 반복 성공률을 만들지 않는다. 별도의 봉인 형식 재검증 `impact-agent-v4/verified_marker` 1건 PASS도 앞선 6건 집계에 중복 합산하지 않는다.

## 바뀐 내용과 확인된 성과

| 문제 | 변경 | 확인된 효과 |
| --- | --- | --- |
| Impact 계획 시점이 `blind_replay`로 기록 | 계획 전에 `developing`, 종료 후 `blind_replay` 복원 | 초기 계획 4건의 단계 누락에서, 실제 Impact Agent 재실험의 계획 필요 5건 모두 DEVELOPING 기록으로 개선 |
| Attack 출처 요청 ID와 현 단계 증거 ID 혼동 | `source_request_ids`와 `evidence_ids` 분리, 각 허용 집합 검증 | 초기 3건의 ID 오류를 재현·수정. 실제 Impact Agent 통제 재실험 6/6 PASS |
| 같은 응답의 재평가만으로 점수가 상승 | 동일 Blind 입력·범위·응답의 기존 UNDERPOWERED 축 보존; 원점수·적용 점수 감사 기록 | partial_boundary의 재평가 (1,1,2)를 기존 (0,0,2)로 제한. 새 관측은 민감도에만 반영되어 최종 (0,2,2) UNDERPOWERED 유지 |
| 약한 `users` 문자열이 source-leak 재현 신호로 사용 | 프로필과 맞는 `"password":` 필드명 신호, 계약 의미 검사 추가 | 기존 약한 계약은 `runtime_profile_semantics`로 거부. 필드명만으로는 민감도 0을 유지하며 별도 Impact 증거 요구 |
| 동일 재현 증거에 서로 다른 시작 축을 가정 | 개발 전 증거 해시 비교·사전 검사 | 특수 축 2건을 `shared_replay_evidence`로 실제 Blind 실행 전에 거부. 정답지 정의를 관측에 맞춰 변경하지 않음 |
| Agent의 사전조건 선언만으로 개발 진입 가능 | 경로·액션 해시·출처·현재 증거를 확인한 봉인 영수증과 계획의 영수증 ID 인용 필수화 | 양성·거짓 마커 2건 모두 영수증을 인용하고 기대 판정. 영수증 없는 weak_marker는 회귀 테스트에서 Agent 호출 없이 skip |
| B/S/A의 양수 점수에 증거 인용이 부족 | 경계는 target+negative control, 민감도·요구 축은 target 인용 요구 | control만 인용한 회귀 사례는 원점수 (1,0,2) → 적용 (0,0,0). 실제 Agent 양성 1건은 규칙 위반 없이 전이 PASS |
| 재개·반복 조치의 상태 혼동 | 봉인 평가·사용 증거 복원, 동일 조건 BLOCKED 재실행 방지, `outcome_unknown` 검토 | 회귀 테스트로 같은 조건의 중복 조치 방지와 불명확한 결과의 INCONCLUSIVE 확인 |

정량적으로 확인된 개선은 **실제 Impact Agent·통제 Blind 모드의 시나리오 PASS 2/6→6/6**, 프로필 신호 강화 후 **전체 Agent 모드의 유효한 양성 전이 0→1건**이다. 후자는 응답 주입 조건에서의 결과이며 실시간 서버 연결 성공이나 임의 후보의 일반 성능을 입증하지 않는다.

## 프로필 보정 결과와 검증 기록

[프로필 보정 JSON](_archive/validation/PROFILE_EVIDENCE_CALIBRATION.json)은 과거 저장 상태를 읽기만 한 별도 점검이다. 준비된 공식 후보 7건 중 저장 상태의 정답 일치는 1건, 현재 감사 결합 유효 건수는 0건이었다. 합성 축 시나리오 6/6의 판정식 일치와 프로필 58개 중 축 강제 적용 준비 0개를 기록했다. **결정 증거의 독립 채점이나 Agent 축 정확도 측정은 아니다.** 이를 후속 전이 실험의 성적과 합치지 않는다.

- 원본에 기록된 DB 검증: 초기 12개 DB 모두 SQLite `ok`; 리팩토링 검증 범위 19개 격리 DB의 무결성·채점 대조 완료.
- 원본에 기록된 테스트: Validation 핵심 132개/120 subtests, 전송·정책 경계 32개/35 subtests, 실습 29개 통과. `compileall`, `git diff --check` 통과.
- 남은 과제: minimal_threshold·partial_boundary의 실제 Blind 시작 축을 뒷받침할 서로 다른 증거 준비, 다른 취약점 프로필의 축별 의미 규칙, 실시간 전송과 반복 실행에서의 재현성 검증.

## 원본 근거

- [초기 실제 Agent 전이 실험](_archive/validation/VALIDATION_TRANSITION_EXPERIMENT.md).
- [리팩토링·프로필 신호·영수증·축별 인용 재검증](_archive/validation/VALIDATION_TRANSITION_REFACTOR.md).
- [과거 저장 상태의 프로필 보정 JSON](_archive/validation/PROFILE_EVIDENCE_CALIBRATION.json).
- 실행 원본 위치: `result/test-runs/validation-candidates/validation-transition-*`, `validation-proof-signal-full-agent-v3`, `validation-axis-evidence-v1`, `validation-admission-v2`, `validation-axis-grounding-real-v1`. 원본 문서에 각 번들의 Trace·Score·Pipeline DB가 연결돼 있다.
