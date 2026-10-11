# 실제 Validation Agent 판정 실험 (2026-09-26)

## 방법

공식 정답지 10건 중 로컬 GET 재생 준비가 된 7건을 새 격리 DB에 구축했다. Attack claim은 의도적으로 합성된 입력이고, Validation의 Eligibility·Blind·ClaimComparison은 실제 Codex Agent가 수행했다. 대상 및 대조군 GET은 로컬 Juice Shop과 VulnBank에 보냈다. Agent에게 정답 DB를 제공하지 않았고, 완료된 최종 결정은 별도의 `score_validation_lab.py`로 출처·대조군·인용 증거까지 채점했다.

주 실행 DB는 `result/test-runs/validation-candidates/validation-real-agent-20260926`, PrivacyRequests 재시도 DB는 `validation-real-agent-privacy-retry-20260926`, 별도 Impact 실행 DB는 `validation-real-agent-impact-fixed-20260926`이다. 세 DB의 SQLite 무결성 검사 결과는 `ok`다. [기계 판독 결과](REAL_AGENT_ACCURACY.json)에 후보별 상태를 보존했다.

## 관측 결과

| 실행 | 증거가 뒷받침된 정답 `PASS` | 미완료 | 정답 미도달 |
| --- | ---: | ---: | ---: |
| 주 실행, 준비된 7건 | 음성 5건 | PrivacyRequests 1건 | 양성 `/debug/users` 1건 `UNDERPOWERED` |
| PrivacyRequests 분리 재시도 및 실패 단계 재개 | 음성 1건 | 0건 | 0건 |
| `/debug/users` 별도 Impact Development 실행 | 양성 1건 `CONFIRMED` | 0건 | 0건 |

주 실행의 Blind 평가에서는 음성 6건을 모두 `reproduced=false`, 양성 1건을 `reproduced=true`로 분류했다. PrivacyRequests도 Blind 평가는 완료됐지만 같은 Codex 세션의 ClaimComparison이 장시간 응답하지 않았다. 새 DB 재시도에서도 이 호출이 120초 제한에 걸렸다. 실패 단계의 봉인된 Blind 평가를 **새 비교 세션으로 재개**하자 최종 `DISPROVEN`이 생성되고 독립 채점 `PASS`를 받았다. 따라서 정상 단일 실행의 완료율은 6/7이고, 재개 결과까지 합친 음성 후보의 증거 기반 정답은 6/6이다.

양성 `/debug/users`는 주 실행에서 재현됐고 `assertion_differential` 및 비어 있지 않은 값의 `json_value_differential` 영수증이 남았다. Agent의 원점수는 B/S/A `2/2/2`였으나 현재 `hunt-source-leak` 증거 규칙이 민감도를 0으로 제한해 적용 점수 `2/0/2`, 최종 `UNDERPOWERED`가 됐다. 주 실행에는 Impact Development 실행 계약이 없으므로 이 결과를 Agent의 취약점 미인식으로 해석할 수 없다.

별도 Impact 계약을 준 실행에서는 실제 Impact Agent가 가설을 `execute`로 선택했고 제한된 GET 1회가 추가 증거를 만들었다. 적용 점수 `1/2/2`, 최종 `CONFIRMED`였으며 전용 `score_validation_impact_lab.py`와 일반 `score_validation_lab.py`가 모두 `PASS`를 반환했다. 첫 Impact 실행은 `CONFIRMED`였지만 오래된 채점기가 사전조건 영수증을 배제하고 저장 영수증 해시도 불일치해 `UNRESOLVED`였다. 채점기의 영수증 결합 조건과 저장 전 정규화 해시를 수정한 뒤 **새 DB에서 재실행**해 `PASS`를 확인했다. 첫 실행 DB는 수정하지 않았다.

## 결론과 범위

이 실험은 로컬 공식 GET 음성 6건에 대한 실제 Agent의 Blind 분류와 최종 반증, 그리고 별도 Impact 계약이 있는 양성 1건의 확증 경로를 증명한다. **단일 설정에서 7/7 정확도를 입증한 실험은 아니다.** 주 실행의 양성은 추가 Impact 계약 없이는 `UNDERPOWERED`였고, PrivacyRequests는 ClaimComparison 세션 지연으로 재개가 필요했다. 나머지 공식 후보 3건은 인증 전제 조건이 없어 실행하지 않았다. 표본이 작고 후보별 반복 실행이 없어 일반적인 정확도나 신뢰구간을 추정할 수 없다.

후속 검증에서는 PrivacyRequests의 세션 재개 지연을 별도 재현하고, 프로필별 독립 B/S/A 라벨을 마련해야 한다. 현재 보고서의 축 점수는 Agent 출력과 봉인된 평가의 결합을 확인한 값이며, 축 자체의 독립 정답은 아니다.

강화된 Impact 채점기는 검증된 사전조건 영수증의 저장과 계획 인용을 필수로 확인한다. 이 영수증이 없던 과거 `validation-impact-provenance-v7` 번들을 새 기준으로 재채점하면 `UNRESOLVED`이며, 과거 실행에 새 증거가 있었다고 소급 판단하지 않는다.

이 실험 뒤 기본 실행기에 Impact 경로를 연결하고 Unblind 세션을 분리해 [단일 실행 재검증](SINGLE_RUN_ACCURACY.md)에서 준비된 7건 모두 독립 채점 `PASS`를 확인했다.
