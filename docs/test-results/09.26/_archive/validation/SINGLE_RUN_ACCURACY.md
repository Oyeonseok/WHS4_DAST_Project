# 실제 Validation Agent 단일 실행 실험 (2026-09-26)

## 실행

공식 정답지의 `GET_REPLAY_READY` 후보 7건을 새 `validation-single-run-20260926` DB에 준비했다. 준비 단계에서 로컬 Juice Shop·VulnBank의 응답 해시와 고정 소스 마커를 확인하고, `/debug/users`의 제한된 GET Impact 계약을 포함했다. Attack claim은 의도적인 합성 실험 입력이며 정답지는 Agent 입력이나 Pipeline.db에 넣지 않았다.

```bash
PYTHONPATH=. .venv/bin/python scripts/prepare_validation_lab.py \
  --impact-probe \
  --output result/test-runs/validation-candidates/validation-single-run-20260926
PYTHONPATH=. .venv/bin/python scripts/run_validation_lab.py \
  result/test-runs/validation-candidates/validation-single-run-20260926
```

두 번째 명령 **한 번**으로 준비된 7건을 순차 실행했다. 각 사례는 실제 Eligibility·Blind·ClaimComparison Agent를 사용했고, 양성은 실제 Impact Agent가 사전조건을 판단한 뒤 허용된 GET만 실행했다. 음성 재생에는 출처가 고정된 대조군 증거 포트를 유지했다. 변경된 비교기는 봉인된 Blind 평가를 명시적 입력으로 전달하면서 Unblind를 새 Codex 세션에서 수행한다.

## 결과

| 항목 | 관측 |
| --- | ---: |
| 단일 DB의 완료된 Validation 단계 | 7/7 |
| 음성 최종 판정 `DISPROVEN` | 6/6 |
| 양성 최종 판정 `CONFIRMED` | 1/1 |
| 별도 정답지와 결정 증거를 확인한 일반 채점 `PASS` | 7/7 |
| 양성의 Impact 전용 증거 채점 | `PASS` |
| 재생 시도 | 36회: 기본 35회, Impact GET 1회 |
| 프로필 감사 기록 및 봉인된 평가 결합 | 7/7 |
| Impact 가설 | 성공 1건 |
| 사전조건 영수증 저장 해시 | 일치 |
| SQLite 무결성 | `ok` |

PrivacyRequests는 이전 실험과 달리 별도 재개 없이 같은 실행에서 `DISPROVEN`으로 완료됐다. 양성은 Development 이후 적용 B/S/A 점수 `2/2/2`로 `CONFIRMED`가 됐다. 일반 채점의 나머지 공식 3건은 `NEEDS_PREREQUISITES`다. 후보별 결과는 [기계 판독 결과](SINGLE_RUN_ACCURACY.json)에 있다.

## 해석 범위

이 실행은 **준비된 로컬 GET 7건이 하나의 설정과 실행 명령에서 증거 기반 정답 판정으로 끝날 수 있음**을 보여준다. 인증 전제 조건이 필요한 공식 후보 3건은 아직 실행하지 않았다. 한 번의 성공으로 ClaimComparison 지연이 모든 실행에서 사라졌다고 단정할 수 없고, 프로필별 독립 B/S/A 축 정답도 없어 축 점수 자체의 정확도를 별도로 추정할 수 없다. 이 결과는 로컬 고정 버전과 합성 Attack claim에 한정된다.
