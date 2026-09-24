# Validation 부정 증거·Developing 후속 실행 (2026-09-24)

## 변경

- 공통 `DecisionEngine`은 3회 또는 5회의 target이 모두 `not_observed`이고 명시적 부정 증거가 완전할 때만 `DISPROVEN`을 선택한다. 장애 원인이 있더라도 해당 요청의 부정 결과가 별도 근거로 확정되면 이를 우선하며, 근거가 없거나 일부 target이 `blocked`·`error`이면 `INCONCLUSIVE`로 남긴다. 코디네이터와 실습 채점기도 모든 target의 증거를 확인한다.
- Native Development는 프로필의 허용 액션과 같은 종류·장애 축의 실행 계약이 있을 때만 진입한다. 계약이 없으면 조치 기록을 만들지 않고 `INCONCLUSIVE`로 남기며 `development_unavailable_reason`을 판정에 기록한다.
- 실습 전용 `scripts/validation_lab_negative_proof.py`는 정답지를 읽지 않는다. 후보 인벤토리의 출처 SHA-256, 고정 소스의 정확한 라우트·가드 줄, 로컬 컨테이너 이미지·소스 신원, 스테이징된 런타임 계약, 동일한 음성 대조군 본문 해시와 새 target 응답을 확인해 해당 요청에만 `explicit_non_exploit`을 표시한다. 일반 `aidast validate run`의 기본 HTTP 어댑터는 이 실습 전용 근거를 사용하지 않는다.

## 새 격리 번들 실행

입력은 `result/test-runs/validation-candidates/validation-lab-proof-v3/`에 새로 준비했다. 기존 첫 실행 DB와 별도 정답지는 수정하지 않았다. 승인된 로컬 GET Scope에서 7건을 실행했고, 최신 판정 단계마다 한 사례당 양성·음성 대조군 각 1회와 target 3회를 기록했다. 증거 형식과 판정 우선순위 수정 후에는 일부 사례를 같은 DB의 새 단계로 재실행했다.

| 사례 | 양성·음성 대조군 | target 3회 | 판정 | 채점 |
| --- | --- | --- | --- | --- |
| Juice Shop 무인증 노출 가설 4건 | 각 401·401 | 각 401 × 3 | `DISPROVEN` 4 | `PASS` 4 |
| VulnBank 정수 라우트 SQLi 가설: billers | 200·404 | 404 × 3 | `DISPROVEN` | `PASS` |
| VulnBank 정수 라우트 SQLi 가설: virtual cards | 401·404 | 404 × 3 | `DISPROVEN` | `PASS` |
| VulnBank `/debug/users` 노출 | 200·404 | 200 × 3 | `CONFIRMED` | `PASS` |

최신 단계에서 여섯 부정 사례의 target 18회 모두 `signal_observed=false`, `explicit_non_exploit=true`이며, 출처 정보와 동일 단계 음성 대조군의 응답 해시가 결합돼 있다. 양성 `/debug/users` target 3회는 `signal_observed=true`, `explicit_non_exploit=false`다. 최신 단계의 Development 동작은 0건이고, DB 무결성 검사는 `ok`다. 채점 요약은 **`PASS` 7, `NEEDS_PREREQUISITES` 3**이다. 두 merchant 신원이 필요한 3건은 여전히 실행하지 않았다.

VulnBank billers 사례는 재실행 중 평가 모델이 `encoding_transport` 또는 `environment_topology` 장애 축을 제시했지만, 고정된 Flask 정수 라우트와 동일 단계 대조군·target의 일치가 별도로 확인됐다. 판정 엔진은 이 완전한 부정 증거를 우선하고, 증거가 빠진 장애 사례는 계속 `INCONCLUSIVE`로 둔다. 채점기는 음성·양성 대조군, target의 실제 outcome, 인용된 증거와 출처 메타데이터를 다시 확인했다.

이 결과는 정확히 스테이징한 무인증 GET과 문자열 경로 페이로드에 한정된다. 같은 엔드포인트의 다른 요청·인증 상태·취약점 일반을 배제하지 않는다. 부정 증거 어댑터가 없는 기본 Validation에서 `DISPROVEN`이 자동으로 나오도록 바꾼 결과도 아니다.

기본 `aidast validate run`의 Development 분류도 별도 `validation-lab-classification-v2` DB에서 VulnBank 두 건을 다시 확인했다. 둘 다 `INCONCLUSIVE`, Development 동작 0건이었다. billers 사례에서 모델이 `encoding_transport`를 지정했지만 조치 계약이 없어서 `development_unavailable_reason=development_contract_missing`이 기록됐다. virtual cards 사례는 모델이 blocker를 지정하지 않았다. 이는 기본 경로가 근거 없이 `DISPROVEN`을 생성하지 않으면서 계약 없는 Developing 시도도 하지 않음을 보여 준다.

## 재현 및 검증

```bash
.venv/bin/python scripts/prepare_validation_lab.py --output result/test-runs/validation-candidates/validation-lab-proof-v3
.venv/bin/python scripts/run_validation_lab.py result/test-runs/validation-candidates/validation-lab-proof-v3
.venv/bin/python scripts/score_validation_lab.py \
  --mapping result/test-runs/validation-candidates/validation-lab-proof-v3/CandidateFindingMap.json \
  --pipeline result/test-runs/validation-candidates/validation-lab-proof-v3/Pipeline.db \
  --output result/test-runs/validation-candidates/validation-lab-proof-v3/ValidationScore.json
```

`prepare_validation_lab.py`는 같은 출력 폴더를 덮어쓰지 않으므로 재실행할 때 새 이름을 지정한다. 실측 상태와 상세 시도는 격리 DB, 채점은 `ValidationScore.json`에 남았다.

최종 확인: `git diff --check`와 Python 컴파일 검사는 통과했고, 전체 Validation 테스트는 로컬 루프백 접근 환경에서 **434 passed, 4 skipped, 395 subtests passed**였다.
