# 웹 대시보드 반복 실행 결과 검증

`scripts/observe_dashboard_runs.py`는 웹 대시보드에서 이미 시작한 스캔 ID를
관찰하고 JSON/Markdown 증거를 저장한다. 스캔 실행·재개·중단 API를 호출하지
않는다. 이 문서의 검증 스크립트는 대상 서버에 요청을 보내지 않는다.

검증은 10~20개의 서로 다른 스캔이 모두 아래 기준을 충족해야 성공한다.

- 최종 상태 `completed`, Scope/Recon/Attack/Chaining/Validation/Report 단계가
  `completed` 또는 `skipped`이고 실패하거나 실행 중인 단계가 없음.
- 대시보드 로그/감사 이벤트에 오류가 없으며 관찰 중 API 오류가 없음.
- 해당 스캔의 요약 보고서 또는 내용을 읽을 수 있는 finding 보고서가 존재함.
- 원래 선택한 모델이 `result/.webui/scan-models/<scan_id>.json`에 저장되어 있음.
  `--expected-models`를 지정하면 저장된 6개 선택값도 정확히 비교함.

## 대시보드에서 준비할 항목

1. 승인된 로컬 실습 프로그램과 대상을 대시보드에서 선택하고, 원래 승인된
   설정 및 모델 선택으로 실행한다. 각 실행의 상세 화면에서 스캔 ID를 확인한다.
   이 관찰 스크립트가 실행한 것처럼 기록하지 않는다.
2. ID를 `result/dashboard-scan-ids.txt`에 한 줄씩 기록한다. 이미 실행 중인
   스캔과 완료한 스캔을 함께 관찰할 수 있다. 중복 ID는 허용하지 않는다.
3. 실행 중 오류 메시지, 수동 로그인 대기, 실패한 단계가 있으면 원인을
   해결한다. 과거 실행의 오류 기록은 이 스크립트가 지우지 않으며 그 실행을
   성공으로 처리하지 않는다. 실제로 수정한 뒤 새로 실행한 결과를 검증한다.

관찰 도구는 대시보드의 조회 API만 호출한다.

```bash
uv run python scripts/observe_dashboard_runs.py \
  --base-url http://127.0.0.1:8000 \
  --scan-ids result/dashboard-scan-ids.txt \
  --output result/dashboard-observation
```

모델 선택을 비교하려면 다음 형식의 JSON 파일을 `--expected-models`에 넘긴다.
실제 실행 때 선택한 ID를 기입한다. Chaining은 현재 대시보드의 Attack 모델
선택에 대응하고, Main은 Recon 선택에 대응한다.

```json
{
  "main_model": "selected-recon-model",
  "recon_model": "selected-recon-model",
  "attack_model": "selected-attack-model",
  "chaining_model": "selected-attack-model",
  "validation_model": "selected-validation-model",
  "report_model": "selected-report-model"
}
```

## 결과 확인

출력 디렉터리의 `dashboard-observation.md`에서 스캔별 상태, 오류 개수,
보고서 존재 여부, 실패 기준을 확인한다. 상세 값과 저장된 모델은
`dashboard-observation.json`에 있다. 종료 코드는 성공 `0`, 기준 미충족 `1`,
설정/연결 준비 오류 `2`이다. 10개 미만이면 개별 결과가 좋아도 전체 성공으로
처리하지 않는다. `PASS`는 관찰한 배치의 명시된 기준 충족을 의미한다.

기본값은 5초 간격, 최대 4시간, 최종 상태 확인 후 5초의 산출물 생성 여유다.
필요하면 `--timeout`, `--poll-seconds`, `--settle-seconds`를 조정한다.
서버가 다른 result root를 사용하면 `--result-root`도 동일하게 설정한다.

로그 API는 최근 500개로 제한된다. 제한에 걸린 실행은 기존
`result/.webui/events.db`의 정제된 전체 로그를 읽기 전용으로 확인한다.
관찰한 snapshot cursor까지 포함되어야 로그 완전성을 인정한다. 해당 파일이
없거나 다른 result root를 지정하면 검증에 실패하므로 서버와 동일한 경로를
지정한다. 원본 오류 메시지, 요청 본문, 인증정보 및 보고서 본문은 증거 파일에
저장하지 않는다.

finding이 없어도 실행 요약 보고서는 정상 보고서 산출물이다.
