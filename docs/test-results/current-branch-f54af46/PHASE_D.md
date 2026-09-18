# Phase D — 통합 pipeline shakedown

## 판정

**PASS — 실행 경로 기준**

두 대상 모두 Recon → Attack → Chaining → Validation 네 stage가 `completed`로
종결됐다. Validation decision 품질과 Report 가능 여부는 Phase E에서 별도로
판정한다.

## Stage 결과

| 대상 | Scan ID | Recon | Attack | Chaining | Validation |
| --- | --- | ---: | ---: | ---: | ---: |
| Juice Shop | `scan_64307e53306d4868af8a961a83ed2f82` | completed, 986.6초 | completed, 745.7초 | completed, 168.0초 | completed, 0.0초 |
| VulnBank | `scan_f994442262fa4511ad9cf8b716e1159b` | completed, 2,334.9초 | completed, 569.7초 | completed, 261.2초 | completed, 0.0초 |

## Recon

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| endpoints | 25 | 166 |
| observations | 184 | 327 |
| annotations | 185 | 350 |
| HTTP transactions | 387 | 476 |

Handoff의 Recon.db SHA-256과 최종 파일 hash는 일치했다.

- Juice Shop: `0254be190f3bb75882a98757cee59e9c03b16d3fc4a3ec2341c734626a775a3b`
- VulnBank: `0bf911ccc3ba7683702a758592a64c8495560260d527c777906497e8a034cece`

## Attack, Chaining, Validation

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| Attack task completed / skipped | 4 / 4 | 6 / 4 |
| attempts | 7 | 7 |
| confirmed attack attempts | 1 | 2 |
| findings | 1 | 2 |
| reproduction specs | 1 | 2 |
| finding chains | 0 | 0 |
| Validation cases | 1 | 2 |
| Validation decision | INCONCLUSIVE 1 | INCONCLUSIVE 2 |

모든 `attack_http_requests`는 terminal 상태였다. Juice Shop은 completed 7건,
VulnBank는 completed 7건과 failed 1건이었다. VulnBank failed request는
`GET /static/openapi.json` 응답 200을 받은 뒤 `RequestGuardError`로 terminal
처리됐다. `reserved`, `running`, `outcome_unknown` request는 남지 않았다.

Validation은 candidate preflight에서 끝나 실제 validation attempt/evidence/request가
생성되지 않았다. 사유는 다음과 같다.

- Juice Shop SQL injection: `http_runtime_contract_missing`
- VulnBank OpenAPI exposure: `http_runtime_contract_missing`
- VulnBank authentication bypass: `candidate_integrity`

산출물:

- `result/test-runs/current-branch-f54af46/phase-d/Runs/scan_64307e53306d4868af8a961a83ed2f82/`
- `result/test-runs/current-branch-f54af46/phase-d/AttackRuns/scan_64307e53306d4868af8a961a83ed2f82/Pipeline.db`
- `result/test-runs/current-branch-f54af46/phase-d/Runs/scan_f994442262fa4511ad9cf8b716e1159b/`
- `result/test-runs/current-branch-f54af46/phase-d/AttackRuns/scan_f994442262fa4511ad9cf8b716e1159b/Pipeline.db`
