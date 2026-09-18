# Phase B — Recon-only shakedown

## 판정

**PASS — attempt 3 채택**

두 대상의 최종 anonymous Recon scan과 Recon stage가 모두 `completed`였고,
deferred tagging 실패는 0건이었다.

## Attempt 이력

| Attempt | Juice Shop | VulnBank | 처리 |
| --- | --- | --- | --- |
| 1 | `scan_d2724ce7a2c144748e902693cf30e9b8`, failed | `scan_40288876d2474f84beabacbba9631b6d`, failed | Playwright Chromium v1234 부재를 확인했다. |
| 2 | `scan_9f81d8cbb77f4e8d8f722b53668de21b`, interrupted | `scan_20591221f6c7407e9509885383bbc177`, interrupted | non-TTY 선택적 로그인 대기 중 상태 확인을 위해 operator interrupt했다. 결과로 채택하지 않았다. |
| 3 | `scan_8e172b07dc584c02ba771652d9b50c6e`, completed | `scan_57fdcbce22974b5ea9e8e96468c25942`, completed | TTY에서 로그인 입력 없이 anonymous session으로 진행한 최종 결과다. |

앞선 attempt의 DB와 로그는 덮어쓰지 않았다.

## 최종 결과

| 항목 | Juice Shop | VulnBank |
| --- | ---: | ---: |
| Recon 시간 | 1,234.0초 | 2,360.8초 |
| endpoints | 23 | 166 |
| endpoint observations | 168 | 328 |
| endpoint annotations | 205 | 436 |
| HTTP transactions | 355 | 476 |
| tagging 처리 | 168 | 328 |
| tagging 실패 | 0 | 0 |

Juice Shop의 첫 ffuf root는 180초 timeout 경고가 있었지만 이후 root와 Recon
stage는 완료됐다. VulnBank의 `/static/openapi.json`은 발견됐으나 대상 fixture의
`requestBody.schema.required` 형식 오류 때문에 ZAP OpenAPI import가 실패했다.
이 오류도 보조 도구 경고로 격리됐고 Recon stage는 완료됐다.

최종 산출물:

- `result/test-runs/current-branch-f54af46/phase-b/attempt-3/juice-shop/`
- `result/test-runs/current-branch-f54af46/phase-b/attempt-3/vuln-bank/`
- `result/logs/scan_8e172b07dc584c02ba771652d9b50c6e/recon.jsonl`
- `result/logs/scan_57fdcbce22974b5ea9e8e96468c25942/recon.jsonl`
