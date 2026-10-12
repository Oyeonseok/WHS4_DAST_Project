# VulnBank 웹 대시보드 운영 가이드

이 문서는 로컬 VulnBank(`http://127.0.0.1:5002/`)를 웹 대시보드에서 정찰부터 보고서까지 실행하고 반복 검증하는 절차를 정리합니다.

현재 10~20회 반복 실행이 모두 통과했다고 가정하지 않습니다. 아래의 반복 검증 조건을 다 충족한 후에만 운영 검증 완료로 판정합니다.

## 실행 전 확인

1. 대시보드 `http://127.0.0.1:8000/`와 VulnBank `http://127.0.0.1:5002/`에 접속합니다.
2. **Scopes / Programs**에서 VulnBank의 실행 대상이 `http://127.0.0.1:5002/`로 승인되어 있는지 확인합니다.
## 새 스캔 설정

대시보드에서 **New scan**을 열고 다음 값을 사용합니다. 반복 검증 중에는 이 값과 VulnBank 버전을 바꾸지 않습니다.

| 화면 필드 | 설정값 |
| --- | --- |
| Verified Scope | 승인된 로컬 VulnBank Scope |
| Recon model | `gpt-5.6-sol` |
| Attack model | `gpt-6-sol` (공격 가설 계획과 Chaining에도 적용됨) |
| Validation model | `gpt-6-sol` |
| Report model | `gpt-5.6-sol` |
| Targets | `http://127.0.0.1:5002/` 하나만 선택 |
| Execution profile | `Focused discovery` |
| 공유 스캔 요청 예산 | `2000` |
| Requests per second | `1.0` |
| Concurrency | `2` |
| Timeout seconds | `20` |
| Maximum depth | `3` |
| 추가 경로 탐색 **전체** 시간 | `150` 초 |
| Tag batch size | `25` |
| Login behavior | 기본 반복 검증은 `No login prompt` |

`150`초는 루트별 제한이 아니라 모든 ffuf 루트가 함께 소비하는 전체 제한입니다. 요청 속도와 예산은 Recon·Attack·Validation에 공통으로 적용되므로 Scope에 표시된 상한을 넘지 말아야 합니다.

`scan_7399cae6593b4c6484739cdac1295550`과 같은 모델 분할은 Recon·Report에 `gpt-5.6-sol`, Attack·Chaining·Validation에 `gpt-6-sol`을 사용합니다. Attack 모델이 일시적으로 capacity에 도달하면 남은 배치만 닫고 이미 선택된 다른 모델인 `gpt-5.6-sol`로 전환합니다. 완료된 finding과 요청 증거는 유지됩니다.

로컬 VulnBank Scope는 Attack 시작 전에 승인된 등록·로그인 API만 사용해 일회용 사용자 A/B, 합성 사용자, 합성 상인 세션과 소유 객체를 자동 준비합니다. 토큰은 프로세스 메모리의 불투명 참조로만 전달되며 DB와 보고서에는 저장되지 않습니다. 따라서 다중 사용자 IDOR와 인증 우회 검증을 위해 사용자가 두 계정을 번갈아 로그인할 필요가 없습니다.

보호된 화면을 포함한 별도 인증 실행은 **Login behavior**를 `Open runtime browser`로 선택합니다. 반복 결과를 비교할 때는 비로그인 실행과 인증 실행을 같은 집합으로 계산하지 않습니다.

정책이 요구하는 헤더·사용자명·확인 항목이 나오면 승인된 정책에 맞는 값을 입력합니다. **선택한 대상의 테스트 권한…** 확인을 체크한 뒤 **Start scan**을 누릅니다.

## 진행 상태와 HITL

**Scans**에서 현재 scan ID를 선택하고 **도구 작업·발견 URL 보기** 또는 **진행 창 열기**로 다음 순서를 확인합니다.

```text
Recon → Attack → Chaining → Validation → Report
```

AI가 로그인, MFA, CAPTCHA 또는 접근 확인처럼 사람의 UI 조작이 필요하다고 판별하면 대시보드에 **사용자 조치 대기** 안내가 나옵니다.

1. 이미 열린 Chromium 창에서 필요한 로그인·MFA·CAPTCHA·접근 절차를 사용자가 직접 마칩니다.
2. VulnBank 대상 화면으로 돌아옵니다.
3. 로그인 요청이면 **로그인 완료**, 정찰 중 조치이면 **조치 완료 · 같은 세션으로 계속**을 누릅니다.
4. 안내가 남으면 화면에 표시된 사유를 확인하고 조치한 뒤 다시 완료를 누릅니다.

확인 대기 시간은 5분입니다. `No login prompt`로 시작한 headless 실행은 중간에 사용자 조치용 화면 브라우저로 바꾸지 않습니다. `runtime_browser_required`가 표시되면 `Open runtime browser`로 새 스캔을 시작합니다.

## 종료 결과 확인

스캔이 `completed`가 되면 **Scans**에서 Scope, Recon, Attack, Chaining, Validation,
Report 단계가 모두 완료됐는지 확인합니다. 발견 URL과 공격 작업에는 실제 관측 및 실행
증거가 표시되어야 합니다. **Validation**에서 각 후보의 최종 상태와 증거를 확인하고,
**Reports**에서 실행 요약과 확정 finding 보고서를 확인합니다.

`failed` 또는 `cancelled` 결과는 정상 완료로 계산하지 않습니다. 오류가 있으면 활동 로그의
첫 실패 단계와 진단 로그를 확인하고 아래 재개 절차를 따릅니다.

## 실패 시 재개와 보고서 재생성

- Recon에서 실패하면 **정찰부터 다시 스캔**으로 새 scan ID를 만듭니다. 부분 Recon DB를 성공 결과로 취급하지 않습니다.
- Attack, Chaining, Validation에서 일시적 실행 오류가 발생하면 **실패 단계부터 재실행**을 누릅니다. 완료된 Recon과 저장된 모델 선택을 그대로 사용하고 처음 완료되지 않은 후속 단계부터 계속합니다.
- 일시적 model capacity 또는 다중 작업의 모델 정책 거절은 현재 배치에서 격리되어야 하며 전체 파이프라인을 실패시키지 않아야 합니다. 예전 코드로 시작한 프로세스가 이 사유로 종료됐다면 업데이트된 코드에서 **실패 단계부터 재실행**을 눌러 완료된 Recon과 finding을 유지한 채 계속합니다.
- Report에서 실패하면 **보고서만 다시 생성**을 누릅니다. 이 작업은 Recon, Attack, Chaining, Validation을 반복하지 않고 타깃에 새 요청을 보내지 않은 채 현재 검증 결과에서 보고서만 다시 생성합니다.
- `cancelled`는 재개 대상이 아닙니다. 필요하면 새 scan ID로 다시 시작합니다.

재개한 결과도 Report 단계와 **Reports → 스캔 실행 보고서**까지 확인해야 합니다. 확정 취약점이 0개여도 실행 요약은 생성되어야 합니다.

## 10~20회 반복 검증

각 회차는 완료된 스캔에서 **정찰부터 다시 스캔**을 눌러 새 scan ID로 시작합니다. 각 실행은 새 scan ID와 독립된 실행 증거를 가져야 합니다.

각 scan ID별로 다음을 기록합니다.

| 확인 항목 | 통과 조건 |
| --- | --- |
| 종료 상태 | `completed` |
| 단계 | Scope → Recon → Attack → Chaining → Validation → Report가 모두 `completed` |
| 검증 | Validation case가 하나 이상이고 전부 처리 완료되며 `CONFIRMED`가 하나 이상 존재 |
| 보고서 | 모든 `CONFIRMED` case에 한국어·영어 보고서가 각각 존재하고 제목에 마스킹 토큰 오염이 없음 |
| 오류 | 미처리 종료 오류 0개 |
| 조치 | HITL이 있었다면 유형과 완료 여부를 기록 |

10~20회 모두에서 개별 통과 조건을 충족해야 합니다. 평균 재현율이 90%를 넘는 것으로 90% 미만 회차를 상쇄하지 않습니다. 재개로 획득한 정상 결과는 기록하되, 최초 실패도 숨기지 않고 별도로 남깁니다.

## 정찰 결과가 부족할 때

1. 스캔 대상, 포트, 배포 버전이 승인 Scope와 같은지 확인합니다.
2. 실행 설정과 로그인 방식이 운영 가이드와 같은지 확인합니다.
3. 발견 URL과 도구 활동에서 브라우저 관측, JavaScript 분석, API 문서 탐색 중 어느 단계가 부족한지 확인합니다.
4. `404`는 유효 경로 확인이 아니고, `200`도 기능 동작이나 취약점을 확정한 것이 아닙니다.
5. 원인을 일반화된 정찰 로직, 우선 경로, 세션 유지 문제로 수정한 뒤 새 스캔으로 다시 검증합니다.
