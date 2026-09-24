# Recon application GET route 수집률 — Phase B·C·D

## 기준과 계산 방식

[고정 기준 목록](../main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)의 Juice Shop 20.2.0 application GET route 71개와 VulnBank `5e5ea5425fcf309373a0655dd111ecfb45037cbf`의 application GET route 47개를 사용했다. 해당 목록은 source/runtime route 선언에서 정적 파일, Swagger UI 지원 경로, Socket.IO transport, generic middleware 및 ffuf 후보를 제외한 것이다. 인증이 필요한 GET route도 분모에 포함한다.

기준 목록 파일 SHA-256: `6a42267059ac45cb049a53e8b157c190bc062eaeec49f0a8db402c7978757b86`.

각 **완료된** 실행의 `Recon.db`에서 `endpoints`의 GET method와 `path`·`normalized_path`를 읽었다. `is_excluded=1` endpoint와 순수 ffuf 후보는 제외했다. trailing slash를 정규화하고, 실제 경로의 한 segment를 기준 route의 `:parameter` 한 칸에 대응시켰다. 같은 기준 route가 여러 번 관측돼도 한 번만 센다. `DB endpoints` 총수는 평가 기준 밖 경로와 다른 method를 포함하므로 분자가 아니다.

`수집률 = 기준 목록과 일치한 고유 GET route 수 ÷ 기준 GET route 수 × 100`이며 소수점 첫째 자리로 표시했다. 대상별 여러 scan의 **단계 합집합**은 적중 route 집합을 먼저 합친 뒤 계산한다. 대상 전체 합계도 적중 수와 분모를 각각 더해 계산한다. 비율의 단순 평균이나 이전 단계까지의 누적값은 사용하지 않는다. 이 수치는 취약점 탐지율 또는 finding recall이 아니다.

## 실행별 결과

| Phase | 대상·실행 | scan ID | DB endpoints | 적중 / 기준 | 누락 | 수집률 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| B | Juice Shop 공개 루트 | `scan_ebd5060a8e7b43b1822c05ab3eb9855f` | 24 | 7 / 71 | 64 | 9.9% |
| B | VulnBank 공개 루트 | `scan_2624aff2c41441adb12084d6a4970980` | 68 | 11 / 47 | 36 | 23.4% |
| C | Juice Shop primary 인증 | `scan_0d60a30c055b4c6e97a2f5a3b5a06f3d` | 17 | 9 / 71 | 62 | 12.7% |
| C | VulnBank primary, `/` 시작 | `scan_5608dd73ba7e435b8250154c198e5459` | 61 | 5 / 47 | 42 | 10.6% |
| C | VulnBank primary, `/dashboard` 시작 | `scan_402f79eb92d140ea8a7eff2ebeecd697` | 5 | 5 / 47 | 42 | 10.6% |
| C | VulnBank secondary, `/dashboard` 시작 | `scan_6f5494a4ef464afa8c47f358af07e04b` | 5 | 5 / 47 | 42 | 10.6% |
| D | Juice Shop primary 인증 | `scan_b96c39ed94034315b911ed9f75287fd5` | 26 | 9 / 71 | 62 | 12.7% |
| D | VulnBank primary, `/dashboard` 시작 | `scan_489efa6c771844e3b0790e85006a4d08` | 5 | 5 / 47 | 42 | 10.6% |
| D | VulnBank 비로그인, `/` 시작 | `scan_843d0e9fd97548cbac8e66a016d5097f` | 67 | 11 / 47 | 36 | 23.4% |

## 단계별 대상 합집합

| Phase | 대상 | 포함한 실행 | 고유 적중 / 기준 | 누락 | 수집률 |
| --- | --- | --- | ---: | ---: | ---: |
| B | Juice Shop | 공개 루트 | 7 / 71 | 64 | 9.9% |
| B | VulnBank | 공개 루트 | 11 / 47 | 36 | 23.4% |
| **B 합계** | **두 대상** | 대상별 합집합 | **18 / 118** | **100** | **15.3%** |
| C | Juice Shop | primary 인증 | 9 / 71 | 62 | 12.7% |
| C | VulnBank | primary `/` + primary·secondary `/dashboard` | 10 / 47 | 37 | 21.3% |
| **C 합계** | **두 대상** | 대상별 합집합 | **19 / 118** | **99** | **16.1%** |
| D | Juice Shop | primary 인증 | 9 / 71 | 62 | 12.7% |
| D | VulnBank | primary `/dashboard` + 비로그인 `/` | 16 / 47 | 31 | 34.0% |
| **D 합계** | **두 대상** | 대상별 합집합 | **25 / 118** | **93** | **21.2%** |

Phase D의 Juice Shop은 Phase B 공개 실행보다 `GET /rest/basket/:id`와 `GET /rest/user/whoami`를 더 수집했다. 이 실행에서 basket은 실제 경로 `/rest/basket/8`로 관측됐다. VulnBank Phase D의 공개 실행은 Phase B와 동일한 11개를 수집했고, 인증 dashboard 실행에서 서로 다른 5개를 추가해 합집합 16개가 됐다. Phase C VulnBank primary `/` 실행의 5개와 dashboard 실행의 5개도 서로 겹치지 않으며, secondary dashboard의 적중 집합은 primary dashboard와 동일하다.

### 단계별 고유 적중 경로

Phase B의 대상별 7개·11개 목록은 [기준 문서](../main-branch/phase_b/PHASE_B_ENDPOINT_BASELINE.md)의 `수집` 절에 있다. 다음은 인증과 단계 합집합에서 추가로 확인된 경로다.

- C·D Juice Shop primary의 적중 집합은 B의 7개에 `GET /rest/basket/:id`, `GET /rest/user/whoami`를 더한 9개다.
- C VulnBank primary `/`의 적중 5개는 `GET /`, `GET /compliance`, `GET /login`, `GET /merchant/login`, `GET /merchant/register`다.
- C VulnBank primary·secondary `/dashboard`와 D VulnBank primary `/dashboard`의 적중 집합은 모두 `GET /dashboard`, `GET /api/bill-categories`, `GET /api/bill-payments/history`, `GET /api/virtual-cards`, `GET /transactions/:account_number`다.
- D VulnBank 비로그인 `/`의 적중 집합은 B VulnBank의 11개와 동일하다. 각 행의 누락 route는 고정 기준 목록에서 해당 적중 집합을 뺀 결과다.

VulnBank의 실제 관측 경로 `GET /transactions/0778427681`은 기준 목록의 `GET /transactions/:account_number`에 대응한다. DB의 `normalized_path`는 `GET /transactions/:id`이므로 parameter 이름 문자열의 동일성만 요구하지 않고 실제 경로를 기준 template과 비교했다.

## 원본과 해석 범위

| Phase | 원본 `Recon.db` 경로 |
| --- | --- |
| B | `result/test-runs/09.23/phase-b/{juice-shop-final2,vuln-bank-final2}/Recon.db` |
| C | `result/test-runs/09.23/phase-c/{juice-shop-primary,vuln-bank-primary,vuln-bank-primary-dashboard,vuln-bank-secondary-dashboard}/Recon.db` |
| D | `result/test-runs/09.23/phase-d/Runs/lab-aidast-invalid/{juice-shop,vuln-bank}/<scan_id>/Recon.db` — 위 실행별 표의 scan ID 사용 |

Phase B의 실패·중단 scan과 프록시 시작 실패 scan은 집계에서 제외했다. Phase C·D의 인증 세션과 공개 실행은 실행별 표에서 분리했다. 이 전체 route 분모는 인증·권한·실제 parameter 값에 따른 접근 가능성을 따로 제한하지 않으므로, 각 실행의 `ELIGIBLE` route recall로 해석하지 않는다. 특히 C·D의 한 scan에서 낮은 비율이 나와도 그 scan이 시작하지 않은 다른 영역의 실패 판정은 아니다.

이후 결과 세트에는 [Recon 수집률 기록 형식](../RECON_COVERAGE_TEMPLATE.md)을 복사해 같은 기준, 실행별 표, 단계별 대상 합집합, 원본 경로와 예외를 기록한다. 기준 버전이나 포함 route가 바뀌면 기준 목록을 새로 고정하고 기존 수치와 직접 비교하지 않는다.
