# Neon 로컬 Scope 대시보드 즉시 적용 확인

2026-09-29 실행 중인 대시보드 서버는 정책 변경 전 코드로 시작되어 있었다. 실제 `/api/v1/scopes` 응답에는 기존 로컬 기본 Scope만 있었고, 새 Neon 실험 Scope 두 개는 없었다. 최신 코드로 직접 읽은 카탈로그에서는 두 실험 Scope 모두 `ready`였다.

활성 스캔이 없음을 확인하고 WebUI를 다시 빌드한 뒤, 같은 `127.0.0.1:8000` 주소에서 대시보드를 정상 재시작했다. 승인 산출물과 기존 스캔을 수정하지 않았다.

- WebUI 빌드 성공. 로컬 Node 20.16에 대한 Vite 버전 경고는 있었으며 빌드 종료 코드는 0이었다.
- `tests/test_local_neon_policy_lab.py`: 11 passed.
- 실행 중인 서버 API: Juice Shop·VulnBank 실험 Scope 모두 `ready`, 요청 상한 10/초, 필수 헤더 `X-Bug-Bounty`.
- 실제 Chromium 화면: 각 실험 Scope와 대상을 선택하면 정책이 표시되고 권한 확인 체크박스가 활성화된다. 실행 요구 사항 재해석 POST 요청은 0회였다.
- 스캔 시작 버튼은 누르지 않았다. 이번 검증은 정책 준비 및 표시 경로를 확인한다.

증거는 `result/test-runs/09.29/neon-common-policy/dashboard-ready.json`, `dashboard-browser-ready.json`, `dashboard-juice_shop-ready.png`, `dashboard-vuln_bank-ready.png`에 저장했다. 재현 스크립트는 같은 폴더의 `verify_dashboard_ready.py`다.
