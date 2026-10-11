# 프로젝트 Python 환경의 mitmproxy 실행

2026-09-29 Juice Shop 스캔 `scan_aab835ec187b4100bccd1a4a79f8bb35`에서
HTTP probe는 200으로 성공했으나 엔드포인트 수집은
`required policy proxy did not become ready`로 실패했다.
시스템의 `/opt/homebrew/bin/mitmdump`로 addon 시작을 별도 재현하면
`request_governor.py`의 `import sqlite3`에서 `ModuleNotFoundError`가 발생했다.
독립 실행 바이너리의 Python 환경에 sqlite3가 없었던 것이 원인이다.

## 변경

- `pyproject.toml`에 `mitmproxy>=12.2.3,<13`을 필수 의존성으로 추가하고
  `uv.lock`을 갱신했다. 기존 프로젝트 환경에 설치된 버전은 12.2.3이다.
- 프록시는 AI DAST의 `sys.executable`로 mitmproxy의 Python 진입점을 실행한다.
  시스템 PATH의 별도 바이너리를 사용하지 않는다.
- 현재 Python 환경에 패키지가 없으면 설치/갱신 방법을 알리고 기존 필수
  프록시 시작 실패 동작을 유지한다.
- 새 가상환경의 첫 로드에서 기존 8초 준비 제한을 넘는 실패도 재현했다.
  최대 준비 시간을 30초로 늘렸고 프로세스 조기 종료 감지는 유지했다.
- README와 운영 문서에 신규 설치 및 기존 editable tool 갱신 방법을 기록했다.

## 검증

| 항목 | 결과 |
|---|---|
| 회귀 테스트 | `tests/test_mitm_proxy.py`, `tests/test_request_broker.py`, `tests/test_request_governor.py`, `tests/test_recon_workflow.py`: 92 passed, 13 subtests passed |
| 잠금 파일 | `uv lock --check --offline` 통과 |
| 새 사용자 설치 | 깨끗한 Git 사본에 이번 변경을 적용하고 새 가상환경에서 `uv sync --locked --no-dev` 통과 |
| 실제 프록시 | 프로젝트 환경 및 새 환경에서 준비 완료 |
| 로컬 Juice Shop GET | 200 응답 수집 및 식별 헤더 적용 확인 |
| 허용하지 않은 POST | 실제 프록시에서 403 차단 |
| 종료 처리 | 프록시 종료 및 임시 Scope 파일 제거 확인 |
| 대시보드 환경 | 실행 중 서버가 프로젝트 `.venv/bin/aidast`를 사용하는 것 확인 |

대상 요청 검증은 macOS에서 로컬 `http://127.0.0.1:3001/`로 수행했다.
Windows/Linux에서 실행하지 않았으며 대시보드에서 전체 스캔을 새로 시작하거나
외부 모델을 호출하지 않았다. 관련 스캔 DB와 기존 실패 로그는 수정하지 않았다.

재현 및 검증 산출물은 로컬
`result/test-runs/09.29/mitmproxy-project-runtime/`에 있다.

## 변경을 받은 사용자

저장소에서 `uv sync --locked`를 실행한다. `uv tool install --editable .`로
설치했던 사용자는 `uv tool install --force --editable .`도 실행한 뒤 대시보드를
재시작한다. 새 설치에서는 기존 README 설치 명령이 mitmproxy까지 설치한다.
