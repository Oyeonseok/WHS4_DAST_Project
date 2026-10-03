# 08. 대시보드와 CLI의 관계

**질문:** WebUI에서 스캔을 시작하고 진행 상황을 보는 경로는 CLI와 어떻게 이어지는가?

대시보드의 launch 서비스는 승인된 Scope와 준비 상태를 확인하고, 선택한 대상과 실행 옵션을 인자로 만들어 별도 프로세스에서 `python -m aidast run`을 호출한다. 따라서 WebUI가 별도의 Recon·Attack 파이프라인을 구현하는 구조가 아니다. [launch 서비스](../../src/aidast/web/launch.py), [CLI](../../src/aidast/cli.py)

상태 조회는 저장된 스캔 데이터를 투영한다. projection 코드는 스캔 ID가 들어 있는 DB를 찾을 때 `AttackRuns`의 `Pipeline.db`를 먼저 살피고, 아직 통합 DB가 없으면 `Runs`의 `Recon.db` 등도 살핀다. 선택된 DB는 읽기 전용으로 연다. 서버는 상태 조회와 스캔별 WebSocket 이벤트를 제공한다. 따라서 Recon 중에도 대시보드가 상태를 읽을 수 있다. [DB 선택과 읽기 전용 연결](../../src/aidast/web/projection.py), [서버](../../src/aidast/web/server.py)

`WebUI/`는 화면 구현이고, `src/aidast/web/`는 서버·launch·projection 계층이다. 사용 방법과 화면 설명은 [WebUI README](../../WebUI/README.md)를 본다.

## 확인할 질문

1. 대시보드에서 누른 실행 버튼이 최종적으로 어떤 CLI 명령을 만드는가?
2. WebSocket 이벤트가 끊겼을 때 저장된 단계 상태는 어디에서 다시 읽는가?
