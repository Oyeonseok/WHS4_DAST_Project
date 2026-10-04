# 코드 길잡이

**질문:** 특정 동작을 확인하려면 어느 파일과 검사를 함께 읽어야 하는가?

전체 순서는 [파이프라인 지도](pipeline-map.md), 용어와 조건은 01~11 페이지를 본다. 이 페이지는 현재 구현의 **진입점과 확인할 함수**를 모은다. 파일 이름이 역할과 비슷해도 실제 호출 위치로 소속 단계를 판단한다.

| 확인하려는 것 | 먼저 열 파일·함수 | 함께 확인할 경계 |
| --- | --- | --- |
| 명령 연결·통합 실행 | [pyproject.toml](../../pyproject.toml), [cli.py](../../src/aidast/cli.py): `entrypoint`, `main`, `_run_recon` | 명령을 직접 부른 테스트와 실제 CLI 호출 기록; 실패 시 후속 호출 |
| 결과 루트·과거 스캔 탐색 | [paths.py](../../src/aidast/paths.py), [locations.py](../../src/aidast/pipeline/locations.py) | 환경 설정·기본 경로·플랫폼/프로그램별 및 평면 레이아웃 |
| Scope 수집·검토·승인 | [orchestration/scope.py](../../src/aidast/orchestration/scope.py), [scope/reader.py](../../src/aidast/scope/reader.py), [agents/main.py](../../src/aidast/agents/main.py) | native 수집과 Python Reader 수집; 초안과 승인 파일 |
| Scope 정책 참조·실행 규칙 | [policy_references.py](../../src/aidast/scope/policy_references.py), [execution_rules.py](../../src/aidast/scope/execution_rules.py) | 원문·참조 근거, 강제 조건·주의사항, 승인 원문과 별도 캐시 |
| Recon 계획·Task 준비 | [orchestration/recon.py](../../src/aidast/orchestration/recon.py), [cli.py](../../src/aidast/cli.py) | 메모리 Plan·Task와 승인 자산·TargetPolicy |
| Recon 실행·전송 제어 | [recon/executor.py](../../src/aidast/recon/executor.py), [core/request_broker.py](../../src/aidast/core/request_broker.py), [endpoint_discovery.py](../../src/aidast/recon/tools/endpoint_discovery.py) | 도구 실행·개별 실패·프록시·요청 예산과 DB 관측 |
| Recon 태깅·오프라인 검토 | [annotations.py](../../src/aidast/recon/annotations.py), [recon/agent.py](../../src/aidast/recon/agent.py) | 사실 태깅·집계 기반 추가 정찰 추천; 자동 재실행 여부 |
| Handoff 기록·검증·DB 복제 | [cli.py](../../src/aidast/cli.py): `_write_recon_handoff`, [models.py](../../src/aidast/pipeline/models.py), [materialize.py](../../src/aidast/pipeline/materialize.py) | 파일 역할·크기·해시, 승인 자료 연결, 원본 보존 |
| Native Attack 가설 계획 | [recon_hypotheses.py](../../src/aidast/attack/recon_hypotheses.py), [hypothesis_validation.py](../../src/aidast/attack/hypothesis_validation.py) | 저장된 관측에서의 제안·Python 검사; 계획과 실제 증거의 차이 |
| Attack Coverage·배치·완료 | [orchestration/attack.py](../../src/aidast/orchestration/attack.py), [coverage_attack.py](../../src/aidast/orchestration/coverage_attack.py), [coverage.py](../../src/aidast/attack/coverage.py) | 미완료 항목·Task·attempt·재현 명세·완료 JSON과 DB 대조 |
| Native Agent·도우미 연결 | [native_pipeline.py](../../src/aidast/agents/native_pipeline.py), [helper_broker.py](../../src/aidast/agents/helper_broker.py) | AI 계획과 도구 사용, 배치당 Agent, 브로커 환경 조건 |
| Chaining | [orchestration/chaining.py](../../src/aidast/orchestration/chaining.py), [chaining/db_cli.py](../../src/aidast/chaining/db_cli.py) | 입력 finding과 현재 실행에 연결된 chain 증거 |
| Validation 선택·실행·판정 | [coordinator.py](../../src/aidast/validation/orchestration/coordinator.py), [native.py](../../src/aidast/validation/orchestration/native.py), [decision.py](../../src/aidast/validation/core/decision.py) | case 선택·정책·재현 포트·구조화된 최종 상태 |
| Validation 의미·증거 검사 | [profile_evidence.py](../../src/aidast/validation/core/profile_evidence.py), [profiles.py](../../src/aidast/validation/core/profiles.py) | Skill·프로필 연결, 감사 모드와 강제 판정 조건의 차이 |
| Report 준비·작성·저장 | [auto.py](../../src/aidast/reporting/auto.py), [runtime.py](../../src/aidast/reporting/runtime.py), [case_runtime.py](../../src/aidast/reporting/case_runtime.py) | 현재 CONFIRMED case, 컨텍스트·인용·최신성 검사와 별도 Report.db |
| 상태·재개 | [lifecycle.py](../../src/aidast/pipeline/lifecycle.py), [resume.py](../../src/aidast/pipeline/resume.py), [coverage_snapshot.py](../../src/aidast/attack/coverage_snapshot.py) | Task 검사 대상, 종료·재시도 가능 상태, 검사와 실행의 분리 |
| WebUI 등록·Scope 작업·실행 | [programs.py](../../src/aidast/web/programs.py), [scope_workflow.py](../../src/aidast/web/scope_workflow.py), [launch.py](../../src/aidast/web/launch.py), [server.py](../../src/aidast/web/server.py) | 등록·수집·승인·스캔 시작·재개 각각의 API와 저장소 |
| WebUI 읽기·이벤트·모델 호출 | [projection.py](../../src/aidast/web/projection.py), [core/model_calls.py](../../src/aidast/core/model_calls.py) | 원본 DB 조회와 파생 events.db, 호출 메타데이터 |
| 테스트가 증명하는 범위 | [test_merged_pipeline_e2e.py](../../tests/test_merged_pipeline_e2e.py), [test_scan_resume.py](../../tests/test_scan_resume.py), [test_generic_reporting.py](../../tests/test_generic_reporting.py) | fake Agent·fixture·실제 모델/대상 실행의 구분 |

코드가 바뀌면 위키 설명도 바뀔 수 있다. 중요한 조건은 클래스명이나 주석만으로 확정하지 않고 **호출 위치·SQL 필터·실행 옵션·실패 분기·테스트 입력**을 함께 읽는다. 현재 검토 범위와 수정 이력은 [위키 변경 기록](log.md)에 남긴다.

## 확인할 질문

1. `recon_hypotheses.py`의 이름만 보고 가설 계획을 Recon 단계로 분류하면 왜 틀리는가?
2. `Pipeline.db`와 `Report.db`의 기록을 확인할 때 어떤 함수들을 함께 읽어야 하는가?
3. “테스트 통과”를 탐지 성능의 증명으로 읽기 전에 어떤 fixture·대체 객체를 확인해야 하는가?
