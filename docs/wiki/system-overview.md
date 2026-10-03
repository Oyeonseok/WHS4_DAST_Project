# 코드 길잡이

**질문:** 파이프라인 동작을 확인하려면 어느 파일부터 읽어야 하는가?

전체 순서는 [파이프라인 그림](pipeline-map.md), 의미와 경계는 01~11 페이지를 본다. 여기에는 구현의 **진입 파일**만 모았다.

| 확인하려는 것 | 먼저 열 파일 |
| --- | --- |
| 명령 파싱과 통합 실행 순서 | [`pyproject.toml`](../../pyproject.toml), [`cli.py`](../../src/aidast/cli.py) |
| Scope 수집·승인·재검사 | [`orchestration/scope.py`](../../src/aidast/orchestration/scope.py) |
| Recon Task·정책·실행 | [`orchestration/recon.py`](../../src/aidast/orchestration/recon.py), [`recon/executor.py`](../../src/aidast/recon/executor.py), [`core/request_broker.py`](../../src/aidast/core/request_broker.py) |
| Handoff 검증과 DB 복제 | [`pipeline/models.py`](../../src/aidast/pipeline/models.py), [`pipeline/materialize.py`](../../src/aidast/pipeline/materialize.py) |
| Attack과 Chaining의 조건 | [`orchestration/attack.py`](../../src/aidast/orchestration/attack.py), [`orchestration/chaining.py`](../../src/aidast/orchestration/chaining.py) |
| Validation case 선택·판정 | [`validation/orchestration/coordinator.py`](../../src/aidast/validation/orchestration/coordinator.py), [`validation/core/decision.py`](../../src/aidast/validation/core/decision.py) |
| Report 대상과 증거 | [`reporting/auto.py`](../../src/aidast/reporting/auto.py), [`reporting/case_runtime.py`](../../src/aidast/reporting/case_runtime.py) |
| 단계 상태와 재개 | [`pipeline/lifecycle.py`](../../src/aidast/pipeline/lifecycle.py), [`pipeline/resume.py`](../../src/aidast/pipeline/resume.py) |
| WebUI 실행·상태 표시 | [`web/launch.py`](../../src/aidast/web/launch.py), [`web/projection.py`](../../src/aidast/web/projection.py), [`web/server.py`](../../src/aidast/web/server.py) |
| Agent가 쓰는 실행 도구와 내부 도우미 | [`recon/executor.py`](../../src/aidast/recon/executor.py), [`agents/native_pipeline.py`](../../src/aidast/agents/native_pipeline.py), [`validation/orchestration/native.py`](../../src/aidast/validation/orchestration/native.py) |
| Skill 선택과 Validation 짝짓기 | [`attack/recon_hypotheses.py`](../../src/aidast/attack/recon_hypotheses.py), [`orchestration/coverage_attack.py`](../../src/aidast/orchestration/coverage_attack.py), [`validation/core/profiles.py`](../../src/aidast/validation/core/profiles.py) |
| 단계별 테스트 사례 | [`test_merged_pipeline_e2e.py`](../../tests/test_merged_pipeline_e2e.py), [`test_generic_reporting.py`](../../tests/test_generic_reporting.py) |

코드가 바뀌면 위키의 설명도 바뀔 수 있다. 특히 조건을 확인할 때는 함수 이름과 SQL 분기를 현재 체크아웃에서 직접 읽는다.

## 확인할 질문

1. “Recon 완료”라는 주장을 확인할 때 CLI와 수명주기 코드 중 어디를 함께 읽어야 하는가?
2. “보고서가 생성된다”는 주장을 확인할 때 case 선택과 증거 검사를 어디서 찾는가?
