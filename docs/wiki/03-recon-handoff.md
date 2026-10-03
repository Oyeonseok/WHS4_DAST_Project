# 03. Recon 결과가 Handoff를 거쳐 공용 DB가 되기까지

**질문:** Recon의 관측은 어떤 조건에서 Attack이 읽을 수 있는 데이터가 되는가?

## Recon 내부 흐름

`ReconCoordinator`가 만든 Task는 `ReconExecutor.run()`에서 의존관계 순서대로 실행된다. 한 타깃의 Task가 실패하면 그에 의존한 Task는 건너뛰지만 독립 타깃은 계속 처리하고 실패 건수를 반환한다. HTTP 단계는 자산별 `TargetPolicy`와 요청 브로커를 사용한다. [Task 생성](../../src/aidast/orchestration/recon.py), [Executor](../../src/aidast/recon/executor.py), [RequestBroker](../../src/aidast/core/request_broker.py)

`aidast run`은 Recon 실행 후 관측 태깅, 오프라인 Recon 검토, `Surface.json` 내보내기를 수행한다. 실패 Task가 남았다면 통합 실행의 Handoff·Attack으로 이어가지 않는다. [CLI의 통합 흐름](../../src/aidast/cli.py)

## Handoff의 구성

`_write_recon_handoff()`는 승인된 Scope와 TargetPolicy를 실행 폴더에 복사하고, `Recon.db`·`Surface.json`·`ReconReview.json`·`Scope.md`·`Scope.json`·`Approval.json`·`TargetPolicy.json`의 역할, 크기, SHA-256을 `Handoff.json`에 기록한다. [Handoff 작성](../../src/aidast/cli.py), [manifest 모델](../../src/aidast/pipeline/models.py)

`materialize_pipeline()`은 manifest가 가리키는 파일을 검증한다. `Recon.db`를 읽기 전용 SQLite 연결로 열어 backup API로 새 `Pipeline.db`에 복제한 뒤 후속 단계의 테이블을 추가한다. 복제 전후 원본 해시가 달라지면 실패한다. 따라서 원본 Recon 데이터와 후속 단계의 쓰기 작업이 분리된다. [DB 생성 코드](../../src/aidast/pipeline/materialize.py)

| 파일 | 역할 | 다음 단계에서의 취급 |
| --- | --- | --- |
| `Recon.db` | 정찰의 원본 관측 | Handoff 검증 대상, 복제 원본 |
| `Handoff.json` | 어떤 원본 파일을 넘겼는지 기록 | 해시·역할 검증의 기준 |
| `Pipeline.db` | Recon 복제본과 후속 테이블 | Attack부터 Validation까지 기록하는 공용 DB |

`Pipeline.db`의 `pipeline_sources`는 원본 manifest와 DB의 해시를 보관하며 UPDATE·DELETE를 막는 트리거가 있다. [Live schema](../../src/aidast/pipeline/live_schema.py)

## 중요한 구분

manifest 해시 검사는 **파일의 변경 여부**를 확인한다. 누가 처음 파일을 만들었는지를 암호학적으로 인증하는 기능이라고 해석하면 안 된다. [Artifact 검증 코드](../../src/aidast/pipeline/models.py)

실행 폴더의 실제 경로와 보존 규칙은 [운영 상세](../OPERATIONS.md#통합-파이프라인과-데이터-무결성)를 참고한다.

## 확인할 질문

1. Handoff에 `Scope.json`과 `Approval.json`이 함께 들어가는 이유는 무엇인가?
2. 원본 `Recon.db`가 바뀌었다면 복제 또는 재개에서 어떤 검사가 실패하는가?
