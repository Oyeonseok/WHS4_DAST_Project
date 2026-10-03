# 01. 통합 파이프라인의 시작점

**질문:** `aidast run` 명령은 실제로 어떤 함수와 단계를 거쳐 실행되는가?

그림으로 먼저 보려면 [통합 파이프라인 지도](pipeline-map.md)를, 가상 endpoint가 실제 테스트에서 어떻게 흘러가는지 보려면 [테스트 사례 추적](11-test-trace.md)을 연다.

## 한눈에 보기

```text
사용자: aidast run <프로그램 URL> --target <승인 자산>
  → CLI entrypoint() → main()
  → _run_recon(prepare_attack=True)
  → Scope 확인 → Recon 계획·정책·실행·태깅
  → Handoff.json → 오프라인 Legacy Attack 계획 저장 → Pipeline.db
  → AttackCoordinator.run()
  → ChainingCoordinator.run()
  → ValidationCoordinator.run()
  → CONFIRMED case의 Report 초안
```

이것은 [README의 제품 흐름](../../README.md#동작-흐름)을 [CLI 구현](../../src/aidast/cli.py)에서 따라간 지도다. 사용자에게 보이는 단계와 내부 함수의 이름은 1:1로 일치하지 않는다.

## 입구: 명령을 함수로 연결

[`pyproject.toml`](../../pyproject.toml)의 `[project.scripts]`는 `aidast` 명령을 `aidast.cli:entrypoint`에 연결한다. `entrypoint()`는 모델 호출 기록을 위한 컨텍스트를 열고 `main()`을 호출한다. `main()`은 인자를 파싱한 후 `run`, `recon`, `resume` 등을 분기한다. [CLI 코드](../../src/aidast/cli.py)

`aidast run`은 `args.execute=True`, `args.tag_after=True`를 설정하고 `_run_recon(..., prepare_attack=True)`를 호출한다. 즉, 통합 실행의 앞부분은 별도의 Recon 구현이 아니라 `aidast recon`과 같은 `_run_recon()` 경로를 재사용한다. [CLI의 `run` 분기](../../src/aidast/cli.py)

## 중간: Recon에서 후속 단계로 넘어가는 조건

`_run_recon()`은 승인된 Scope를 재사용하거나 승인 절차를 거친다. 승인된 대상에서 Recon Plan과 Task를 만들고, 타깃 정책을 구성한 후 `ReconExecutor`를 실행한다. 통합 실행에서는 관측 태깅과 Recon 검토도 수행한다. [`_run_recon()`](../../src/aidast/cli.py), [Recon Task 생성](../../src/aidast/orchestration/recon.py)

Recon 실패가 없을 때만 Handoff와 후속 단계로 진입한다. Handoff에는 원본 산출물의 무결성 정보가 들어간다. CLI는 먼저 `_plan_attack()`으로 오프라인 Legacy Attack 계획을 저장하고, 이어서 `materialize_pipeline()`이 `Recon.db`를 읽기 전용으로 검증·복제하여 쓰기 가능한 `Pipeline.db`를 만든다. 이 Legacy 계획을 저장하는 것과 아래의 Native Attack 실행은 다른 작업이다. [`_run_recon()`](../../src/aidast/cli.py), [오프라인 계획](../../src/aidast/cli.py), [`materialize_pipeline()`](../../src/aidast/pipeline/materialize.py)

## 후반: 같은 Pipeline.db를 이어서 사용

CLI는 `AttackCoordinator.run(scan_id)`, `ChainingCoordinator.run(scan_id)`, Validation coordinator의 `run(scan_id)`를 순서대로 호출한다. Attack은 완료된 Recon scan을 요구하고, Chaining은 완료된 Attack stage를 요구한다. Validation이 완료된 경우 Report 생성을 시도하며, `generate_scan_reports()`는 최신 결정이 `CONFIRMED`이고 처리가 끝난 case만 고른다. [CLI의 후속 단계 호출](../../src/aidast/cli.py), [Attack gate](../../src/aidast/orchestration/attack.py), [Chaining gate](../../src/aidast/orchestration/chaining.py), [Report case 선택](../../src/aidast/reporting/auto.py)

Recon 결과와 Handoff는 `result/Runs/<platform>/<program>/<scan_id>/`, 통합 DB는 `result/AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db`에 저장된다. [결과 폴더 설명](../../README.md#결과-폴더)

## 가상의 자산 하나로 따라가기

아래의 `https://app.example.test`는 **구조를 설명하기 위한 가상 주소**다. 실제 승인이나 스캔 결과를 뜻하지 않는다. 후보 finding이나 보고서는 반드시 생성되는 것이 아니다.

| 단계 | 이 자산에 대해 남을 수 있는 데이터 |
| --- | --- |
| Scope | `Scope.json`의 승인 대상 목록에 자산이 들어가고, 검토·승인 결과가 `Approval.json`으로 남는다. |
| 실행 정책 | `TargetPolicy.json`에 이 자산에 허용된 호스트·방법·요청 한도 등이 기록된다. |
| Recon | `Recon.db`의 `assets`에서 자산을, `origins`에서 실제 origin을, `endpoints`에서 관측된 경로와 HTTP 방법을 찾는다. |
| Handoff | `Handoff.json`에 Recon DB와 Scope·정책 등 전달 파일의 해시가 기록된다. 별도의 오프라인 Legacy Attack 계획도 저장된다. |
| Native Attack | `Pipeline.db`에 복제된 Recon 관측을 바탕으로 가설을 조사하고, 결과가 있다면 `findings`와 `attack_attempts` 등에 남는다. |
| Validation | 선택된 finding 또는 chain이 `validation_cases`의 case가 되고 현재 판정 상태가 기록된다. |
| Report | 현재 case가 완료된 `CONFIRMED`이고 결정이 최신이면 `Report.md`·`Report.json` 초안 대상이 된다. |

각 데이터의 실제 조건은 [Scope와 Recon](02-scope-recon.md), [Handoff](03-recon-handoff.md), [Attack과 Chaining](04-attack-chaining.md), [Validation과 Report](05-validation-report.md)에서 확인한다. 테이블 구조는 [Recon DB](../../src/aidast/recon/db.py), [후속 DB 스키마](../../src/aidast/pipeline/schema.py), [Validation case 스키마](../../src/aidast/pipeline/live_schema.py)에 있다.

## `run`, `recon`, `resume`를 구분하기

| 명령 | 파이프라인에서 하는 일 |
| --- | --- |
| `aidast recon` | 승인된 Scope에서 Recon 계획을 만들고 선택적으로 실행한다. 후속 단계까지 자동으로 이어가지는 않는다. |
| `aidast run` | Recon을 실행하고 Handoff·Attack·Chaining·Validation 및 조건에 맞는 Report 초안까지 이어간다. |
| `aidast resume` | 저장된 Handoff와 DB를 검증한 후 Attack·Chaining·Validation 중 첫 미완료 단계부터 이어간다. Recon 재실행과 Report 자동 생성은 포함하지 않는다. |

근거: [CLI 명령 분기](../../src/aidast/cli.py), [재개 검사·실행](../../src/aidast/pipeline/resume.py), [README 명령표](../../README.md#주요-명령).

## 확인할 질문

1. 왜 `aidast run`이 `_run_recon()`을 재사용할까?
2. `Recon.db`와 `Pipeline.db`를 분리해 두면 어떤 문제가 예방될까?
3. Attack을 시작하기 전에 완료 상태를 검사하는 코드는 어디인가?
