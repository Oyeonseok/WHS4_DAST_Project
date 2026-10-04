# 01. 통합 파이프라인의 시작점

**질문:** 프로그램 URL이 들어온 뒤, 어느 단계에서 무엇을 만들고 다음 단계로 넘어가는가?

이 페이지는 현재 기본 **Native 통합 실행**을 설명한다. 전체 그림은 [파이프라인 지도](pipeline-map.md), WebUI의 URL 등록·Scope 수집·실행 버튼은 [대시보드](08-dashboard.md)에서 본다. URL 등록과 실행 시작은 서로 다른 동작이다.

## 먼저 기억할 순서

```text
aidast run
  → entrypoint() → main() → _run_recon(prepare_attack=True)
  → Scope 수집·검토·승인 또는 기존 승인본 확인
  → Recon 계획·TargetPolicy·Task 준비
  → Recon 실행·관측 태깅·오프라인 검토·내보내기
  → Handoff 기록 → 별도 Legacy 계획 저장 → Pipeline.db 생성
  → Attack 가설 계획 → Coverage·배치 Task → Attack Agent 조사
  → Chaining → Validation → 조건에 맞는 Report 초안
```

이는 사용자에게 보이는 단계와 현재 함수 호출을 연결한 설명이다. Native 가설 계획은 **Recon 원본이 전달되고 Pipeline.db가 만들어진 뒤, Attack 단계의 시작 부분**에서 수행한다. [CLI 호출 순서](../../src/aidast/cli.py), [Attack 시작](../../src/aidast/orchestration/attack.py), [가설 계획](../../src/aidast/attack/recon_hypotheses.py)

## 명령은 어떤 함수로 연결되는가?

[프로젝트 설정](../../pyproject.toml)의 `[project.scripts]`는 `aidast`를 `aidast.cli:entrypoint`에 연결한다. `entrypoint()`는 호출 기록 저장소를 연결하고 `main()`을 실행한다. `main()`은 명령을 분기한다. 실제 entrypoint의 호출 기록 DB는 `<RESULT_ROOT>/logs/CodexCalls.db`이며, `main()`만 직접 부르는 테스트와 구분한다. [CLI](../../src/aidast/cli.py), [호출 기록](../../src/aidast/core/model_calls.py)

`run` 분기는 실행·관측 태깅을 켜고 `_run_recon(..., prepare_attack=True)`를 호출한다. 즉 앞부분은 `recon`과 같은 실행 경로를 재사용하고, 성공한 경우 후속 단계를 이어 호출한다. [명령 분기](../../src/aidast/cli.py)

## 각 단계의 입력과 결과

| 단계 | 맡는 일 | 주요 결과와 저장 위치 |
| --- | --- | --- |
| Scope | 프로그램 정책·허용 자산을 수집·해석하고 사용자의 검토·승인을 기록 | `Scope.md`, `Scope.json`, `Manifest.json`, `Approval.json` 파일 |
| Recon 준비 | 승인 자산을 선택하고 정찰 계획·실행 정책·Task를 구성 | 계획·Task는 메모리 객체; 실행 정책은 `TargetPolicy.json` |
| Recon 실행 | 도구를 실행하고 관측을 저장·태깅 | `Recon.db`; 내보내기 파일 `Surface.json`, 검토 파일 `ReconReview.json` |
| Handoff | 전달 파일 목록·크기·해시를 기록하고 원본을 검증·복제 | `Handoff.json`, 복제본 `Pipeline.db` |
| Attack 계획·조사 | 관측에서 가설을 제안·검사하고 작업을 배정해 조사 | `Pipeline.db`의 계획·Coverage·Task·요청·attempt·finding·재현 명세 |
| Chaining | 근거 있는 finding의 연결 가능성과 재현 결과를 기록 | 같은 `Pipeline.db` |
| Validation | 선택된 finding·chain을 case로 만들어 재현 자료와 정책·영향을 판정 | 같은 `Pipeline.db`의 Validation case·증거·결정 |
| Report | 최신 확정 case를 바탕으로 로컬 문안 초안 생성 | case별 `Report.db`, `Report.context.json`, `Report.json`, `Report.md`; Report stage 상태는 `Pipeline.db` |

근거: [Scope](../../src/aidast/orchestration/scope.py), [Recon 준비](../../src/aidast/orchestration/recon.py), [CLI와 Handoff](../../src/aidast/cli.py), [DB 복제](../../src/aidast/pipeline/materialize.py), [Attack](../../src/aidast/orchestration/attack.py), [Chaining](../../src/aidast/orchestration/chaining.py), [Validation](../../src/aidast/validation/orchestration/coordinator.py), [Report 선택](../../src/aidast/reporting/auto.py), [Report 저장](../../src/aidast/reporting/case_runtime.py).

`Scope.json`처럼 이름이 JSON인 산출물은 파일이다. 위 표에서 공용 후속 조사 DB는 `Pipeline.db`이고, 보고서 저장 DB는 별도 `Report.db`다. 자세한 저장소 목록은 [대시보드](08-dashboard.md), Report의 검증 범위는 [Validation과 Report](05-validation-report.md)를 본다.

Recon의 Plan·Task 객체를 Native Attack의 DB Task와 혼동하지 않는다. 현재 CLI는 Recon Plan·Task를 만들고 실행기에 전달하며, `Recon.db.pipeline_runs`는 `task_id`가 연결된 도구 실행 기록을 보관한다. Native Attack의 계획·Task는 별도로 `Pipeline.db`에 저장된다. [Recon 준비·실행](../../src/aidast/cli.py), [Recon 실행 기록](../../src/aidast/recon/db.py), [Attack 작업 준비](../../src/aidast/attack/coverage.py)

## Handoff와 두 종류의 Attack 계획

통합 CLI의 실제 순서는 다음과 같다.

1. `_write_recon_handoff()`가 전달 파일을 기록한다.
2. `_plan_attack()`이 오프라인 Legacy 계획을 별도 `legacy/Attack.db`에 저장한다.
3. `materialize_pipeline()`이 전달 파일을 검사하고 `Recon.db`를 복제해 `Pipeline.db`를 만든다.
4. `AttackCoordinator.run()`이 Native 가설 계획·Coverage·배치 조사를 시작한다.

Legacy 계획 저장과 Native 조사에 쓰는 가설 계획은 다른 작업이다. 발표에서 주 흐름을 단순화할 때는 **Recon → Handoff → Attack 계획 → Attack 조사**로 설명하고, 코드 상세를 볼 때 이 호환 산출물도 확인한다. [CLI](../../src/aidast/cli.py), [Legacy 저장](../../src/aidast/attack/store.py), [Native 계획](../../src/aidast/attack/recon_hypotheses.py)

## 다음 단계로 넘어가는 조건

Recon 실행에 실패 Task가 남으면 통합 CLI는 후속 Handoff·Attack을 호출하지 않는다. 관측 태깅 실패도 예외로 실행을 중단시킨다. 반면 오프라인 Recon 검토의 추천은 자동 실행 Task가 아니고, 검토의 `stop_reason` 자체를 CLI가 Handoff 차단 조건으로 삼지는 않는다. [CLI](../../src/aidast/cli.py), [오프라인 검토](../../src/aidast/recon/agent.py)

이후 Attack은 완료된 Recon을, Chaining은 완료된 Attack을 요구한다. Validation이 `completed`를 반환하면 CLI가 Report 생성을 호출한다. Report 대상은 **현재 `CONFIRMED`, 처리 완료, 최신 결정**인 case이며, 대상이 없으면 보고서 없이 끝날 수 있다. 단계의 완료와 취약점 확정은 서로 다른 상태다. [Attack](../../src/aidast/orchestration/attack.py), [Chaining](../../src/aidast/orchestration/chaining.py), [Report 선택](../../src/aidast/reporting/auto.py), [상태와 재개](06-state-resume.md)

## 저장 경로를 읽는 기준

이 위키의 `<RESULT_ROOT>`는 결과 루트다. 소스 체크아웃에서는 기본값이 저장소의 `result/`이고, `AIDAST_RESULT_ROOT` 설정이 이를 바꿀 수 있다. 패키지만 설치한 경우에는 별도의 사용자 데이터 경로를 사용한다. 현재 작업 디렉터리만으로 기본 경로가 바뀌는 것은 아니다. [경로 결정](../../src/aidast/paths.py)

기본 통합 레이아웃은 다음과 같다. 각 명령의 출력 경로 옵션에 따라 달라질 수 있다.

| 기본 위치 | 내용 |
| --- | --- |
| `<RESULT_ROOT>/Scope/<platform>/<program>/` | 프로그램의 Scope·승인 파일; 재수집 버전은 하위 revisions 경로 |
| `<RESULT_ROOT>/Runs/<platform>/<program>/<scan_id>/` | `Recon.db`, Scope·정책 복사본, Surface·검토·Handoff 파일 |
| `<RESULT_ROOT>/AttackRuns/<platform>/<program>/<scan_id>/Pipeline.db` | Native 후속 공용 DB |
| 같은 AttackRuns 경로의 `legacy/Attack.db` | CLI가 별도로 남기는 Legacy 계획 DB |
| `<RESULT_ROOT>/ReportRun/<scan_id>/` | case별 Report 산출물; generic 영문은 `en/` 하위 |

근거: [CLI 경로 구성](../../src/aidast/cli.py), [Scope 작업 버전](../../src/aidast/web/scope_workflow.py), [Report 출력](../../src/aidast/reporting/auto.py). 과거 평면 스캔 경로도 조회·재개 코드가 지원한다. [경로 탐색](../../src/aidast/pipeline/locations.py)

## 명령별 범위

| 명령 이름 | 현재 역할 |
| --- | --- |
| `aidast scope` | Scope 수집·초안·검토·승인 |
| `aidast recon` | Recon 계획을 만들고 선택적으로 실행; 통합 후속 단계 자동 호출은 포함하지 않음 |
| `aidast run` | Recon과 Handoff 이후 Native 후속 단계 및 조건에 맞는 Report 초안 생성 |
| `aidast resume` | 저장된 Handoff·DB를 검사하고 선택된 후속 단계부터 Validation까지 재개 |
| `aidast report` | 조건에 맞는 case의 Report를 별도 준비·생성·조회하는 경로 |

이는 명령의 역할 비교이며 실행 방법은 [README](../../README.md)에서 확인한다. `resume`은 Recon 재수집과 Report 자동 생성을 수행하지 않는다. [명령 분기](../../src/aidast/cli.py), [재개 범위](../../src/aidast/pipeline/resume.py)

## 확인할 질문

1. Handoff가 끝난 뒤 Native 가설 계획을 호출하는 주체는 누구인가?
2. `Recon.db`, `Pipeline.db`, `Report.db`는 각각 무엇을 보관하는가?
3. 단계가 완료됐는데도 finding·Validation case·Report가 없을 수 있는 이유는 무엇인가?
