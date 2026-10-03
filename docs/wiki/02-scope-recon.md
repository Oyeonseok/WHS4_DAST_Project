# 02. Scope 승인이 Recon 작업이 되기까지

**질문:** 프로그램 규칙을 읽은 결과가 어떻게 실제 Recon 대상과 정책으로 바뀌는가?

## 데이터 변환

`프로그램 페이지 → Scope 초안 → 사람의 승인 → 승인 스냅샷 → 대상 선택 → Recon Plan → Task → TargetPolicy`

1. `ScopeCoordinator.collect_draft()`는 프로그램 페이지를 수집하고 Agent의 분석을 구조화된 `ScopeDocument`로 받는다. 출처에 없는 자산이나 규칙 인용을 거부한 뒤 `Scope.md`, `Scope.json`, `Manifest.json` 초안을 만든다. [ScopeCoordinator](../../src/aidast/orchestration/scope.py)
2. `approve_draft()`는 초안의 해시를 검증하고 `Approval.json`을 함께 게시한다. 재사용할 때도 `load_approved_scope()`가 Scope 문서, manifest, approval의 ID와 해시를 대조한다. 따라서 “AI가 Scope를 읽었다”와 “실행이 승인됐다”는 서로 다른 상태다. [ScopeCoordinator](../../src/aidast/orchestration/scope.py)
3. `aidast run`은 `--target` 또는 `--all-targets`를 요구한다. `_run_recon()`은 승인된 `in_scope_assets` 중 요청한 자산을 선택하고, 그 범위에서 Plan을 만든다. [CLI의 run 파서와 _run_recon](../../src/aidast/cli.py)
4. `ReconCoordinator.create_tasks()`는 Plan의 자산이 승인된 집합에 속하는지 다시 검사하고, 단계별 Task와 선행 Task 의존관계를 만든다. [ReconCoordinator](../../src/aidast/orchestration/recon.py)
5. `_run_recon()`은 자산별 `TargetPolicy`를 생성한 다음 Scope 제외 조건과 요청 상한을 적용하고 실행 규칙을 결합한다. 정책은 `TargetPolicy.json`으로 남는다. [CLI의 정책 구성](../../src/aidast/cli.py), [TargetPolicy 모델](../../src/aidast/recon/policy.py)

## 왜 중간 단계가 많은가?

| 경계 | 막는 혼동 |
| --- | --- |
| 초안 → 승인 스냅샷 | Agent의 해석을 운영자의 승인으로 오해하는 일 |
| 승인 자산 → Plan/Task | Plan에 승인되지 않은 자산이 섞이는 일 |
| Plan/Task → TargetPolicy | “무엇을 탐색할지”를 “어디에, 어떤 한도로 요청할 수 있는지”와 혼동하는 일 |

이 표는 위 코드 흐름에 대한 **설계 해석**이다. 세부 사용 절차와 옵션 우선순위는 [운영 상세](../OPERATIONS.md#scope-수집과-정책)를 원본으로 본다.

## 다음 연결

`TargetPolicy`와 의존관계가 있는 Task가 [Recon 실행기](03-recon-handoff.md)로 넘어간다. 정책이 없는 Task는 정책 강제 모드에서 거부된다. [ReconExecutor._policy_for](../../src/aidast/recon/executor.py)

## 확인할 질문

1. `Scope.json`과 `Approval.json`에서 같은 Scope를 가리키는 값은 무엇인가?
2. Plan의 “탐색할 단계”와 TargetPolicy의 “허용된 요청”은 어떻게 다른가?
