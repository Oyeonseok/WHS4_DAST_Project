# 통합 파이프라인 지도

**질문:** `aidast run`에서 각 단계와 산출물은 어떻게 이어지는가?

```mermaid
flowchart TD
    U[사용자: aidast run] --> CLI[CLI: entrypoint → main]
    CLI --> S[Scope 승인 확인 또는 수집]
    S --> SA[(Scope.json · Approval.json)]
    S --> P[Recon Plan · Task · TargetPolicy 생성]
    P --> RE[Recon 실행 · 관측 태깅 · 검토]
    RE --> RD[(Recon.db · Surface.json)]
    RE --> RG{Recon 성공?}
    RG -- 아니요 --> STOP[후속 단계 중단]
    RG -- 예 --> H[Handoff 생성 · 원본 무결성 기록]
    RD -. 근거 .-> H
    SA -. 승인 근거 .-> H
    H --> HM[(Handoff.json)]
    H --> LP[오프라인 Legacy Attack 계획 저장]
    LP --> LD[(Legacy 계획 DB)]
    LP --> M[Recon.db 검증 · 복제]
    M --> PD[(Pipeline.db)]
    PD --> A[Attack: 후보 조사]
    A --> C[Chaining: finding 연결]
    C --> V[Validation: 재현 · 판정]
    V --> VG{Validation 완료?}
    VG -- 아니요 --> STOP
    VG -- 예 --> RC{현재 CONFIRMED case 존재?}
    RC -- 아니요 --> END[보고서 없이 완료]
    RC -- 예 --> R[Report: 로컬 초안 생성]
    R --> OUT[(Report.md · Report.json)]
```

## 읽는 법

- 사각형은 **작업**, 원통형은 **저장되는 산출물**, 마름모는 **다음 단계로 넘어갈 조건**이다.
- `Recon.db`는 원본 정찰 결과이며, 후속 단계는 검증·복제한 `Pipeline.db`를 사용한다. [파이프라인 생성 코드](../../src/aidast/pipeline/materialize.py)
- Legacy 계획은 Handoff 뒤에 저장되지만 `aidast run`이 자동 실행하는 Attack은 `Pipeline.db`를 사용하는 Native Attack이다. [CLI의 호출 순서](../../src/aidast/cli.py)
- `aidast run`의 단계 호출은 [CLI의 `_run_recon()`](../../src/aidast/cli.py)에 있다. Recon 실패가 있으면 후속 단계 호출을 시작하지 않는다.
- Report 생성 함수는 Validation이 완료됐을 때 호출되며, 현재 결정이 `CONFIRMED`인 완료 case만 초안을 만든다. [CLI](../../src/aidast/cli.py), [Report case 선택](../../src/aidast/reporting/auto.py)
- 실제 저장 경로와 결과 파일은 [README의 결과 폴더](../../README.md#결과-폴더)를 참고한다.

관련 설명: [01. 통합 파이프라인의 시작점](01-pipeline-entrypoints.md), [02~08 학습 순서](study-path.md).

## 확인할 질문

1. `Recon.db` 대신 `Pipeline.db`에 후속 단계 결과를 기록하는 이유는 무엇인가?
2. `Handoff.json`은 어떤 원본을 검증할 수 있게 해주는가?
