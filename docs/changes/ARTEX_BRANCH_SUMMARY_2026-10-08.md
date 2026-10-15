# `artex` 브랜치 변경 요약

작성일: 2026-10-08  
기준 브랜치: `benchmark` (`314729e`)  
대상 범위: `500a5fd`부터 `bf32284`까지

## 목적

ARTEX의 장점인 실행 중 재계획, 공격 단서 추적, 상태 기반 UI 탐색을 AIDAST에 적용하되
기존의 승인 Scope, 물리 요청별 정책 검사, 요청 예산, 독립 Validation 경계를 유지했다.
공개 기준 데이터로 탐지율을 인위적으로 높이는 Recon/Attack Wiki 기능은 최종 구현에서
제거했다.

## 동작 변화

| 영역 | 변경 전 | `artex` 브랜치 |
| --- | --- | --- |
| 공격 지식 | Recon 종료 시 만든 가설을 배치로 소진 | Attack 중 확인된 endpoint, fact, finding, credential, identity, object와 전제조건을 온라인 그래프로 누적 |
| 작업 선택 | coverage 작업 중심 | coverage 바닥선과 고가치 lead queue를 함께 처리하며 어느 한쪽도 굶기지 않음 |
| 전제조건 | 세션·역할·객체 부족 시 종료되기 쉬움 | 구조화된 resolver가 자동 복구 작업 또는 구체적인 HITL 요청 생성 |
| 취약점 체이닝 | Attack 이후 별도 단계 중심 | 확인된 finding과 재사용 가능한 fact로 같은 Attack 안에서 제한된 후속 작업 예약 |
| UI 정찰 | 현재 페이지의 직접 관측 중심 | 상태 기반 frontier와 HTML/JS의 literal route를 제한적으로 수집하고 실제 HTTP 관측 후에만 endpoint로 승격 |
| 외부 도구 | 고정 native adapter 중심 | 구조화된 nuclei/sqlmap adapter를 RequestBroker와 정책·증거 ledger에 연결 |
| 재시도 품질 | 작업 단위의 이전 시도 맥락이 제한적 | intent checkpoint에 전략군, payload군, control request와 남은 Todo를 append-only로 보존 |
| 음성 판정 | 제한된 실패가 terminal negative가 될 수 있음 | 대조 요청과 서로 다른 전략이 충분할 때만 `tested_negative`로 확정 |
| 실제 버그바운티 | 로컬 benchmark 중심의 실행 흐름 | 한 자산, 낮은 속도와 동시성, 공유 요청 예산, 정확한 HTTPS 시작 URL을 강제하는 안전 프로필 추가 |

## 주요 구현

### 온라인 Attack Graph와 두 작업 큐

- `src/aidast/attack/graph.py`는 Pipeline DB의 durable evidence를 안전한 메타데이터
  그래프로 투영한다. 원문 응답, 토큰과 credential 값은 그래프에 저장하지 않는다.
- `src/aidast/attack/work_queue.py`는 endpoint×취약점 class coverage와 새 증거에서 파생된
  lead를 함께 예약한다.
- `src/aidast/attack/online_chaining.py`는 기존 Recon coverage와 동일 endpoint/origin 경계
  안에서만 후속 가설을 재우선화한다.

### 전제조건 복구와 HITL

- `src/aidast/attack/preconditions.py`가 session, role, second identity, scanner-owned object,
  fresh token과 prior state를 구조화한다.
- 자동으로 충족할 근거가 없으면 WebUI에 운영자가 수행해야 할 로그인·계정·객체 준비 작업을
  표시한다.
- 운영자의 단순 확인만으로 전제조건이 충족된 것으로 만들지 않고, 이후 관측 증거를 다시
  확인한다.

### 제한된 상태 기반 UI 탐색

- `src/aidast/ui_testing/`에 탐색 frontier, 폼 분류와 요청 예산을 따르는 explorer를 추가했다.
- 이미 본 화면이라도 새로운 안전 상태에서 도달한 분기는 제한된 횟수로 다시 방문한다.
- `src/aidast/recon/ui_synthesis.py`가 정적 literal route를 synthetic candidate로 기록한다.
  합성 결과는 인증 성공, 실제 endpoint 또는 finding 증거로 바로 사용되지 않는다.

### 정책 경계 안의 외부 도구

- `src/aidast/attack/external_tools.py`가 `nuclei-http-template-v1`과
  `sqlmap-payload-family-v1` manifest를 지원한다.
- shell/raw workflow, 임의 proxy와 credential header를 거부한다.
- 모든 물리 요청은 RequestBroker, TargetPolicy, rate/concurrency/request budget과 request
  ledger를 통과한다.

### Intent checkpoint와 진단

- `src/aidast/attack/intent_checkpoint.py`가 재시도에 필요한 비밀이 아닌 실행 상태를 보존한다.
- `aidast.benchmarks.diagnostics.inspect_scan`의 `adaptive_attack`에서 graph revision,
  queue, HITL, online chain, synthetic UI, external tool, negative evidence 품질을 확인할 수 있다.
- 진단 수치는 실행 상태이며 취약점 발견 또는 recall의 증거로 해석하지 않는다.

### 실제 버그바운티 안전 실행

- 대시보드와 CLI에 `bug_bounty_safe` 실행 흐름을 추가했다.
- 승인 Scope에서 자산 하나와 정확한 HTTPS 시작 URL을 선택한다.
- 기본 상한은 초당 0.2회, 동시 요청 1개, 전체 300회, 탐색 깊이 2이며 더 엄격한 프로그램
  정책이 우선한다.
- 자동화 금지, 필수 식별 헤더, 사전 연락, 계정 조건처럼 지원하지 못한 요구가 남으면 시작을
  차단한다.
- 상세 운영 절차는 `docs/REAL_BUG_BOUNTY_MODE.md`에 기록했다.

### Recon Wiki와 Attack Wiki 제거

- Wiki UI, API, CLI, 자동 누적, 과거 baseline 우선순위와 전용 스크립트/문서를 제거했다.
- 정찰과 공격은 현재 실행에서 관측한 블랙박스 증거를 기준으로 진행한다.
- 기존 결과 루트에 저장된 역사 데이터는 삭제하지 않았지만 런타임은 더 이상 읽거나 쓰지
  않는다.

### Aikido bare hostname 시작 오류 수정

- 승인 Scope가 URL 자산을 `app.aikido.dev`처럼 bare hostname으로 저장해도 정책 모듈과
  startup preparation이 같은 HTTPS 기본값을 사용한다.
- 시작 작업은 `HTTP_PROBE https://app.aikido.dev/`로 생성된다.
- 와일드카드 `*.aikido.dev` 자체는 요청 URL로 사용하지 않으며 운영자가
  `https://app.aikido.dev/` 같은 정확한 인스코프 호스트를 지정한다.

## 커밋 구성

| 커밋 | 내용 |
| --- | --- |
| `500a5fd` | 온라인 evidence graph |
| `75fec8a` | coverage/lead 이중 queue |
| `e5a53e3` | 전제조건 resolver와 bounded HITL |
| `ada45d4` | Attack 중 chain follow-up |
| `936504f`–`593e938` | 상태 기반 UI 탐색과 synthetic candidate |
| `32f34b9` | RequestBroker 기반 외부 도구 adapter |
| `ca8be77` | intent checkpoint와 음성 증거 품질 |
| `9ee826c` | adaptive attack 진단 |
| `2e27d9c` | 실제 버그바운티 안전 실행 모드 |
| `bf32284` | Recon/Attack Wiki 제거와 bare URL 시작 수정 |

## 검증

2026-10-08의 `bf32284` 기준으로 다음 검증을 통과했다.

- 핵심 Python 테스트: `360 passed, 20 subtests passed`
- WebUI 테스트: `150 passed`
- `VITE_TRANSPORT=live npm run build`: 성공
- 라이브 대시보드 health: HTTP 200, `mode=local-operator`
- 제거한 Recon/Attack Wiki API: HTTP 404
- 실제 Aikido Scope의 startup operation: `HTTP_PROBE https://app.aikido.dev/`

전체 저장소에는 이 변경과 무관한 기존 Validation fixture/schema 기대값 실패가 남아 있다.
위 결과는 `artex`가 변경한 공격, UI 탐색, Recon 정책, dashboard 경계를 대상으로 한 회귀
검증 결과다.

## 평가 시 주의사항

기능 추가 자체는 90% recall을 증명하지 않는다. 실제 개선율은 공개 답안을 실행 입력에 넣지
않고, 동일 Scope·계정·모델·요청 수·시간 예산으로 여러 번 실행한 뒤 독립 재현된 고유
root cause 기준으로 측정해야 한다. 범위 밖 요청 수, confirmed finding당 요청/모델 비용,
보고서까지 완료된 비율과 최저 회차 성능을 함께 기록한다.
