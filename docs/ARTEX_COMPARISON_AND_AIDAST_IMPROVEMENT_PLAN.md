# ARTEX 비교와 AIDAST 개선안

작성일: 2026-10-06  
분석 대상: [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)  
분석한 ARTEX 커밋: [`b55ceb1`](https://github.com/Autumn-27/ARTEX/commit/b55ceb1fdd84a813d77de09a06af83d323a81f85)

## 결론

ARTEX의 주된 장점은 자유로운 도구 실행 자체보다 공격 도중 얻은 사실과 취약점을 즉시 다음 계획에 반영하는 이벤트 기반 공격 그래프다. AIDAST는 승인된 범위, 요청 예산, 재현 사양, 독립 Validation을 강하게 보장하지만 Recon 종료 시점에 공격 가설을 대부분 확정하고 이를 배치로 소진한다. 그 결과 공격 중 새로 얻은 세션, 계정, 객체 ID, API와 취약점이 현재 Attack 단계의 다른 작업을 충분히 확장하지 못한다.

ARTEX를 그대로 이식하는 대신 AIDAST의 정책 경계와 독립 검증을 유지하면서 온라인 Attack Graph, 전제조건 resolver, coverage/lead 이중 queue, 공격 중 chaining을 도입하는 것이 적합하다.

## 구조 비교

| 항목 | ARTEX | 현재 AIDAST | 판단 |
| --- | --- | --- | --- |
| 공격 계획 | 탐색 그래프가 변할 때마다 planner를 다시 실행 | Recon 완료 후 endpoint별 가설과 coverage를 먼저 생성 | ARTEX가 새 단서 추적에 유리 |
| 작업 상태 | 사실, finding, worker trace를 공유 그래프에 기록 | DB에 기록하지만 이후 배치의 즉시 재계획 입력으로 쓰는 범위가 제한적 | AIDAST에 실시간 공격 지식판 필요 |
| 탐색 전략 | 고가치 경로의 depth를 우선하면서 다른 경로도 병행 | endpoint×vulnerability coverage를 순차 소진 | AIDAST가 넓지만 얕아질 수 있음 |
| 체이닝 | planner가 의존 관계를 Todo에 기록하고 순차 실행 | Attack 완료 후 별도 Chaining 단계 실행 | 현재 AIDAST의 체이닝 시점이 늦음 |
| 도구 | Bash/Kali 도구를 기록 프록시 뒤에서 폭넓게 사용 | 허용된 native adapter와 RequestBroker 중심 | ARTEX가 유연하고 AIDAST가 안전함 |
| 정찰 | JS chunk, route, permission tree, UI action, 요청 diff 수집 | 실제 관측과 승인된 요청 기반 endpoint/parameter 정찰 | ARTEX의 SPA 내부 기능 노출 방식이 유용함 |
| finding 증거 | 실제 trigger와 PoC를 요구하지만 traffic binding은 선택 사항 | atomic reproduction spec을 필수로 저장 | AIDAST의 자동 검증 입력이 더 엄격함 |
| 재검증 | finding별 retest를 별도로 시작 | 독립 Validation 단계가 재현과 영향을 판정 | AIDAST 우위 |
| coverage | fact가 연결된 asset을 기준으로 한 대략적 수치 | endpoint×vulnerability hypothesis별 상태 | AIDAST가 더 측정 가능함 |
| 범위 통제 | prompt constraint와 사용자 intercept rule 중심 | TargetPolicy, 요청 예산, rate/concurrency, redirect를 코드로 강제 | AIDAST 우위 |

## ARTEX에서 참고할 부분

### 이벤트 기반 planner

[ARTEX planner](https://github.com/Autumn-27/ARTEX/blob/main/agent/planner.go)는 worker 완료, 사실 추가, finding 발생 등으로 그래프가 변하면 다시 실행된다. 목표가 미달성이고 대기 중인 intent가 없으면 새로운 탐색 방향을 생성한다. 부정 결과도 증거가 충분한지 검토하고 약한 부정 결과는 한 번 다른 방식으로 확인하도록 설계되어 있다.

### 공유 탐색 그래프와 지속되는 공격 순서

worker는 한 intent만 수행하고 종료하지만 사실과 finding을 공유 탐색 그래프에 기록한다. 다른 worker의 trace도 검색할 수 있다. planner의 Todo는 여러 planner 회차에 걸쳐 유지되므로 `진입점 발견 → 자격 증명 확보 → 보호 기능 접근 → 권한 경계 검증`과 같은 의존성 있는 공격을 앞 단계 결과가 생긴 뒤 순서대로 실행할 수 있다.

### 클라이언트 UI 정찰

[ARTEX API Recon Skill](https://github.com/Autumn-27/ARTEX/blob/main/skills/api-recon/SKILL.md)은 lazy JS chunk와 route를 정적으로 수집하고 브라우저 document-start hook으로 로그인, 권한, 메뉴 bootstrap 응답을 임시 stub한다. 이 방식은 SPA 내부 화면을 렌더링해 UI action이 만들 outbound 요청의 URL, method, parameter shape를 수집하는 데 사용된다. 여러 UI action의 요청을 비교하고 validation error도 parameter 추론에 활용한다.

AIDAST에서 사용할 때는 이 결과를 `synthetic candidate`로 구분하고 실제 target에서 동일 endpoint가 확인된 뒤에만 Attack 대상으로 승격해야 한다. Stub 결과를 인증 성공이나 취약점 증거로 사용해서는 안 된다.

### 공격 도구와 트래픽 기록

[ARTEX worker](https://github.com/Autumn-27/ARTEX/blob/main/agent/worker.go)는 Bash와 보안 도구를 사용할 수 있고 target 트래픽을 기록 프록시로 보낸다. 이 유연성은 고정 adapter가 지원하지 않는 프로토콜과 payload를 빠르게 시험하는 데 유리하다.

AIDAST에서는 자유 Bash 대신 sqlmap, nuclei, 브라우저 자동화 같은 도구를 allowlist adapter로 제공하고 모든 실제 요청을 RequestBroker 또는 동일한 정책·증거 계층에 연결해야 한다.

## 그대로 도입하지 않을 부분

[ARTEX Guard](https://github.com/Autumn-27/ARTEX/blob/main/guard/guard.go)는 코드 주석상 기존 RoE authorization-scope 메커니즘이 제거되어 있다. intercept rule과 fallback judge가 연결되지 않은 호출은 허용될 수 있다. AIDAST의 TargetPolicy와 물리 요청별 scope 검사는 유지해야 한다.

[ARTEX finding 도구](https://github.com/Autumn-27/ARTEX/blob/main/agent/tools.go)는 HTTP traffic reference가 없는 finding도 저장할 수 있다. 별도 retest 기능은 존재하지만 기본 finding 생성 과정에서 독립 재현이 필수는 아니다. AIDAST의 atomic reproduction spec과 독립 Validation은 유지해야 한다.

ARTEX coverage는 범위 안 asset 가운데 fact가 연결된 asset의 비율에 가까운 참고 수치다. endpoint×vulnerability class 단위의 완료 여부를 보장하지 않는다. AIDAST의 coverage ledger를 없애고 ARTEX의 depth 중심 완료 판정을 대신 사용하면 누락을 측정하기 어려워진다.

ARTEX 저장소에는 [TSec benchmark compose](https://github.com/Autumn-27/ARTEX/blob/main/docker-compose.bench.yml)가 있지만 분석한 트리에는 재현 가능한 recall, precision, 요청 예산 결과가 없다. README의 수상 설명이나 finding 개수만으로 AIDAST보다 실제 recall이 높다고 단정하지 않는다.

## AIDAST 개선 순서

### 1. 온라인 Attack Graph

Attack 중 발생한 다음 항목을 노드와 의존 관계로 저장한다.

- 확인된 finding과 재현 가능한 lead
- credential/session reference
- scanner-owned object와 second identity
- 역할과 권한 경계
- 새 endpoint, parameter, response differential
- 누락된 전제조건과 이를 획득하는 작업

새 durable fact나 finding이 생길 때 planner를 다시 실행한다. 기존 Pipeline DB를 진실 원본으로 유지하고 모델 transcript는 보조 자료로만 사용한다.

### 2. Coverage queue와 Lead queue

endpoint×vulnerability coverage는 빠뜨림을 막는 바닥선으로 유지한다. 별도의 Lead queue는 새 세션, 권한, 객체, credential, 높은 영향의 response differential에서 파생한 작업을 우선 처리한다. scheduler는 정해진 요청·시간 예산 안에서 두 queue 사이의 비율을 동적으로 조정한다.

### 3. 전제조건 resolver

`unsupported`나 `blocked_auth`를 다음과 같은 구조적 원인으로 분류한다.

- usable session 없음
- 필요한 role 없음
- second identity 없음
- scanner-owned object 없음
- CSRF, reset, invitation 같은 fresh token 없음
- 선행 요청이나 상태 변화가 실행되지 않음

복구 가능한 원인은 곧바로 종료하지 않고 전제조건 획득 task를 만든다. 성공하면 의존 coverage를 자동 재등록한다. 격리된 로컬 benchmark에서는 disposable fixture를 사용할 수 있고 일반 target에서는 대시보드에 구체적인 HITL action을 표시한다.

### 4. 공격 중 chaining

현재의 최종 Chaining 단계는 전체 chain을 확정하고 보고서용 증거를 정리하는 역할로 줄인다. Attack 중 finding이나 reusable fact가 생기면 후속 가설을 즉시 생성한다. 예를 들어 reset secret 노출이 확인되면 controlled reset, protected session, cross-account boundary 검증을 같은 Attack 실행 안에서 순서대로 예약한다.

### 5. 제한된 클라이언트 UI 합성

ARTEX 방식의 auth/permission/menu stub을 Recon 보조 모드로 사용해 숨겨진 SPA route와 outbound request schema를 수집한다. 합성된 요청은 실제 접근 증거나 finding으로 취급하지 않고 live target 확인을 통과해야 한다.

### 6. Broker 기반 외부 도구 adapter

외부 도구에는 승인된 origin, method, request budget, rate, concurrency를 주입한다. 도구가 생성한 모든 물리 요청과 응답을 기존 evidence ledger에 연결할 수 없는 경우 실행하지 않는다.

### 7. intent checkpoint와 부정 증거 품질

재시도 시 intent별로 이미 사용한 전략, payload family, 응답 특징, 획득한 사실, 남은 Todo를 이어받는다. 단일 401/403이나 한 종류 payload 실패는 `tested_negative`로 확정하지 않는다. 대조 요청과 대체 전략이 충분한 경우만 terminal negative로 처리한다.

## 비교 평가 기준

VulnBank와 OWASP Juice Shop을 초기화하고 ARTEX와 AIDAST에 동일한 scope, 계정, 모델, 요청 수, 시간 예산을 제공한다. 공개 답안은 실행 전에 agent에 제공하지 않고 완료 후 대조한다.

측정 항목은 다음과 같다.

- 독립 재현된 고유 root-cause recall
- 독립 재현 precision
- endpoint와 parameter recall
- missing precondition 때문에 종료된 비율
- confirmed finding당 요청 수와 모델 호출량
- 수동 복구 없이 보고서까지 완료된 비율
- 범위 밖 요청과 정책 위반 수
- 첫 confirmed finding까지 걸린 시간

90% 목표는 공개 finding 이름을 맞춘 비율이 아니라 독립 재현된 고유 root cause를 기준으로 두 로컬 benchmark에서 각각 계산한다. 최소 10회 반복 실행으로 평균과 최저치를 함께 확인한다.
