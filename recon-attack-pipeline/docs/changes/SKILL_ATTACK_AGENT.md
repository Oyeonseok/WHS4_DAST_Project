# Recon 기반 SKILL Attack Agent 구현

## 목표

확정된 파이프라인은 다음과 같다.

```text
Recon Agent → Attack Agent → Validation Agent → Report Agent
```

Attack Agent는 Recon이 전달한 완료된 스캔을 분석하고, 관찰 근거에 맞는
SKILL을 선택해 가설을 세운다. 이후 현재 실행에 대해 미리 승인된 테스트만
수행하고, 결과가 가설을 뒷받침할 때 Finding과 증거를 `Attack.db`에 저장한다.

## 변경 후 동작

1. `Handoff.json`과 읽기 전용 `Recon.db`의 해시·scan ID·완료 상태를 검증한다.
2. endpoint annotation을 `category:tag` 신호로 변환한다.
3. 신호와 일치하는 최대 8개의 `hunt-*` SKILL을 카탈로그에서 선택한다.
4. 패키지에 포함된 SKILL 본문을 읽고 SHA-256과 frontmatter 이름을 검증한다.
5. 신뢰된 테스트 실행기가 해당 endpoint·SKILL에 허용된 테스트 ID를 제공한다.
6. Codex 또는 주입된 planner가 Recon 근거와 SKILL을 보고 가설을 생성한다.
7. Python 검증기가 task, endpoint, skill, test ID의 정확한 귀속을 검사한다.
8. 승인된 테스트를 실행하고 attempt와 evidence를 먼저/직후에 기록한다.
9. planner가 실제 테스트 결과를 가설과 비교해 confirmed, rejected,
   inconclusive 중 하나로 판정한다.
10. confirmed 결과만 `findings`와 `attack_requests`에 기록한다.
11. Validation Agent가 기존 방식으로 `Attack.db`의 Finding, evidence, request를
    읽고 독립적으로 재검증한다.

## 실행 경계

SKILL은 AI가 참고하는 Markdown 지침이며 Python이나 shell로 직접 실행되지
않는다. 모델은 URL, 명령, 자격증명, payload를 실행 입력으로 만들 수 없다.
모델이 선택할 수 있는 것은 신뢰된 실행기가 현재 run에 대해 노출한
`test_id`뿐이다. 실제 네트워크·브라우저 동작과 Scope, 승인, 예산 검증은
`AttackTestExecutor` 구현이 담당한다.

이 분리는 SKILL 선택과 가설 수립을 AI에 맡기면서도, 실제 요청 권한은 기존
`RunAuthorization`, `TargetPolicy`, `PolicyService` 경계에 남기기 위한 것이다.

## 주요 코드

- `src/aidast/attack/skills.py`: SKILL 선택, 본문 로딩, 해시 검증
- `src/aidast/attack/skill_agent.py`: 가설 → 승인 테스트 → 판정 → Finding 루프
- `src/aidast/attack/store.py`: attempt, evidence, finding, request 저장 API
- `src/aidast/attack/workflow.py`: CLI의 신뢰 workflow 경계와 Agent 연결
- `src/aidast/agents/main.py`: Codex 구조화 가설·판정 planner
- `src/aidast/skills/attack/controller/SKILL.md`: Attack controller 지침
- `src/aidast/skills/attack/library/*/SKILL.md`: 59개 취약점·플랫폼 지침
- `tests/test_skill_attack_agent.py`: 전체 단계와 Validation handoff 검증

저장소 정리 과정에서 통합 폴더에 누락되어 CLI import를 막던
`src/aidast/scope/`와 `src/aidast/skills/scope/`도 직전 통합 소스에서
복구했다. 이 복구는 Scope → Recon 진입점이 새 Attack 흐름까지 도달하기 위해
필요하다.

## 데이터 계약

모델의 가설은 다음 값에 묶인다.

- `task_id`, `endpoint_id`: 검증된 Recon/Attack plan 식별자
- `skill_id`: 해시를 검증한 패키지 SKILL
- `test_ids`: 실행기가 제공한 승인 테스트 식별자
- `rationale`, `expected_result`: Recon 근거와 성공·실패 판단 기준

확인된 Finding은 동일한 run, scan, plan revision, task, endpoint에 묶인다.
응답 본문은 기존 Validation 계약에 따라 request에 보관되고, evidence에는
본문의 SHA-256과 길이가 저장된다. Validation Agent는 두 값이 일치하는지
검사한다. Finding과 supporting request는 하나의 SQLite transaction에서
저장되어 중간 실패로 불완전한 Finding이 공개되지 않는다.

## 호스트 통합 지점

`SkillAttackAgent`에는 두 구현을 주입한다.

- `SkillAttackPlanner`: `propose()`로 가설을 만들고 `assess()`로 결과를 판정
- `AttackTestExecutor`: `available_tests()`로 승인 테스트를 노출하고
  `execute()`로 선택된 테스트를 수행

기본 CLI가 신뢰할 실행기 없이 임의 요청을 보내지 않는 기존 정책은 유지된다.
`SkillAttackWorkflow`가 기존 CLI의 `AttackWorkflow` 프로토콜을 구현한다.
애플리케이션은 서명·만료·plan/policy/intent digest를 검증하는
`AttackAuthorizationProvider`와 PolicyService에 묶인 executor를 주입한다.
기본 CLI는 신뢰 provider가 없는 상태에서 승인을 추측하지 않는다.

## Astra 검토 반영

독립 검토에서 발견한 다음 문제를 수정했다.

- 실행 결과가 불명확할 때 반환값만 paused이고 DB가 running으로 남던 문제
- refutes 결과를 supporting evidence로 지정해 confirmed Finding을 만들 수 있던 문제
- task/skill/test 귀속 검증 전에 planner iteration을 valid로 기록하던 문제
- Finding과 supporting request가 서로 다른 transaction에 저장되던 문제
- 완료 실행을 다시 호출할 때 동일 테스트가 재실행될 수 있던 문제
- paused/running 실행의 재승인과 동시 worker가 중복 테스트를 전송할 수 있던 문제
- 외부 승인 취소 실패 후 로컬 승인까지 먼저 지워 재시도할 수 없던 문제
- Attack Agent가 failed/paused를 반환해도 CLI가 성공 종료하던 문제
- 같은 task의 여러 가설에서 나온 evidence가 Finding마다 뒤섞이던 문제

완료 run은 기존 Finding ID를 반환하며 다시 실행하지 않는다. running 또는
paused run의 자동 재실행도 차단해 불명확한 요청이 반복되지 않게 했다.
실행 전체에 SQLite lease를 적용하고 이미 존재하는 attempt는 전송 허가로
사용하지 않는다.
외부 승인 취소가 성공한 뒤 로컬 상태를 폐기하고, 완료되지 않은 Agent 실행은
CLI 오류로 전달한다. Finding에는 `hypothesis_id`를 별도로 저장하며 Validation
Agent는 동일한 가설의 attempt에서 나온 evidence만 읽는다.
승인 교체 이력이 있는 run은 아직 취소되지 않은 모든 외부 승인 ID를 SQLite
쓰기 잠금 안에서 취소한다. 외부 취소 하나라도 실패하면 로컬 변경을 롤백해
전체 취소를 다시 시도할 수 있고, 같은 시간의 승인 활성화와도 직렬화된다.

## 검증 항목

- 원본 controller 1개와 library SKILL 59개의 패키지 포함 여부
- 카탈로그 경로와 실제 본문의 SHA-256 일치 여부
- Recon annotation에 따른 SKILL 선택
- 가설이 허가되지 않은 endpoint, skill, test ID를 만들 때의 fail-closed 처리
- attempt가 테스트보다 먼저 저장되는 계약
- confirmed 결과만 Finding으로 저장되는 계약
- evidence body hash와 request response hash의 일치
- 생성된 `Attack.db`를 Validation Agent가 읽을 수 있는지 확인
- 같은 task에 여러 가설이 있어도 Finding별 evidence가 분리되는지 확인
- 외부 승인 취소 실패 및 Agent 실패가 성공으로 처리되지 않는지 확인
