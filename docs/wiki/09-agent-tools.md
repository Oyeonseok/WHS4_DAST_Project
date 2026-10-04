# 09. 에이전트별 도구와 실제 작업

**질문:** 각 에이전트는 무엇을 판단하고, 어떤 도구가 실제 작업을 수행하는가?

## 먼저 구분할 네 가지

| 이름 | 뜻 |
| --- | --- |
| Agent | 이 위키에서는 AI의 작업 역할을 가리킨다. 모델 호출 자체와 자율적인 행동 선택은 구분한다. 정해진 입력을 해석하는 호출은 LLM 워크플로이며, 관측을 바탕으로 다음 도구 행동을 선택하는 부분은 제한된 에이전트 동작으로 해석할 수 있다. [역할 경계](07-agent-boundaries.md) |
| Skill | Agent에게 주는 작업 지침 파일이다. `SKILL.md` 자체가 스캔 프로그램은 아니다. 자세한 선택 경로는 [Skill의 역할](10-skills.md)을 본다. |
| 실행 도구 | Python 코드나 `subfinder`·`katana` 같은 외부 프로그램이다. 실제 파일·DB·네트워크 작업을 한다. |
| Coordinator | 입력·정책·상태를 확인하고 Agent의 결과와 실행 도구를 연결한다. |

예를 들어 “Recon Agent가 `ffuf`를 쓴다”는 표현은 단순화다. Recon의 모델은 루트 경로를 제안할 수 있지만, `ffuf` 프로세스를 시작하고 결과를 저장하는 주체는 Python 실행 코드다. [ffuf 루트 선택](../../src/aidast/recon/tools/ffuf_root_selector.py), [endpoint 실행](../../src/aidast/recon/tools/endpoint_discovery.py)

이 페이지는 기본 Native 통합 경로를 중심으로 설명한다. 레거시·standalone 명령의 별도 adapter와 DB를 모든 Agent에게 공통 제공되는 도구로 일반화하지 않는다. [CLI의 경로 분기](../../src/aidast/cli.py), [Attack 상세](04-attack-chaining.md)

## Scope와 Recon 계획

| 구성 요소 | 맡는 일 | 실제 도구·입력 |
| --- | --- | --- |
| Scope 역할의 AI | 프로그램 화면 선택과 대상·제외 조건·규칙 해석을 맡는다. | CLI 기본 native는 `collect_scope()`에서 Codex 브라우저 수집과 분석을 함께 받는다. WebUI 기본 runtime-browser는 Python Reader가 수집하고 `choose_scope_view()`·`interpret_captured_scope()`를 호출한다. 공통 구현 클래스는 `CodexMainAgent`다. [Agent](../../src/aidast/agents/main.py), [WebUI 작업자](../../src/aidast/web/scope_workflow.py), [입출력 상세](02-scope-recon.md) |
| Recon 계획 Agent | 승인 자산에 대한 실행 단계와 대상별 정책을 제안한다. | `create_recon_plan()`, `create_target_policies()`. 실제 Task·`TargetPolicy`는 Python이 승인 범위와 정책 조건을 검사한다. [Agent](../../src/aidast/agents/main.py), [Task](../../src/aidast/orchestration/recon.py) |
| Recon 보조 Agent | 관측 태그, 오프라인 검토, JS 패턴 후보, `ffuf` 시작 경로 등을 제안한다. | 저장된 관측이나 endpoint를 입력으로 받아 구조화된 결과를 낸다. 제안 자체가 새 요청이나 승인 범위를 만들지는 않는다. [태깅](../../src/aidast/recon/annotations.py), [오프라인 검토](../../src/aidast/recon/agent.py), [패턴 제안](../../src/aidast/recon/tools/ai_patterns.py), [ffuf 루트](../../src/aidast/recon/tools/ffuf_root_selector.py) |

## Recon 실행기: 어떤 프로그램이 무엇을 하나?

이 도구들은 `ReconExecutor`가 Task 유형과 `TargetPolicy`에 따라 실행한다. URL 자산에는 도메인·wildcard 자산 발견 단계가 필요하지 않을 수 있다. 선택 도구가 빠진 경우 일부 단계는 건너뛰지만, wildcard 발견의 `subfinder`와 정책 강제에 필요한 `mitmproxy`는 해당 조건에서 필수다. [Task 실행](../../src/aidast/recon/executor.py), [설치·선택 조건](../../README.md#recon-실행-도구)

| 도구 | 하는 작업 | 코드 위치 |
| --- | --- | --- |
| `subfinder` | 허용된 wildcard 도메인 아래의 하위 도메인 후보를 찾는다. 나온 주소는 다시 범위 검사한다. | [자산 발견](../../src/aidast/recon/executor.py), [실행 래퍼](../../src/aidast/recon/tools/asset_dns_port.py) |
| `dnsx` | 호스트 이름의 DNS 해석 결과를 수집한다. | [DNS Task](../../src/aidast/recon/executor.py), [실행 래퍼](../../src/aidast/recon/tools/asset_dns_port.py) |
| `naabu`·`nmap` | 허용된 포트 범위에서 열린 포트를 찾는다. | [포트 Task](../../src/aidast/recon/executor.py), [실행 래퍼](../../src/aidast/recon/tools/asset_dns_port.py) |
| Python HTTP probe | URL 응답 여부와 상태·헤더·본문을 확인하고 origin 판단의 재료를 만든다. 별도 `httpx` 바이너리를 호출하지 않는다. | [HTTP probe](../../src/aidast/recon/tools/http_probe.py), [origin Task](../../src/aidast/recon/executor.py) |
| `Playwright` | 브라우저 로그인·화면 상호작용·브라우저에서 보이는 요청과 링크를 수집한다. | [endpoint 발견](../../src/aidast/recon/tools/endpoint_discovery.py), [브라우저 드라이버](../../src/aidast/recon/tools/playwright_driver.py) |
| `katana` | 표준·headless 크롤링으로 URL과 endpoint 후보를 찾는다. | [Katana 경로](../../src/aidast/recon/tools/endpoint_discovery.py) |
| `ffuf` | 선택된 루트에 단어 목록을 적용해 경로 후보를 찾는다. 사용 여부와 루트는 정책·관측에 따라 제한된다. | [ffuf 경로](../../src/aidast/recon/tools/endpoint_discovery.py), [루트 선택](../../src/aidast/recon/tools/ffuf_root_selector.py) |
| `mitmproxy` | endpoint 발견의 HTTP 요청을 정책·예산으로 제어하고 허용·차단 결과를 캡처한다. | [Executor](../../src/aidast/recon/executor.py), [프록시 래퍼](../../src/aidast/recon/tools/mitm_proxy.py) |

앞선 HTTP probe에는 공유 `RequestBroker`가 정책과 요청 한도를 적용한다. endpoint 발견의 Playwright·Katana·ffuf 등은 남은 예산을 공유하는 `mitmproxy` 경로를 사용한다. [RequestBroker](../../src/aidast/core/request_broker.py), [예산 전달](../../src/aidast/recon/executor.py)

Recon 관측과 도구 실행 기록은 **`Recon.db`**에 저장된다. 현재 계획·Recon Task 객체는 메모리에 구성되며, `Recon.db`의 `pipeline_runs`는 Task ID·실행 단계·상태 등의 도구 실행 기록이다. 이를 전체 Task 계획을 저장한 별도 Task 테이블이라고 설명하지 않는다. `TargetPolicy.json`과 Recon 검토 산출물은 별도 파일이다. [CLI의 계획·파일 저장](../../src/aidast/cli.py), [Task 구성](../../src/aidast/orchestration/recon.py), [Recon schema·실행 기록](../../src/aidast/recon/db.py)

## Native Attack Agent

기본 통합 경로에서는 Handoff가 끝난 뒤 `AttackCoordinator`가 `plan_recon_attack()`을 호출한다. **가설 계획 AI**는 저장된 Recon 관측만 분석하고 Python이 결과를 검사한다. 실제 요청을 보내는 **실행 Attack Agent**와 별도 역할이다. 이미 source/benchmark annotation이나 재사용할 계획이 있으면 새 가설 호출을 생략할 수 있다. [시작 순서](../../src/aidast/orchestration/attack.py), [오프라인 가설 계획](../../src/aidast/attack/recon_hypotheses.py), [Handoff 이후 호출](../../src/aidast/cli.py)

Python은 검증된 가설을 Coverage로 만들고, 실행할 항목이 있으면 `ExhaustiveAttackCoordinator`가 배치 Task를 준비한다. 기본 통합 경로는 최대 8개 Task씩 배정한다. Codex 오케스트레이터는 **배치당 실행 Attack Agent 하나**를 호출하도록 지시받는다. Agent에게 선택된 Hunt Skill과 아래 도우미를 제공하며, Skill은 실행 프로그램이 아니라 지침이다. [배치 준비](../../src/aidast/orchestration/coverage_attack.py), [기본 batch 크기](../../src/aidast/orchestration/attack.py), [Agent 준비·호출 지시](../../src/aidast/agents/native_pipeline.py)

| 도우미 | 실제 작업 |
| --- | --- |
| `attack_db` | 허용된 조회와 attempt·fact·finding 기록, Task 상태 전환을 수행한다. [DB CLI](../../src/aidast/attack/db_cli.py) |
| `attack_request` | 단일 HTTP 요청을 정책·Task·공유 요청 한도에 맞춰 검사, 전송, 기록한다. [요청 CLI](../../src/aidast/attack/request_cli.py) |
| `attack_template` | 미리 정의된 템플릿의 probe와 matcher를 실행한다. 내부 전송은 `attack_request`의 보호 경로를 사용하며 템플릿 결과 자체가 finding을 자동 생성하지는 않는다. [템플릿 CLI](../../src/aidast/attack/template_cli.py) |

도우미 호출은 `HelperCommandBroker`가 허용한 패키지 명령으로 전달한다. Agent는 내부 DB 경로 대신 broker 참조를 받아 사용한다. 조사 중 attempt·fact·finding·재현 명세를 **`Pipeline.db`**에 기록하고, 반환 JSON은 마지막에 DB 기록·미해결 attempt·Task 완료 상태와 대조한다. finding은 마지막 검사가 끝난 뒤에만 생기는 것이 아니다. [Broker](../../src/aidast/agents/helper_broker.py), [DB 기록](../../src/aidast/attack/db_cli.py), [배치 검증](../../src/aidast/orchestration/attack.py), [Coverage 갱신](../../src/aidast/orchestration/coverage_attack.py)

현재 broker의 `start()`는 POSIX를 요구한다. 따라서 이 Native 도우미 경로를 Windows Python에서 그대로 실행할 수 있다고 단정하지 않는다. WSL/Linux 등 실제 운영 경로의 검증 여부는 별도로 확인해야 한다. [환경 조건](../../src/aidast/agents/helper_broker.py), [Attack 상세](04-attack-chaining.md)

## Chaining Agent

Chaining Agent는 Attack에서 근거가 있는 finding들을 입력으로 연결 가능성을 살핀다. `attack_db`로 관련 기록을 읽고, `chaining_db`로 후보·chain·실행 단계를 기록하며, `attack_request`로 정책에 묶인 재현 요청을 수행할 수 있다. `attack_template`는 Chaining에 제공되는 도우미 목록에 없다. [Agent 준비](../../src/aidast/agents/native_pipeline.py), [Chaining DB CLI](../../src/aidast/chaining/db_cli.py)

Coordinator는 `demonstrated` chain이 현재 단계의 성공한 실행과 연결됐는지 확인한다. 단순히 “두 finding이 이어질 것 같다”는 Agent 의견만으로 완료하지 않는다. [Chaining 결과 검증](../../src/aidast/orchestration/chaining.py)

## Validation Agent와 재현 실행기

Validation의 모델 호출은 주로 **판단·계획**이다. `CodexEligibilityRunner`는 프로그램 정책상 재현의 적합성을 평가하고, `CodexReplayPreparer`는 부족한 HTTP 재현 계획을 제안한다. `CodexBlindValidationRunner`는 Attack 주장을 숨긴 평가와 평가 동결 뒤 주장을 공개한 비교를 **별도 Codex 세션**으로 분리한다. 필요할 때 영향 보완의 전제 조건도 별도 AI가 계획한다. 이 호출에는 셸·브라우저 도구를 열어 주지 않는다. [재현 준비](../../src/aidast/validation/orchestration/replay_preparation.py), [정책 적합성](../../src/aidast/validation/orchestration/eligibility_runner.py), [Blind·비교 세션](../../src/aidast/validation/orchestration/codex_runner.py), [영향 계획](../../src/aidast/validation/orchestration/impact_runner.py), [Codex 실행 설정](../../src/aidast/agents/native_pipeline.py)

실제 재현은 Python의 `RuntimeReproductionRouter`와 adapter가 수행한다. HTTP, Playwright 브라우저, OOB 관측, chain 경로가 있고, 의존성과 재현 명세가 지원되는 환경에서는 multipart·WebSocket·gRPC·동시 요청 adapter도 붙는다. case·재현·ledger·증거·적합성 평가·판정은 **`Pipeline.db`**에 저장한다. 결과와 대조군·평가·비교의 구조화된 값을 모아 `DecisionEngine`이 최종 상태를 결정한다. [실행기 구성](../../src/aidast/validation/orchestration/native.py), [Coordinator](../../src/aidast/validation/orchestration/coordinator.py), [Repository](../../src/aidast/validation/persistence/repository.py), [판정](../../src/aidast/validation/core/decision.py)

프로필별 의미 증거 검사에는 IDOR의 호출자·객체 소유권 같은 요구사항도 있지만 현재는 **`audit` 모드**다. 부족한 의미 증거 기록 자체가 판정 점수나 확정을 자동 차단하는 강제 게이트는 아니다. 재현 신호·독립 의미 증거·최종 판정의 차이는 [Validation 상세](05-validation-report.md)를 본다. [audit 구현](../../src/aidast/validation/core/profile_evidence.py)

## Report Agent

`ReportAgent`는 Python wrapper다. 먼저 현재 완료된 `CONFIRMED` case와 Scope eligibility·decision 해시·증거 참조를 읽어 별도 **`Report.db`**에 컨텍스트를 준비한다. Writer가 연결돼 있으면 입력을 마스킹하고 `CodexReportWriter`를 호출한다. Writer는 구조화된 문안을 작성하며 기본 호출에는 브라우저·셸·대상 요청 도구가 없다. [준비·저장](../../src/aidast/reporting/case_runtime.py), [Python wrapper·마스킹 입력](../../src/aidast/reporting/runtime.py), [Writer](../../src/aidast/agents/main.py)

Python은 작성 후 소스 최신성을 다시 확인하고 초안의 형식·case·platform·context 해시·허용된 증거 ID를 검사한다. 초안은 `Report.db`의 `report_drafts`, 출력 파일은 **`Report.md`·`Report.json`**이다. 자동 Report 단계의 상태는 **`Pipeline.db`**, CLI sink가 연결된 모델 호출 메타데이터는 **`<RESULT_ROOT>/logs/CodexCalls.db`**에 따로 저장한다. 인용 ID 검사는 문장의 의미적 사실성까지 증명하지 않으며 파일은 로컬 초안이다. [초안 계약](../../src/aidast/reporting/models.py), [불변 저장](../../src/aidast/reporting/case_runtime.py), [자동 stage](../../src/aidast/reporting/auto.py), [호출 로그](../../src/aidast/core/model_calls.py), [Report 상세](05-validation-report.md)

## 확인할 질문

1. `ffuf`의 경로를 Agent가 고르는 일과 실제 HTTP 요청을 보내는 일은 각각 어디서 일어나는가?
2. Attack의 `attack_request`와 Validation의 재현 실행기는 어떤 입력·증거를 기준으로 동작하는가?
3. Skill 이름과 실행 프로그램 이름을 구별할 수 있는가?
