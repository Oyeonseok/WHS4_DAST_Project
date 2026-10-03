# 09. 에이전트별 도구와 실제 작업

**질문:** 각 에이전트는 무엇을 판단하고, 어떤 도구가 실제 작업을 수행하는가?

## 먼저 구분할 네 가지

| 이름 | 뜻 |
| --- | --- |
| Agent | Codex 모델 호출이다. 범위 해석, 계획, 후보 판단, 문서 초안 같은 구조화된 결과를 제안한다. |
| Skill | Agent에게 주는 작업 지침 파일이다. `SKILL.md` 자체가 스캔 프로그램은 아니다. 자세한 선택 경로는 [Skill의 역할](10-skills.md)을 본다. |
| 실행 도구 | Python 코드나 `subfinder`·`katana` 같은 외부 프로그램이다. 실제 파일·DB·네트워크 작업을 한다. |
| Coordinator | 입력·정책·상태를 확인하고 Agent의 결과와 실행 도구를 연결한다. |

예를 들어 “Recon Agent가 `ffuf`를 쓴다”는 표현은 단순화다. Recon의 모델은 루트 경로를 제안할 수 있지만, `ffuf` 프로세스를 시작하고 결과를 저장하는 주체는 Python 실행 코드다. [ffuf 루트 선택](../../src/aidast/recon/tools/ffuf_root_selector.py), [endpoint 실행](../../src/aidast/recon/tools/endpoint_discovery.py)

## Scope와 Recon 계획

| 구성 요소 | 맡는 일 | 실제 도구·입력 |
| --- | --- | --- |
| Scope 분석 Agent | 프로그램 페이지에서 대상·제외 조건·규칙을 구조화한다. | `CodexMainAgent.collect_scope()`, `aidast-scope` Skill, 필요할 때 페이지를 보는 브라우저 기능. Python이 출처를 대조하고 운영자가 초안을 승인한다. [Agent](../../src/aidast/agents/main.py), [승인](../../src/aidast/orchestration/scope.py) |
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

## Native Attack Agent

`AttackCoordinator`는 Recon endpoint에서 가설과 coverage 항목을 계획한다. 실행할 항목이 있으면 `ExhaustiveAttackCoordinator`가 배치 Task를 만들고 Native Attack Agent를 부른다. Agent에게는 선택된 Hunt Skill과 아래 도우미가 임시 작업 공간에 제공된다. Skill은 취약점 유형을 판단하는 지침이며, 요청을 보내는 실행 도구는 아니다. [Attack 시작](../../src/aidast/orchestration/attack.py), [Agent 준비](../../src/aidast/agents/native_pipeline.py)

| 도우미 | 실제 작업 |
| --- | --- |
| `attack_db` | 허용된 조회와 attempt·fact·finding 기록, Task 상태 전환을 수행한다. [DB CLI](../../src/aidast/attack/db_cli.py) |
| `attack_request` | 단일 HTTP 요청을 정책·Task·공유 요청 한도에 맞춰 검사, 전송, 기록한다. [요청 CLI](../../src/aidast/attack/request_cli.py) |
| `attack_template` | 미리 정의된 템플릿의 probe와 matcher를 실행한다. 내부 전송은 `attack_request`의 보호 경로를 사용한다. [템플릿 CLI](../../src/aidast/attack/template_cli.py) |

도우미 호출은 `HelperCommandBroker`가 허용한 패키지 명령으로 전달한다. 배치 결과는 DB의 finding·attempt 및 coverage 상태와 다시 대조한다. [Broker](../../src/aidast/agents/helper_broker.py), [배치 검증](../../src/aidast/orchestration/coverage_attack.py)

## Chaining Agent

Chaining Agent는 Attack에서 근거가 있는 finding들을 입력으로 연결 가능성을 살핀다. `attack_db`로 관련 기록을 읽고, `chaining_db`로 후보·chain·실행 단계를 기록하며, `attack_request`로 정책에 묶인 재현 요청을 수행할 수 있다. `attack_template`는 Chaining에 제공되는 도우미 목록에 없다. [Agent 준비](../../src/aidast/agents/native_pipeline.py), [Chaining DB CLI](../../src/aidast/chaining/db_cli.py)

Coordinator는 `demonstrated` chain이 현재 단계의 성공한 실행과 연결됐는지 확인한다. 단순히 “두 finding이 이어질 것 같다”는 Agent 의견만으로 완료하지 않는다. [Chaining 결과 검증](../../src/aidast/orchestration/chaining.py)

## Validation Agent와 재현 실행기

Validation의 모델 호출은 주로 **판단·계획**이다. `CodexReplayPreparer`는 부족한 HTTP 재현 계획을 제안하고, `CodexEligibilityRunner`는 프로그램 정책상 해당 재현의 적합성을 평가한다. `CodexBlindValidationRunner`는 공격 주장을 보지 않은 평가와 이후 주장 비교를 분리한다. 필요할 때 영향 확대의 전제 조건도 별도 Agent가 계획한다. 이 모델 호출에는 셸·브라우저 도구를 열어 주지 않는다. [재현 준비](../../src/aidast/validation/orchestration/replay_preparation.py), [정책 적합성](../../src/aidast/validation/orchestration/eligibility_runner.py), [Blind 평가](../../src/aidast/validation/orchestration/codex_runner.py), [영향 계획](../../src/aidast/validation/orchestration/impact_runner.py), [Codex 실행 설정](../../src/aidast/agents/native_pipeline.py)

실제 재현은 Python의 `RuntimeReproductionRouter`가 수행한다. HTTP, Playwright 브라우저, OOB 관측, chain 경로가 있고, 의존성이 있는 환경에서는 multipart·WebSocket·gRPC·동시 요청 adapter도 붙는다. 결과와 대조군·증거를 모은 뒤 `DecisionEngine`이 최종 상태를 결정한다. [실행기 구성](../../src/aidast/validation/orchestration/native.py), [판정](../../src/aidast/validation/core/decision.py)

## Report Agent

`CodexReportWriter`는 검증된 case와 허용된 증거 ID를 입력으로 로컬 보고서 문안을 작성한다. 브라우저 탐색, 대상 요청, 제출은 하지 않는다. Python의 case runtime이 최신 `CONFIRMED` 결정과 증거 해시를 확인하고 `Report.md`·`Report.json` 초안을 저장한다. [Writer](../../src/aidast/agents/main.py), [case runtime](../../src/aidast/reporting/case_runtime.py), [ReportAgent](../../src/aidast/reporting/runtime.py)

## 확인할 질문

1. `ffuf`의 경로를 Agent가 고르는 일과 실제 HTTP 요청을 보내는 일은 각각 어디서 일어나는가?
2. Attack의 `attack_request`와 Validation의 재현 실행기는 어떤 입력·증거를 기준으로 동작하는가?
3. Skill 이름과 실행 프로그램 이름을 구별할 수 있는가?
