# Validation 재구조화 변경 기록

이 문서는 Validation 재구조화 구현 변경을 누적 기록한다. 관련 구현을 완료할 때마다 최신 날짜의 항목을 문서 상단에 추가한다.

## 2026-09-14: configured HTTP OOB observer

- `HttpJsonOobObserver`가 `POST arm`에서 발급받은 정수 cursor를 attempt token과 메모리에
  묶고, trigger 이후 `GET poll`에 token·cursor·wait를 전달한다.
- poll 결과 중 arm cursor 이하의 stale event를 제거한 뒤 기존 OOB evaluator에
  token/protocol만 전달한다. 한 번 poll한 token은 다시 사용할 수 없다.
- observer endpoint는 기본 HTTPS, 동일 origin, redirect 금지이며 응답은 2xx JSON object와
  200KB·64 event 한도를 적용한다. 인증 header는 설정에 적힌 환경 변수를 dispatch
  시점에만 읽고 DB나 Validation evidence에 저장하지 않는다.
- `AIDAST_OOB_OBSERVER_CONFIG`가 있으면 native Coordinator가 기본 observer로 구성한다.
  설정이 없으면 기존처럼 OOB case만 preflight `INCONCLUSIVE`가 된다.
- cursor 이전 event 제외, 잘못된 token 보존, runtime auth, one-shot poll, insecure/mixed-origin
  설정 거절을 deterministic transport 테스트로 검증했다.

설계와 다른 점 및 이유:

특정 Interactsh/Burp API를 기본값으로 고정하지 않고 작은 HTTP JSON protocol을
사용했다. 현재 명세에 OOB 공급자가 정해져 있지 않으므로 벤더 API를 추측하면 배포별
인증·cursor 의미가 달라질 수 있다. 운영 adapter나 gateway가 명시된 arm/poll 계약을
제공하게 하면 fresh-callback 불변식을 유지하면서 공급자를 교체할 수 있다.

## 2026-09-14: outcome-unknown resume 차단

- 실패한 Validation stage를 재개할 때 해당 case의 `outcome_unknown` attempt, HTTP request,
  development action 수를 먼저 확인한다.
- 하나라도 있으면 같은 payload를 다시 보내지 않고 case를 `INCONCLUSIVE`로 종결하며
  decision에 `outcome_unknown_requires_manual_review`와 종류별 개수를 기록한다.
- transport 반환 전 중단을 재현한 테스트에서 resume이 새 요청이나 Agent 호출을 하지
  않고 stage를 정상적으로 닫는지 검증했다.

설계와 다른 점 및 이유:

원 설계는 중단 row를 `outcome_unknown`으로 정리하고 resume한다고만 정의했다. 이번
구현은 그 case의 자동 재전송을 금지한다. 원격 서버가 요청을 처리한 직후 local attempt
commit 전에 프로세스가 중단될 수 있어, 같은 요청을 반복하면 상태 변경이나 OOB trigger를
중복 실행할 수 있기 때문이다. 자동 판정 대신 수동 확인이 필요한 `INCONCLUSIVE`가 더
안전한 종결 상태다.

## 2026-09-14: configured credential backend resolver

- `PipelineCredentialResolver`가 `env://` 외 URI를 scheme별 trusted backend callable로
  해석할 수 있다. backend 반환값도 최종적으로 1~32개의 CR/LF 없는 HTTP header map인지
  같은 경계에서 검증한다.
- `keyring://SERVICE/ACCOUNT`는 Python keyring을 dispatch 직전에 지연 로딩하며, 저장된
  secret은 기존 `env://`와 같은 JSON header map 형식을 사용한다.
- `vault://`는 application이 `credential_backends={"vault": callable}`로 명시한 경우에만
  활성화된다. backend 오류나 미구성 상태는 요청 전에
  `credential_reference_unavailable`로 격리된다.
- native Coordinator builder가 configured backend map을 resolver에 전달하며 keyring/Vault
  성공·미구성·header 검증 회귀 테스트를 추가했다.

설계와 다른 점 및 이유:

Vault HTTP client와 인증 방식을 기본값으로 만들지 않았다. 현재 명세와 DB의
`vault://` URI에는 Vault 제품, 주소, namespace, KV 버전, 인증 수단이 없어서 이를
추측하면 엉뚱한 secret을 읽거나 별도 credential service로 임의 요청할 수 있다. 대신
운영 application이 검토한 backend를 명시적으로 주입하는 경계를 완성했다.

## 2026-09-14: demonstrated Chain native runtime replay

- `chain_execution_bindings`가 값 hash뿐 아니라 응답 추출 위치
  (`json_path`/`response_header`)와 다음 요청 주입 위치
  (`path_parameter`/`query_parameter`/`request_header`/`json_body`)를 선택적으로
  보존한다. 실제 scalar 값은 DB에 저장하지 않는다.
- Attack HTTP helper가 기존 `captures`에서 추출 계약을 만들고, Chaining 요청의
  `bindings.target_kind`와 `target_path`를 검증해 request ledger에 기록한다.
- Validation integrity gate는 모든 node에 HTTP runtime contract가 있고 모든 edge에
  명시적 위치 계약이 있을 때 `runtime_kind=chain` 계약을 만든다.
- native `ChainReproductionPort`는 각 control/target 시도마다 첫 단계부터 새로 실행하고,
  현재 응답에서 scalar를 추출해 바로 다음 요청에만 주입한다. 모든 요청은 기존
  TargetPolicy와 `validation_http_requests` budget/ledger를 통과하며 evidence에는 값 대신
  hash만 남긴다.
- 계약·adapter·요청 helper·Chaining producer 회귀 테스트를 추가했다.

설계와 다른 점 및 이유:

기존 demonstrated Chain은 추출/주입 위치를 저장하지 않았으므로 새 native adapter가
이를 추측하지 않는다. 위치 계약이 없는 기존 row는 그대로 읽을 수 있고 injected
adapter 호환성도 유지하지만, native 실행에서는 `INCONCLUSIVE`가 된다. 과거 binding
값을 재사용하거나 문자열 포함 관계만으로 주입 위치를 추정하면 Blind fresh replay와
오탐 방지 조건을 위반하기 때문이다.

## 2026-09-14: browser DOM 및 OOB callback runtime 계약

- 기존 HTTP runtime JSON/hash 호환성을 유지하면서 browser와 OOB 계약은
  `runtime_kind` discriminator로 확장했다. Attack `commit-finding`과 Candidate integrity
  gate가 세 kind를 같은 immutable 저장 경계에서 정규화하고 검증한다.
- browser 계약은 body 없는 navigation, 최대 10초 wait와 selector 존재, text 포함,
  attribute, final URL, console marker assertion을 정의한다. executor는 선언된 selector와
  request ledger ID만 반환해야 하며 실제 DOM/console 값은 evidence에 저장하지 않는다.
- OOB 계약은 trigger 안의 완전한 `{nonce}` token template, 허용 protocol, 최소 callback
  수와 최대 30초 wait를 정의한다. 매 attempt ID에서 새 nonce를 만들고 observer를 arm한
  후 기존 policy/credential broker로 trigger를 전송한다. stale token과 다른 protocol은
  양성 signal에서 제외한다.
- `RuntimeReproductionRouter`가 contract kind에 따라 HTTP/browser/OOB port를 선택한다.
  native builder는 isolated headless Playwright executor를 기본 사용하며 configured OOB
  observer를 받을 수 있다. OOB observer가 없으면 네트워크나 Agent 호출 전에 해당
  case만 격리한다.
- Playwright route는 navigation, script, XHR 등 모든 browser request를 current policy로
  검사하고 `validation_http_requests`에 request lifecycle을 기록한다. policy 밖 dependency는
  전송하지 않으며 incomplete request가 남은 DOM snapshot은 성공 evidence로 사용하지 않는다.

  설계와 다른 점 및 이유: OOB observer 자체는 기본 생성하지 않는다. callback 서비스의
  인증·cursor 계약이 없기 때문에 공개 callback 서비스를 임의로 호출하지 않기 위해서다.
  browser는 로컬 Playwright route와 기존 ledger를 결합해 이 신뢰 경계를 코드로 강제한다.

검증:

- browser selector allowlist, DOM/console 원문 비저장, out-of-scope final URL 거절
- browser subrequest의 current-policy 검사, redacted ledger와 incomplete request 처리
- OOB attempt별 nonce, arm-before-trigger, stale token/protocol 제외와 redacted HTTP ledger
- HTTP/browser/OOB runtime routing 및 기존 HTTP 계약 회귀 집중 unittest 15개 통과
- 전체 unittest 368개 중 코드 테스트 367개와 별도 Reporting pytest 30개 통과

## 2026-09-14: native env credential resolver

- `PipelineCredentialResolver`가 Pipeline.db의 opaque credential ID를 read-only로 조회하고
  `env://NAME`이 가리키는 환경 변수의 JSON HTTP header map을 dispatch 시점에만 해석한다.
- header 이름, 개수, 값 크기와 CR/LF를 검증한다. 환경 변수 값이나 resolved header는
  reproduction spec과 Validation evidence에 저장하지 않으며 기존 request ledger가
  Authorization, Cookie 등 민감 header 값을 제거한다.
- native Coordinator가 이 resolver를 기본 사용한다. 환경 변수가 없거나 malformed인
  경우와 아직 backend가 없는 `keyring://`/`vault://` reference는 요청 전에
  `credential_reference_unavailable`로 case만 격리한다.
- preflight와 실제 dispatch 사이에 환경 값이 사라지는 경우도 raw 오류를 저장하지 않고
  `identity_auth` blocker observation으로 바꾼다.

  설계와 다른 점 및 이유: `env://` 값의 형식을 단일 token으로 추정하지 않고 명시적인
  JSON header map으로 제한했다. Cookie, Authorization 또는 대상별 custom auth header를
  안전하게 구분하면서 credential 원문을 DB schema에 추가하지 않기 위해서다.

검증:

- read-only credential reference 조회와 valid JSON header resolve
- 누락된 env, CR/LF header injection, 미구성 backend의 preflight 거절
- runtime contract/request broker/Coordinator 관련 집중 unittest 12개 통과
- credential 추가 후 전체 unittest의 코드 테스트 359개와 별도 Reporting pytest 30개 통과

## 2026-09-14: native HTTP Validation 기본 실행 연결

- `build_native_validation_coordinator`가 current `TargetPolicy.json`, generic
  `HttpReproductionPort`, lazy Codex runner를 기본 실행 구성으로 묶는다.
- 전체 `aidast run`은 Chaining 직후 이 기본 Coordinator를 자동 실행한다. 별도
  `validate run/resume`은 `--policy`를 받으며 생략하면 `Pipeline.db` 옆
  `TargetPolicy.json`을 사용한다.
- HTTP runtime contract가 없는 기존 Finding, 지원되지 않는 credential backend의 Finding,
  Chain은 preflight에서 요청과 Agent 호출 없이 해당 case만 `INCONCLUSIVE`로 종료한다.
  하나의 미지원 case 때문에 Validation stage 전체가 실패하지 않는다.
- 테스트용 injected Coordinator 경계는 유지해 offline transport와 결정론적 fixture를
  계속 사용할 수 있다.

  설계와 다른 점 및 이유: 이 단계의 기본 연결은 unauthenticated HTTP Finding과
  `env://` JSON header credential을 사용하는 Finding까지만 실제 replay를 수행한다.
  미구성 backend를 추정하거나 HTTP assertion을 browser/OOB/Chain에 적용하면 잘못된
  요청과 판정을 만들 수 있으므로 지원 범위를 preflight에서 명시적으로 제한한다.

검증:

- 전체 run 경로가 DB 옆 policy로 native Coordinator를 구성하고 호출
- shared validate run의 명시적 policy 선택과 기존 injected 경로 호환
- 미지원 HTTP case가 attempt와 Agent 호출 없이 `INCONCLUSIVE`로 격리
- compileall 및 전체 unittest 360개 중 코드 테스트 359개 통과. pytest import가 필요한
  기존 Reporting module은 `/opt/anaconda3/bin/pytest`에서 30개 통과

## 2026-09-14: target별 HTTP runtime contract와 generic replay adapter

- Attack `commit-finding`이 선택적으로 `runtime_contract`를 받아 target, positive control,
  negative control 각각의 HTTP request와 response assertion을 strict schema로 검증한다.
- path/query parameter, 비밀이 아닌 header, JSON/text body를 bounded request로 렌더링하고
  status, header, body marker, JSON path, 최소/최대 duration assertion을 지원한다.
- 정규화한 contract와 SHA-256을 immutable reproduction spec row에 함께 저장한다. Validation
  무결성 게이트가 JSON schema와 hash를 다시 검사한 뒤에만 BlindCase로 전달한다.
- `HttpReproductionPort`는 injected request builder/evaluator가 없어도 저장된 contract로
  요청을 실행하고 assertion을 결정론적으로 평가한다. 실제 assertion 값은 evidence에
  남기지 않고 expected/actual hash와 pass 여부만 저장한다.
- credential header는 contract에서 거절하며 기존 opaque identity reference와 trusted
  credential resolver 경계를 그대로 사용한다. 모든 initial/redirect hop은 기존
  `ValidationRequestBroker`의 current TargetPolicy와 ledger 제한을 통과한다.

  설계와 다른 점 및 이유: profile 파일에 모든 target의 marker, object ID, timing threshold를
  미리 넣지 않았다. 같은 취약점 유형도 실제 endpoint와 응답 형식이 다르므로 Attack이
  확인한 target별 실행값을 Finding과 함께 hash 고정하는 편이 오탐을 줄인다.

  설계와 다른 점 및 이유: runtime contract는 현재 HTTP Finding에서 선택 사항이다. 기존
  Finding 호환성을 유지하고 browser, OOB, 다단계 Chain을 HTTP 응답 assertion으로 잘못
  축소하지 않기 위해서다. contract가 없는 case에서 generic HTTP adapter는 성공을
  추정하지 않고 실행을 거절한다.

검증:

- runtime request 렌더링, credential header 거절, assertion 결과 원문 비저장
- Attack transaction의 canonical contract/hash 저장과 완료 stage 무결성 gate 전달
- 저장 contract를 사용한 실제 HTTP adapter 경로 및 redacted request ledger
- runtime/adapter/Attack/Coordinator/schema 집중 unittest 28개 통과

## 2026-09-13: KNOWN exact key에서 signal 종류 제거

- `signal_types`를 KnownCandidate, KnownMatcher 입력과 exact metadata key에서 제거했다.
- source의 Validation profile hash 일치 조건도 함께 제거했다. profile hash는 signal과
  control 같은 검증 방법의 변경까지 포함하므로 중복 대상의 정체성을 비교하는 key로
  사용하지 않는다.
- KNOWN은 vuln class, normalized endpoint, method, injection 위치, parameter 이름/역할,
  identity 역할, Hunt Skill이 정확히 같은지를 기준으로 판정한다.

  설계와 다른 점 및 이유: 직전 구현은 expected signal 종류를 exact key에 포함했다.
  signal은 같은 취약점을 OOB callback, response diff, authorization 등 어떤 방식으로
  관찰했는지를 나타내며 취약점 자체의 endpoint·trigger·권한 조건이 아니다. 검증 방법이
  다르다는 이유만으로 동일 대상을 별개 Finding으로 취급하지 않도록 중복 key에서 제외한다.

검증:

- signal field 없이 나머지 exact metadata가 모두 같을 때 deterministic source 선택
- 각 exact metadata 또는 source current status가 다르면 match하지 않음
- matching, Coordinator, Repository, schema 집중 unittest 22개 통과

## 2026-09-13: KNOWN을 실행 메타데이터 exact match로 단순화

- KNOWN 판정에서 payload Levenshtein 계산과 `0.85` threshold를 제거했다.
- 같은 scan의 현재 `CONFIRMED` Finding 중 vuln class, normalized endpoint, method,
  injection 위치, parameter 이름/실행 역할, identity 역할, Hunt Skill, expected signal
  종류가 모두 정확히 일치하는 source만 KNOWN으로 선택한다.
- identity 역할과 signal 종류는 집합 의미로 정렬해 비교하고, 여러 source가 맞으면
  case ID lexical 순으로 결정한다. source의 저장 Skill과 현재 profile hash도 일치해야 한다.
- shared Pipeline.db v9 계약에서 `known_similarity` column과 Repository 인자를 제거했다.
  기존 v9 DB도 case와 foreign key를 보존하며 table을 재구성한다.
- payload normalization과 구조 hash는 reproduction spec 변조 검출에만 유지한다.

  설계와 다른 점 및 이유: 기존 §8.6은 세 개 exact key 뒤 payload 문자열의 Levenshtein
  유사도 `0.85`를 사용했다. 표현이 다른 동등 payload를 놓치고, 반대로 문자가 비슷한
  다른 mechanism을 KNOWN으로 처리해 fresh replay를 생략할 수 있으므로 문자열 거리를
  중복의 의미 근거로 사용하지 않는다. 이번 범위는 구조화된 메타데이터 exact match까지만
  구현하며 payload semantic 비교 LLM은 아직 연결하지 않는다.

  설계와 다른 점 및 이유: 현재 reproduction spec에는 독립된 `parameter_role`과 권한
  boundary field가 없다. 이번 구현은 `(injection_location, parameter_name)`을 parameter의
  실행 역할로, `required_identity_roles`를 사용 가능한 identity/권한 조건으로 비교한다.
  더 세밀한 semantic role이 필요하면 Attack producer와 schema 계약을 함께 확장해야 한다.

검증:

- 8개 실행 메타데이터 각각이 다를 때 match하지 않고 순서만 다른 role/signal은 동일하게 처리
- v9의 `known_similarity` column 제거 후 case와 foreign key 보존
- matching, schema, repository, Coordinator, shared Reporting, pipeline contract 관련
  집중 unittest 37개 통과
- 전체 unittest 350개 중 코드 테스트 349개 통과. `.venv`에 pytest가 없어 import되지
  않은 Reporting module은 시스템 pytest에서 34개 통과

## 2026-09-13: 구현 현황 이해 문서 추가

- 커밋별 누적 기록과 구현 계획을 오가지 않고도 현재 구조를 파악할 수 있도록
  `VALIDATION_IMPLEMENTATION_OVERVIEW.md`를 추가했다.
- 후보 무결성 검사부터 KNOWN, replay, Blind/unblind, 결정론적 상태 판정, impact,
  Chain, Reporting까지의 전체 흐름과 각 계층의 책임을 한 문서로 정리했다.
- KNOWN에서 임베딩을 사용하지 않는 이유, LLM이 담당하는 의미 판정의 범위, impact와
  설치 수·버그바운티 eligibility의 차이, production adapter가 아직 남아 있다는 현재
  한계를 명시했다.
- 기존 설계와 달라진 Agent 권한, persisted Codex session, runtime assertion 보류와
  legacy Reporting 병행의 이유도 해당 항목 아래에 기록했다.

## 2026-09-13: Hunt Skill별 Validation 효과 기준 구체화

- 58개 profile의 `profile_defined_*` placeholder를 제거하고 각 Hunt Skill에서 fresh
  replay가 입증해야 하는 보안 효과를 서로 다른 criterion으로 명시했다. 예를 들어
  IDOR는 다른 test identity의 object/state, CORS는 credentialed cross-origin read,
  SSRF는 target server에서 비롯된 controlled callback을 요구한다.
- positive control은 동일 transport·identity·parser·browser·callback·timing channel의
  harmless health baseline으로, negative control은 inert same-shape input에서 target
  effect가 없어야 하는 조건으로 통일해 두 control의 역할을 분명히 했다.
- signal class별 impact rule을 작성해 단순 오류·지연·markup을 곧바로 높은 영향으로
  평가하지 못하게 하고, boundary·sensitivity·actor requirements가 인용해야 할 실제
  관찰을 구분했다.
- development action은 signal class에 맞춰 credential refresh, second identity/resource
  setup, encoding adjustment, callback registration, timing baseline/concurrency 보정 중
  최대 두 개만 허용하도록 정리했다.

  설계와 다른 점 및 이유: profile의 effect criterion은 구체화했지만 status/body/DOM/OOB
  관찰을 판정하는 정량 threshold나 selector·marker는 임의로 만들지 않았다. 이 값은
  실제 target과 Attack이 남긴 runtime slot에 종속되므로 공통 문구로 자동 생성하면
  false positive를 만들 수 있다. concrete adapter 연결 전까지 profile은 허용된 의미와
  control 목적을 제한하고, 실행 가능한 assertion 세부값은 별도 검증 계약으로 남긴다.

검증:

- packaged Hunt Skill 58개가 각각 고유한 target criterion과 stable kind를 가지며
  `profile_defined` placeholder가 남지 않는지 검사
- 모든 profile이 공통 harmless positive control, inert negative control과 최대 2개
  development action 제한을 통과

## 2026-09-13: 단일 native Validation Agent 세션

- `CodexMainAgent`에 Validation 전용 structured session 실행 경계를 추가했다.
  첫 Blind pass에서 받은 Codex thread ID를 고정하고, claim comparison과 다음 case는
  `codex exec resume <thread-id>`로 같은 세션에서 이어간다.
- Validation 모델은 요청대로 낮춘 `gpt-5.6-sol`을 별도 기본값으로 고정했다.
  각 pass마다 `BlindAssessment` 또는 `ClaimComparison` strict output schema를 새로
  적용하며, resume 결과가 다른 thread ID를 반환하면 실패한다.
- 해당 세션은 read-only sandbox에서 shell, unified exec, apps, web, browser와
  computer 도구를 모두 비활성화한다. replay가 필요한 첫 case에서만 runner를
  lazy 생성하므로 KNOWN·무결성 실패 등 network 전 종결 case만 있으면 Agent ID가 없다.
- demonstrated Chain은 합성 hash를 다시 검증하고 모든 node의 연결 Hunt Skill과
  profile을 순서대로 같은 세션에 제공하되 terminal profile을 판정 기준으로 표시한다.
- Coordinator가 직접 만든 native runner의 임시 staging directory는 stage 성공 또는
  실패 시 정리한다. 외부에서 주입한 runner의 lifecycle은 호출자가 계속 소유한다.

  설계와 다른 점 및 이유: §6.3은 Agent에게 target/control 실행용 restricted helper를
  제공하는 형태를 설명한다. 현재 구현은 Agent의 도구를 전부 제거하고 Coordinator가
  고정한 batch를 trusted `ReproductionPort`로 먼저 실행한 뒤, Agent에는 정제된 observation
  DTO만 전달한다. LLM이 요청 시점·대상·payload를 선택할 권한 자체를 없애 scope 및 횟수
  제한을 Python 상태 머신 한곳에서 강제하기 위해 더 좁은 권한 경계를 택했다.

  설계와 다른 점 및 이유: 같은 native Agent를 unblind pass까지 유지하려면 Codex의
  persisted thread가 필요하므로 이 경로에는 `--ephemeral`을 사용하지 않는다. staging
  파일은 stage 종료 시 삭제하지만 Codex 자체의 로컬 session 보존 정책은 따른다.

검증:

- Blind prompt에는 claim이 없고 같은 work directory와 정확한 thread ID로 unblind
  prompt가 resume되는지 검증
- native command가 `gpt-5.6-sol`, tool-disabled read-only 시작, exact thread resume를
  사용하는지 subprocess fixture로 검증
- replay case에서 runner가 정확히 한 번 lazy 생성되고 결과의 Agent ID가 실제 thread
  ID와 연결되는지 검증
- `TMPDIR=/private/tmp` 기준 전체 unittest 351개 중 코드 테스트 350개 통과.
  `.venv`의 pytest 미설치로 import되지 않은 Reporting module은 시스템 pytest에서
  34개 통과

## 2026-09-12: demonstrated Chain 종단간 Blind replay

- 모든 node의 최신 Validation 결과가 `CONFIRMED|KNOWN`인 demonstrated Chain을
  node gate 이후 실제 end-to-end Blind replay로 연결했다.
- chain integrity gate가 성공한 Chaining stage와 execution, 연속된 2~4개 node,
  execution step의 finding 순서, 마지막 step의 성공 terminal assertion, 각 node의
  immutable reproduction spec과 최신 Validation snapshot을 재검증한다.
- 각 node의 endpoint, method, payload template, identity reference와 단계 사이의
  binding 이름·방향을 순서가 있는 합성 Blind case로 만든다. 이전 실행의 binding
  값·response와 terminal impact claim은 assessment가 고정될 때까지 공개하지 않는다.
- chain은 finding과 별개의 control/target batch를 실행하며 terminal effect를 세 영향
  축으로 다시 평가한다. node impact 점수를 더하지 않으며 `UNDERPOWERED` chain에는
  Finding용 impact expansion hypothesis를 생성하지 않는다.
- Validation은 chain 결과를 `validation_cases`, attempt, evidence에만 기록한다.
  통합 테스트는 replay 전후 9개 Chaining write table의 전체 row가 같은지 검증한다.

  설계와 다른 점 및 이유: 별도의 chain Validation profile 형식은 명세에 정의되어
  있지 않다. 따라서 chain Blind contract는 node별 Skill/profile hash를 canonical
  aggregate hash로 묶고, 관측 signal과 control 기준은 terminal node의 검증된 profile을
  사용한다. 체인의 판정 대상이 마지막 단계에서 실제 도달한 terminal effect라는 §9
  규칙을 따르면서, 아직 정의되지 않은 임의 chain profile을 생성하지 않기 위해서다.

검증:

- 두 node가 각각 `CONFIRMED`, `KNOWN`인 demonstrated Chain에서 별도 5회 replay 후
  terminal impact를 재평가해 chain case `CONFIRMED`
- replay 전후 Chaining 관련 9개 table의 row 불변
- `TMPDIR=/private/tmp` 기준 전체 unittest 348개 중 코드 테스트 347개 통과.
  `.venv`의 pytest 미설치로 pytest 기반 module import 1건만 제외했으며 해당
  Reporting suite는 시스템 pytest에서 34개 통과
- 소스 compileall과 `git diff --check` 통과

## 2026-09-12: Blind freeze 이후 실행 재개

- Validation stage가 Blind assessment를 DB에 고정한 뒤 claim 비교 중 중단돼도
  같은 `stage_run_id`로 `unblinding` 단계부터 재개하도록 연결했다.
- 재개 시 저장된 assessment의 strict schema, case·Blind case hash와 canonical
  content hash를 다시 검증하고, assessment가 인용한 완료 attempt와 observation
  evidence를 같은 case·stage에서 재구성한다.
- claim comparison evidence까지 이미 저장된 crash 상태에서는 해당 객체의 schema,
  content hash, assessment·Attack claim binding을 검증한 뒤 재사용한다.
- 고정 assessment 재개 경로는 HTTP replay와 Blind assessment Agent 호출을 다시
  수행하지 않으며, 동일 assessment/comparison evidence도 중복 저장하지 않는다.

  설계와 다른 점 및 이유: 명세는 crash 지점 전체에 대한 복구를 요구하지만 현재
  구현은 DB transaction 경계로 식별 가능한 완료 batch, 고정 assessment, 저장된
  comparison을 재사용한다. transport가 응답을 받았지만 ledger·attempt 완료 transaction
  전에 프로세스가 종료된 경우에는 원격 부작용 발생 여부를 증명할 수 없으므로 기존
  lifecycle대로 `outcome_unknown`으로 보존하며 성공으로 추정하지 않는다.

검증:

- claim 비교 직전에 강제 중단한 뒤 resume 시 request 0회, assessment 재호출 0회,
  comparison 1회로 `CONFIRMED` 완료
- 기존 attempt 5개와 Blind assessment evidence 1개가 중복 없이 유지됨

## 2026-09-12: shared Validation 실행 계층 1차 연결

- native Attack `commit-finding`이 Finding, supporting Attack request, 공식
  `finding_reproduction_specs`를 한 transaction에서 기록하도록 변경했다.
  supporting attempt의 Skill·endpoint·fingerprint와 request의 method·policy
  digest가 일치하지 않으면 Finding 자체를 commit하지 않는다.
- `CandidateIntegrityGate`를 추가해 completed Attack stage, confirmed attempt,
  단일 Hunt Skill, packaged Skill hash, endpoint, request, policy, payload 및 spec
  digest, credential role과 Attack evidence를 재현 전에 검증한다. 실패 case는
  요청 없이 `INCONCLUSIVE`로 종결한다.
- chain 항목을 제외한 packaged Hunt Skill 58개에 machine-readable Validation
  profile을 추가하고, profile schema·이름·Skill hash·전체 coverage를 검사하는
  `SkillProfileResolver`를 구현했다.

  설계와 다른 점 및 이유: 이번 profile들은 실행 계약을 먼저 고정하기 위한
  보수적인 signal-class mapping과 공통 control 초안이다. IDOR에는 실제 impact
  expansion path 두 개를 작성했지만 나머지 Skill의 control/impact 기준은 아직
  취약점별로 세분화되지 않았다. 이름만 채운 profile을 실제 취약점별 검증이
  끝난 것으로 오인하지 않도록 전체 profile 의미 검토를 남은 작업으로 유지한다.

- `ValidationCoordinator`를 추가해 scan 및 targeted case 선택, 기존 case
  revalidation, KNOWN 선판정, control과 fresh target 3회, 혼재 시 추가 2회,
  blocker development 1 cycle, Blind assessment 고정, claim 공개·비교, impact와
  최종 상태 commit을 shared DB 흐름으로 연결했다. Agent schema 오류는 한 번
  수정 기회를 준 뒤 해당 case만 `INCONCLUSIVE`로 격리한다.
- `ReproductionPort`, `PrerequisiteResolverPort`, `HttpReproductionPort` 계약을
  추가했다. Coordinator가 Agent에게 범용 DB나 command helper를 주지 않고,
  검증된 관찰 DTO만 전달하도록 실행 권한을 좁혔다.
- `CodexBlindValidationRunner`를 추가해 검증된 base Skill, 연결 Hunt Skill과
  machine profile로 BlindAssessment와 ClaimComparison을 분리된 strict structured
  output으로 생성할 수 있게 했다. 두 pass는 하나의 논리 runner ID와 case에 묶인다.
- `ValidationRequestBroker`를 추가했다. initial request와 redirect hop마다
  current TargetPolicy, stage/case/attempt ownership, rate, concurrency와 총 요청
  예산을 dispatch 직전에 검사하고 `validation_http_requests`에 예약·결과를
  기록한다. query와 credential header 값은 ledger에 저장하지 않는다.
- `ImpactGapAnalyzer`를 추가했다. `UNDERPOWERED` Finding에서 현재 stage
  evidence와 검증된 profile path만 사용해 최대 3개의 비실행 가설을 저장한다.
- shared CLI 계약에 `validate run Pipeline.db --scan-id`의 finding/chain selector와
  `validate resume Pipeline.db --stage-run-id`를 추가했다. 실행 권한을 가진
  application이 주입한 동일 Coordinator만 호출하며, 기본 CLI가 임의로 네트워크
  실행 객체를 만들지는 않는다.
- 정상 `aidast run`도 application이 ValidationCoordinator를 주입한 경우 Chaining
  직후 같은 `run(scan_id)` API를 자동 호출한다.
- reproduction spec을 update/delete할 수 없도록 DB trigger를 추가했고 Validation
  evidence 저장과 attempt 완료 경계에 metadata sanitization을 적용했다.

  설계와 다른 점 및 이유: native Codex Validation Agent의 단일 프로세스 staging,
  취약점별 real request builder/evaluator는 아직 연결되지 않았다. 현재 shared CLI가
  injected Coordinator를 요구하는 이유는 이 adapter들이 없는 상태에서 기본 CLI가
  네트워크 요청을 실행하거나 성공을 가장하지 않게 하기 위해서다. 이 기록 당시
  chain은 node gate까지만 구현됐으며, end-to-end replay는 위의 후속 변경에서 연결됐다.

검증:

- 전체 unittest 346개 중 코드 테스트 345개 통과
- `.venv`에 pytest가 없어 전체 unittest의 pytest 기반 module import 1건은 환경상
  제외됐고, 해당 Reporting suite는 `TMPDIR=/private/tmp`를 지정한 시스템 pytest로
  별도 실행해 34개 통과
- 신규 Coordinator, profile, request broker 및 native Attack 계약 테스트 통과
- Validation/Attack/Pipeline 관련 unittest suite와 Reporting pytest 34개 통과

남은 작업:

- 58개 profile의 실제 adapter threshold, selector·marker와 전문가 의미 검토
- 실제 HTTP/browser/OOB request builder와 signal evaluator 연결
- 기본 native adapter 구성으로 `Recon -> Attack -> Chaining` 자동 호출 활성화
- 새 실행 경로가 기본 동작이 된 뒤 legacy 7 Question Validation.db 제거

## 2026-09-12: shared Validation 기반 구현

- Pipeline.db를 schema v9로 올리고 Validation case, attempt, evidence, development action, impact hypothesis, HTTP ledger, reproduction spec 테이블을 추가했다.
- Blind 입력과 Attack claim을 분리하고 Blind assessment가 고정된 뒤에만 claim을 공개하도록 제한했다.
- 당시 KNOWN 판정은 임베딩 없이 exact key와 정규화된 Levenshtein 유사도 `0.85` 기준으로 구현했다. 이 단계는 2026-09-13 변경에서 완전히 제거됐다.

  이유: 이 방식은 원 설계 §8.6과 같다. 먼저 취약점 유형, endpoint template, parameter 이름이 모두 같은 후보만 비교하므로 의미 검색이 필요하지 않다. 이후 payload 구조의 작은 차이만 결정론적으로 계산하면 된다. 임베딩은 모델·버전·실행 환경에 따라 결과가 변할 수 있고 동일 입력의 재현성, 오프라인 실행, 임계값 설명 가능성을 약화하므로 KNOWN 자동 판정에 사용하지 않았다. 현재 `0.85`는 동일 취약점 확률이 아니라 정규화된 문자열 편집 유사도다.

- Boundary, Sensitivity, Actor requirements의 세 축 영향 점수와 `UNDERPOWERED`, 상태 판정 우선순위를 결정론적으로 구현했다.

  참고: 이 점수는 원 설계의 보편적인 기술 영향 기준이다. 설치 수나 개별 버그바운티의 접수·보상 규칙은 포함하지 않으며, 이후 별도의 프로그램 eligibility 판단으로 분리해야 한다.

- Repository에 case·stage·evidence 소유권 검증, decision hash, optimistic concurrency와 KNOWN source 무효화를 추가했다.
- Validation stage 실패 시 진행 중 record를 `outcome_unknown`/`interrupted`로 정리하고 동일 stage ID로 재개할 수 있게 했다.
- 증거 메타데이터에서 secret, 민감 헤더, raw body를 제거하고 깊이·항목·바이트 제한을 적용했다.
- CONFIRMED case를 읽는 Report.db v2를 추가했다. KNOWN은 source case를 반환하고 CONTESTED는 review-only이며, decision 변경 시 기존 보고서를 `stale`로 표시한다.

  설계와 다른 점 및 이유: 원 설계는 기존 `validation_id` 기반 Report binding을 새 case binding으로 교체하도록 요구한다. 현재는 기존 Report.db v1 reader를 제거하지 않고 case 기반 v2와 병행한다. 새 Validation 실행 경로가 아직 완성되지 않은 상태에서 v1을 즉시 제거하면 기존 보고서와 회귀 테스트를 읽을 방법이 없어지므로, 전환 완료 전까지 읽기 호환성을 유지했다. 새 case 보고서는 설계대로 DB 전체 hash 대신 `scan_id`, `case_id`, decision hash와 정렬된 evidence hash에 묶인다.

- `validate status --scan-id/--case-id`와 `report run Pipeline.db --case-id`를 추가했다.

  설계와 다른 점 및 이유: 원 설계는 `validate run`, targeted run, `resume`과 pipeline 자동 실행까지 새 Coordinator에 연결한다. 현재 Coordinator와 ReproductionPort가 없으므로 실행 명령을 성공한 것처럼 노출하지 않고, 완성된 shared DB 기능인 status와 Report만 새 계약에 연결했다. 기존 `validate run`은 전환 중 호환성을 위해 아직 7 Question Validation.db 경로를 사용한다.

- 새 Attack HTTP request에 canonical TargetPolicy SHA-256을 기록한다. 기존 request의 digest는 추정해 채우지 않는다.

검증:

- 관련 unittest 53개 통과
- 기존 Reporting pytest 31개 통과
- 전체 unittest 330개에서 코드 테스트 통과. `.venv`의 pytest 미설치로 pytest 기반 모듈 import 1건은 별도 시스템 pytest로 검증
- 소스 compileall 및 `git diff --check` 통과

남은 작업:

- reproduction spec producer와 CandidateIntegrityGate
- Validation profile 전체 및 Skill binding
- ReproductionPort, Validation request broker와 실제 adapter
- restricted helper, native Validation Agent와 Coordinator
- retry/development 실행 연결과 ImpactGapAnalyzer
- demonstrated Chain Validation
- `validate run/resume`, targeted run과 pipeline 자동 실행
- 새 실행 경로 전환 후 기존 7 Question Validation.db 제거

상세 구현 상태와 작업별 수용 조건은 [implementation plan](../superpowers/plans/2026-09-12-validation-refactor-implementation.md)을 따른다.
