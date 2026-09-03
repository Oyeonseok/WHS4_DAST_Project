# Recon 정책 실행기 구현 설명

이 문서는 `recon-policy-compiler`가 만든 정형 JSON을 읽어 버그바운티의 여러
대상과 허용 도구를 안전하게 연결하는 코드의 역할을 설명한다.

## 실행 흐름

1. `recon-policy.json`을 schema 1.0 모델로 검증한다.
2. 정책의 allow 대상 중 URL, host, IP를 구체적인 HTTP(S) URL로 변환한다.
3. `execution_decision: allow`이고 blocking review가 없으며 전체 HTTP proxy를
   지원하는 등록 adapter만 선택한다.
4. 대상 하나마다 mitmdump와 정책 addon을 시작한다.
5. addon이 실제 요청마다 deny 우선으로 scheme, host, port, path를 재검사한다.
6. 실행 결과와 redacted flow를 execution ID로 묶어 SQLite에 저장한다.

wildcard host와 CIDR은 가능한 주소의 범위를 임의로 확대할 수 있어 자동으로
열거하지 않는다. 별도 발견 단계에서 얻은 구체 URL을 `--target`으로 전달하면
동일한 deny 우선 정책 검사를 거쳐 사용할 수 있다.

## 만든 파일

### `src/aidast/recon/policy.py`

정책 JSON용 strict Pydantic 모델과 `ScopeGuard`를 제공한다. 알 수 없는 필드,
잘못된 enum, 허용 근거 없는 도구, 기본 허용 정책을 거부한다. URL 검사는 deny
규칙을 먼저 적용하고 allow 규칙과 일치할 때만 성공한다.

### `src/aidast/recon/policy_plan.py`

정형 JSON을 실제 실행 계획으로 바꾼다. 명시적인 target/tool이 없으면 정책의
모든 구체 대상과 안전한 등록 도구를 자동 선택한다. 실행하지 못한 도구와
자동 확장하지 않은 대상에는 사유를 남긴다.

### `src/aidast/recon/policy_runner.py`

mitmdump 생명주기와 도구 실행을 담당한다. 임의 shell 문자열을 실행하지 않고
curl, httpx, katana, Playwright, ffuf, nuclei의 고정 adapter만 사용한다. proxy,
rate, concurrency, duration, header를 정책에서 가져오며 도구별 요청을 내부
execution ID로 추적한다.

### `src/aidast/recon/tools/mitm_addon.py`

mitmproxy 요청 hook이다. 범위 밖 요청, 필수 header 누락, rate 초과 요청을 대상에
전달하기 전에 403 또는 429로 차단한다. 내부 추적 header는 외부 서버에 보내지
않고 flow 기록에만 사용한다.

### `src/aidast/recon/policy_store.py`

`policy_runs`, `tool_executions`, `proxy_flows` SQLite 테이블을 관리한다. addon의
JSONL을 실행 종료 후 적재해 proxy 프로세스와 메인 프로세스의 동시 DB 쓰기를
피한다. header 인자와 민감 header는 redacted 형태로만 저장한다.

### `tests/test_policy_execution.py`

deny 우선 범위 검사, 자동 target/tool 계획, proxy 강제, Playwright 연결, 고정
header 보호, 민감 값 마스킹, SQLite 연결을 검증하는 테스트다.

## 변경한 파일

### `src/aidast/cli.py`

`aidast policy-run` 명령을 추가했다. 인자 없이 정책 전체를 계획하거나 실행할 수
있으며 `--plan-only`, 반복 가능한 `--target`/`--tool`, runtime input, header,
ffuf wordlist 옵션을 제공한다.

### `pyproject.toml`과 `uv.lock`

동일한 Python 환경에서 addon을 읽을 수 있도록 mitmproxy 런타임 의존성과 잠금
정보를 추가했다.

### `README.md`와 `docs/observation-mitmproxy.md`

자동 계획 사용법, 차단 기준, 저장 구조와 현재 안전 경계를 설명하도록 갱신했다.

## 확장 방법

새 도구는 사용자 입력을 shell 명령으로 그대로 전달하는 방식으로 추가하지 않는다.
`policy_runner.py`에 고정 인자 adapter를 구현하고 지원 ID 목록에 등록한 뒤 proxy
적용, 정책 제약, execution flow 연결 테스트를 추가해야 한다. 그러면
`policy_plan.py`가 같은 canonical tool ID를 가진 JSON 판별 결과를 자동으로
선택한다.
