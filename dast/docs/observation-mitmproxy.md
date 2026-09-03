# 정책 기반 mitmproxy 실행 구조

`aidast policy-run`은 승인된 `scope.md`에서 컴파일된
`recon-policy.json`을 실행 시점의 유일한 정책 입력으로 사용한다.

```text
recon-policy.json
        ↓ validate
PolicyToolRunner
        ├─ tool/target/runtime input 검사
        ├─ 안전한 고정 command adapter 생성
        └─ mitmdump 시작
                ↓
        PolicyEnforcer addon
        ├─ deny 우선 scope 검사
        ├─ required header/rate 검사
        ├─ 허용 요청만 목적지로 전달
        └─ redacted JSONL 기록
                ↓
        PolicyRunStore → SQLite
```

## 실행 예

```bash
aidast policy-run ./recon-policy.json https://app.example.com \
  --tool katana \
  --db ./recon-policy.sqlite3 \
  --flow-log ./recon-policy-flows.jsonl \
  --header "X-Bug-Bounty:researcher-name"
```

임의의 셸 명령이나 사용자 지정 옵션 문자열은 받지 않는다. runner에 등록된
adapter가 정책의 rate, concurrency, duration, proxy 설정만 사용해 명령을
만든다. 정책의 `required_arguments`가 adapter에 구현되지 않았거나
`forbidden_arguments`가 명령에 포함되면 실행을 중단한다.

## 차단 기준

- policy에 없는 tool
- `execution_decision`이 `allow`가 아닌 tool
- blocking review item이 남아 있는 tool
- allow rule과 일치하지 않거나 deny rule과 일치하는 target/request
- 필수 runtime input 또는 header가 없는 실행
- provider/raw/mixed 트래픽처럼 현재 target HTTP guard로 통제할 수 없는 tool
- 실행 후 해당 execution ID로 proxy flow가 한 건도 확인되지 않은 tool

URL, host, scheme, port, path prefix를 요청마다 검사한다. deny rule이 항상
allow rule보다 우선하므로 크롤러가 외부 호스트로 이동하거나 redirect를
따르더라도 addon에서 다시 차단된다.

## 저장 데이터

addon 프로세스는 SQLite에 직접 쓰지 않는다. 메인 프로세스와의 동시 쓰기를
피하기 위해 redacted JSONL을 append하고, proxy가 종료된 뒤 메인 프로세스가
SQLite로 옮긴다.

SQLite 테이블:

- `policy_runs`: 정책 파일, 대상, 전체 실행 상태
- `tool_executions`: tool ID, redacted 인자, 종료 코드, stdout/stderr
- `proxy_flows`: 요청 메타데이터, allow/block 판정과 근거

요청·응답 body는 저장하지 않는다. Authorization, Cookie, API key와 정책에
정의된 필수 header 값은 `<redacted>`로 저장한다. 내부
`X-AIDAST-Execution` header는 addon이 목적지 전달 전에 제거하고 DB 연결에만
사용한다.

## 현재 경계

`subfinder` 같은 provider 도구는 대상이 아닌 외부 API에 요청한다. 현재
policy schema에는 provider 목적지 allowlist가 없으므로 target allowlist를
재사용하지 않고 실행을 거부한다. `nmap` 같은 raw network tool도 mitmproxy로
전체 트래픽을 검증할 수 없어 실행하지 않는다.
