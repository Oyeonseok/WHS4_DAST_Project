# 정책 실행 상황별 구조

이 문서는 승인된 `Scope.md`가 정책으로 컴파일된 뒤 각 상황에서 어디까지
실행되는지 설명한다.

## 전체 구조

```text
approved Scope.md
        │
        ▼
aidast-recon-policy Skill
        │  network/tool execution 없음
        ▼
ReconPolicy schema 1.0 검증
        │
        ▼
recon-policy.json 원자적 저장
        │
        ▼
PolicyExecutionPlan ── block/review/unsupported 제거
        │
        ▼
PolicyToolRunner ── runtime input/header/tool 설치 선검사
        │
        ▼
mitmdump + PolicyEnforcer addon
        │  요청마다 deny 우선 scope 재검사
        ▼
허용된 대상 요청 ── 결과와 redacted flow를 SQLite 저장
```

## 상황 1: 바로 실행 가능한 정책

`execution_decision`이 `allow`이고 필수 입력이 모두 준비된 target HTTP 도구는
고정 adapter에 연결된다. runner가 로컬 mitmdump를 시작하고 모든 도구 요청에
proxy와 내부 execution ID를 강제로 넣는다. addon은 ID를 기록한 뒤 외부 서버에
보내기 전에 내부 header를 제거한다.

```bash
aidast policy-run ./recon-policy.json --tool curl
```

성공하면 `policy_runs`, `tool_executions`, `proxy_flows`에 같은 실행 관계가
저장된다. proxy flow가 한 건도 확인되지 않으면 성공으로 인정하지 않는다.

## 상황 2: 필수 사용자명·토큰·header가 없는 경우

정책에는 실제 값을 저장하지 않는다. `runtime_inputs`와 `required_headers`에
필요 조건만 기록한다. 실행 시 값이 없으면 runner가 mitmdump와 도구를 시작하기
전에 차단한다.

```bash
aidast policy-run ./recon-policy.json \
  --runtime-input researcher_identity=example-researcher \
  --header "X-Program-Researcher:example-researcher"
```

입력값은 SQLite 명령 인자에서 마스킹되며, 정책이 고정한 header와 내부 execution
ID는 CLI 입력으로 덮어쓸 수 없다.

## 상황 3: 금지 또는 검토가 필요한 도구

`block`과 `review`는 실행 가능한 값이 아니다. 자동 계획에서는 제외 사유를
출력하고, `--tool`로 명시 요청하면 오류로 종료한다. 이 경우 proxy와 도구는
시작되지 않는다.

```text
ffuf: execution_decision=block  → 실행 안 함
nuclei: execution_decision=review → 실행 안 함
curl: execution_decision=allow → 나머지 조건 검사
```

## 상황 4: 범위 밖 요청 또는 redirect

초기 target뿐 아니라 도구가 만든 모든 후속 요청을 addon에서 다시 검사한다.
deny 규칙이 allow보다 우선한다. 외부 host, 금지 path, 허용되지 않은 port 또는
scheme으로 이동하면 addon이 로컬 403 응답을 만들고 실제 목적지에는 전달하지
않는다. 초당 요청 제한을 넘으면 429로 차단한다.

## 상황 5: wildcard host 또는 CIDR

정책 컴파일러는 wildcard와 CIDR을 보존하지만 실행 계획은 이를 임의로 열거하지
않는다. 별도 승인된 발견 단계에서 구체 URL을 얻었다면 `--target`으로 전달한다.
그 URL이 전체 allow/deny 규칙을 통과할 때만 실행된다.

```bash
aidast policy-run ./recon-policy.json \
  --target https://concrete.example.test \
  --tool httpx
```

## 상황 6: provider API 또는 raw network 도구

`subfinder`의 provider API 트래픽과 `nmap`의 raw network 트래픽은 target용
mitmproxy allowlist만으로 완전히 검증할 수 없다. 현재 schema에 provider 목적지
allowlist와 raw traffic guard가 없으므로 자동 실행하지 않는다.

## 상황 7: 기존 schema 0.1 파일

`exact_allowlist`, `deny_patterns`, 문자열형 `tools`를 가진 0.1 파일은 실행하지
않는다. 승인된 원본 Scope를 1.0으로 다시 컴파일한다.

```bash
aidast policy-compile ./artifacts/program/scope.md \
  --output ./artifacts/program/recon/recon-policy.json

aidast policy-run ./artifacts/program/recon/recon-policy.json --plan-only
```

`--plan-only`이 성공한 뒤 필요한 runtime input과 header를 넣어 실제 실행한다.
