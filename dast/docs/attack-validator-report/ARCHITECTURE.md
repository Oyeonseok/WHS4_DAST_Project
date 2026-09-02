# Attack → Validator → Report 파이프라인 설계

## 1. 핵심 원칙

**LLM이 공격의 주체이고, Python은 결과 저장만 한다.**

- Recon과 동일한 패턴: Python은 정규화/저장에만 사용, 판단/실행은 LLM Agent가 수행
- 각 Agent는 전용 SKILL.md를 로드하여 해당 취약점의 전체 공격 지식을 갖춤
- 블랙박스 동적 분석: LLM이 직접 HTTP 요청을 보내고, 응답을 읽고, 취약점을 판정
- LLM은 DB를 직접 건드리지 않는다. 구조화된 JSON만 반환하고, 오케스트레이터가 DB 저장 처리

## 2. 전체 아키텍처

```
AttackCoordinator.run(scan_id)        ← orchestration/attack.py
    │
    ├─ [Recon 완료] DB에 endpoints, parameters, sessions 적재됨
    │
    ├─ Phase 1: Attack Agent (Codex CLI subprocess)
    │     ├─ SKILL.md 스테이징 (aidast-hunt-idor)
    │     ├─ Pydantic → output schema JSON 생성
    │     ├─ 프롬프트에 recon 데이터 + scope 임베딩
    │     ├─ LLM이 후보 선별 → curl로 HTTP 요청 전송
    │     ├─ LLM이 응답을 읽고 IDOR 여부 판정
    │     └─ AttackResult JSON 반환 (output schema 강제)
    │               ↓
    │     오케스트레이터가 finding + evidence → DB 저장
    │
    ├─ Phase 2: Validator Agent (finding마다 즉시 생성)
    │     ├─ SKILL.md 스테이징 (aidast-validator)
    │     ├─ 프롬프트에 finding + evidence + 기존 confirmed 목록 임베딩
    │     ├─ LLM이 curl로 공격 재실행 (재현 검증)
    │     ├─ LLM이 7 Gate Question 판정
    │     └─ ValidationResult JSON 반환
    │               ↓
    │     오케스트레이터가 validation + finding status → DB 저장
    │
    ├─ Phase 3: Report Agent (CONFIRMED만)
    │     ├─ SKILL.md 스테이징 (aidast-report)
    │     ├─ 프롬프트에 finding + evidence + validation 임베딩
    │     ├─ LLM이 보고서 작성
    │     └─ ReportResult JSON 반환
    │               ↓
    │     오케스트레이터가 마크다운 파일 저장
    │
    └─ confirmed finding_id 목록 반환
```

## 3. Codex CLI 실행 패턴

모든 LLM Agent는 `CodexMainAgent._run_attack_agent()`로 실행된다.

```
codex exec
  --skip-git-repo-check --ephemeral --ignore-user-config
  --disable apps --disable standalone_web_search
  --disable browser_use --disable computer_use --disable in_app_browser
  --color never
  --cd {work_dir}                      ← 임시 디렉토리
  --output-schema {schema.json}        ← Pydantic → JSON Schema
  --output-last-message {result.json}  ← 결과 파일
  -                                    ← stdin으로 프롬프트 입력
```

**Scope 수집(`_run_structured`)과의 차이점:**
- `shell_tool` 활성화 (curl 사용을 위해 `--disable shell_tool` 제거)
- `--sandbox read-only` 제거 (네트워크 접근 필요)
- 타임아웃 3배 (`timeout_seconds * 3`)
- 브라우저 비활성화 (API 테스트에 불필요)

## 4. Output Schema 패턴

LLM이 자유형 텍스트가 아닌 **구조화된 JSON**만 반환하도록 강제한다.

```
Pydantic Model (models.py)
    ↓ model_json_schema()
JSON Schema 파일 (work_dir/{name}.schema.json)
    ↓ --output-schema 플래그
Codex CLI가 스키마에 맞는 JSON만 출력
    ↓ --output-last-message
결과 파일 (work_dir/{name}.json)
    ↓ model_validate_json()
Python Pydantic 객체 → 오케스트레이터에서 사용
```

### 모델 정의 (`attack/models.py`)

| 모델 | Agent | 용도 |
|---|---|---|
| `AttackResult` | Attack | findings 목록 + 요약 |
| `AttackFinding` | Attack | 취약점 1건 (title, severity, CVSS, CWE, evidence) |
| `AttackEvidence` | Attack | HTTP 요청/응답 증거 1건 (role, method, url, headers, body, status) |
| `ValidationResult` | Validator | verdict + 7 gate 상세 + confidence |
| `GateDetail` | Validator | Gate 1개의 pass/fail/null + detail |
| `ReportResult` | Report | title, severity, CVSS, CWE, report_markdown |

## 5. Python vs LLM 역할 분리

```
LLM Agent (두뇌)                     Python (저장소)
──────────────────                   ─────────────────
recon 데이터로 후보 판단               ← 프롬프트에 JSON 임베딩
curl로 HTTP 요청 직접 전송            
응답을 직접 읽고 해석                  
IDOR 여부 판정                        
CVSS/CWE 분류                        
JSON 결과 반환              →         DB에 저장 (attack/db.py)
7 Gate 판정 실행             →         DB에 저장 (attack/db.py)
보고서 작성                  →         파일로 저장 (reports/)
```

**Python이 하지 않는 것:**
- HTTP 요청 전송 (LLM이 curl로 직접)
- 응답 비교/해석 (LLM이 직접)
- 후보 선별 로직 (LLM이 직접)
- 심각도 판정 (LLM이 직접)
- 보고서 생성 (LLM이 직접)

## 6. 파이프라인 실행 방식: Orchestrator Callback

| 대안 | 문제점 |
|---|---|
| DB Polling | 지연시간 발생, 불필요한 쿼리 반복 |
| Message Queue (Redis 등) | MVP에 과잉한 외부 의존성 |
| Direct Function Call | attack → validator 강결합 |
| **Orchestrator Callback** ✅ | 분리 + 즉시성 + 외부 의존 없음 |

`AttackCoordinator`가 Attack Agent의 finding을 받으면 즉시 Validator Agent를 생성하여 검증.
CONFIRMED이면 즉시 Report Agent를 생성하여 보고서 작성.

## 7. DB 스키마 확장

Recon DB에 3개 테이블만 추가 (기존 테이블 수정 없음):

### findings (취약점 발견 기록)
```sql
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    endpoint_id TEXT,                    -- nullable (recon에 없는 엔드포인트도 가능)
    vuln_type TEXT NOT NULL,
    severity TEXT,
    title TEXT NOT NULL,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cwe_id TEXT,
    status TEXT DEFAULT 'pending',       -- pending → confirmed/rejected/inconclusive
    found_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
);
```

### attack_requests (공격 요청/응답 증거)
```sql
CREATE TABLE IF NOT EXISTS attack_requests (
    request_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    role TEXT NOT NULL,                  -- user_a, user_b, unauthenticated
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    request_headers TEXT,                -- JSON
    request_body TEXT,
    response_status INTEGER,
    response_headers TEXT,               -- JSON
    response_body TEXT,                  -- 최대 10,000자로 자름
    response_time_ms INTEGER,
    sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
```

### validations (7 Gate 판정 결과)
```sql
CREATE TABLE IF NOT EXISTS validations (
    validation_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    verdict TEXT NOT NULL,               -- CONFIRMED / REJECTED / INCONCLUSIVE
    gate_results TEXT,                   -- JSON (7 Gate 상세)
    reasoning TEXT,
    confidence REAL,                     -- 0.0 ~ 1.0
    validated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
```

### 인덱스
```sql
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint_id ON findings(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_attack_requests_finding_id ON attack_requests(finding_id);
CREATE INDEX IF NOT EXISTS idx_validations_finding_id ON validations(finding_id);
```

## 8. 디렉토리 구조

```
dast/src/aidast/
├── agents/
│   └── main.py                     _run_attack_agent() 추가
├── orchestration/
│   ├── scope.py                    (기존 - 수정 안 함)
│   ├── recon.py                    (기존 - 수정 안 함)
│   └── attack.py                   AttackCoordinator (신규)
├── attack/
│   ├── __init__.py
│   ├── db.py                       DB 스키마 + 저장 헬퍼
│   └── models.py                   Pydantic output schema (AttackResult 등)
├── recon/                          (기존 - 수정 안 함)
└── skills/
    ├── scope/SKILL.md              (기존)
    ├── attack/idor/SKILL.md        IDOR 블랙박스 동적 분석
    ├── validator/SKILL.md          7 Gate Question 검증
    └── report/SKILL.md             버그바운티 보고서 작성
```

## 9. SKILL.md 파일 역할

| SKILL.md | LLM Agent가 하는 일 | 출력 |
|---|---|---|
| `attack/idor/SKILL.md` | recon 데이터로 후보 판단 → curl로 HTTP 전송 → 응답 해석 → IDOR 판정 | `AttackResult` JSON |
| `validator/SKILL.md` | curl로 공격 재실행 → 7 Gate 검증 → verdict 판정 | `ValidationResult` JSON |
| `report/SKILL.md` | 증거 조합 → 마크다운 보고서 작성 | `ReportResult` JSON |

## 10. 데이터 흐름 요약

```
Recon DB (endpoints, parameters, sessions)
    ↓ _load_recon_data()로 JSON 추출
Attack Agent 프롬프트 (recon JSON + Scope.md 임베딩)
    ↓ Codex CLI subprocess
AttackResult JSON
    ↓ save_finding_with_evidence()
findings + attack_requests 테이블
    ↓ finding별로 Validator 생성
ValidationResult JSON
    ↓ save_validation()
validations 테이블 + finding status 업데이트
    ↓ CONFIRMED만 Report 생성
ReportResult JSON
    ↓ write_text()
reports/{finding_id}_report.md 파일
```
