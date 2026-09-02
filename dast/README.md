# AI DAST

멀티에이전트 AI DAST의 Scope 수집 CLI입니다. 로그인된 Codex CLI가 네이티브 Scope Skill을 읽고 프로그램 URL에 직접 접속해 정책을 해석한 뒤, 검토 가능한 `Scope.md`를 생성합니다.

## Requirements

- Python 3.13 이상
- [uv](https://docs.astral.sh/uv/)
- [Codex CLI](https://github.com/openai/codex)
- Playwright Chromium

## Install from GitHub

```bash
uv tool install git+https://github.com/<OWNER>/<REPOSITORY>.git
uvx --from playwright playwright install chromium
```

설치 확인과 최초 로그인:

```bash
aidast --help
aidast login
```

`aidast login`은 설치된 Codex CLI의 로그인 화면을 열고, 완료 후 로그인 상태를 자동 검증합니다. 인증 정보는 AI DAST나 저장소가 아니라 Codex CLI의 사용자 설정에 저장됩니다.

## Collect Scope

```bash
aidast scope "프로그램 URL"
```

산출물은 프로그램별로 구분됩니다.

```text
Scope/<platform>/<program>/
├── Scope.md
├── Scope.json
├── Manifest.json
└── Approval.json
```

기존 프로그램 산출물은 자동으로 덮어쓰지 않습니다.

## Review and Approve Scope

명령을 실행하면 임시 `Scope.md` 경로가 출력됩니다. 원본 프로그램 페이지와 임시 문서를 대조한 뒤 터미널에서 승인 여부를 입력합니다.

```text
이 Scope를 승인하고 저장할까요? [y/N]:
```

- `y`: 프로그램별 공식 경로에 Scope 산출물을 저장합니다.
- `n` 또는 Enter: 임시 산출물을 모두 폐기하고 종료합니다.

검토자 이름을 명시하려면 다음과 같이 실행합니다. 생략하면 현재 운영체제 사용자명이 기록됩니다.

```bash
aidast scope "<PROGRAM_URL>" --by "<REVIEWER>"
```

승인 상태와 파일 무결성을 확인합니다.

```bash
aidast scope status "<PROGRAM_URL>"
```

승인 후 `Scope.md` 또는 `Scope.json`이 변경되면 무결성 검사가 실패합니다.

## Create Recon Plan and Tasks

```bash
aidast recon "<PROGRAM_URL>"
```

동작 순서:

1. 승인된 기존 Scope가 있으면 무결성을 검증한 뒤 재사용합니다.
2. 기존 Scope가 없으면 Scope 수집과 대화형 승인을 먼저 수행합니다.
3. Main Agent가 승인된 `Scope.md`를 읽고 Recon Plan을 생성합니다.
4. Coordinator가 Plan의 단계들을 의존 관계가 있는 Recon Task로 변환합니다.

현재 Recon Plan과 Task는 같은 프로세스 안의 구조화된 객체로 전달되며 DB나 파일에 저장하지 않습니다. Recon Agent 실행은 아직 포함되지 않습니다.

## Attack → Validator → Report 파이프라인

Recon 완료 후, IDOR 취약점을 자동으로 탐지하고 검증하고 보고서를 생성합니다.

```
Recon 완료 (DB에 endpoints, parameters, sessions 적재)
    ↓
Attack Agent — curl로 IDOR 공격 수행, 취약점 발견
    ↓
Validator Agent — 7 Gate Question으로 독립 재검증
    ↓ (CONFIRMED만)
Report Agent — 버그바운티 제출용 보고서 작성
    ↓
reports/{finding_id}_report.md 파일 출력
```

### 핵심 원칙

- **LLM이 공격의 주체, Python은 결과 저장만**
- LLM이 curl로 직접 HTTP 요청 전송, 응답 해석, 취약점 판정
- Python은 LLM이 반환한 JSON을 DB에 저장하는 역할만 수행
- 모든 공격/검증/보고 지식은 SKILL.md에 담겨있음

### Attack (IDOR 탐지)

1. 오케스트레이터가 Recon DB에서 엔드포인트/파라미터/세션 추출
2. LLM이 IDOR 후보 선별 (is_identifier, RESTful 패턴 등)
3. LLM이 User A(소유자) / User B(공격자) / 비인증 3개 컨텍스트로 curl 요청
4. LLM이 응답을 비교하여 IDOR 여부 판정 + 오탐 검증
5. 결과 JSON → 오케스트레이터가 DB 저장

### Validator (7 Gate Question)

각 finding에 대해 7단계 독립 검증 수행:

| Gate | 검증 내용 |
|---|---|
| G1 | 재현 가능성 — curl로 공격 재실행 |
| G2 | 권한 경계 침해 — 다른 사용자 데이터 접근 확인 |
| G3 | 비즈니스 영향 — 민감 데이터(PII, 금융, 인증) 노출 여부 |
| G4 | 서버 측 검증 부재 — 200 + 데이터 반환 확인 |
| G5 | 의도된 동작 제외 — 공개 엔드포인트가 아닌지 확인 |
| G6 | 스코프 준수 — 승인된 범위 내 테스트인지 확인 |
| G7 | 중복 확인 — 기존 confirmed finding과 같은 근본 원인이 아닌지 확인 |

- 7개 전부 PASS → CONFIRMED
- 1개라도 FAIL → REJECTED
- G1만 FAIL 또는 N/A → INCONCLUSIVE

### Report (보고서 생성)

CONFIRMED된 finding에 대해 버그바운티 제출용 보고서 자동 생성:
- 10개 섹션 구조 (Title, Severity, Summary, PoC, Impact, Remediation 등)
- 실제 HTTP 요청/응답 증거 포함
- CVSS v3.1 점수 + CWE 분류
- `reports/` 디렉토리에 마크다운 파일로 저장

## Skills

각 Agent는 전용 SKILL.md를 로드하여 동작합니다.

```text
src/aidast/skills/scope/SKILL.md          — Scope 수집/해석
src/aidast/skills/attack/idor/SKILL.md    — IDOR 블랙박스 동적 분석
src/aidast/skills/validator/SKILL.md      — 7 Gate Question 검증
src/aidast/skills/report/SKILL.md         — 버그바운티 보고서 작성
```

실행 시 Skill은 Codex 표준 경로인 `.agents/skills/` 아래에 임시 배치되고 Codex가 이를 읽어 동작합니다.

## 프로젝트 구조

```
src/aidast/
├── agents/main.py                  Codex CLI 실행 (Scope/Recon/Attack 공통)
├── orchestration/
│   ├── scope.py                    Scope 수집 오케스트레이터
│   ├── recon.py                    Recon 오케스트레이터
│   └── attack.py                   Attack→Validator→Report 오케스트레이터
├── attack/
│   ├── db.py                       DB 스키마 + 저장 헬퍼 (findings, attack_requests, validations)
│   └── models.py                   Pydantic output schema (Codex --output-schema용)
├── recon/                          Recon 모듈 (기존)
├── scope/                          Scope 모듈 (기존)
└── skills/
    ├── scope/SKILL.md              Scope 수집 지침
    ├── attack/idor/SKILL.md        IDOR 공격 지침
    ├── validator/SKILL.md          7 Gate 검증 지침
    └── report/SKILL.md             보고서 작성 지침
```

## Development

```bash
uv sync
uv run python -m unittest discover -s tests -v
```

## Security Notes

- 페이지 내용은 신뢰할 수 없는 입력으로 처리합니다.
- Codex 로그인 정보는 저장소에 포함하지 않습니다.
- `Scope/`, `.env`, `.venv/`는 Git에 포함하지 않습니다.
- 로그인 전용 프로그램의 인증 세션 기능은 아직 구현되지 않았습니다.
