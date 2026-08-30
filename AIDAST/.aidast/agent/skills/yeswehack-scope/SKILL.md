---
name: yeswehack-scope
description: YesWeHack 프로그램 페이지를 agent-browser로 동적으로 탐색하여 Scopes, Scope Type, Asset Value, Reward Grid, Hunting Requirements, Qualifying/Non-Qualifying Vulnerabilities, Systemic Issues, Leak/Credential Policy, Program Rules와 근거를 정확하게 수집한다.
version: 0.3.0
author: AIDAST Team
license: MIT
platforms: [linux]
compatibility: Requires AIDAST, agent-browser, bash, and Python 3.
metadata:
  tags: [scope, yeswehack, bug-bounty, vdp, policy, aidast]
  category: scope
---

# YesWeHack Scope Collection

## 목적

이 Skill은 YesWeHack의 특정 Bug Bounty / Featured VDP / Program URL을 시작점으로 사용해,
AIDAST가 이후 Recon을 안전하게 수행하는 데 필요한 Scope와 테스트 정책을 수집한다.

YesWeHack에서 Scope는 단순 Domain 목록이 아니다.

Program에 따라 다음 정보가 함께 존재할 수 있다.

- Program Type
- Public / Private
- Program Status
- Supported Languages
- Program Description
- Scope Type
- Scope
- Asset Value
- Reward Grid
- Out-of-Scope Rule
- Qualifying Vulnerabilities
- Non-Qualifying Vulnerabilities
- Leaks and Exposed Credentials
- Systemic Issues
- Program Rules
- Hunting Requirements
  - VPN
  - Account Access
  - User-Agent
  - Credentials
  - Email Alias
- Attachments
- Program Version / Bug Bounty History
- Reward Policy
- Disclosure / Data Handling Rules

따라서 Scope Agent는 Scope 표만 읽고 종료하면 안 된다.

핵심 원칙:

1. 사용자가 제공한 `program_url`을 그대로 연다.
2. 현재 렌더링된 Program 페이지를 직접 보고 구조를 판단한다.
3. YesWeHack 내부 URL 경로나 Tab 이름을 하드코딩하지 않는다.
4. 실제 화면에서 발견한 메뉴·섹션·링크·Scope Row만 사용한다.
5. 페이지에 적힌 사실과 Agent의 해석을 분리한다.
6. 전체 Scope / Policy 원본은 `scope.json`에 저장한다.
7. Recon에 필요한 핵심만 `scope.md`에 요약한다.
8. 모든 중요한 판단은 YesWeHack 공식 Program 페이지 또는 Program이 직접 연결한 공식 자료의 근거와 연결한다.
9. 목록형 정책은 일부 예시로 줄이지 않고 전부 수집한다.
10. Scope Agent는 공격, Endpoint 탐색, 서브도메인 열거, Payload 전송을 수행하지 않는다.

---

# 실제 YesWeHack 프로그램에서 대응해야 하는 Scope 형태

## 1. 서로 다른 Scope Type이 섞일 수 있음

실제 Public Program은 다음처럼 여러 Scope Type을 동시에 가질 수 있다.

- Web application
- API
- Mobile application
- Wildcard
- Domain
- Desktop software
- IoT
- Firmware
- IP / Network
- Cloud / Third-party Service
- Other

따라서 "YesWeHack Scope = Domain 목록"이라고 가정하지 않는다.

## 2. Asset Value가 Scope마다 다를 수 있음

같은 Program 안에서도 Scope별 Asset Value가 다를 수 있다.

예:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

Asset Value는 Scope의 비즈니스 중요도와 Reward Grid 연결에 사용되며,
Scope 여부와는 별개다.

## 3. Web + API 혼합 Program

Program은 Web Application과 API Scope를 동시에 가질 수 있다.

따라서 Recon Task Builder는 `Scope Type`을 보존해야 한다.

## 4. Wildcard 또는 Pattern 형태

일부 Scope는 다음처럼 Pattern 형태일 수 있다.

```text
app-*.example.com
*.example.com
```

Wildcard를 실제 Host 목록으로 펼치는 것은 Scope Agent의 역할이 아니다.

## 5. 명시적 기본 Out-of-Scope Rule

Program은 다음과 같은 문구를 Out-of-Scope로 둘 수 있다.

```text
All domains or subdomains not listed in the above list of Scopes are out of scope.
```

이러한 Rule은 매우 중요하므로 Asset Out-of-Scope와 별도로 `scope_rules`에 보존한다.

## 6. Reward Grid가 Asset Value에 연결됨

YesWeHack Reward는 일반적으로:

```text
Final CVSS
+
해당 Scope의 Asset Value에 연결된 Reward Grid
```

를 기준으로 한다.

따라서 Scope Agent는 Reward Grid를 Program 전체 단일 값으로 단순화하지 않는다.

---

# 입력

```json
{
  "scan_id": "scan-001",
  "program_url": "https://yeswehack.com/programs/example",
  "output_root": "./artifacts",
  "browser_profile": null
}
```

규칙:

- `program_url`을 변경하지 않는다.
- `/scope`, `/history`, `/credentials`, `/policy` 등의 경로를 임의 생성하지 않는다.
- 인증정보, Cookie, Token, Password, API Key를 결과에 저장하지 않는다.
- 제공되지 않은 값을 추측하지 않는다.
- Public Program은 비로그인 상태에서 먼저 확인한다.
- Private Program의 필수정보가 실제로 인증 뒤에 숨겨진 경우에만 인증 세션을 사용한다.

---

# 출력 경로

```text
artifacts/
└── YesWeHack/
    └── Scope/
        └── <program_slug>/
            ├── scope.json
            ├── scope.md
            ├── run-state.json
            ├── evidence/
            │   ├── sources.jsonl
            │   └── screenshots/
            ├── attachments/
            └── raw/
                └── snapshots/
```

`program_slug`는 실제 YesWeHack Program 화면 또는 최종 URL에서 확인한 공식 Program 식별자를 사용한다.

---

# Browser 사용 규칙

기본 Browser Tool은 `agent-browser`다.

최초:

```bash
agent-browser open "<program_url>"
agent-browser wait 1200
agent-browser snapshot
```

필요한 경우에만:

```bash
agent-browser click <ref>
agent-browser snapshot
```

을 반복한다.

## 금지

- 동일 화면에서 이유 없이 Snapshot 반복
- 이미 방문한 URL 반복 방문
- 이전 화면의 오래된 `<ref>` 재사용
- YesWeHack 내부 URL 구조 추측
- Scope와 무관한 Leaderboard / Hunter Profile / Hall of Fame 탐색
- Report 제출 화면 진입
- Credential Request 자동 수행
- VPN 다운로드 자동 수행
- Email Alias 생성 자동 수행
- Program에 없는 Scope 생성
- 제3자 Scope 사이트를 최종 Evidence로 사용

## 페이지 이동 기준

다음 필수 항목을 채우기 위한 경우에만 이동한다.

- Program Summary / Description
- Scopes
- Out of Scope
- Reward Grid
- Program Rules / Policy
- Hunting Requirements
- Qualifying Vulnerabilities
- Non-Qualifying Vulnerabilities
- Leaks and Exposed Credentials
- Systemic Issues
- Attachments
- Program Version / Bug Bounty History

---

# 인증 전략

## Public Program

공개 Program은 비로그인 상태에서 먼저 확인한다.

다음 정보가 실제로 보이면 그대로 수집한다.

- Program Description
- Scopes
- Reward Grid
- Rules
- Hunting Requirements
- Qualifying / Non-Qualifying
- Out of Scope

로그인 또는 Submit 버튼이 보인다는 이유만으로 `SCOPE_NEEDS_AUTH`를 반환하지 않는다.

## Private Program

Private Program은 로그인과 초대가 필요할 수 있다.

필수 Scope 정보가 보이지 않고 유효한 Browser Session도 없으면:

```text
SCOPE_NEEDS_AUTH
```

## Credential Pool

Grey-box Scope에서 Credentials가 제공될 수 있다.

Scope Agent는 다음만 수집한다.

- Credential이 필요한가
- 어떤 Scope에 적용되는가
- Email Credential / Login Credential 유형
- YesWeHack Email Alias 허용/필수 여부
- Credential Pool 설명
- 몇 개 계정이 제공되는가
- Credential 발급 절차

Scope Agent는 다음을 자동 수행하지 않는다.

- Ask for credentials
- Email Alias 생성
- Password 확인
- Credential Request

Secret 값은 저장하지 않는다.

## KYC

Credential 또는 Email Alias는 KYC Verification이 필요할 수 있다.

KYC가 필요하다는 사실은 Access Requirement로 기록할 수 있지만,
Scope Agent가 KYC 절차를 자동 수행하지 않는다.

---

# 탐색 상태

`run-state.json`:

```json
{
  "scan_id": "",
  "platform": "yeswehack",
  "program_slug": null,
  "program_url": "",
  "current_url": "",
  "visited_urls": [],
  "collected_sections": [],
  "missing_fields": [],
  "source_ids": [],
  "last_action": null,
  "last_updated_at": ""
}
```

필수 항목:

```text
program_identity
program_type
program_status
visibility
supported_languages
description
scopes
scope_types
asset_values
scope_rules
reward_grids
systemic_issues
out_of_scope_assets
qualifying_vulnerabilities
non_qualifying_vulnerabilities
leaks_and_credentials
program_rules
automation_policy
rate_limit
vpn_requirement
user_agent_requirement
account_access
credentials
email_alias
data_handling
disclosure
attachments
program_history
conflicts
unknowns
```

---

# 1. Program 기본정보

다음을 수집한다.

- Program 이름
- Program slug
- Platform: YesWeHack
- 공식 Program URL
- 최종 도착 URL
- Program Type
  - Bug Bounty
  - Featured VDP
  - 기타 현재 표시값
- Public / Private
- Program Status
  - Active / Enabled
  - Disabled
  - Unknown
- Supported Languages
- Organization
- Program Description
- Last Updated가 보이면 해당 값
- Reward Type
  - Bounty
  - Gift
  - None
  - Unknown
- Reward Visibility가 보이면 해당 값
- Submission Cost / Credit 정보가 Program 화면에 직접 표시되는 경우 해당 값

확인하지 못한 값은 `null` 또는 `unknown`.

---

# 2. Program Description / Policy

Program Description과 Policy에서 다음을 수집한다.

- Organization / Product 설명
- Program 목적
- 중요한 Service / Product
- 테스트 맥락
- 중요 비즈니스 기능
- 특별히 원하는 테스트
- 특별히 피해야 할 테스트
- Environment 설명
- Account / Role 설명
- Technical Context
- Data Handling
- Disclosure
- Program-specific Rules

Recon / Attack 우선순위에 유용한 공식 문구만 `priority_scenarios`에 저장한다.

Agent가 임의로 공격 시나리오를 추가하지 않는다.

---

# 3. Scopes

페이지에 표시된 **모든 Scope Row**를 수집한다.

각 Scope:

```json
{
  "raw_value": "",
  "normalized_value": "",
  "scope_type": "",
  "scope_status": "in_scope",
  "asset_value": null,
  "environment": null,
  "instructions": [],
  "reward_grid_id": null,
  "source_ids": []
}
```

## Scope Type

현재 UI 표시값을 원문대로 저장한다.

가능한 형태:

- Web application
- Mobile application
- API
- Desktop software
- IoT device
- Firmware
- IP address
- Cloud infrastructure
- Third-party service
- Wildcard / Pattern
- Other
- 현재 UI의 추가 Type

## Scope Value

원문을 그대로 저장한다.

예:

```text
https://www.example.com
https://api.example.com
*.example.com
app-*.example.com
```

Agent가 상위/하위 Domain으로 확장하지 않는다.

## Asset Value

현재 표시값을 저장한다.

```text
CRITICAL
HIGH
MEDIUM
LOW
UNKNOWN
```

표시되지 않으면 `null`.

Asset Value는 Scope Status가 아니다.

---

# 4. Scope 안전 규칙

## 명시된 Scope만 자동 Recon 후보

YesWeHack 공식 Program Scope에 명시되지 않은 자산은 기본적으로 Out-of-Scope로 취급한다.

```text
not_listed
→ out_of_scope
→ deny
```

Program이 별도 Broad Rule을 명시하면 원문 Rule을 저장하되,
페이지에 없는 구체 Asset을 Agent가 생성하지 않는다.

## Wildcard

Wildcard를 그대로 저장한다.

```text
*.example.com
app-*.example.com
```

Scope Agent는 실제 Host 목록으로 열거하지 않는다.

Recon Agent가 발견한 Host에 Scope Matcher를 적용한다.

## URL과 API

다음은 별도 Scope로 보존한다.

```text
https://www.example.com
https://api.example.com
*.example.com
```

Scope Type까지 함께 보존한다.

## Third-party

Program이 명시적으로 Scope로 등록한 Third-party Service는 Scope일 수 있다.

그러나 Program에 링크되었다는 이유만으로 Third-party Service를 자동 포함하지 않는다.

---

# 5. Out of Scope

Out-of-Scope 영역과 Program Policy의 제외 규칙을 모두 수집한다.

두 종류를 분리한다.

## Asset / Scope Exclusion

예:

- 모든 미등록 Domain/Subdomain
- 특정 Domain
- 특정 API
- 특정 Environment
- Third-party Asset

저장:

```json
{
  "raw_text": "",
  "rule_type": "asset",
  "source_ids": []
}
```

## Testing / Vulnerability Exclusion

특정 Vulnerability 또는 테스트 방식은 Asset Scope와 별도로 저장한다.

Vulnerability Exclusion을 Asset Out-of-Scope로 바꾸지 않는다.

---

# 6. Reward Grid

YesWeHack Reward Grid는 Scope의 Asset Value와 연결된다.

모든 표시 Grid를 수집한다.

예:

```json
{
  "asset_value": "CRITICAL",
  "rewards": {
    "low": null,
    "medium": null,
    "high": null,
    "critical": null
  },
  "currency": null,
  "source_ids": []
}
```

가능하면 다음을 수집한다.

- Asset Value
- Low Reward
- Medium Reward
- High Reward
- Critical Reward
- Currency
- Reward Type
- Reward Visibility
- 기타 Program-specific Reward Rule

표시되지 않은 Severity는 `null`.

## Reward와 Scope 분리

Reward가 없거나 낮아도 Scope는 In-Scope일 수 있다.

```text
reward != scope_status
```

## CVSS

Program이 YesWeHack 기본 Reward Model을 사용한다면 Reward는 최종 CVSS와 해당 Scope의 Reward Grid에 의해 결정될 수 있다.

하지만 Scope Agent가 실제 Report Severity를 계산하지 않는다.

---

# 7. Systemic Issues

Program이 Systemic Issues 정책을 제공하면 전체 수집한다.

예:

```json
{
  "enabled": null,
  "decreasing_rewards": [],
  "raw_text": null,
  "source_ids": []
}
```

감소형 Reward가 표시되면 순서를 그대로 저장한다.

예:

```json
[
  {"occurrence": 1, "percentage": 100},
  {"occurrence": 2, "percentage": 100},
  {"occurrence": 3, "percentage": 75}
]
```

표에 더 많은 행이 있으면 전부 수집한다.

`etc.`로 축약하지 않는다.

Systemic Issues는 Recon Scope가 아니라 Reward / Reporting Policy다.

---

# 8. Qualifying Vulnerabilities

Program이 표시하는 Qualifying Vulnerabilities를 **전부** 수집한다.

```json
{
  "name": "",
  "raw_text": "",
  "source_ids": []
}
```

다음 방식으로 줄이지 않는다.

```text
examples include ...
and others
etc.
```

Program이 별도 Condition / Impact Requirement를 붙이면 같이 저장한다.

---

# 9. Non-Qualifying Vulnerabilities

Program이 표시하는 Non-Qualifying Vulnerabilities를 **전부** 수집한다.

```json
{
  "name": "",
  "raw_text": "",
  "source_ids": []
}
```

특히 다음을 구분한다.

- 항상 Non-Qualifying
- Impact가 없을 때만 Non-Qualifying
- 특정 Scope에만 적용
- 특정 Scenario에서만 제외

Non-Qualifying Vulnerability를 Asset Out-of-Scope로 변환하지 않는다.

---

# 10. Leaks and Exposed Credentials

Program이 Leaks / Exposed Credentials Policy를 제공하면 전체 수집한다.

YesWeHack에서는 Eligibility가 다음 두 축과 연결될 수 있다.

```text
Source of leak
Impacted asset
```

수집:

- Leak Source 조건
- Impacted Asset 조건
- Reward Eligibility
- Credential Validity 확인 방식
- Compromised Account 사용 금지
- Post-auth Testing 금지
- PII Redaction
- Data Handling
- Reporting Requirement
- Scope-specific Condition

구조:

```json
{
  "enabled": null,
  "source_rules": [],
  "impacted_asset_rules": [],
  "testing_constraints": [],
  "data_handling_rules": [],
  "source_ids": []
}
```

실제 Credential을 사용해 로그인하지 않는다.

Credential 유효성 확인 범위를 Program Rule 이상으로 확장하지 않는다.

---

# 11. Hunting Requirements

YesWeHack의 Hunting Requirements는 Recon에 직접 영향을 준다.

반드시 각각 별도 필드로 수집한다.

## VPN

```json
{
  "required": null,
  "raw_text": null,
  "source_ids": []
}
```

Program의 `Hunting Requirements`에 VPN이 명시된 경우에만 `required = true`.

YesWeHack에 VPN 기능이 존재한다는 사실만으로 현재 Program의 VPN Requirement를 추측하지 않는다.

Program별 특정 Scope에만 VPN이 적용되면 그 Scope Mapping도 보존한다.

## User-Agent

```json
{
  "required": null,
  "required_value": null,
  "raw_text": null,
  "source_ids": []
}
```

Program이 특정 문자열 Append를 요구하면 정확한 문자열을 그대로 저장한다.

정확한 User-Agent 요구사항은 AIDAST가 자동 적용할 수 있으므로,
요구사항 존재 자체를 무조건 `manual_review`로 만들지 않는다.

## Account Access

수집:

- Grey-box 여부
- Test Account 필요
- Credential Pool 제공
- Email Credential / Login Credential
- Self Registration
- Access Level
- Scope Mapping
- 계정 개수
- KYC Requirement
- Instruction

## Credentials

Scope Agent는 Credential이 존재한다는 사실과 사용 조건만 저장한다.

Credential Secret은 저장하지 않는다.

자동으로 `Ask for credentials`를 누르지 않는다.

## Email Alias

Program이 YesWeHack Email Alias를 요구하면 저장한다.

```json
{
  "required": null,
  "raw_text": null,
  "source_ids": []
}
```

Email Alias 기능이 플랫폼에 있다는 이유만으로 Program이 요구한다고 추측하지 않는다.

---

# 12. Automation Policy

YesWeHack Program의 Automation 문구는 자유형 Program Rule에 존재할 수 있다.

다음 상태를 사용한다.

```text
allowed
denied
conditional
unknown
```

저장:

```json
{
  "status": "unknown",
  "conditions": [],
  "raw_text": null,
  "source_ids": []
}
```

예:

```text
Do not use automated scanners/tools generating large network traffic.
```

→

```text
conditional
```

의미:

- 모든 Automation이 금지됐다고 단정하지 않는다.
- 대량 Traffic을 발생시키는 Scanner가 제한됐다는 사실을 저장한다.
- 최종 Tool 허용 여부는 Policy Evaluator가 결정한다.

## Rate Limit

별도 숫자가 있으면 저장한다.

```json
{
  "status": "unknown",
  "raw_text": null,
  "requests": null,
  "period_seconds": null,
  "source_ids": []
}
```

숫자가 없으면 만들어내지 않는다.

---

# 13. Program Rules / Prohibited Actions

Program Policy에 적힌 Rule을 전부 수집한다.

예:

- DoS / DDoS
- Service Degradation
- Brute Force
- Social Engineering
- Physical Testing
- Large-traffic Automated Scanning
- User Data Leak
- Copy / Manipulate / Destroy Data
- Spam
- Real User Impact
- Disclosure 금지
- 계정 관련 제한
- 비용 발생 제한
- 기타 Program-specific Rule

목록을 일부 예시로 줄이지 않는다.

---

# 14. Data Handling

다음을 확인한다.

- PII 접근
- Leak / Copy / Modify / Destroy 금지
- Credential Handling
- Screenshot / PoC 제한
- Data Redaction
- 최소 증명 원칙
- 실제 사용자 데이터 처리
- Exposed Secret 처리

Recon에 직접 영향을 주는 Rule은 `scope.md`에 요약한다.

---

# 15. Disclosure

가능한 범위에서:

- Public Disclosure 허용 여부
- 사전 승인 요구
- Vulnerability 공개 금지
- Coordinated Disclosure
- 외부 채널 사용 제한
- Program-specific Disclosure Rule

전체 원본은 `scope.json`.

---

# 16. Attachments

YesWeHack Program은 Policy 또는 Hunting Requirements에서 Attachment Reference를 사용할 수 있다.

예:

```text
YWH-PXXXX
{YWH-PXXXX}
```

지원 가능한 자료 예:

- PNG / JPEG
- TXT
- PDF
- APK / AAB
- IPA
- ZIP
- Test Guide
- Architecture Diagram
- Scope File

처리:

1. Program이 직접 연결한 공식 Attachment인지 확인
2. File ID / Reference 저장
3. 필요한 경우 다운로드
4. Hash 기록
5. 대량 Data는 Python Parser 사용
6. LLM Context에 전체 파일 반복 입력 금지

---

# 17. Program Version / Bug Bounty History

Program은 시간에 따라 다음이 바뀔 수 있다.

- Scopes
- Reward Grids
- Rules
- Test Conditions

현재 Program에 `Bug bounty history` / `Compare versions` 기능이 실제로 노출되면 확인한다.

수집:

```json
{
  "version": null,
  "changed_at": null,
  "changed_fields": [],
  "raw_summary": null,
  "source_ids": []
}
```

우선 관심 변경:

- Scope 추가 / 삭제
- Asset Value 변경
- Reward Grid 변경
- Program Rule 변경
- VPN 변경
- User-Agent 변경
- Account Access 변경
- Qualifying / Non-Qualifying 변경
- Leak Policy 변경
- Automation 제한 변경

History가 UI에 노출되지 않으면 URL을 추측해서 접근하지 않는다.

---

# 18. Evidence

모든 중요한 값에 `source_id`.

```json
{
  "source_id": "src-001",
  "url": "",
  "page_title": "",
  "section": "",
  "raw_text": "",
  "collected_at": "",
  "requires_auth": false,
  "screenshot_path": null
}
```

최종 Evidence:

- 공식 YesWeHack Program 페이지
- Program이 직접 연결한 공식 Attachment / Document
- YesWeHack 공식 Platform Policy

제3자 Scope Tracker는 Debug/비교용이며 최종 Evidence로 사용하지 않는다.

Cookie / Token / Password / PII 저장 금지.

---

# 19. scope.json

전체 Scope / Policy 기준 원본:

```json
{
  "schema_version": "0.3",
  "scan_id": "",
  "status": "SCOPE_COMPLETE",
  "platform": "yeswehack",
  "collected_at": "",
  "program": {
    "name": "",
    "organization": "",
    "slug": "",
    "program_url": "",
    "final_url": "",
    "program_type": null,
    "visibility": null,
    "program_status": null,
    "supported_languages": [],
    "last_updated": null
  },
  "scopes": [],
  "scope_rules": [],
  "reward_policy": {
    "reward_type": null,
    "reward_visibility": null,
    "reward_grids": [],
    "systemic_issues": {}
  },
  "testing_requirements": {
    "automation_policy": {
      "status": "unknown",
      "conditions": [],
      "raw_text": null,
      "source_ids": []
    },
    "rate_limit": {
      "status": "unknown",
      "raw_text": null,
      "requests": null,
      "period_seconds": null,
      "source_ids": []
    },
    "vpn": {
      "required": null,
      "scope_mapping": [],
      "raw_text": null,
      "source_ids": []
    },
    "user_agent": {
      "required": null,
      "required_value": null,
      "raw_text": null,
      "source_ids": []
    },
    "account_access": {
      "required": null,
      "credential_types": [],
      "scope_mapping": [],
      "instructions": [],
      "source_ids": []
    },
    "email_alias": {
      "required": null,
      "raw_text": null,
      "source_ids": []
    },
    "allowed_environments": [],
    "time_restrictions": [],
    "regional_restrictions": []
  },
  "qualifying_vulnerabilities": [],
  "non_qualifying_vulnerabilities": [],
  "leaks_and_exposed_credentials": {
    "enabled": null,
    "source_rules": [],
    "impacted_asset_rules": [],
    "testing_constraints": [],
    "data_handling_rules": [],
    "source_ids": []
  },
  "prohibited_actions": [],
  "priority_scenarios": [],
  "data_handling_rules": [],
  "disclosure_rules": [],
  "attachments": [],
  "program_history": [],
  "sources": [],
  "conflicts": [],
  "unknowns": []
}
```

검증:

```bash
python3 -m json.tool "<scope.json>" >/dev/null
```

---

# 20. scope.md

`scope.md`는 Recon용 핵심 요약이다.

전체 YesWeHack Policy를 복사하지 않는다.

```md
# Scope

## Program
- Platform: YesWeHack
- Program:
- Type:
- Status:
- Source:

## In Scope
- ...

## Out of Scope
- ...

## Testing Restrictions
- Automation:
- Rate Limit:
- Required User-Agent:
- VPN:
- Account / Credential Requirement:
- Email Alias:
- Environment / Time Restriction:

## Prohibited Actions
- ...

## Manual Review
- 없음 또는 Recon 전에 확인할 항목

## Source
- 공식 YesWeHack Program URL
```

기본 `scope.md`에 장황하게 넣지 않는 항목:

- Reward Grid 전체
- Systemic Issue 보상표 전체
- Qualifying 전체
- Non-Qualifying 전체
- Leak / Credential Policy 전체
- Program History 전체
- Attachments 전체
- Evidence 전체

이 내용은 `scope.json`에 완전하게 저장한다.

단, Recon 수행 방식에 직접 영향을 주는 내용은 `Recon Restrictions`에 요약한다.

---

# 21. Recon용 안전 해석

## 명시적 Scope

Recon 후보.

## Scope 목록에 없음

YesWeHack 기본 원칙:

```text
out_of_scope
deny
```

## Wildcard

그대로 저장.

Scope Agent가 Host 열거하지 않는다.

Recon에서 발견한 Host에 Matcher 적용.

## User-Agent Requirement

정확한 값이 확인되면 자동 적용 가능한 설정으로 저장한다.

Requirement 존재 자체를 `manual_review`로 만들지 않는다.

## VPN

Program에 명시된 경우에만 Required.

## Account / Credentials

Secret 없이 Requirement만 저장.

## Automation

`allowed / denied / conditional / unknown`으로 저장.

최종 Tool 실행 허용 여부는 Compiler / Policy Evaluator가 결정한다.

---

# 22. Verification

## Program
- [ ] YesWeHack Program 확인
- [ ] 이름 / slug 확인
- [ ] Program Type 확인
- [ ] Public / Private 확인
- [ ] Status 확인 또는 unknown
- [ ] Supported Languages 확인

## Scopes
- [ ] 모든 Scope Row 수집
- [ ] Scope Value 수집
- [ ] Scope Type 수집
- [ ] Asset Value 수집
- [ ] Reward Grid 연결
- [ ] Wildcard 그대로 보존
- [ ] 미등록 Asset 기본 Out-of-Scope Rule 확인
- [ ] Program-specific Out-of-Scope 전체 수집

## Reward
- [ ] 모든 Asset Value Reward Grid 수집
- [ ] Severity별 Reward 수집
- [ ] Reward Type 확인
- [ ] Systemic Issues 정책 확인
- [ ] 감소형 Grid 전체 수집

## Hunting Requirements
- [ ] VPN 확인
- [ ] User-Agent 확인
- [ ] Account Access 확인
- [ ] Credential Requirement 확인
- [ ] Email Alias 확인
- [ ] Automation 원문 + 상태 저장
- [ ] Rate Limit 확인 또는 unknown

## Vulnerability Policy
- [ ] Qualifying Vulnerabilities 전체 수집
- [ ] Non-Qualifying Vulnerabilities 전체 수집
- [ ] 예시만 남기지 않음
- [ ] Leak / Exposed Credential 정책 전체 확인

## Rules
- [ ] Program Rules 전체 수집
- [ ] Prohibited Actions 전체 수집
- [ ] Data Handling 확인
- [ ] Disclosure 확인

## History / Attachments
- [ ] Attachment Reference 확인
- [ ] Program History 기능이 노출되면 확인
- [ ] Scope/Reward/Rule 변경 확인

## Evidence
- [ ] 모든 중요 값에 Source
- [ ] 공식 YesWeHack 근거
- [ ] 인증정보 없음
- [ ] Conflict / Unknown 기록

## Output
- [ ] scope.json 존재
- [ ] JSON 검증 성공
- [ ] scope.md 존재
- [ ] JSON/MD 충돌 없음
- [ ] run-state.json 존재

---

# 23. Targeted Retry

누락된 항목만 다시 확인한다.

예:

```text
missing_fields:
- rate_limit
- email_alias
- program_history
```

이미 수집한 Scope 표를 처음부터 다시 읽지 않는다.

두 번째 확인에도 없으면 `unknown`으로 확정하고 이유를 기록한다.

---

# 24. 종료 상태

## SCOPE_COMPLETE

- 모든 Scope / Scope Type / Asset Value 수집
- Out-of-Scope Rule 수집
- Hunting Requirements 수집
- Qualifying / Non-Qualifying 전체 수집
- Program Rules 수집
- 공식 Evidence 연결
- scope.json 검증 완료

## SCOPE_NEEDS_AUTH

- Private Program 필수 Scope가 인증 없이는 보이지 않음
- 사용 가능한 인증 세션 없음

Credential Request만 필요한 상태와 Program Scope 자체가 비공개인 상태를 구분한다.

## SCOPE_NEEDS_REVIEW

- Automation 조건 모호
- Scope / Policy 충돌
- 중요한 VPN / Account Requirement를 기계적으로 판단하기 어려움
- Program History와 현재 Rule 충돌
- Credential Request 등 사용자 동작이 필요한 단계가 남음
- 필수 Testing Rule 누락

## SCOPE_FAILED

- Program 접근 실패
- YesWeHack Program 아님
- Browser Tool 반복 실패
- Output 생성 / 검증 실패

---

# 25. Main Agent 반환

```json
{
  "agent": "scope",
  "platform": "yeswehack",
  "program_slug": "",
  "status": "SCOPE_COMPLETE",
  "scope_json": "",
  "scope_md": "",
  "run_state": "",
  "blocking_reasons": []
}
```
