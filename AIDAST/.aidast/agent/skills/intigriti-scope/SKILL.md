---
name: intigriti-scope
description: Intigriti 프로그램 페이지를 agent-browser로 동적으로 탐색하여 Assets, Bounty Tiers, Rules of Engagement, Testing Requirements, In/Out Scope, Known Issues, Safe Harbour, Severity Assessment, FAQ, Updates와 근거를 정확하게 수집한다.
version: 0.3.0
author: AIDAST Team
license: MIT
platforms: [linux]
compatibility: Requires AIDAST, agent-browser, bash, and Python 3.
metadata:
  tags: [scope, intigriti, bug-bounty, vdp, policy, aidast]
  category: scope
---

# Intigriti Scope Collection

## 목적

이 Skill은 Intigriti의 특정 Bug Bounty / VDP 프로그램 URL을 시작점으로 사용해,
AIDAST가 이후 Recon을 안전하게 수행하는 데 필요한 Scope와 테스트 정책을 수집한다.

Intigriti 프로그램 페이지에서 Scope는 단순 Asset 목록만으로 결정되지 않는다.
실제 프로그램에는 다음 정보가 함께 존재할 수 있다.

- Public / Application / Registered / Invite-only
- Program Status
- Description
- Bounty Table
- Bounty Tier
- Rules of Engagement
- @intigriti.me 요구사항
- User-Agent / Request Header
- Automated Tooling / Rate Limit
- Safe Harbour
- Assets
- Asset Groups
- Asset Type
- Asset Description
- In-Scope / Out-of-Scope Asset
- In Scope 설명과 Priority / Worst-case Scenarios
- Out of Scope Vulnerability 목록
- Known Issues
- Severity Assessment
- FAQ / Test Account 정보
- Program Updates
- Attachments / Documentation

Scope Agent는 이들 중 일부만 읽고 종료하면 안 된다.

핵심 원칙:

1. 사용자가 제공한 `program_url`을 그대로 연다.
2. 현재 렌더링된 페이지를 직접 보고 구조를 판단한다.
3. Intigriti 내부 URL 경로나 탭 이름을 하드코딩하지 않는다.
4. 실제 화면에서 발견한 메뉴·탭·링크·Asset·버튼만 사용한다.
5. 페이지에 적힌 사실과 Agent의 해석을 분리한다.
6. 전체 Scope / Policy 원본은 `scope.json`에 저장한다.
7. Recon에 필요한 핵심만 `scope.md`에 요약한다.
8. 모든 중요한 판단은 Intigriti 공식 프로그램 페이지 또는 공식 연결 자료의 근거와 연결한다.
9. 목록형 정책은 일부 예시로 줄이지 않고 전부 수집한다.
10. Scope Agent는 공격, Endpoint 탐색, 서브도메인 열거, Payload 전송을 수행하지 않는다.

---

# 실제 Intigriti 프로그램에서 반드시 대응해야 하는 구조

## 1. Program Header

실제 Program은 다음처럼 표시될 수 있다.

```text
Public
Open
Industry
Organization / Program / Detail
```

여기서:

- `Public` 등은 Program Confidentiality / Visibility와 관련될 수 있다.
- `Open` 등은 Program 상태와 관련될 수 있다.

둘을 하나의 값으로 합치지 않는다.

## 2. Bounty Table

Program에 따라 여러 Tier가 존재할 수 있다.

예:

```text
Tier 2
Tier 3
No Bounty
```

각 Tier에는 Severity별 Reward가 붙을 수 있다.

- Low
- Medium
- High
- Critical
- Exceptional

Reward와 Scope 여부를 구분한다.

## 3. Rules of Engagement의 구조화된 요구사항

Program 상단에 다음 필드가 직접 표시될 수 있다.

```text
@intigriti.me
User agent
Automated tooling
Request header
```

이 값들을 Program Description 안의 자유형 문장과 별도로 수집한다.

## 4. 자유형 Rules

`Our promise to you`, `Your promise to us`와 같은 섹션에서 다음 정책이 추가로 나타날 수 있다.

- 자동 Scanner 금지
- Submission 품질 요구
- Disclosure 금지
- 실제 사용자 영향 최소화
- 테스트 데이터 정리
- 특정 언어로 Report 제출
- 기타 Program-specific Rule

구조화 필드와 자유형 문장을 모두 저장한다.

## 5. Assets

Program에 따라 다음처럼 여러 Asset Type이 섞일 수 있다.

- URL
- Wildcard
- Android
- iOS
- IP Range
- Device
- Source code
- AI Model
- Other

각 Asset에는:

- Bounty Tier
- In-Scope / Out-of-Scope
- Description
- Group

이 붙을 수 있다.

## 6. Broad Wildcard + Specific Exception

실제 Program에서는 다음과 같은 구조가 가능하다.

```text
In Scope: *.example.com
Out of Scope: admin.example.com
```

이 경우 **가장 구체적인 Asset Rule이 우선**한다.

## 7. In Scope Priority Scenarios

Program의 `In scope` 설명에는 단순 자산 목록 외에 다음이 포함될 수 있다.

- Personal Data Exposure
- Smart Meter Data Exposure
- Privilege Escalation
- Impersonation
- Fraud / Abuse
- Business Logic Manipulation
- Unauthorized Data Manipulation

이 내용은 Attack Agent 우선순위에 활용할 수 있도록 `priority_scenarios`에 저장한다.

## 8. Out of Scope / Known Issues / General

Program에 따라 Out of Scope는 여러 카테고리로 나뉠 수 있다.

예:

```text
Domain
Known issues
Application
General
```

각 카테고리를 구분하고 목록 전체를 수집한다.

## 9. Severity Assessment

Program이:

- Intigriti Triage Standards
- Program-specific Severity Examples
- CVSS
- Impact-based Severity
- Zero-day Cool-down

등을 설명할 수 있다.

Scope와 분리하여 전체 Policy 원본에 저장한다.

## 10. FAQ

FAQ에는 Recon에 직접 필요한 내용이 들어갈 수 있다.

예:

- Test Account
- Self Registration
- Account 개수 제한
- @intigriti.me 필수
- 특정 Target용 등록 절차
- Language
- Environment

FAQ를 무시하지 않는다.

## 11. Updates

일부 Program은 별도 `Updates` 탭을 제공한다.
다른 Program은 Detail 본문에 `UPDATE <date>` 형식으로 변경사항을 넣을 수 있다.

Updates에서 다음이 변경될 수 있다.

- Scope
- Out-of-Scope
- Testing Method
- PII 사용
- Automated Tooling
- Rate Limit
- Bounty
- Credentials
- Feature / Attack Surface
- Zero-day 정책

따라서 현재 Detail만 읽고 끝내지 않는다.

---

# 입력

```json
{
  "scan_id": "scan-001",
  "program_url": "https://app.intigriti.com/researcher/programs/company/program/detail",
  "output_root": "./artifacts",
  "browser_profile": null
}
```

규칙:

- `program_url`을 수정하지 않는다.
- `/updates`, `/scope`, `/assets` 등의 경로를 임의 생성하지 않는다.
- 인증정보, Cookie, Token, Password, API Key를 결과에 저장하지 않는다.
- 제공되지 않은 값을 추측하지 않는다.
- Public Program은 비로그인 상태에서 먼저 확인한다.
- 필수정보가 실제로 인증 뒤에 숨겨진 경우에만 인증 세션을 사용한다.

---

# 출력 경로

```text
artifacts/
└── Intigriti/
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

`program_slug`는 실제 Intigriti Program 화면 또는 최종 URL에서 확인한 공식 Program 식별자를 사용한다.

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
- Intigriti 내부 URL 구조 추측
- Scope와 무관한 Leaderboard / Researcher Profile / Overall Stats / Activity 탐색
- Report 제출 / Application / Invite 수락 자동 수행
- Terms Accept / Identity Check 자동 수행
- 페이지에 없는 Asset 생성
- 제3자 Scope Mirror를 최종 Evidence로 사용

## 페이지 이동 기준

다음 필수 항목을 채우기 위한 경우에만 이동한다.

- Detail
- Assets
- Rules of Engagement
- Safe Harbour
- In Scope
- Out of Scope
- Known Issues
- Severity Assessment
- FAQ
- Updates
- Attachment / Documentation

---

# 인증 전략

## Public

Public Program은 프로그램 상세 전체가 공개될 수 있다.

로그인 버튼이 보여도 Detail, Asset, Rule이 실제로 보이면 그대로 수집한다.

Submission에 Login이 필요하다는 이유만으로 `SCOPE_NEEDS_AUTH`를 반환하지 않는다.

## Application

Application Program은 공개 사용자에게 일부 설명과 Bounty만 보이고,
전체 Scope는 승인 후에 보일 수 있다.

필수 Scope가 가려져 있으면:

```text
SCOPE_NEEDS_AUTH
```

## Registered

로그인 후에만 전체 Program이 보일 수 있다.

세션이 없으면:

```text
SCOPE_NEEDS_AUTH
```

## Invite-only

초대된 Researcher만 접근한다.

접근 권한이 없으면:

```text
SCOPE_NEEDS_AUTH
```

## Additional Access Gate

Program은 다음을 요구할 수 있다.

- Identity Check
- Program-specific Terms & Conditions

Scope Agent는 이를 자동 수행하지 않는다.

사용자 동의 또는 별도 절차가 필요하면:

```text
SCOPE_NEEDS_REVIEW
```

또는 접근 자체가 불가능하면:

```text
SCOPE_NEEDS_AUTH
```

---

# 탐색 상태

`run-state.json`:

```json
{
  "scan_id": "",
  "platform": "intigriti",
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
confidentiality
program_status
industry
description
bounty_table
bounty_tiers
reward_policy
structured_testing_requirements
free_text_rules
safe_harbour
assets
asset_groups
asset_descriptions
in_scope_assets
out_of_scope_assets
priority_scenarios
out_of_scope_vulnerabilities
known_issues
severity_assessment
faq
test_account_requirements
updates
attachments
conflicts
unknowns
```

---

# 1. Program 기본정보

다음을 수집한다.

- Program 이름
- Organization
- Program slug
- Platform: Intigriti
- 공식 Program URL
- 최종 도착 URL
- Program Type
- Confidentiality / Visibility
  - Public
  - Application
  - Registered
  - Invite-only
  - Unknown
- Program Status
  - Open
  - Closed
  - Paused
  - Unknown
- Industry
- Bounty 제공 여부
- Last Updated가 보이면 해당 값

확인하지 못한 값은 `null` 또는 `unknown`으로 저장한다.

---

# 2. Description

Program Description에서 다음을 수집한다.

- Organization / Service 설명
- Program 목적
- 테스트 맥락
- 중요 서비스
- 고객 / 사용자 맥락
- 기술 / 환경 정보

Description 자체를 Recon Target 목록으로 사용하지 않는다.

공식 Asset과 Scope Rule이 우선한다.

---

# 3. Bounty Table

Bounty Table을 가능한 경우 전체 수집한다.

Severity:

```text
Low
Medium
High
Critical
Exceptional
```

각 Tier:

```json
{
  "tier": "",
  "low": null,
  "medium": null,
  "high": null,
  "critical": null,
  "exceptional": null,
  "currency": null,
  "no_bounty": false,
  "source_ids": []
}
```

확인:

- Tier 1 ~ Tier 5
- No Bounty Tier
- Fixed / Ranged Reward
- Currency
- Reward Policy
- Custom Reward
- Duplicate / Bonus / Campaign 관련 Rule

## No Bounty

No Bounty Asset도 In-Scope일 수 있다.

```text
no_bounty != out_of_scope
```

을 반드시 유지한다.

---

# 4. Structured Testing Requirements

Rules of Engagement 위쪽에 구조화된 필드가 표시될 수 있다.

반드시 각각 별도 저장한다.

## @intigriti.me

```json
{
  "required": null,
  "raw_text": null,
  "source_ids": []
}
```

## User-Agent

```json
{
  "status": "unknown",
  "required_value": null,
  "raw_text": null,
  "source_ids": []
}
```

`Not applicable`을 "아무 User-Agent나 허용"과 동일한 의미로 과도하게 해석하지 않는다.
그냥 Program 요구사항이 없다는 사실로 저장한다.

## Request Header

```json
{
  "status": "unknown",
  "required_headers": [],
  "raw_text": null,
  "source_ids": []
}
```

정확한 Header가 있으면 이름과 형식을 그대로 저장한다.

Secret 값은 저장하지 않는다.

## Automated Tooling / Rate Limit

Intigriti Program은 화면에 다음처럼 표시할 수 있다.

```text
Automated tooling
max. 5 requests /sec
```

이 값은 **Request Rate Limit**으로 저장한다.

```json
{
  "rate_limit": {
    "status": "specified",
    "raw_text": "max. 5 requests /sec",
    "requests": 5,
    "period_seconds": 1,
    "source_ids": []
  }
}
```

하지만 이것만 보고 "모든 자동 Scanner가 허용"된다고 판단하지 않는다.

자유형 Program Rule에서 Scanner를 금지할 수 있기 때문이다.

---

# 5. Automation Policy를 둘로 분리

Intigriti Program에서는 구조화된 Rate Limit과 자유형 Scanner 금지 문구가 동시에 존재할 수 있다.

따라서 다음을 분리한다.

```json
{
  "automation_policy": {
    "automated_scanners": {
      "status": "unknown",
      "raw_text": null,
      "source_ids": []
    },
    "general_automation": {
      "status": "unknown",
      "raw_text": null,
      "source_ids": []
    },
    "rate_limit": {
      "status": "unknown",
      "raw_text": null,
      "requests": null,
      "period_seconds": null,
      "source_ids": []
    }
  }
}
```

가능한 상태:

```text
allowed
denied
conditional
unknown
not_applicable
```

예:

```text
"Please do not use automatic scanners"
```

→

```text
automated_scanners.status = denied
```

동시에:

```text
max. 5 requests /sec
```

가 있으면 Rate Limit도 그대로 저장한다.

이 두 사실을 충돌로 단순 처리하지 않는다.

의미가 다를 수 있으므로 원문을 모두 보존하고,
최종 Recon Tool 정책은 Scope Compiler / Policy Evaluator가 결정한다.

---

# 6. Free-text Rules of Engagement

`Our promise to you`, `Your promise to us` 등 실제 Program 문구를 전부 확인한다.

수집 대상:

- Scanner 금지
- Report 작성 언어
- Reproduction Step 요구
- Attack Scenario 요구
- Quality 기준
- Disclosure 금지
- 실제 사용자 영향 금지
- Test Data 정리 요구
- Account 사용 Rule
- PII Handling
- DoS / DDoS
- Brute Force
- Social Engineering
- Physical Testing
- 기타 Program-specific Rule

목록을 일부 예시로 줄이지 않는다.

Program에서 실제로 표시한 각 Rule을 전부 저장한다.

---

# 7. Safe Harbour

화면에:

```text
Safe harbour for researchers is applied
Show safe harbour
```

와 같은 UI가 있으면 반드시 실제 `Show safe harbour` 영역을 펼쳐 확인한다.

저장:

```json
{
  "present": null,
  "summary": null,
  "conditions": [],
  "exceptions": [],
  "source_ids": []
}
```

확인:

- Good-faith Testing 조건
- Program Rule 준수
- Researcher Guideline 준수
- 법적 보호 범위
- 예외
- Third-party 영향
- 금지 활동

Safe Harbour는 Asset Scope를 확장하지 않는다.

---

# 8. Assets 수집

화면의 Assets 영역에서 모든 Asset을 수집한다.

가능한 Asset Type:

- URL / Domain
- Wildcard
- Android
- iOS
- IP Range
- Device
- Source code
- AI Model
- Other
- 현재 UI의 추가 Type

각 Asset:

```json
{
  "raw_value": "",
  "normalized_value": "",
  "asset_type": "",
  "scope_status": "unknown",
  "bounty_tier": null,
  "group": null,
  "description": null,
  "instructions": [],
  "documentation_urls": [],
  "source_ids": []
}
```

확인:

- Expand all
- Asset Description
- Asset Group
- Bounty Tier
- Out of Scope 표시
- 페이지네이션 / 추가 로딩

Out-of-Scope Asset도 생략하지 않는다.

---

# 9. Asset Groups

Program이 Asset Group을 사용하면 다음을 별도로 저장한다.

```json
{
  "name": "",
  "description": null,
  "instructions": [],
  "asset_count": 0,
  "source_ids": []
}
```

Group 설명에는 다음이 포함될 수 있다.

- Environment
- 공통 Testing Rule
- 역할 / 권한
- 기술 정보
- Test Account
- Documentation

Asset Description과 Group Description을 모두 보존한다.

---

# 10. Intigriti Scope Matcher

## 기본 규칙

Intigriti 공식 Scope 원칙:

```text
Assets 섹션에 명시되지 않은 자산은 기본적으로 Out-of-Scope
```

따라서 Page에 없는 자산을 조직 소유로 추측해 Recon하지 않는다.

## 가장 구체적인 Rule 우선

예:

```text
In Scope: *.example.com
Out of Scope: admin.example.com
```

→

```text
admin.example.com = out_of_scope
www.example.com = in_scope
```

반대:

```text
In Scope: admin.example.com
Out of Scope: *.example.com
```

→

```text
admin.example.com = in_scope
www.example.com = out_of_scope
```

가장 구체적인 Asset Rule이 우선한다.

## Wildcard 의미

예:

```text
*.sub.example.com
```

은 다음과 같은 대상에 적용될 수 있다.

```text
sub.example.com
a.sub.example.com
deep.a.sub.example.com
```

하지만:

```text
example.com
```

까지 자동 포함하지 않는다.

Scope Agent는 Wildcard를 실제 Host 목록으로 열거하지 않는다.

Recon Agent가 발견한 Host에 Scope Matcher가 적용한다.

---

# 11. In Scope 설명

Asset 목록 아래 또는 별도 In Scope 영역을 확인한다.

여기에는 Program이 원하는 Priority Scenario가 포함될 수 있다.

다음과 같은 의미를 전부 수집한다.

- Data Exposure
- Personal Data Exposure
- Financial Data Exposure
- Smart Meter Data Exposure
- Account Takeover
- Impersonation
- Horizontal Privilege Escalation
- Vertical Privilege Escalation
- Business Logic
- Fraud / Abuse
- Unauthorized Data Manipulation
- Cross-tenant Access
- 기타 Program 공식 Priority

저장:

```json
{
  "scenario": "",
  "raw_text": "",
  "source_ids": []
}
```

Program이 나열한 항목은 전부 저장한다.

`...`가 실제 원문에 존재하면 그 사실은 저장할 수 있지만,
그 뒤의 시나리오를 Agent가 추측해서 추가하지 않는다.

---

# 12. Out of Scope 수집

Out of Scope 영역은 카테고리를 유지한다.

예:

```text
Domain
Known issues
Application
General
```

구조:

```json
{
  "asset_exclusions": [],
  "known_issues": [],
  "non_qualifying_vulnerabilities": [],
  "general_exclusions": []
}
```

## Asset / Domain

명시적인 Out-of-Scope Domain/URL/Wildcard는 Asset Exclusion으로 저장한다.

## Known Issues

이미 알려진 문제는 별도 저장한다.

Known Issue는 다음을 의미할 수 있다.

- Report 가능하지만 Bounty 없음
- Duplicate 예상
- Program이 이미 인지
- 현재 테스트 우선순위 낮음

원문을 그대로 저장한다.

## Application

Program이 Application 관련 Non-Qualifying 목록을 제공하면 **전부 수집**한다.

## General

General Exclusion도 **전부 수집**한다.

다음 표현으로 줄이지 않는다.

```text
examples include
and others
etc.
외 다수
```

---

# 13. Zero-day / Cool-down

Program이 새로 공개된 Zero-day에 Cool-down을 적용하면 저장한다.

예:

```json
{
  "cool_down_days": 14,
  "bounty_eligibility": "usually_not_eligible",
  "raw_text": "",
  "source_ids": []
}
```

Scope/Report 가능 여부와 Bounty Eligibility를 분리한다.

---

# 14. Severity Assessment

Severity Assessment 영역을 확인한다.

가능한 형태:

## Platform Standard

```text
This program follows Intigriti's triage standards.
```

## Program-specific Examples

Severity별 Vulnerability 예시를 제공할 수 있다.

- Exceptional
- Critical
- High
- Medium
- Low

전체 예시를 `scope.json`에 저장한다.

```json
{
  "standard": "intigriti_triage_standard",
  "impact_based": null,
  "cvss_version": null,
  "examples": {
    "exceptional": [],
    "critical": [],
    "high": [],
    "medium": [],
    "low": []
  },
  "source_ids": []
}
```

Recon용 `scope.md`에는 기본적으로 상세 예시를 넣지 않는다.

---

# 15. FAQ

FAQ를 반드시 확인한다.

Recon에 필요한 항목:

- Test Account
- Self Registration
- Max Account Count
- @intigriti.me 필수
- 특정 Asset용 Registration
- Language
- VPN
- Environment
- Feature 접근 조건
- Account Karma / Reputation 조건
- 기타 Access Requirement

예:

```json
{
  "question": "",
  "answer": "",
  "recon_relevant": true,
  "source_ids": []
}
```

FAQ에 Test Account 정보가 있으면 `testing_requirements.account_requirements`에도 구조화한다.

---

# 16. Updates

Program에 `Updates` 탭이 있으면 Scope/Testing에 영향을 주는 Update를 확인한다.

또한 Detail 안의:

```text
UPDATE <date>
```

형식도 확인한다.

## 우선 확인할 Update

- Scope 추가/삭제
- Public Website 추가
- Out-of-Scope 변경
- PII Testing Rule
- Automated Tooling / Rate-limit
- Scanner Traffic
- Bounty 변경
- Credentials
- Test Account
- Feature / Attack Surface 변경
- Zero-day 정책
- Intrusive Testing Warning

Update:

```json
{
  "title": "",
  "published_at": null,
  "raw_text": "",
  "effect": "unknown",
  "affected_assets": [],
  "source_ids": []
}
```

`effect`:

```text
scope_add
scope_remove
testing_restriction
automation_restriction
data_handling_restriction
reward_change
feature_change
informational
unknown
```

## Update와 Detail 충돌

Update가 현재 Detail Rule과 충돌하면 임의로 삭제하거나 덮어쓰지 않는다.

둘 다 저장하고:

```json
{
  "field": "",
  "current_detail_value": "",
  "update_value": "",
  "update_date": "",
  "source_ids": [],
  "resolution": "manual_review"
}
```

로 `conflicts`에 기록한다.

최신 Update가 명확하게 "now in scope", "out of scope", "do not use"처럼 상태 변경을 선언하면
그 변경 사실은 현재 Scope 판단에 반영할 수 있지만 Evidence와 날짜를 반드시 보존한다.

---

# 17. Data Handling / PII

Detail과 Updates에서 다음을 확인한다.

- Real PII 사용 금지
- Third-party PII 사용 금지
- Synthetic Data 사용
- Redaction
- 실제 사용자 영향
- Production Process Trigger 위험
- Test Data 정리
- 실제 식별자 사용 제한
- 민감 Data 저장/복사 금지

Recon에 직접 영향을 주는 규칙은 `scope.md`의 `Recon Restrictions`에 포함한다.

---

# 18. Attachments / Documentation

Program이 공식 자료를 제공하면 Scope/Testing 관련 것만 처리한다.

예:

- CSV Scope 목록
- PDF
- API Documentation
- Test Account Guide
- Architecture Diagram
- Environment Guide

다운로드 시:

- Program이 직접 연결한 공식 자료인지 확인
- Hash 기록
- 대량 CSV는 Python Parser 사용
- Parsed Count 기록
- LLM Context에 전체 데이터를 반복 입력하지 않음

---

# 19. Evidence

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

- 공식 Intigriti Program Detail
- 공식 Updates
- Program이 직접 연결한 공식 문서
- Intigriti 공식 정책 문서

금지:

- Cookie
- Token
- Password
- 개인정보
- Private Program 정보의 공개 저장

---

# 20. scope.json

전체 Scope / Policy 원본:

```json
{
  "schema_version": "0.3",
  "scan_id": "",
  "status": "SCOPE_COMPLETE",
  "platform": "intigriti",
  "collected_at": "",
  "program": {
    "name": "",
    "organization": "",
    "slug": "",
    "program_url": "",
    "final_url": "",
    "program_type": null,
    "confidentiality": null,
    "program_status": null,
    "industry": null,
    "bounty_available": null,
    "last_updated": null
  },
  "bounty": {
    "tiers": [],
    "reward_policy": {}
  },
  "asset_groups": [],
  "assets": [],
  "testing_requirements": {
    "required_intigriti_email": null,
    "user_agent": {
      "status": "unknown",
      "required_value": null,
      "raw_text": null,
      "source_ids": []
    },
    "request_headers": [],
    "automation_policy": {
      "automated_scanners": {
        "status": "unknown",
        "raw_text": null,
        "source_ids": []
      },
      "general_automation": {
        "status": "unknown",
        "raw_text": null,
        "source_ids": []
      },
      "rate_limit": {
        "status": "unknown",
        "raw_text": null,
        "requests": null,
        "period_seconds": null,
        "source_ids": []
      }
    },
    "required_vpn": null,
    "account_requirements": [],
    "allowed_environments": [],
    "time_restrictions": [],
    "regional_restrictions": []
  },
  "rules_of_engagement": [],
  "priority_scenarios": [],
  "scope_exclusions": {
    "assets": [],
    "known_issues": [],
    "non_qualifying_vulnerabilities": [],
    "general_exclusions": []
  },
  "safe_harbour": {
    "present": null,
    "summary": null,
    "conditions": [],
    "exceptions": [],
    "source_ids": []
  },
  "severity_assessment": {
    "standard": null,
    "impact_based": null,
    "cvss_version": null,
    "examples": {
      "exceptional": [],
      "critical": [],
      "high": [],
      "medium": [],
      "low": []
    },
    "source_ids": []
  },
  "faq": [],
  "updates": [],
  "attachments": [],
  "data_handling_rules": [],
  "disclosure_rules": [],
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

# 21. scope.md

`scope.md`는 Recon용 핵심 요약이다.

전체 Intigriti Policy를 복사하지 않는다.

```md
# Scope

## Program
- Platform: Intigriti
- Program:
- Confidentiality:
- Status:
- Source:

## In Scope
- ...

## Out of Scope
- ...

## Testing Restrictions
- Automated Scanners:
- Request Rate Limit:
- Required @intigriti.me:
- Required User-Agent:
- Required Headers:
- VPN:
- Account / Test Account Requirement:
- Environment:
- Time / Region Restriction:
- PII / Test Data Restriction:

## Prohibited Actions
- ...

## Scope Update Warnings
- 현재 Recon에 영향을 주는 최신 Update만

## Manual Review
- 없음 또는 Recon 전 확인할 항목

## Source
- 공식 Intigriti Program URL
```

기본 `scope.md`에 장황하게 넣지 않는 항목:

- Bounty Table 전체
- Severity 예시 전체
- Safe Harbour 상세
- Non-Qualifying 전체
- Known Issues 전체
- FAQ 전체
- Update History 전체
- Evidence 전체

이 내용은 `scope.json`에 완전하게 저장한다.

---

# 22. Recon용 Scope 해석 안전 규칙

## Explicit In-Scope Asset

Recon 후보.

## Explicit Out-of-Scope Asset

```text
deny
```

## Asset 목록에 없음

Intigriti 기본 원칙에 따라:

```text
out_of_scope
deny
```

## Wildcard + Specific Exception

가장 구체적인 Asset Rule 우선.

## Automation

Scope Agent는 다음을 직접 하나의 Boolean으로 뭉개지 않는다.

```text
Automated Scanner Policy
General Automation Policy
Request Rate Limit
```

을 분리한다.

최종 Tool 허용 여부는 Compiler / Policy Evaluator가 결정한다.

---

# 23. Verification

## Program
- [ ] Intigriti Program 확인
- [ ] 이름/slug 확인
- [ ] Confidentiality 확인
- [ ] Program Status 확인
- [ ] Industry 확인 또는 null
- [ ] Bounty 여부 확인

## Bounty
- [ ] 모든 표시 Tier 수집
- [ ] Low/Medium/High/Critical/Exceptional 저장
- [ ] No Bounty Tier 확인
- [ ] Reward와 Scope 구분

## Rules
- [ ] @intigriti.me 확인
- [ ] User-Agent 확인
- [ ] Request Header 확인
- [ ] Structured Automated Tooling / Rate Limit 확인
- [ ] 자유형 Scanner Rule 확인
- [ ] 두 Automation 정보를 별도 저장
- [ ] Our Promise / Your Promise 전체 저장
- [ ] Disclosure Rule 확인
- [ ] Data Handling 확인

## Safe Harbour
- [ ] 적용 여부 확인
- [ ] Show Safe Harbour 펼쳐 상세 확인
- [ ] Conditions / Exceptions 저장

## Assets
- [ ] 모든 Asset 확인
- [ ] 모든 In-Scope 저장
- [ ] 모든 Out-of-Scope 저장
- [ ] Asset Type 저장
- [ ] Bounty Tier 저장
- [ ] Description 확인
- [ ] Asset Group 확인
- [ ] Wildcard 처리
- [ ] Most-specific Rule 적용 가능하게 원문 보존

## In Scope
- [ ] Priority / Worst-case Scenario 전부 수집
- [ ] `...` 뒤 내용을 임의 추측하지 않음

## Out of Scope
- [ ] Domain/Asset Exclusion 전체
- [ ] Known Issues 전체
- [ ] Application Non-Qualifying 전체
- [ ] General Exclusion 전체
- [ ] 일부 예시로 축약하지 않음

## Severity
- [ ] Severity Assessment 확인
- [ ] Triage Standard 확인
- [ ] Severity 예시가 있으면 전부 저장
- [ ] Zero-day Cool-down 확인

## FAQ
- [ ] Test Account 확인
- [ ] Self Registration 확인
- [ ] Account Count 제한 확인
- [ ] @intigriti.me Requirement 반영
- [ ] Recon 관련 FAQ를 구조화

## Updates
- [ ] Updates 탭 존재 여부 확인
- [ ] Inline UPDATE 존재 여부 확인
- [ ] Scope/Test Method/PII/Automation 관련 최신 Update 확인
- [ ] Detail과 Update 충돌 기록

## Evidence
- [ ] 모든 중요 값에 Source
- [ ] 공식 Intigriti 근거
- [ ] 인증정보 없음
- [ ] Private Program 정보 공개 안 함
- [ ] Conflict / Unknown 기록

## Output
- [ ] scope.json 존재
- [ ] JSON 검증 성공
- [ ] scope.md 존재
- [ ] JSON/MD 충돌 없음
- [ ] run-state.json 존재

---

# 24. Targeted Retry

누락된 항목만 다시 확인한다.

예:

```text
missing_fields:
- safe_harbour
- faq
- updates
```

이미 수집한 Assets 전체를 다시 읽지 않는다.

두 번째 확인에도 없으면 `unknown`으로 확정하고 이유를 기록한다.

---

# 25. 종료 상태

## SCOPE_COMPLETE

- Asset Scope 수집 완료
- Out-of-Scope / Known Issues / Vulnerability Exclusion 수집 완료
- Testing Requirements 수집 완료
- Safe Harbour 확인
- Severity / FAQ / 최신 Testing Update 확인
- 공식 Evidence 연결
- scope.json 검증 완료

## SCOPE_NEEDS_AUTH

- Application / Registered / Invite-only Program의 필수 Scope가 가려짐
- 인증 세션 없음
- Access 권한 부족

Submission Login만 필요한 Public Program은 여기에 해당하지 않는다.

## SCOPE_NEEDS_REVIEW

- Identity Check / Terms Accept 등 사용자 동의가 필요한 Access Gate
- Automation Rule이 서로 충돌해 자동 Tool 정책을 확정할 수 없음
- Detail과 최신 Update가 충돌
- 가장 구체적인 Asset Rule을 기계적으로 판단하기 어려움
- 필수 Testing Rule 누락

## SCOPE_FAILED

- Program 접근 실패
- Intigriti Program이 아님
- Browser Tool 반복 실패
- Output 생성/검증 실패

---

# 26. Main Agent 반환

```json
{
  "agent": "scope",
  "platform": "intigriti",
  "program_slug": "",
  "status": "SCOPE_COMPLETE",
  "scope_json": "",
  "scope_md": "",
  "run_state": "",
  "blocking_reasons": []
}
```
