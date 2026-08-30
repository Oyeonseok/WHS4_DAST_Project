---
name: bugcrowd-scope
description: Bugcrowd Engagement Brief를 agent-browser로 동적으로 탐색하여 Target Groups, Targets, Scope/Rewards, Program Rules, VRT Scope Rules, Known Issues, Updates와 근거를 정확하게 수집한다.
version: 0.3.0
author: AIDAST Team
license: MIT
platforms: [linux]
compatibility: Requires AIDAST, agent-browser, bash, and Python 3.
metadata:
  tags: [scope, bugcrowd, bug-bounty, vdp, engagement, policy, aidast]
  category: scope
---

# Bugcrowd Scope Collection

## 목적

이 Skill은 Bugcrowd의 특정 Engagement URL을 시작점으로 사용해,
AIDAST가 이후 Recon을 안전하게 수행하는 데 필요한 Scope와 테스트 정책을 수집한다.

Bugcrowd에서는 Scope가 단순 Domain 목록이 아니라 다음 정보의 조합으로 표현될 수 있다.

- In-Scope Target Groups
- Out-of-Scope Target Groups
- 개별 Targets
- Target URL / Location
- Target Category
- Target Tags / Technology
- Target Documentation
- Group별 Reward Range
- Program / Engagement Rules
- Testing Problems
- Disclosure Rules
- VRT Scope Rules
- Known Issues
- Program Updates / What's New
- Safe Harbor
- Additional Information / Resources

따라서 Scope Agent는 Target 목록만 읽고 종료하면 안 된다.

핵심 원칙:

1. 사용자가 제공한 `program_url`을 그대로 연다.
2. 현재 화면을 직접 보고 Brief 구조를 파악한다.
3. URL 경로나 Tab 이름을 하드코딩하지 않는다.
4. 실제 화면에서 발견한 메뉴·탭·링크·Target Group·버튼만 사용한다.
5. 페이지에 적힌 사실과 Agent의 해석을 분리한다.
6. 전체 Scope와 Policy 원본은 `scope.json`에 저장한다.
7. Recon에 필요한 핵심만 `scope.md`에 요약한다.
8. 모든 중요한 판단은 Bugcrowd 공식 Brief 또는 공식 연결 자료의 근거와 연결한다.
9. Private Engagement 정보는 공개 산출물로 취급하지 않는다.
10. Scope Agent는 공격, Endpoint 탐색, 서브도메인 열거, Payload 전송을 수행하지 않는다.

---

# Bugcrowd에서 대응해야 하는 Scope 형태

## 1. Target Group 기반 Scope

Bugcrowd는 하나 이상의 Target Group으로 Scope를 구성할 수 있다.

각 Group은 다음 속성을 가질 수 있다.

- In Scope / Out of Scope
- Group 이름
- Group 설명
- Monetary Reward 지급 여부
- Group별 Reward Range
- Group에 속한 Target 목록
- Group 공통 Testing Instruction

따라서 단순히 Program 전체 Reward만 수집하지 않는다.

## 2. Target 단위 Scope

각 Target은 서로 다른 형태일 수 있다.

예:

- Website
- API
- Mobile
- Network
- Binary
- Hardware
- Other

Target마다 다음 정보가 다를 수 있다.

- URL / Location
- Category
- Tags
- Documentation
- Reward Range
- Scope 변경 Flag
- VRT Scope Rule
- Known Issues

## 3. Mixed Surface

실제 Program은 Web + Mobile, Domain + Wildcard, API + Other처럼 서로 다른 Target Category를 함께 포함할 수 있다.

Agent는 "Bugcrowd Scope = Domain 목록"이라고 가정하지 않는다.

## 4. Scope 변경이 잦은 Engagement

Bugcrowd는 Target에 다음 변경 Flag를 표시할 수 있다.

- New
- Now OOS
- Now in-scope
- Reward increased
- Reward decreased

따라서 저장된 Scope만 믿지 않고 현재 Brief의 상태를 우선한다.

---

# 입력

```json
{
  "scan_id": "scan-001",
  "program_url": "https://bugcrowd.com/engagements/example",
  "output_root": "./artifacts",
  "browser_profile": null
}
```

규칙:

- `program_url`을 변경하지 않는다.
- `/targets`, `/details`, `/known_issues`, `/scope` 등의 경로를 추측해서 만들지 않는다.
- 인증정보, Cookie, Token, Credential Secret을 결과에 저장하지 않는다.
- 제공되지 않은 값은 추측하지 않는다.
- Public Engagement는 비로그인 상태에서 먼저 확인한다.
- 필수 정보가 실제로 인증 뒤에 숨겨진 경우에만 인증 세션을 사용한다.

---

# 출력 경로

```text
artifacts/
└── Bugcrowd/
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

`program_slug`는 실제 Bugcrowd Engagement 화면 또는 최종 URL에서 확인한 공식 식별자를 사용한다.

---

# Browser 사용 규칙

기본 Browser Tool은 `agent-browser`다.

최초 탐색:

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

을 수행한다.

## 금지

- 동일 화면에서 이유 없이 Snapshot 반복
- 이미 방문한 URL 반복 방문
- 이전 화면의 오래된 `<ref>` 재사용
- Bugcrowd 내부 URL 구조 추측
- Scope와 무관한 Hall of Fame / Crowd Highlights / Researcher Profile 탐색
- Report Submission 화면 진입
- Invite 수락 / Credential Claim / NDA 동의 같은 상태 변경
- 페이지에 없는 Target 생성
- 제3자 Scope 사이트를 최종 Evidence로 사용

## 페이지 이동 기준

다음 필수 항목을 채우기 위한 경우에만 이동한다.

- Engagement Header / Status
- Overview / Description
- Targets / Scope and Rewards
- Target Groups
- Program / Engagement Rules
- Things to Know
- Testing Problems
- Disclosure
- VRT Scope Rules
- Known Issues
- What's New / Program Updates
- Safe Harbor
- Additional Information / Resources

---

# 인증 전략

## Public Engagement

먼저 비로그인 상태에서 현재 Brief를 확인한다.

다음 핵심 정보가 보이면 그대로 수집한다.

- Overview / Description
- Targets
- In / Out Scope
- Rewards
- Rules
- Disclosure
- Safe Harbor
- Program Updates

로그인 버튼이 보인다는 이유만으로 `SCOPE_NEEDS_AUTH`를 반환하지 않는다.

## Known Issues

Known Issues는 Public Engagement에서도 로그인이 필요할 수 있다.

상태를 다음처럼 저장한다.

```text
available
auth_required
not_enabled
unknown
```

Known Issues가 Optional이고 Core Scope와 Rules가 완전하다면,
Known Issues 미확인만으로 전체 Scope 수집을 실패 처리하지 않는다.

## Private Engagement

Private Engagement는 접근 권한을 가진 사용자만 확인한다.

Scope Agent는 다음 동작을 자동 수행하지 않는다.

- Accept Invite
- Ignore Invite
- NDA Accept
- Identity Verification 시작
- Background Check 시작

필수 Scope 정보가 Private 상태이고 접근 권한이 없으면:

```text
SCOPE_NEEDS_AUTH
```

## Credentials

Credential 관련 UI를 발견해도 자동으로 다음을 수행하지 않는다.

- Claim Credentials
- Request Credentials
- Get Credentials
- Reset Credentials

Scope Agent가 수집하는 것은:

- Credential이 필요한가
- 어떤 Target에 적용되는가
- 어떤 종류인가
- VPN과 연결되는가
- 발급 절차가 무엇인가

Secret 값 자체는 저장하지 않는다.

---

# 탐색 상태

`run-state.json`:

```json
{
  "scan_id": "",
  "platform": "bugcrowd",
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
engagement_identity
engagement_type
engagement_status
testing_period
visibility
managed_status
safe_harbor_status
scope_rating
overview
description
in_scope_target_groups
out_of_scope_target_groups
targets
target_categories
target_tags
target_documentation
reward_ranges
target_change_flags
program_rules
testing_problems
automation_policy
rate_limit
credential_requirements
traffic_identification
environment_requirements
data_handling
disclosure
vrt_scope_rules
known_issues_status
program_updates
resources
conflicts
unknowns
```

---

# 1. Engagement 식별

다음을 수집한다.

- Engagement 이름
- Organization
- Engagement slug
- Platform: Bugcrowd
- 공식 Engagement URL
- 최종 도착 URL
- Engagement Type
- Public / Private
- 현재 Status
- Status 적용 시각이 보이면 해당 값
- Testing Period
- Managed by Bugcrowd 여부
- Bounty / VDP 여부
- Industry
- Tagline
- Collaboration Enabled 여부
- Safe Harbor 상태
- Scope Rating

확인하지 못한 값은 `null`로 저장하고 `unknowns`에 이유를 기록한다.

---

# 2. Engagement Header

Header에서 다음 항목을 확인한다.

## Engagement Type

예:

- On-Demand Bug Bounty
- Pen Test
- Private Bug Bounty
- Public Bug Bounty
- Vulnerability Disclosure
- 기타 현재 UI 표시값

현재 표시값을 원문대로 저장한다.

## Status

현재 Testing 가능 여부 판단에 중요하다.

다음과 같은 상태 또는 의미를 발견하면 원문을 저장한다.

- Active / In Progress
- Paused
- Testing Paused
- Completed
- Canceled
- 기타

Scope 수집 완료 여부와 Recon 실행 허용 여부는 별개다.

예:

```json
{
  "scope_status": "SCOPE_COMPLETE",
  "workflow_gate": "blocked",
  "blocking_reasons": ["testing_paused"]
}
```

## Testing Period

시작/종료 날짜 또는 Continuous/Ongoing 표현이 있으면 저장한다.

기간 밖이면 Recon을 자동 시작하지 않는다.

## Safe Harbor

Header에 Full / Partial 등 상태가 표시되면 저장한다.

상세 조건은 별도 Safe Harbor 섹션에서 확인할 수 있는 경우 추가 수집한다.

## Scope Rating

Scope Rating은 Scope의 깊이/크기 신호다.

하지만 Rating 자체를 Target Scope 판정에 사용하지 않는다.

---

# 3. Overview / Description

다음 내용을 수집한다.

- 회사/서비스 설명
- Engagement 목적
- Testing Objective
- Focus Area
- 고가치 기능
- 기술 Stack
- 역할/권한 설명
- Test Account 설명
- Environment 설명
- API / Mobile / Web 관계
- 특정 테스트 힌트
- 특별히 피해야 할 Workflow
- 실제 사용자/실데이터 관련 제한
- 금전/결제 Flow 제한

Attack 우선순위에 도움이 되는 공식 문구만 `priority_scenarios`에 저장한다.

Agent가 임의로 공격 시나리오를 추가하지 않는다.

---

# 4. Target Groups 수집

화면에 표시되는 모든 In-Scope / Out-of-Scope Target Group을 수집한다.

각 Group:

```json
{
  "name": "",
  "scope_status": "unknown",
  "description": null,
  "pays_monetary_rewards": null,
  "reward_range": null,
  "focus_areas": [],
  "documentation_urls": [],
  "instructions": [],
  "target_count": 0,
  "source_ids": []
}
```

확인:

- Group 이름
- In Scope / Out of Scope
- Group 설명
- Reward 여부
- Reward Range
- Target 수
- Focus Area
- Group-level Instruction
- Documentation / Diagram

In-Scope Group만 읽고 Out-of-Scope Group을 생략하지 않는다.

---

# 5. Targets 수집

모든 Target을 수집한다.

각 Target:

```json
{
  "name": "",
  "url_or_location": null,
  "normalized_value": null,
  "category": null,
  "tags": [],
  "scope_status": "unknown",
  "target_group": null,
  "reward_range": null,
  "instructions": [],
  "documentation_urls": [],
  "change_flags": [],
  "source_ids": []
}
```

## Target Name

화면 표시값을 그대로 저장한다.

## URL / Location

가능한 형태:

- URL
- Domain
- Wildcard
- API Endpoint/Base
- Mobile App
- Binary
- Hardware
- Network 위치
- 기타 Location

값이 없으면 Target Name에서 URL을 만들어내지 않는다.

## Category

현재 UI 표시값을 원문대로 저장한다.

예:

- Website
- API
- Android
- iOS
- Network
- Binary
- Hardware
- Other

## Tags

Testing 기술/Skill 관련 Tag가 보이면 저장한다.

Tag는 Scope 자체가 아니다.

## Scope Status

```text
in_scope
out_of_scope
unknown
```

## Recon Decision

별도 Compiler/Scope Gate가 최종 판단할 수 있도록
Agent는 우선 사실을 저장한다.

명시적 Out-of-Scope Target은 Recon 금지다.

---

# 6. Bugcrowd Scope 안전 규칙

## 명시적 Scope 우선

In-Scope Target Group에 명시된 Target만 Recon 후보로 취급한다.

Brief에 없는 자산을 조직 소유라고 추측해 추가하지 않는다.

## Out-of-Scope

Out-of-Scope Target은 테스트하지 않는다.

```text
deny
```

## Reward와 Scope 분리

다음을 구분한다.

- In-Scope
- Monetary Reward 지급
- Reward Range
- VDP / No Cash Reward

Reward가 없다고 Out-of-Scope로 바꾸지 않는다.

## Target Category와 Scope 분리

Category / Tag는 Testing 힌트이지 허용 범위 자체가 아니다.

## 제3자 서비스

Brief에 링크되었다는 이유만으로 다음을 Scope에 포함하지 않는다.

- CDN
- Identity Provider
- Payment Provider
- Cloud Provider
- App Store
- Customer Support SaaS
- Bugcrowd 자체 Domain

명시된 Target만 사용한다.

---

# 7. Target Change Flags

Bugcrowd는 최근 Scope/Reward 변경을 Flag로 표시할 수 있다.

반드시 가능한 범위에서 확인한다.

```text
New
Now OOS
Now in-scope
Reward increased
Reward decreased
```

각 Flag:

```json
{
  "type": "",
  "target": "",
  "observed_at": "",
  "effective_at": null,
  "source_ids": []
}
```

규칙:

- `Now OOS` → 현재 Target 상태를 Out-of-Scope로 취급
- `Now in-scope` → 현재 Brief의 Rules 적용 후 Recon 후보
- `New` → 신규 Target으로 기록
- Reward Flag는 Scope와 분리
- 정확한 변경 날짜가 보이지 않으면 추측하지 않음

---

# 8. Rewards

Program 전체와 Group별 Reward를 구분한다.

수집:

- Bounty 제공 여부
- Monetary Reward 여부
- Program-level Reward Range
- Group별 Reward Range
- Technical Severity별 Reward
- Custom Reward 조건
- Reward Increase / Decrease
- Bonus
- No Reward / VDP 여부

예:

```json
{
  "p1": {
    "minimum": null,
    "maximum": null,
    "currency": null
  },
  "p2": {
    "minimum": null,
    "maximum": null,
    "currency": null
  },
  "p3": {
    "minimum": null,
    "maximum": null,
    "currency": null
  },
  "p4": {
    "minimum": null,
    "maximum": null,
    "currency": null
  },
  "p5": {
    "minimum": null,
    "maximum": null,
    "currency": null
  }
}
```

표시되지 않은 값은 `null`.

VRT Priority와 Reward 금액을 같은 개념으로 보지 않는다.

---

# 9. Program / Engagement Rules

Rules 또는 Description/Things to Know에서 다음을 전부 확인한다.

- DoS / DDoS
- Availability 영향 금지
- Automated Scanner 제한
- Rate Limit
- Brute Force
- Social Engineering
- Physical Testing
- Spam
- User Interaction 제한
- 실제 Customer Account 테스트 금지
- 실제 사용자 Data 접근/변경 제한
- Form / Email Noise 제한
- Credential 사용 규칙
- VPN Requirement
- User-Agent Requirement
- Custom Header
- Test Account
- Region Restriction
- Time Restriction
- Production / Test Environment 제한
- 실제 결제/거래 제한
- Disclosure
- Communication Channel
- Collaboration Rule
- 기타 Engagement-specific Restriction

목록을 몇 개 예시로 줄이지 않고 전체 수집한다.

---

# 10. Automation Policy

다음 상태만 사용한다.

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
Automated testing may be used but must stay below 25 requests/second.
```

→

```text
conditional
```

## Stop Scanner Traffic

Announcement / Update에서 Scanner Traffic 중단이 명시되면:

```text
automation_policy.status = denied
workflow_gate = blocked
```

Manual Testing까지 중단인지 별도로 확인한다.

---

# 11. Rate Limit

```json
{
  "status": "unknown",
  "raw_text": null,
  "requests": null,
  "period_seconds": null,
  "source_ids": []
}
```

명시된 숫자만 정규화한다.

예:

```text
25 requests / second
```

→

```json
{
  "requests": 25,
  "period_seconds": 1
}
```

숫자가 없으면 만들지 않는다.

---

# 12. Traffic Identification

다음을 확인한다.

- Bugcrowd 식별 User-Agent
- Custom User-Agent
- Custom Header
- Form Field 식별 문자열
- Researcher Email 요구사항
- Source IP / VPN 요구
- 기타 Traffic Identification

정확한 값은 원문 그대로 저장한다.

값을 찾았다는 이유만으로 자동 `manual_review`로 만들지 않는다.

---

# 13. Credentials / Accounts / VPN

수집:

- Credential 필요 여부
- Test Account 필요 여부
- Self Registration
- Claim Credential 가능 여부
- Request Credential 가능 여부
- VPN 필요 여부
- VPN Certificate / Bundle
- 적용 Target
- Account 생성 규칙
- Credential 관련 Instruction

Secret 자체는 저장하지 않는다.

Claim / Request / Reset은 Scope Agent가 자동 수행하지 않는다.

---

# 14. Testing Problems

Things to Know 또는 Testing Problems 영역에서 다음을 확인한다.

- Broken Credentials 처리
- Inaccessible Application
- VPN 문제
- Email Alias 문제
- Platform Support 절차
- 테스트 전 문의 필요사항

Support Link 자체는 저장할 수 있으나
Scope Agent가 Support Ticket을 자동 제출하지 않는다.

---

# 15. VRT Scope Rules

Bugcrowd VRT Scope Rules를 Program Scope와 별도로 수집한다.

VRT Scope Rule은 특정 Vulnerability 분류에 대해:

- Reminder
- Out-of-Scope Exclusion
- Program-specific Guidance
- Requirement

등을 설정할 수 있다.

각 Rule:

```json
{
  "rule_type": "unknown",
  "vrt_category": "",
  "vrt_subcategory": null,
  "vrt_item": null,
  "applies_to": {
    "all_targets": null,
    "target_groups": [],
    "targets": []
  },
  "notes": [],
  "source_ids": []
}
```

가능한 `rule_type`:

```text
reminder
out_of_scope
exception
unknown
```

규칙:

- VRT Out-of-Scope Rule을 Asset Out-of-Scope로 바꾸지 않는다.
- 적용 Target / Group 범위를 반드시 보존한다.
- 일부 Target Rule을 전체 Engagement에 확대 적용하지 않는다.
- VRT 전체 Taxonomy를 매번 Browser로 다시 수집하지 않는다.
- Program에 실제 표시된 Rule만 저장한다.

---

# 16. Known Issues

Known Issues는 Target별 이미 알려진 Vulnerability 정보다.

상태:

```text
available
auth_required
not_enabled
unknown
```

가능한 범위에서 수집:

- Target
- Unique Issue Count
- Total Finding Count
- VRT Category Breakdown
- 확인 시각

```json
{
  "status": "unknown",
  "unique_count": null,
  "total_count": null,
  "targets": []
}
```

규칙:

- Known Issues는 Optional일 수 있다.
- Public Engagement에서도 로그인이 필요할 수 있다.
- Known Issue가 없다고 Asset Scope를 변경하지 않는다.
- Known Issue Category를 Vulnerability 존재의 확정 증거로 사용하지 않는다.
- Core Scope가 완전한 경우 Known Issues 인증 필요만으로 전체 Scope 수집을 실패시키지 않는다.
- Program이 Known Issues 확인을 필수로 요구한 경우는 예외.

---

# 17. Safe Harbor

가능한 상태:

```text
full
partial
none
unknown
```

저장:

```json
{
  "status": "unknown",
  "summary": null,
  "conditions": [],
  "disclose_io": null,
  "source_ids": []
}
```

확인:

- Full / Partial
- disclose.io 표시
- Authorization
- CFAA 관련 문구
- DMCA 관련 문구
- Terms 제한 Waiver
- Disclosure 조건
- Program-specific 제한

Safe Harbor는 Target Scope 확장 근거가 아니다.

Partial을 Full과 동일하게 처리하지 않는다.

---

# 18. Disclosure

다음을 확인한다.

- Public Disclosure 허용 여부
- Standard Disclosure Terms
- Coordinated Disclosure
- 사전 승인
- Private Engagement 존재 공개 금지
- Official Communication Channel
- 외부 채널 사용 금지

전체 원본은 `scope.json`.
Recon에 직접 영향이 있으면 `scope.md`에 요약한다.

---

# 19. Data Handling

다음을 확인한다.

- 실제 사용자 Data 접근
- Data 변경 / 삭제 금지
- PII Handling
- 최소 증명
- Exfiltration 제한
- Screenshot 제한
- 저장 후 삭제 조건
- Sensitive Data Report 방식

Recon에 영향이 있으면 `scope.md`에 요약한다.

---

# 20. What's New / Program Updates

현재 Engagement에서 공식적으로 접근 가능한 중요 Update만 확인한다.

우선:

- New Target
- Target Scope 변경
- Pause Testing
- Resume Testing
- Stop Testing
- Stop Scanner Traffic
- Reward 변경
- Credential 변경
- Program Rule 변경
- Disclosure 변경
- Safe Harbor 변경

Update:

```json
{
  "type": "",
  "title": "",
  "raw_text": "",
  "published_at": null,
  "affected_targets": [],
  "workflow_effect": null,
  "source_ids": []
}
```

`workflow_effect`:

```text
none
manual_review
block_all_testing
block_automated_testing
resume_testing
```

전체 Recent Activity를 무차별 수집하지 않는다.

---

# 21. Resources / Additional Information

Scope 또는 Testing에 관련된 자료만 확인한다.

예:

- API Documentation
- System Diagram
- Architecture Diagram
- Test Guide
- Mobile App Link
- Binary
- VPN Guide
- Credential Guide
- CSV / TXT / PDF
- Environment Guide

다운로드 시:

- 공식 Brief에서 직접 연결된 자료인지 확인
- Hash 기록
- 대량 데이터는 Python Parser 사용
- LLM Context에 반복 입력하지 않음

Private Engagement Attachment는 공개 저장소에 저장하지 않는다.

---

# 22. Evidence

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

Evidence 원칙:

- 공식 Bugcrowd Brief 우선
- Brief가 직접 연결한 공식 자료 사용 가능
- 제3자 Scope Mirror는 Debug/비교용이며 최종 Evidence로 사용하지 않음
- Cookie / Token / Password / Credential / PII 저장 금지
- Private Engagement 정보 공개 금지

---

# 23. scope.json

전체 Scope/Policy 기준 원본:

```json
{
  "schema_version": "0.3",
  "scan_id": "",
  "status": "SCOPE_COMPLETE",
  "workflow_gate": "manual_review",
  "blocking_reasons": [],
  "platform": "bugcrowd",
  "collected_at": "",
  "program": {
    "name": "",
    "organization": "",
    "slug": "",
    "program_url": "",
    "final_url": "",
    "engagement_type": null,
    "visibility": null,
    "program_status": null,
    "testing_period": null,
    "managed_by_bugcrowd": null,
    "bounty_available": null,
    "industry": null,
    "tagline": null,
    "collaboration_enabled": null,
    "scope_rating": null,
    "last_updated": null
  },
  "target_groups": [],
  "targets": [],
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
    "required_user_agent": null,
    "required_headers": [],
    "required_vpn": null,
    "credential_requirements": [],
    "account_requirements": [],
    "allowed_environments": [],
    "time_restrictions": [],
    "regional_restrictions": []
  },
  "rules": {
    "prohibited_actions": [],
    "testing_problems": [],
    "data_handling_rules": [],
    "disclosure_rules": []
  },
  "reward_policy": {},
  "vrt": {
    "scope_rules": [],
    "program_exceptions": []
  },
  "known_issues": {
    "status": "unknown",
    "unique_count": null,
    "total_count": null,
    "targets": []
  },
  "safe_harbor": {
    "status": "unknown",
    "summary": null,
    "conditions": [],
    "disclose_io": null,
    "source_ids": []
  },
  "priority_scenarios": [],
  "updates": [],
  "attachments": [],
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

# 24. scope.md

`scope.md`는 Recon용 핵심 요약이다.

전체 Bugcrowd Brief를 복사하지 않는다.

```md
# Scope

## Program
- Platform: Bugcrowd
- Program:
- Type:
- Status:
- Testing Period:
- Workflow Gate:
- Source:

## In Scope
- ...

## Out of Scope
- ...

## Testing Restrictions
- Automation:
- Rate Limit:
- Required User-Agent:
- Required Headers:
- VPN:
- Credential / Account Requirement:
- Allowed Environment:
- Time / Region Restriction:

## Prohibited Actions
- ...

## Scope Change Warnings
- Now OOS / New / Now in-scope 등 현재 Recon에 영향 있는 항목만

## Manual Review
- 없음 또는 Recon 전에 확인할 항목

## Source
- 공식 Bugcrowd Engagement URL
```

기본 `scope.md`에는 다음을 장황하게 넣지 않는다.

- Reward Table 전체
- Known Issues 전체
- VRT 전체
- Safe Harbor 상세
- Program Statistics
- Hall of Fame
- Recent Activity 전체
- Evidence 전체
- Target Tags 전체

단, Recon에 직접 영향을 주면 요약한다.

---

# 25. Workflow Gate

Scope 수집 Status와 Recon 허용 여부를 분리한다.

```text
proceed
blocked
manual_review
```

## proceed

- Engagement가 Testing 가능한 상태
- In-Scope Target 명확
- Automation/Restrictions 적용 가능
- Blocking Update 없음

## blocked

예:

- Testing Paused
- Engagement Completed
- Stop Testing
- 명시적 Automation 금지인데 현재 Recon 방식이 Automation에 의존
- Testing Period 종료

## manual_review

예:

- Program Status 불명확
- Automation 조건 모호
- Scope/Update 충돌
- 중요한 Credential Rule이 불명확
- VRT Scope Rule이 Target Scope와 충돌해 해석 필요

---

# 26. Verification

## Program
- [ ] Bugcrowd Engagement 확인
- [ ] 이름/slug 확인
- [ ] Engagement Type 확인
- [ ] Public/Private 확인
- [ ] Status 확인
- [ ] Testing Period 확인 또는 unknown
- [ ] Safe Harbor 상태 확인 또는 unknown
- [ ] Workflow Gate 결정

## Scope
- [ ] 모든 In-Scope Target Group 확인
- [ ] 모든 Out-of-Scope Target Group 확인
- [ ] 모든 Target 확인
- [ ] Target Name 저장
- [ ] URL/Location 저장 또는 null
- [ ] Category 저장
- [ ] Tags 저장
- [ ] Group 연결
- [ ] Reward 연결
- [ ] Target Instruction 저장
- [ ] Target Change Flag 확인
- [ ] Brief에 없는 Target 생성 안 함

## Policy
- [ ] Overview / Description 확인
- [ ] Program Rules 확인
- [ ] Testing Problems 확인
- [ ] Automation 원문+상태 저장
- [ ] Rate Limit 확인 또는 unknown
- [ ] User-Agent/Header 확인
- [ ] VPN 확인 또는 unknown
- [ ] Credential/Account Requirement 확인
- [ ] Environment 제한 확인
- [ ] Prohibited Actions 전체 수집
- [ ] Data Handling 확인
- [ ] Disclosure 확인
- [ ] Safe Harbor 확인

## VRT / Known Issues
- [ ] VRT Scope Rule 확인 또는 없음 기록
- [ ] 적용 Target 범위 보존
- [ ] Known Issues 상태 기록
- [ ] Known Issues를 Target Scope와 혼동하지 않음

## Updates
- [ ] Scope 변경 Flag 확인
- [ ] What's New / Update 확인
- [ ] Pause/Resume/Stop Testing 확인
- [ ] Stop Scanner Traffic 확인
- [ ] 충돌은 conflicts에 기록

## Evidence
- [ ] 모든 중요 값에 Source
- [ ] 공식 Bugcrowd Brief 근거
- [ ] 인증정보 없음
- [ ] Private Engagement 정보 공개 안 함

## Output
- [ ] scope.json 존재
- [ ] JSON 검증 성공
- [ ] scope.md 존재
- [ ] JSON/MD 충돌 없음
- [ ] run-state.json 존재

---

# 27. Targeted Retry

누락된 항목만 다시 확인한다.

예:

```text
missing_fields:
- rate_limit
- safe_harbor
- target_documentation
```

이미 수집한 Target Group 전체를 처음부터 다시 읽지 않는다.

두 번째 확인에도 없으면 `unknown`으로 확정하고 이유를 기록한다.

---

# 28. 종료 상태

## SCOPE_COMPLETE

- Target Group / Target Scope 수집 완료
- 필수 Testing Restriction 수집 완료
- 공식 Evidence 연결
- scope.json 검증 완료

`SCOPE_COMPLETE`여도 `workflow_gate = blocked`일 수 있다.

## SCOPE_NEEDS_AUTH

- Private Engagement 접근 필요
- 필수 Scope/Rules가 인증 없이는 보이지 않음
- 사용 가능한 세션 없음

Known Issues만 인증 필요하고 Core Scope가 완전한 경우에는
무조건 `SCOPE_NEEDS_AUTH`로 만들지 않는다.

## SCOPE_NEEDS_REVIEW

- Automation 조건 모호
- Scope와 Update 충돌
- 중요한 Testing Rule 불명확
- Program Status / Testing Period 불명확
- Invite/NDA/Credential Claim 같은 사용자 확인이 필요한 상태 변경이 있음

## SCOPE_FAILED

- Engagement 접근 실패
- Bugcrowd Engagement가 아님
- Browser Tool 반복 실패
- Output 생성/검증 실패

---

# 29. Main Agent 반환

```json
{
  "agent": "scope",
  "platform": "bugcrowd",
  "program_slug": "",
  "status": "SCOPE_COMPLETE",
  "workflow_gate": "proceed",
  "scope_json": "",
  "scope_md": "",
  "run_state": "",
  "blocking_reasons": []
}
```
