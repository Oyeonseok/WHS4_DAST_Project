---
name: hackerone-scope
description: HackerOne 프로그램 페이지를 agent-browser로 동적으로 탐색하여 Structured Scope, 자유형 Scope 규칙, Program Policy, Testing Requirements, Scope Exclusions와 근거를 정확하게 수집한다.
version: 0.1.0
author: AIDAST Team
license: MIT
platforms: [linux]
compatibility: Requires AIDAST, agent-browser, bash, and Python 3.
metadata:
  tags: [scope, hackerone, bug-bounty, vdp, policy, aidast]
  category: scope
---

# HackerOne Scope Collection

## 목적

이 Skill은 HackerOne의 특정 Bug Bounty / VDP 프로그램 URL을 시작점으로 사용해,
AIDAST가 이후 Recon을 안전하게 수행하는 데 필요한 Scope와 정책을 수집한다.

핵심 원칙:

1. 사용자가 준 URL을 그대로 연다.
2. 현재 화면을 직접 보고 어디에 있는지 판단한다.
3. URL 경로나 탭 이름을 하드코딩하지 않는다.
4. 실제 화면에서 발견한 메뉴·탭·링크·표·버튼만 따라간다.
5. 페이지에 적힌 사실과 Agent의 해석을 분리한다.
6. 전체 정책 원본은 `scope.json`에 저장한다.
7. Recon에 필요한 핵심만 `scope.md`에 요약한다.
8. 모든 중요한 판단은 공식 HackerOne 페이지의 근거와 연결한다.

Scope Agent는 공격, Endpoint 탐색, 서브도메인 열거, Payload 전송을 수행하지 않는다.

---

# HackerOne에서 반드시 대응해야 하는 Scope 형태

## Structured Scope

프로그램에 따라 다음처럼 여러 Asset이 개별 행으로 제공될 수 있다.

- URL
- Wildcard
- Domain
- iOS
- Android
- 기타 Asset Type

In-Scope와 Out-of-Scope를 모두 수집한다.

Asset Type이 Web URL만 있을 것이라고 가정하지 않는다.
VDP처럼 Bounty가 없어도 Scope는 동일하게 수집한다.

## Free-text Scope Rule

일부 Program은 `Other` 또는 자유형 문장으로 Scope를 표현할 수 있다.

예를 들어 "조직이 소유·운영·통제하는 제품 또는 웹사이트"와 같은 문구가 있으면:

- 문구를 그대로 `scope_rules`에 저장한다.
- 페이지에 없는 구체 Domain/Asset을 생성하지 않는다.
- 자동 Recon Target으로 안전하게 변환할 수 없으면 `manual_review`로 넘긴다.

Structured Asset과 Free-text Rule을 모두 지원한다.

---

# 입력

```json
{
  "scan_id": "scan-001",
  "program_url": "https://hackerone.com/example?type=team",
  "output_root": "./artifacts",
  "browser_profile": null
}
```

규칙:

- `program_url`을 변경하지 않는다.
- `/policy`, `/scope`, `/policy_scopes` 등의 경로를 만들어내지 않는다.
- 인증정보, Cookie, Token, API Key를 결과에 저장하지 않는다.
- 제공되지 않은 값은 추측하지 않는다.

---

# 출력 경로

```text
artifacts/
└── HackerOne/
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

`program_slug`는 실제 HackerOne 프로그램 화면 또는 최종 프로그램 URL에서 확인한 공식 Handle을 사용한다.

---

# Browser 사용 규칙

기본 Browser Tool은 `agent-browser`다.

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

금지:

- 동일 화면에서 이유 없이 snapshot 반복
- 이미 방문한 URL 반복 방문
- 이전 페이지의 오래된 `<ref>` 재사용
- HackerOne 내부 URL 구조 추측
- Scope와 무관한 Leaderboard / Top Hackers / Profile / Hacktivity 탐색
- 페이지에 없는 정보 생성
- 제3자 Scope 사이트를 최종 Evidence로 사용

다음 정보를 채우기 위한 경우에만 이동한다.

- Scope
- Program Policy
- Scope Exclusions
- Testing Requirements
- Safe Harbor
- Platform Standards / Deviations
- Rewards
- Program Overview / Must Read
- Program Update

---

# 탐색 상태

`run-state.json`:

```json
{
  "scan_id": "",
  "platform": "hackerone",
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
scope_mode
structured_assets
free_text_scope_rules
scope_exclusions
program_overview
testing_requirements
automation_policy
rate_limit
traffic_identification
account_requirements
environment_requirements
data_handling
disclosure
safe_harbor
platform_standards
deviations
core_ineligible_policy
program_specific_exceptions
reward_summary
conflicts
unknowns
```

---

# 1. 프로그램 식별

다음을 수집한다.

- 프로그램 이름
- 프로그램 Handle / slug
- 플랫폼: HackerOne
- 프로그램 유형: Bug Bounty / VDP / 기타
- Public / Private 여부
- Program Status
- 공식 Program URL
- 최종 도착 URL
- Last Updated가 보이면 해당 값
- Bounty 제공 여부

확인할 수 없는 값은 `null`로 저장하고 `unknowns`에 이유를 기록한다.

---

# 2. Program Highlights

## Scope Mode

```text
open
closed
unknown
```

Closed Scope:
- 명시된 Asset 기준
- 명시되지 않은 Asset은 자동 Recon 대상에 추가하지 않음

Open Scope:
- 미등록이지만 조직이 소유한 Asset의 Report를 받을 수 있는 정책
- AIDAST는 조직 전체 인터넷 자산을 자동으로 스캔하지 않음
- Structured Asset은 Recon 후보
- Free-text Broad Rule은 Rule로 저장
- 페이지에 없는 구체 Asset의 소유권을 추측하지 않음
- 자동으로 구체 Target을 안전하게 결정하지 못하면 `manual_review`

## Safe Harbor Highlight

- Gold Standard Safe Harbor
- AI Research Safe Harbor

Highlight만 보고 상세 조건을 창작하지 않는다.

## Platform Standards

- 준수
- Deviations 존재
- 확인 불가

## Coordinated Vulnerability Disclosure

보이면:
- standard
- limited
- undeclared
- unknown

---

# 3. Structured Scope

화면에 표시되는 **모든 Asset 행**을 수집한다.

확인:

- 초기 표시 행
- 접힌 행
- 페이지네이션
- Load More
- Asset Group
- Asset Instruction

각 Asset:

```json
{
  "identifier": "",
  "normalized_value": "",
  "asset_type": "",
  "scope_status": "unknown",
  "submission_eligible": null,
  "bounty_eligible": null,
  "environmental_score": {
    "confidentiality": null,
    "integrity": null,
    "availability": null
  },
  "maximum_severity": null,
  "labels": [],
  "instructions": [],
  "environment": null,
  "source_ids": []
}
```

## Asset Type

실제 UI 표시값을 우선 보존한다.

예:

- CIDR
- Domain
- URL
- Wildcard
- iOS App Store
- iOS TestFlight
- iOS IPA
- Android Play Store
- Android APK
- Windows Microsoft Store
- Source Code
- Executable
- Hardware / IoT
- Other

## Scope Status

```text
in_scope
out_of_scope
unknown
```

Out-of-Scope 행도 생략하지 않는다.

## Submission Eligibility

```text
true
false
null
```

## Bounty Eligibility

```text
true
false
null
```

Bounty Eligibility가 false라고 Out-of-Scope로 바꾸지 않는다.

## Environmental Score / Maximum Severity

화면에 노출되는 값만 저장한다.
노출되지 않으면 추측하지 않는다.

## Asset Labels

실제 표시되는 Labels를 전부 저장한다.

## Asset Instructions

Asset별 개별 지침을 Program 전체 Policy와 별도로 저장한다.

---

# 4. Free-text Scope Rules

Structured Asset 외의 자유형 Scope 문구는 별도로 저장한다.

```json
{
  "rule_id": "scope-rule-001",
  "rule_type": "free_text",
  "raw_text": "",
  "normalized_intent": null,
  "auto_recon_decision": "manual_review",
  "source_ids": []
}
```

Broad Rule을 구체 Domain 목록으로 변환하지 않는다.

예:

```text
owned_or_controlled_assets_in_scope
```

같은 수준의 의미 요약만 허용한다.

---

# 5. Scope Exclusions

두 종류를 분리한다.

## Asset Exclusion

- Domain
- URL
- Mobile App
- IP / CIDR
- Source Code
- Third-party Asset
- Environment

## Vulnerability / Testing Exclusion

- 특정 Vulnerability Type
- 위험한 테스트 방식
- 알려진 문제
- 영향이 없는 Report 유형
- Program-specific Non-Qualifying Finding

Vulnerability Exclusion을 Asset Out-of-Scope로 변환하지 않는다.

---

# 6. Core Ineligible Findings

다음을 분리한다.

```json
{
  "core_ineligible_applies": null,
  "program_exceptions": [],
  "additional_program_exclusions": [],
  "source_ids": []
}
```

원칙:

- 적용 여부 기록
- Program-specific 예외 저장
- 추가 Non-Qualifying 저장
- 공통 Core 목록 전체를 매번 Browser로 재탐색하지 않아도 됨
- 검증된 HackerOne 공통 정책 Cache를 사용할 수 있음
- Cache 사용 시 정책 Version/확인 날짜 저장

---

# 7. Program Overview / Must Read / Hints & Tips

테스트와 직접 관련된 내용을 수집한다.

- 테스트 목적
- 우선 관심 영역
- 중요 비즈니스 기능
- 관심 Vulnerability
- Test Account
- Environment
- 기술 Stack
- 고가치 기능
- 금지 Workflow
- 실제 데이터 주의사항
- 비용 발생 기능
- Geo Restriction
- 2FA Requirement

공식적으로 강조된 것만 `priority_scenarios`에 저장한다.

---

# 8. Testing Requirements

## Automation

```text
allowed
denied
conditional
unknown
```

```json
{
  "status": "unknown",
  "conditions": [],
  "raw_text": null,
  "source_ids": []
}
```

명시되지 않은 값을 허용으로 추측하지 않는다.

## Rate Limit

```json
{
  "status": "unknown",
  "raw_text": null,
  "requests": null,
  "period_seconds": null,
  "source_ids": []
}
```

## Traffic Identification

- Custom User-Agent
- Custom Header
- Researcher 식별 방식
- 사전 Notification
- 특정 IP/VPN

정확한 값이 확인되면 그대로 저장한다.

## VPN

- HackerOne Gateway VPN
- Program-specific VPN
- 필요 없음
- 확인 불가

일반 HackerOne 기능이 존재한다는 이유만으로 현재 Program이 요구한다고 추측하지 않는다.

## Account / Credentials

- Self-signup
- Test Account
- Paid Account / 환급
- API Key
- Enterprise License
- 2FA
- PII 요구
- Credential 발급 절차

Secret 자체는 저장하지 않는다.

## Environment

- Production
- Staging
- Sandbox
- Test Environment
- 특정 Environment만 허용
- Staging/Production 차이

## Real-money / Cost

- 실제 결제 금지
- 환급
- Test Credit
- 확인 불가

---

# 9. Prohibited Actions

페이지에 명시된 금지 행동을 **전부** 수집한다.

예:

- DoS / DDoS
- Availability 영향
- Brute Force
- Social Engineering
- Spam
- 사용자/관리자 Noise
- Physical Security
- Data destruction
- 불필요한 PII 접근
- Third-party Infrastructure 테스트

일부 예시만 남기지 않는다.

---

# 10. Data Handling

확인:

- PII 처리
- 실제 사용자 데이터 접근 제한
- Exfiltration 제한
- 최소 증명
- 저장/복사 금지
- 삭제 요구
- Screenshot/PoC 제한

Recon에 영향을 주는 내용은 `scope.md`에도 요약한다.

---

# 11. Disclosure Policy

가능한 범위에서:

- Public Disclosure 허용 여부
- 사전 승인
- Coordinated Disclosure 조건
- Report 공개 조건
- 외부 채널 제한

전체 Policy 원본에는 저장한다.

---

# 12. Safe Harbor

```json
{
  "gold_standard": null,
  "ai_research": null,
  "summary": null,
  "conditions": [],
  "source_ids": []
}
```

- Gold Standard와 AI Research Safe Harbor 구분
- Safe Harbor는 Scope 확장 근거가 아님
- Third-party Infrastructure에는 적용되지 않을 수 있음
- Program-specific 조건이 있으면 저장

---

# 13. Platform Standards / Deviations

```json
{
  "status": "unknown",
  "deviations": [],
  "exemplary_standards": [],
  "source_ids": []
}
```

Testing에 영향을 주는 Deviation은 Recon Restrictions에 반영한다.

---

# 14. Rewards

Bug Bounty라면:

- Bounty 제공 여부
- Severity별 Reward Range
- Asset별 Reward 차이
- Impact-based Reward
- Reward Rule

VDP라면:

```text
bounty_available = false
```

Reward와 Scope를 구분한다.

---

# 15. Program Updates

현재 Program에서 공식적으로 접근 가능한 변경만 확인한다.

- Asset 추가/삭제
- In/Out Scope 변경
- Testing Requirements 변경
- Automation/Rate Limit 변경
- Reward 변경
- Safe Harbor 변경
- Standards/Deviation 변경

전체 Hacktivity를 탐색하지 않는다.

충돌은 `conflicts`에 기록한다.

---

# 16. 첨부자료

Scope/Testing에 관련된 공식 자료만 확인한다.

- API Docs
- Testing Guide
- Credential Guide
- Environment Guide
- CSV / TXT / PDF
- Architecture Diagram

다운로드 시:

- 공식 Program에서 직접 연결되었는지 확인
- Hash 기록
- 대량 데이터는 Python Parser 사용
- LLM Context에 전체 파일을 반복 입력하지 않음

---

# 17. Evidence

모든 중요 값에는 `source_id`.

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
- 공식 HackerOne Program 페이지
- Program이 직접 연결한 공식 자료

제3자 Scope Mirror는 Debug/비교용일 뿐 최종 Evidence로 사용하지 않는다.

Cookie / Token / Password / PII 저장 금지.

---

# 18. scope.json

전체 Scope/Policy 원본:

```json
{
  "schema_version": "0.3",
  "scan_id": "",
  "status": "SCOPE_COMPLETE",
  "platform": "hackerone",
  "collected_at": "",
  "program": {
    "name": "",
    "slug": "",
    "program_url": "",
    "final_url": "",
    "program_type": null,
    "visibility": null,
    "program_status": null,
    "bounty_available": null,
    "scope_mode": "unknown",
    "last_updated": null,
    "coordinated_disclosure": null
  },
  "assets": [],
  "scope_rules": [],
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
    "account_requirements": [],
    "allowed_environments": [],
    "time_restrictions": [],
    "geo_restrictions": [],
    "cost_requirements": []
  },
  "scope_exclusions": {
    "assets": [],
    "vulnerabilities": []
  },
  "core_ineligible_findings": {
    "applies": null,
    "program_exceptions": [],
    "additional_program_exclusions": [],
    "source_ids": []
  },
  "priority_scenarios": [],
  "prohibited_actions": [],
  "reward_policy": {},
  "safe_harbor": {
    "gold_standard": null,
    "ai_research": null,
    "summary": null,
    "conditions": [],
    "source_ids": []
  },
  "platform_standards": {
    "status": "unknown",
    "deviations": [],
    "exemplary_standards": [],
    "source_ids": []
  },
  "data_handling_rules": [],
  "disclosure_rules": [],
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

# 19. scope.md

Recon용 핵심 요약:

```md
# Scope

## Program
- Platform: HackerOne
- Program:
- Type:
- Status:
- Scope Mode:
- Source:

## In Scope
- ...

## Out of Scope
- ...

## Free-text Scope Rules
- 필요한 경우에만

## Testing Restrictions
- Automation:
- Rate Limit:
- Required User-Agent:
- Required Headers:
- VPN:
- Account / Credential Requirement:
- Allowed Environment:
- Time / Geo Restriction:
- Cost / Real-money Restriction:

## Prohibited Actions
- ...

## Manual Review
- 없음 또는 Recon 전에 확인할 항목

## Source
- 공식 HackerOne Program URL
```

기본 `scope.md`에는 장황한 다음 항목을 넣지 않는다.

- Reward Table 전체
- Core Ineligible 전체
- Safe Harbor 상세
- Platform Standards 전체
- Response Efficiency
- Program History 전체
- Evidence 전체
- Asset Labels 전체

단, Recon에 영향을 주면 `Recon Restrictions`에 요약한다.

---

# 20. Scope 안전 규칙

Structured In-Scope Asset:
- Recon 후보

Structured Out-of-Scope Asset:

```text
deny
```

Free-text Broad Rule:
- 구체 Asset 생성 금지
- 안전하게 자동 결정 불가 시 `manual_review`

Wildcard:
- 그대로 저장
- Scope Agent가 서브도메인 열거하지 않음
- Recon에서 발견된 Host에 Scope Matcher가 적용

제3자:
- 명시적 Scope가 아니면 포함하지 않음

---

# 21. Verification

## Program
- [ ] HackerOne Program 확인
- [ ] 이름/Handle 확인
- [ ] Type 확인
- [ ] Public/Private 확인
- [ ] Status 확인 또는 unknown
- [ ] Scope Mode 확인 또는 unknown

## Scope
- [ ] 모든 Structured Asset 확인
- [ ] 모든 In-Scope 저장
- [ ] 모든 Out-of-Scope 저장
- [ ] Asset Type 저장
- [ ] Submission Eligibility 저장 또는 null
- [ ] Bounty Eligibility 저장 또는 null
- [ ] Environmental/Severity 저장 또는 null
- [ ] Labels 저장
- [ ] Instructions 저장
- [ ] Free-text Rule 저장
- [ ] Broad Rule에서 임의 Asset 생성하지 않음

## Policy
- [ ] Scope Exclusions 확인
- [ ] Core Ineligible 적용/예외 확인
- [ ] Program Overview/Must Read 확인
- [ ] Testing Requirements 확인
- [ ] Automation 원문+상태 저장
- [ ] Rate Limit 확인 또는 unknown
- [ ] User-Agent/Header 확인
- [ ] VPN 확인 또는 unknown
- [ ] Account/Credential 확인
- [ ] Environment 제한 확인
- [ ] Data Handling 확인
- [ ] Prohibited Actions 전체 확인
- [ ] Disclosure 확인
- [ ] Safe Harbor 확인
- [ ] Platform Standards/Deviations 확인

## Evidence
- [ ] 모든 중요 값에 Source
- [ ] 공식 HackerOne 근거
- [ ] 인증정보 없음
- [ ] Conflict/Unknown 기록

## Output
- [ ] scope.json 존재
- [ ] JSON 검증 성공
- [ ] scope.md 존재
- [ ] JSON/MD 충돌 없음
- [ ] run-state.json 존재

---

# 22. Targeted Retry

누락만 다시 확인한다.

예:

```text
missing_fields:
- rate_limit
- asset_instructions
- safe_harbor
```

이미 수집한 Scope 표를 처음부터 다시 읽지 않는다.

두 번째 확인에도 없으면 `unknown`으로 확정하고 이유를 기록한다.

---

# 23. 종료 상태

## SCOPE_COMPLETE

- Scope Asset/Rule 수집 완료
- 필수 Testing Restriction 수집 완료
- 공식 Evidence 연결
- 다음 단계가 기계적으로 사용할 수 있음

## SCOPE_NEEDS_AUTH

- 필수 Scope/Policy가 인증 없이는 보이지 않음
- 인증 세션 없음

## SCOPE_NEEDS_REVIEW

- Free-text Broad Rule만 있어 구체 Recon Target을 자동 결정할 수 없음
- Automation 조건 모호
- Scope/Policy 충돌
- Testing에 직접 영향을 주는 필수 정보 누락
- 구체 Asset의 소유/통제 여부를 자동 판정하기 어려움

## SCOPE_FAILED

- Program 접근 실패
- HackerOne Program 아님
- Browser Tool 반복 실패
- Output 생성/검증 실패

---

# 24. Main Agent 반환

```json
{
  "agent": "scope",
  "platform": "hackerone",
  "program_slug": "",
  "status": "SCOPE_COMPLETE",
  "scope_json": "",
  "scope_md": "",
  "run_state": "",
  "blocking_reasons": []
}
```
