# Scope: Glassdoor Managed Bug Bounty Engagement

> Source: https://bugcrowd.com/engagements/glassdoor-ogbb
> Captured at: 2026-08-27T05:13:18.009301+00:00
> Scope ID: `scope_182a6d72dfb84ec5b7b7e9764f1ff5ed`

## Program summary

Glassdoor 및 Fishbowl의 공개 애플리케이션을 대상으로 하는 진행 중인 버그 바운티 프로그램입니다. Bugcrowd Vulnerability Rating Taxonomy를 초기 등급 산정에 사용하되, 가능성 또는 영향에 따라 등급이 조정될 수 있습니다. 예외적인 보고서에는 Glassdoor 재량으로 추가 보너스가 지급될 수 있습니다. 보상 범위는 P1 $3500 – $7000, P2 $1000 – $3000, P3 $300 – $750, P4 $50 – $100입니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| API | https://api.glassdoor.com/\* | 명시적으로 인스코프이며 API Testing 태그가 표시됩니다. | P1 | XML 또는 JSON 형식의 Glassdoor API 엔드포인트입니다. Developer Documentation. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/\* | 명시적으로 인스코프입니다. | P1 | Glassdoor의 주 웹 애플리케이션이며 테스트 시작점으로 제시됩니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/member/\* | 명시적으로 인스코프입니다. | P1 | 사용자 중심 영역으로, 기여·내 계정·내 정보·이력서 업로드·프로필 제어를 포함합니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/employers/ec/\* | 명시적으로 인스코프입니다. | P1 | 고용주가 참여도, 리뷰 및 관리 도구를 관리·검토하는 접근 제어 플랫폼입니다. Documentation: Glassdoor Employee Center Guide. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/Job/\* | 명시적으로 인스코프입니다. | P1 | 구직 검색 기능입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/Reviews/\* | 명시적으로 인스코프입니다. | P1 | 회사 탐색 기능입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/Compare/\* | 명시적으로 인스코프입니다. | P1 | 회사 비교 도구입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/mz-survey/\* | 명시적으로 인스코프입니다. | P1 | 회사 리뷰 설문조사입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.glassdoor.com/Salaries/\* | 명시적으로 인스코프입니다. | P1 | 급여 탐색 도구입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| WILDCARD | https://www.fishbowlapp.com/\* | 명시적으로 인스코프이며 Website Testing 및 Javascript 태그가 표시됩니다. | P1 | 커뮤니티 대화를 위한 Fishbowl 웹사이트입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| API | https://api.fishbowlapp.com/\* | 명시적으로 인스코프이며 API Testing 태그가 표시됩니다. | P1 | Fishbowl의 RESTful API 엔드포인트입니다. 보상: P1 $3500 – $7000 · P2 $1000 – $3000 · P3 $300 – $750 · P4 $50 – $100. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.fishbowlmedia.fishbowl&amp;hl=en\_US | 인스코프 대상 목록에 Android 태그와 함께 표시됩니다. | 명시되지 않음 | Fishbowl - Android App입니다. |
| MOBILE\_APP | https://apps.apple.com/us/app/fishbowl-professional-network/id1005070636 | 인스코프 대상 목록에 iOS 태그와 함께 표시됩니다. | 명시되지 않음 | Fishbowl - iOS입니다. |
| MOBILE\_APP | https://apps.apple.com/us/app/glassdoor-jobs-careers/id589698942 | 인스코프 대상 목록에 iOS 태그와 함께 표시됩니다. | 명시되지 않음 | Glassdoor iOS App입니다. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.glassdoor.app&amp;hl=en\_US | 인스코프 대상 목록에 Android 태그와 함께 표시됩니다. | 명시되지 않음 | Glassdoor Android App입니다. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Glassdoor Help Page | 보상 또는 포인트 기반 보상의 대상이 아닙니다. | 해당 없음 | 아웃오브스코프 대상으로 표시됩니다. |
| OTHER | Glassdoor Design Page | 보상 또는 포인트 기반 보상의 대상이 아닙니다. | 해당 없음 | 아웃오브스코프 대상으로 표시됩니다. |
| OTHER | Glassdoor Blog | 보상 또는 포인트 기반 보상의 대상이 아닙니다. | 해당 없음 | 아웃오브스코프 대상으로 표시됩니다. |

## Allowed activities

- 명시된 인스코프 대상에 대해서만 테스트합니다.
- Glassdoor 및 Fishbowl 계정은 @bugcrowdninja.com 이메일 주소로 등록합니다.
- Glassdoor 페이로드 테스트에는 승인된 Bugcrowd bowl, 직접 만든 private test bowl 또는 Acme Corp/Winkler Web Designs 회사 페이지만 사용합니다.
- Fishbowl 등록 시 @bugcrowdninja.com 이메일을 사용하여 Bugcrowdninja 회사 bowl에서 테스트합니다.
- 취약점으로 의도치 않은 데이터 접근이 가능할 경우, 효과적인 입증에 필요한 최소량만 접근합니다.
- 데이터 변경·파괴로 이어질 수 있는 사후 악용 가능성을 발견하면 테스트를 중단하고 보고합니다.

## Prohibited activities

- 다른 개인의 정보를 열람·복사·변경·파괴하거나 그 밖에 상호작용하는 행위
- 발견한 정보를 보고 목적 외로 복사·저장·전송·공개·보유하는 행위
- 서비스 중단 또는 성능 저하를 유발하는 행위 및 공격적 자동화 도구 사용
- 다른 Glassdoor 사용자와의 모든 상호작용 및 사용자·직원 피싱 시도
- 실제 bowls 또는 실제 회사 페이지에서의 테스트
- 다른 사용자의 데이터를 대상으로 하는 행위
- 사이트 일부의 삭제·제거·편집
- 모든 종류의 DoS 공격 또는 다른 사용자를 위한 대상 기능 훼손
- Intra-Organizational Broken Access Controls, unless integrity impact is high
- Vulnerabilities dependent on unlikely high privileges (eg. malicious admin)
- User enumeration vulnerabilities
- Volumetric DoS vulnerabilities
- Debug/Stack trace/Errors with non-secret data
- Rate-limiting vulnerabilities, unless integrity impact is high
- External SSRF
- Internal SSRF without an impactful proof of concept
- HTMLi without a realistic and impactful proof of concept
- Self-XSS​​- Clickjacking on pages with no sensitive data or actions
- Attacks requiring Man-in-the-Middle or physical access to a user’s device
- WAF-bypass via Origin IP
- Vulnerabilities affecting users of outdated browsers
- SPF/DMARC/DKIM record missing on a domain
- SSTI, without impactful proof of concept
- Public API schema
- P5 vulnerabilities
- DoS/DDoS/Network DoS
- Rate limiting bypass attempts
- Email bombing or flooding
- ALL forms of social Engineering

## Submission requirements

- 보고서에는 문제와 보안 영향에 대한 명확한 설명 및 상세한 재현 절차를 포함해야 합니다. 신뢰성 있게 재현할 수 없으면 보상 부적격으로 판단될 수 있습니다.
- 복잡한 성격의 익스플로잇에는 동영상 PoC를 포함해야 합니다.
- 보고서 하나에는 취약점 하나만 제출해야 합니다. 영향 입증에 여러 취약점 체인이 필요하면 연결 관계를 명확히 설명하여 같은 보고서에 포함할 수 있습니다.
- 저노력 또는 AI 생성 콘텐츠 보고서는 허용되지 않으며, 원본 분석·명확한 이해·실행 가능한 세부사항을 보여야 합니다.
- 결과 공개에는 제출 시 disclosure request 옵션을 선택하는 방식의 명시적 허가가 필요합니다.

## Operational constraints

- 모든 인스코프 애플리케이션은 공개적으로 접근 가능합니다.
- @bugcrowdninja 이외 계정으로 제출한 Fishbowl 보고서는 보상 대상이 아닙니다.
- 추가 계정은 @bugcrowdninja 이메일 주소의 별칭으로 만들 수 있습니다.
- Glassdoor 테스트 회사 Acme Corp 및/또는 Winkler Web Designs 초대는 지정된 Google Form을 통해 요청해야 합니다.
- 현직 Glassdoor 직원 또는 계약자는 참여할 수 없습니다.
- 전직 직원 또는 계약자는 제출 전 1년 이상 퇴사했고, 재직 중 얻은 비공개 정보를 사용하거나 참조하지 않는 경우에만 참여할 수 있습니다.
- 현지화된 Glassdoor 사이트는 같은 코드베이스를 공유할 수 있으므로 여러 사이트에서 발견된 취약점은 한 번만 보상될 수 있습니다.
- 제3자 애플리케이션은 Glassdoor가 완화 조치를 취할 수 있는 합리적인 조치가 있을 때만 보상 대상입니다.

## Safe harbor

정책에 따라 선의로 수행한 연구는 CFAA 및 유사 주법상 승인된 것으로 간주되며, 우발적·선의의 정책 위반에 대해 Glassdoor는 법적 조치를 시작하거나 지원하지 않습니다. 기술적 보호조치 우회에 대해서는 DMCA 청구를 제기하지 않고, 보안 연구를 방해하는 약관 제한도 이 정책 범위에서 제한적으로 면제합니다. 연구는 항상 관련 법을 준수해야 하며, 불확실한 경우 진행 전에 Freshdesk Portal로 문의해야 합니다. 제3자 제품 활동은 Glassdoor가 승인할 수 없고 제3자 법적 책임을 보장하지 않습니다.

## Ambiguities requiring review

- 캡처에는 “Show more”가 보이지만, 확장된 추가 대상의 설명·보상 표는 제공되지 않았습니다. 모바일 앱 4개는 인스코프 대상 목록에서 확인되지만 별도 보상 차트 적용 여부와 최대 심각도는 명시되지 않았습니다.
- Glassdoor에 속하지만 인스코프 목록에 없는 대상에서 취약점을 발견해 보고할 수는 있으나, 보상 또는 포인트 기반 보상에는 부적격입니다.
- 민감 데이터 또는 다른 사용자 데이터를 만나면 즉시 테스트를 중단하고 보고해야 합니다.
- PII와 기타 민감 정보를 접한 경우 관련 개인정보보호 법령을 준수해야 합니다.
- 제재 대상자 또는 제재 국가의 개인에게는 보상을 지급할 수 없습니다.

## Source evidence

- **Program overview:** “Glassdoor Managed Bug Bounty Engagement Find the right job for you, fast. Consumer ServicesSafe harbor”
- **Rewards:** “Payment reward chart P1 $3500 – $7000 P2 $1000 – $3000 P3 $300 – $750 P4 $50 – $100”
- **In Scope:** “https://api.glassdoor.com/\* Glassdoor's API endpoint formatted in XML or JSON. Developer Documentation Privilege Escalation, Sensitive Data Exposure https://www.glassdoor.com/\* Glassdoor's primary web application. A good place to start your testing Injection Attacks, Privilege Escalation https://www.glassdoor.com/member/\* User focused area contributions, my account, my information, resume uploads, and profile controls. Injection Attacks, Privilege Escalation https://www.glassdoor.com/employers/ec/\* Access control platform for employers to manage and review engagement, reviews, and management tools. Documentation: Glassdoor Employee Center Guide Broken Access Control, Privilege Escalation”
- **In Scope:** “https://www.glassdoor.com/Job/\* Job search features. Injection Attacks https://www.glassdoor.com/Reviews/\* Explore company features. Injection Attacks https://www.glassdoor.com/Compare/\* Company comparison tool. Injection Attacks https://www.glassdoor.com/mz-survey/\* Company review survey. Injection Attacks https://www.glassdoor.com/Salaries/\* Salary Discovery tool Injection Attacks https://www.fishbowlapp.com/\* A a place for community conversations Privilege escalation, sensitive data exposure, Injection attacks, broken access control https://api.fishbowlapp.com/\* Fishbowl's Restful API endpoint Privilege escalation, sensitive data exposure”
- **Out of Scope:** “Testing is only authorized on the targets listed as in scope. Any domain/property of Glassdoor not listed in the targets section is out of scope. This includes any/all subdomains not listed above. If you happen to identify a security vulnerability on a target that is not in scope, but it demonstrably belongs to Glassdoor, you can report it to to this engagement. However, be aware that it is ineligible for rewards or points-based compensation.”
- **Vulnerability Exceptions:** “Intra-Organizational Broken Access Controls, unless integrity impact is high Vulnerabilities dependent on unlikely high privileges (eg. malicious admin) User enumeration vulnerabilities Volumetric DoS vulnerabilities Debug/Stack trace/Errors with non-secret data Rate-limiting vulnerabilities, unless integrity impact is high External SSRF Internal SSRF without an impactful proof of concept HTMLi without a realistic and impactful proof of concept Self-XSS​​- Clickjacking on pages with no sensitive data or actions Attacks requiring Man-in-the-Middle or physical access to a user’s device WAF-bypass via Origin IP Vulnerabilities affecting users of outdated browsers SPF/DMARC/DKIM record missing on a domain SSTI, without impactful proof of concept Public API schema”
- **Out of Scope:** “P5 vulnerabilities Availability/volumetric testing e.g.: DoS/DDoS/Network DoS Rate limiting bypass attempts Email bombing or flooding ALL forms of social Engineering”
- **Safe Harbor:** “When conducting vulnerability research according to this policy, we consider this research to be: Authorized in accordance with the Computer Fraud and Abuse Act (CFAA) (and/or similar state laws), and we will not initiate or support legal action against you for accidental, good faith violations of this policy; Exempt from the Digital Millennium Copyright Act (DMCA), and we will not bring a claim against you for circumvention of technology controls; Exempt from restrictions in our Terms &amp; Conditions that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy; and Lawful, helpful to the overall security of the Internet, and conducted in good faith.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
