# Scope: TeamViewer - Bounty Program

> Source: https://yeswehack.com/programs/teamviewer-bounty-program
> Captured at: 2026-08-27T04:53:24.826367+00:00
> Scope ID: `scope_b5152c374388495285fd344223a91652`

## Program summary

TeamViewer Germany GmbH의 원격 연결·증강현실·IT 관리 솔루션 대상 공개 버그바운티 프로그램입니다. 명시된 9개 스코프에 한정됩니다. Critical 자산 보상: Low €200 · Medium €1,000 · High €4,000 · Critical €10,000. High 자산 보상: Low €100 · Medium €500 · High €2,000 · Critical €5,000.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| URL | https://www.teamviewer.com/en/products/teamviewer/ | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | Critical | TeamViewer Remote desktop client 무료 다운로드 페이지. 자산 가치: Critical. 보상: Low €200 · Medium €1,000 · High €4,000 · Critical €10,000. |
| URL | https://web.teamviewer.com | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | Critical | TeamViewer 클라이언트의 웹 버전. 자산 가치: Critical. 보상: Low €200 · Medium €1,000 · High €4,000 · Critical €10,000. |
| URL | https://account.teamviewer.com | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | Critical | 연결된 로그인 서비스. 자산 가치: Critical. 보상: Low €200 · Medium €1,000 · High €4,000 · Critical €10,000. |
| URL | https://login.teamviewer.com | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | Critical | TeamViewer Remote 관리 콘솔. 자산 가치: Critical. 보상: Low €200 · Medium €1,000 · High €4,000 · Critical €10,000. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.teamviewer.teamviewer.market.mobile&amp;hl=en&amp;gl=US | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | High | TeamViewer Remote Control Android 앱. 자산 가치: High. 보상: Low €100 · Medium €500 · High €2,000 · Critical €5,000. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.teamviewer.quicksupport.market&amp;hl=en&amp;gl=US | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | High | TeamViewer QuickSupport Android 앱. 수신 원격 세션 전용 모바일 클라이언트입니다. 자산 가치: High. 보상: Low €100 · Medium €500 · High €2,000 · Critical €5,000. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.teamviewer.host.market&amp;hl=en&amp;gl=US | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | High | Teamviewer Host Android 앱. 모바일 기기의 무인 액세스용 앱입니다. 자산 가치: High. 보상: Low €100 · Medium €500 · High €2,000 · Critical €5,000. |
| MOBILE\_APP | https://apps.apple.com/de/app/teamviewer-remote-control/id692035811 | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | High | TeamViewer Remote Control iOS 앱. 자산 가치: High. 보상: Low €100 · Medium €500 · High €2,000 · Critical €5,000. |
| MOBILE\_APP | https://apps.apple.com/de/app/teamviewer-quicksupport/id661649585 | 명시된 프로그램 스코프이며, qualifying vulnerability 및 기타 프로그램 요건을 충족해야 합니다. | High | TeamViewer QuickSupport iOS 앱. 수신 원격 세션 전용 모바일 클라이언트입니다. 자산 가치: High. 보상: Low €100 · Medium €500 · High €2,000 · Critical €5,000. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| WILDCARD | All domains not listed In-Scope | 보상 및 테스트 대상이 아닙니다. | N/A | 명시적인 인스코프 목록에 없는 모든 도메인. |

## Allowed activities

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Insecure Direct Object Reference (IDOR)
- 수평 및 수직 권한 상승
- Authentication bypass &amp; broken authentication
- 실질적 보안 영향이 있는 Business Logic Errors vulnerability
- Local files access and manipulation (LFI, RFI, XXE, SSRF, XSPA)
- 실질적 보안 영향이 있는 Cross-Origin Resource Sharing (CORS)
- 실질적 보안 영향이 있는 Cross-site Request Forgery (CSRF)
- Open Redirect
- 조직이 통제하고 최소 하나의 스코프에 영향을 미치는 자산에서의 노출된 비밀정보·자격증명·민감 정보
- 클라이언트 앱에서 직접 상호작용하는 백엔드 서비스 테스트

## Prohibited activities

- 모든 형태의 Denial of Service (DoS) attacks
- 네트워크 장비 및 TeamViewer Germany GmbH 인프라에 대한 간섭
- 서비스 저하 또는 중단을 일으킬 수 있는 테스트
- 자동화 도구 사용
- 사용자 데이터 유출, 조작 또는 파괴
- Broken Link/Social media Hijacking
- Tabnabbing
- Leaked User IDs
- Missing cookie flags
- Content/Text injections
- Clickjacking/UI redressing
- 최근 공개된 CVE(패치 릴리스 후 30일 미만)
- 악용 가능한 취약점과 PoC가 없는 CVE
- 악용 가능한 취약점과 PoC가 없는 열린 포트 또는 서비스
- 직원 또는 계약자 대상 사회공학
- 웹 폼의 autocomplete 속성 존재
- 구식 브라우저 또는 플랫폼에 영향을 미치는 취약점
- 다른 사용자에게 영향을 줄 수 없는 Self-XSS 또는 XSS
- 악용 가능한 취약점과 PoC가 없는 가상적 결함 또는 모범 사례 문제
- SSL/TLS 문제(예: 만료된 인증서, 모범 사례)
- 악용 불가능한 취약점(예: Self-XSS, HTTP 헤더를 통한 XSS 또는 Open Redirect)
- MITM 또는 피해자 기기의 물리적 접근이 필요한 공격 시나리오
- 직접 악용 가능한 취약점과 PoC로 이어지지 않는 누락된 보안 관련 HTTP 헤더
- 낮은 심각도의 CSRF(예: 비인증·로그아웃·로그인·장바구니 업데이트)
- 유효하지 않거나 누락된 이메일 보안 레코드(예: SPF, DKIM, DMARC)
- 세션 관리 문제(예: 만료 부재, 비밀번호 변경 시 로그아웃 없음, 동시 세션)
- 악용 가능한 취약점과 PoC가 없는 정보 노출(예: 스택 트레이스, 경로 노출, 디렉터리 목록, 소프트웨어 버전, IP 노출, 제3자 비밀정보, EXIF Metadata, Origin IP)
- CSV injection
- 악성 파일 업로드(예: EICAR 파일, .EXE)
- HTTP Strict Transport Security Header (HSTS)
- 완전한 악용 가능 취약점과 PoC가 없거나 스코프에 적용되지 않는 Subdomain takeover
- 악용 가능한 취약점과 PoC가 없는 Blind SSRF(예: DNS 및 HTTP pingback, Wordpress XMLRPC)
- rate-limiting·brute-forcing·captcha 부족 또는 우회
- User enumeration(예: 이메일, 별칭, GUID, 전화번호, 일반 CMS 엔드포인트)
- 약한 비밀번호 정책(예: 길이, 복잡성, 재사용)
- 사용자 스팸 가능성(이메일·SMS·다이렉트 메시지 플러딩)
- 공개되었거나 잘못 구성된 공개 API 키(예: Google Maps, Firebase, analytics tools)
- 외부 서비스로 HTTP referer를 통해 전송된 비밀번호 재설정 토큰
- 조직이 통제하지 않는 제3자 자산에서 수집한 탈취 비밀정보·자격증명·정보
- 프로그램 스코프에 적용되지 않는, 조직 통제 자산의 노출된 비밀정보·자격증명·정보
- Pre-account takeover(예: oAuth를 통한 계정 생성)
- GraphQL Introspection is enabled

## Submission requirements

- 취약점은 발견 후 24시간 이내에 yeswehack.com을 통해서만 보고해야 합니다.
- 명확한 텍스트 설명과 재현 단계를 제출하고, 필요 시 스크린샷 또는 PoC 코드 같은 첨부물을 포함해야 합니다.
- 최초 보고자여야 합니다.
- 유효한 보고서이며 qualifying vulnerability여야 합니다.
- 보고하려면 hunter 계정으로 로그인해야 합니다.

## Operational constraints

- 테스트는 비파괴적이어야 하며 proof of concept 범위에 머물러야 합니다.
- 자동화 도구를 사용하지 말고 초당 요청 수를 제한해야 합니다.
- 바이너리는 https://www.teamviewer.com/en/products/teamviewer 에서 내려받아 사용합니다.
- 웹 버전은 https://web.teamviewer.com 에서, Login Service는 https://account.teamviewer.com 에서, Management Console (MCO)은 https://login.teamviewer.com 에서 접근하도록 안내됩니다.
- 라이선스 제한 우회에 의존하는 보고서는 구체적이고 심각한 사업 영향이 입증되지 않으면 Informative로 종료되며 보상되지 않습니다.
- 현직 또는 전직 TeamViewer Germany GmbH 직원이나 계약자는 금전 보상 대상이 아닙니다.

## Safe harbor

명시적인 safe harbor 조항은 확인되지 않았습니다. 프로그램은 책임 있는 공개와 비파괴적 PoC 범위의 테스트를 요구합니다.

## Ambiguities requiring review

- 제공된 캡처 상태는 COMPLETE이며, 명시된 Scopes 9개가 모두 표에 포함되어 있습니다.
- 'Backend services you might directly interact with from the client app are considered part of the scope.'라고 하나, 개별 백엔드 서비스의 호스트명·URL·자산 유형은 명시되지 않았습니다.
- 라이선스 제한 우회는 심각한 사업 영향을 사례별로 입증한 경우에만 보상 여부를 분석하므로, 보상 적격성이 사전 확정되지 않습니다.
- 프로그램은 책임 있는 공개를 언급하지만, 법적 면책 또는 safe-harbor의 구체적 범위는 명시하지 않습니다.

## Source evidence

- **SCOPE DETAILS:** “For now, the scope of this program is limited to the following:”
- **SCOPES:** “Scopes 9”
- **SCOPES:** “https://www.teamviewer.com/en/products/teamviewer/ Application Critical”
- **SCOPES:** “https://web.teamviewer.com Web application Critical”
- **SCOPES:** “https://account.teamviewer.com Web application Critical”
- **SCOPES:** “https://login.teamviewer.com Web application Critical”
- **SCOPES:** “https://play.google.com/store/apps/details?id=com.teamviewer.teamviewer.market.mobile&amp;hl=en&amp;gl=US Mobile application Android High”
- **SCOPES:** “https://play.google.com/store/apps/details?id=com.teamviewer.quicksupport.market&amp;hl=en&amp;gl=US Mobile application Android High”
- **SCOPES:** “https://play.google.com/store/apps/details?id=com.teamviewer.host.market&amp;hl=en&amp;gl=US Mobile application Android High”
- **SCOPES:** “https://apps.apple.com/de/app/teamviewer-remote-control/id692035811 Mobile application IOS High”
- **SCOPES:** “https://apps.apple.com/de/app/teamviewer-quicksupport/id661649585 Mobile application IOS High”
- **OUT OF SCOPES:** “All domains not listed In-Scope”
- **PROGRAM RULES:** “Any type of denial of service attacks is strictly forbidden, as well as any interference with network equipment and TeamViewer Germany GmbH infrastructure. Your work should be non-destructive and remain within a proof of concept framework.”
- **ELIGIBILITY AND RESPONSIBLE DISCLOSURE:** “Any vulnerability found must be reported no later than 24 hours after discovery and exclusively through yeswehack.com”
- **ELIGIBILITY AND RESPONSIBLE DISCLOSURE:** “You must avoid tests that could cause degradation or interruption of our service (refrain from using automated tools, and limit yourself about requests per second).”
- **VULNERABILITY TYPES:** “QUALIFYING VULNERABILITIES”
- **VULNERABILITY TYPES:** “NON-QUALIFYING VULNERABILITIES”
- **HUNTING REQUIREMENTS:** “Download and use the binary from https://www.teamviewer.com/en/products/teamviewer”
- **LICENSE RESTRICTION BYPASS – REWARDS:** “All vulnerability reports that demonstrate an issue relying on bypassing our license limitations will be considered as Informative and closed without reward, except if a concrete and severe business impact can be demonstrated.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
