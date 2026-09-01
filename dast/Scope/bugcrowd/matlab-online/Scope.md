# Scope: MATLAB Online - Ongoing Bug Bounty Engagement

> Source: https://bugcrowd.com/engagements/matlab-online
> Captured at: 2026-08-27T09:35:57.457001+00:00
> Scope ID: `scope_830cb1caa1ce480c9a9c53bbec3077a0`

## Program summary

MATLAB Online은 MATLAB 및 Simulink 기능을 클라우드로 확장하는 브라우저 기반 플랫폼입니다. 프로그램은 진행 중이며, 범위는 명시된 MATLAB Online 프로덕션 환경 하나입니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| URL | https://matlab.mathworks.com/ | 명시적으로 In Scope이며, 테스트는 이 프로덕션 스택에서 수행해야 합니다. | 명시되지 않음 | 브라우저 기반 MATLAB 경험을 제공하는 MATLAB Online 프로덕션 환경입니다. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Any domain/property of MathWorks not listed explicitly in the targets section is out of scope. | 보상 및 포인트 기반 보상 대상이 아닙니다. | N/A | Targets 섹션에 명시되지 않은 MathWorks의 모든 도메인·속성 및 모든 미명시 서브도메인은 범위 밖입니다. |
| OTHER | Denial of Service attacks of any type. | 명시적 제외 | N/A | 모든 유형의 서비스 거부 공격 |
| OTHER | Open redirects (through headers and parameters) / Lack of security speedbump when leaving the site | 명시적 제외 | N/A | 헤더·파라미터 기반 오픈 리다이렉트 및 사이트 이탈 경고 부재 |
| OTHER | Internal IP address disclosure | 명시적 제외 | N/A | 내부 IP 주소 공개 |
| OTHER | Accessible non-sensitive files and directories (e.g., README.TXT, CHANGES.TXT, robots.txt, gitignore, etc.) | 명시적 제외 | N/A | 비민감 파일 및 디렉터리 접근 가능성 |
| OTHER | Social engineering/phishing attacks | 명시적 제외 | N/A | 사회공학·피싱 공격 |
| OTHER | Self XSS | 명시적 제외 | N/A | Self XSS |
| OTHER | Text injection | 명시적 제외 | N/A | 텍스트 인젝션 |
| OTHER | Descriptive error messages (e.g., stack traces, application/server errors, path disclosure) | 명시적 제외 | N/A | 설명적인 오류 메시지, 스택 트레이스, 경로 노출 |
| OTHER | Fingerprinting/banner disclosure on common/public services. | 명시적 제외 | N/A | 일반·공개 서비스의 핑거프린팅 및 배너 공개 |
| OTHER | Clickjacking and issues only exploitable through clickjacking. | 명시적 제외 | N/A | 클릭재킹 및 클릭재킹으로만 악용 가능한 이슈 |
| OTHER | CSRF issues that don't impact the integrity of an account (e.g. login or out, contact forms and other publicly accessible forms) | 명시적 제외 | N/A | 계정 무결성에 영향을 주지 않는 CSRF |
| OTHER | Email spoofing, lack of DMARC, SPF records, or DKIM configuration | 명시적 제외 | N/A | 이메일 스푸핑 및 DMARC·SPF·DKIM 구성 부재 |
| OTHER | Lack of Secure and HTTPOnly cookie flags (critical systems may still be in scope). | 명시적 제외(중요 시스템은 예외 가능) | N/A | Secure 및 HTTPOnly 쿠키 플래그 부재 |
| OTHER | Login or Forgot Password page brute force, account lockout not enforced, or insufficient password strength requirements | 명시적 제외 | N/A | 로그인·비밀번호 찾기 브루트포스, 계정 잠금 부재, 불충분한 비밀번호 강도 |
| OTHER | HTTPS mixed content scripts. | 명시적 제외 | N/A | HTTPS 혼합 콘텐츠 스크립트 |
| OTHER | Username / email enumeration by brute forcing / error messages (e.g. login / signup / forgotten password). | 명시적 제외 | N/A | 브루트포스 또는 오류 메시지를 통한 사용자명·이메일 열거 |
| OTHER | TLS/SSL configuration issues are not in scope unless they are egregious. Lack of pinning or allowing theoretically insecure cipher-suites is not in scope. | 명시적 제외 | N/A | 심각하지 않은 TLS/SSL 구성 문제, 인증서 고정 부재 및 이론적으로 약한 암호군 허용 |
| OTHER | Bugs that don't work in the latest version of Chrome, Firefox, Safari, IE11, and Edge | 명시적 제외 | N/A | 최신 Chrome, Firefox, Safari, IE11, Edge에서 재현되지 않는 버그 |
| OTHER | Out-of-date software or use of a known-vulnerable component (exceptional cases, such as where you are able to provide proof of exploitation, may still be in scope) | 명시적 제외(실제 악용 증명 등 예외 가능) | N/A | 구식 소프트웨어 또는 알려진 취약 구성요소의 사용 |
| OTHER | Lack of rate limiting on login, registration, or email generating forms. | 명시적 제외 | N/A | 로그인·등록·이메일 생성 양식의 속도 제한 부재 |
| OTHER | Attempt to overwhelm the LLM by sending an excessive number of requests in a short period (exceeding 25 within a minute), you may not receive the anticipated response and will be blocked. | 명시적 제외 | N/A | 1분 내 25회를 초과하는 과도한 요청으로 LLM을 과부하시키려는 행위 |
| OTHER | The presence of virus scanning on uploaded files | 명시적 제외 | N/A | 업로드 파일의 바이러스 검사 존재 |
| OTHER | Content admin pages present on the Internet. | 명시적 제외 | N/A | 인터넷에 노출된 콘텐츠 관리 페이지 |
| OTHER | Security issues in 3rd party services, applications. | 명시적 제외 | N/A | 제3자 서비스·애플리케이션의 보안 이슈 |
| OTHER | Weak Captcha / Captcha Bypass | 명시적 제외 | N/A | 약한 CAPTCHA 또는 CAPTCHA 우회 |
| OTHER | Missing HTTP security headers, specifically (https://www.owasp.org/index.php/List\_of\_useful\_HTTP\_headers), e.g. | 명시적 제외 | N/A | 누락된 HTTP 보안 헤더 |
| OTHER | The following SSL Issues: | 명시적 제외 | N/A | BEAST, BREACH, 재협상 공격, Forward Secrecy 부재, 약한·안전하지 않은 암호군을 포함한 SSL 이슈 |
| OTHER | EXIF meta-data not stripped on images | 명시적 제외 | N/A | 이미지에서 EXIF 메타데이터가 제거되지 않는 문제 |
| OTHER | XSS vulnerabilities that follow the same steps across different file types or extensions will be considered duplicates and are out of scope for additional rewards. | 추가 보상 대상 제외 | N/A | 서로 다른 파일 형식·확장자에서 동일 절차를 따르는 XSS는 중복으로 취급됩니다. |

## Allowed activities

- 명시된 In-Scope 대상에서의 테스트
- 사용자 제공 MATLAB 코드 실행이 아닌, 권한 있는 root 사용자로 명령을 실행하게 하는 취약점 연구
- Docker 컨테이너에서 호스트 운영체제로 탈출하게 하는 취약점 연구
- XSS, CSRF, SQLi, 인증·인가, 데이터 노출, RCE 및 독창적·영향력 있는 이슈에 대한 연구

## Prohibited activities

- MATLAB 프롬프트 또는 MATLAB 프로그램에서 단순히 system()·네트워크 지원 함수를 사용해 명령을 실행하는 행위
- MathWorks 직원에게 연락하는 기능의 사용
- 사후 악용으로 데이터 수정 또는 파괴가 발생할 수 있는 테스트의 계속 수행
- 공개 기능에 대한 지속적 테스트
- 콘텐츠를 5분 넘게 유지
- 지원 요청 기능으로 버그 보고 또는 기술·고객 지원 연락
- 공개적으로 보이는 지속적 콘텐츠 생성
- 비정상적이거나 악의적으로 보이는 임시 표시 콘텐츠 생성
- 동일 취약점을 여러 채널로 중복 제출

## Submission requirements

- 저노력 또는 AI 생성 콘텐츠가 아닌, 독창적 분석·문제 이해·실행 가능한 세부사항을 담은 보고서를 제출해야 합니다.
- 테스트에 사용한 역할(해당 시), 문제와 보안 영향의 명확한 설명, 상세 재현 절차를 포함해야 합니다.
- 보고서당 취약점은 하나만 제출해야 하며, 영향 입증에 필요한 체인은 연계가 명확할 때 같은 보고서에 포함할 수 있습니다.
- 여러 경로·엔드포인트·파라미터 또는 환경에서 발견된 동일 취약점은 중복으로 취급되므로 하나만 제출해야 합니다.
- 이 프로그램은 공개를 허용하지 않으며, 발견한 취약점 정보를 공개하면 안 됩니다.

## Operational constraints

- 모든 요청에 \`X-Request-Purpose: BugcrowdResearch\` 헤더를 포함해야 합니다.
- 선택적으로 \`X-Bugcrowd-Ninja: \[username\]\` 헤더를 포함할 수 있습니다.
- 테스트는 \`@bugcrowdninja.com\` 계정으로 생성한 콘텐츠에서만 허용됩니다.
- MATLAB Online 계정을 Bugcrowd Ninja 이메일로 생성하고 MathWorks Researcher Intake에서 시험 라이선스를 활성화해야 합니다.
- 라이선스 연결 후 모든 테스트는 \`https://matlab.mathworks.com/\` 프로덕션 스택에서 수행해야 합니다.
- 잠재적 사후 악용이 데이터 수정·파괴로 이어질 수 있으면 테스트를 중단하고 보고서를 제출해야 합니다.
- 생성한 콘텐츠는 5분 이내에 삭제해야 합니다.
- LLM에 1분 내 25회를 초과하는 요청을 보내면 차단될 수 있습니다.

## Safe harbor

정책에 따라 선의로 취약점 연구를 수행하면 CFAA 및 유사 주법상 승인된 연구로 간주되고, 우발적 선의의 위반에 대해 법적 조치를 시작·지원하지 않습니다. DMCA 기술적 보호조치 우회 청구를 제기하지 않으며, 연구를 방해하는 약관 제한을 제한적으로 면제합니다. 연구는 선의로 수행될 경우 합법적이고 인터넷 보안에 도움이 되는 행위로 간주됩니다. 다만 모든 관련 법률을 준수해야 하며, 불확실하면 Bugcrowd Support에 문의해야 합니다.

## Ambiguities requiring review

- 자산별 최대 심각도 한도는 캡처의 대상 표에서 명시되지 않았습니다.
- 범위 밖의 MathWorks 자산은 보고할 수 있다고 하나 보상 또는 포인트 기반 보상 대상이 아닙니다.
- 저장형 XSS는 더 넓고 심각한 영향을 입증하지 않는 한 P3로 취급되며, 파일명 기반 저장형 XSS도 P3로 취급됩니다.

## Source evidence

- **Targets:** “https://matlab.mathworks.com/”
- **Target Overview:** “The production environment for MATLAB Online is https://matlab.mathworks.com/”
- **Targets:** “Testing is only authorized on the targets listed as In-Scope.”
- **Targets:** “Any domain/property of MathWorks not listed explicitly in the targets section is out of scope. This includes any/all subdomains not listed above.”
- **Targets:** “If you happen to identify a security vulnerability on a target that is not in-scope, but that demonstrably belongs to MathWorks, it may be reported to this program. However, note that out of scope targets are ineligible for rewards or points-based compensation. Please do not submit the same report through multiple channels.”
- **Target Overview:** “Executing MATLAB commands at the prompt or within a MATLAB program does not meet the standard for any "Server-Side Injection" vulnerabilities.”
- **Target Overview:** “We are interested in vulnerabilities that allow a user to execute commands as a privileged (root) user.”
- **Target Overview:** “We are particularly interested in any vulnerabilities that allow a user to escape from the Docker container to the host operating system.”
- **Focus Areas:** “Cross Site Scripting (XSS)”
- **Focus Areas:** “Cross-Site Request Forgery (CSRF)”
- **Focus Areas:** “SQL Injection (SQLi)”
- **Focus Areas:** “Authentication related issues”
- **Focus Areas:** “Authorization related issues”
- **Focus Areas:** “Data Exposure”
- **Focus Areas:** “Remote Code Execution”
- **Focus Areas:** “Particularly clever vulnerabilities or unique issues that do not fall into explicit categories”
- **Target Overview:** “MATLAB Online has several features that contact MathWorks. For example, "Send feedback". Do not use these features to contact MathWorks staff.”
- **Engagement Guidelines:** “Potential post-exploitation scenarios: If you believe you've identified a vulnerability that may lead to post-exploitation activity including modification or destruction of data please stop testing and submit your finding.”
- **Standards:** “Persistent testing on any publicly facing functionality is not permitted.”
- **Standards:** “Any created content must be deleted within FIVE minutes.”
- **Standards:** “Do not submit a bug report or contact technical or customer support. The service request feature of the MathWorks Account profile page will open service requests. Using this feature is prohibited by this brief.”
- **Standards:** “Any testing that results in temporary content being displayed must look normal to our regular site visitors and be non-malicious.”
- **Engagement Guidelines:** “We do not accept reports that contain low-effort or AI-generated content. Submissions must demonstrate original analysis, clear understanding of the issue, and actionable detail. Reports lacking meaningful human input will be rejected”
- **Report Guidelines:** “Reports must contain the role used for testing (if any), a clear explanation of the issue and the security impact along with detailed steps to reproduce it. If the issue cannot be reliably reproduced based on your report, it may be considered ineligible for a reward”
- **Report Guidelines:** “Do not submit more than one vulnerability per report. In cases where demonstrating impact requires chaining multiple vulnerabilities together, those can be included in the same report as long as the linkage is clearly explained”
- **Out of Scope:** “Denial of Service attacks of any type.”
- **Out of Scope:** “Open redirects (through headers and parameters) / Lack of security speedbump when leaving the site”
- **Out of Scope:** “Internal IP address disclosure”
- **Out of Scope:** “Accessible non-sensitive files and directories (e.g., README.TXT, CHANGES.TXT, robots.txt, gitignore, etc.)”
- **Out of Scope:** “Social engineering/phishing attacks”
- **Out of Scope:** “Self XSS”
- **Out of Scope:** “Text injection”
- **Out of Scope:** “Descriptive error messages (e.g., stack traces, application/server errors, path disclosure)”
- **Out of Scope:** “Fingerprinting/banner disclosure on common/public services.”
- **Out of Scope:** “Clickjacking and issues only exploitable through clickjacking.”
- **Out of Scope:** “CSRF issues that don't impact the integrity of an account (e.g. login or out, contact forms and other publicly accessible forms)”
- **Out of Scope:** “Email spoofing, lack of DMARC, SPF records, or DKIM configuration”
- **Out of Scope:** “Lack of Secure and HTTPOnly cookie flags (critical systems may still be in scope).”
- **Out of Scope:** “Login or Forgot Password page brute force, account lockout not enforced, or insufficient password strength requirements”
- **Out of Scope:** “HTTPS mixed content scripts.”
- **Out of Scope:** “Username / email enumeration by brute forcing / error messages (e.g. login / signup / forgotten password).”
- **Out of Scope:** “TLS/SSL configuration issues are not in scope unless they are egregious. Lack of pinning or allowing theoretically insecure cipher-suites is not in scope.”
- **Out of Scope:** “Bugs that don't work in the latest version of Chrome, Firefox, Safari, IE11, and Edge”
- **Out of Scope:** “Out-of-date software or use of a known-vulnerable component (exceptional cases, such as where you are able to provide proof of exploitation, may still be in scope)”
- **Out of Scope:** “Lack of rate limiting on login, registration, or email generating forms.”
- **Out of Scope:** “Attempt to overwhelm the LLM by sending an excessive number of requests in a short period (exceeding 25 within a minute), you may not receive the anticipated response and will be blocked.”
- **Out of Scope:** “The presence of virus scanning on uploaded files”
- **Out of Scope:** “Content admin pages present on the Internet.”
- **Out of Scope:** “Security issues in 3rd party services, applications.”
- **Out of Scope:** “Weak Captcha / Captcha Bypass”
- **Out of Scope:** “Missing HTTP security headers, specifically (https://www.owasp.org/index.php/List\_of\_useful\_HTTP\_headers), e.g.”
- **Out of Scope:** “The following SSL Issues:”
- **Out of Scope:** “EXIF meta-data not stripped on images”
- **Out-of-scope for Stored XSS:** “XSS vulnerabilities that follow the same steps across different file types or extensions will be considered duplicates and are out of scope for additional rewards.”
- **Access:** “Required X-Request-Purpose: BugcrowdResearch”
- **Access:** “Optional X-Bugcrowd-Ninja: \[username\]”
- **Credentials:** “\*\* Testing is only allowed on content created by your @bugcrowdninja.com Account\*\*”
- **Credentials:** “Mathworks offers Researchers Trial Licenses to access the In-scope Targets. In order to activate a trial license, create a MATLAB Online Account with your bugcrowdninja email address and then visit the MathWorks Researcher Intake and sign in using your account which will give you license to access MATLAB Online.”
- **Credentials:** “Once the license association is complete you should use the production stack (https://matlab.mathworks.com/) for all the testing.”
- **Nondisclosure:** “This engagement does not allow disclosure. You may not release information about vulnerabilities found in this engagement to the public.”
- **Safe Harbor:** “Authorized in accordance with the Computer Fraud and Abuse Act (CFAA) (and/or similar state laws), and we will not initiate or support legal action against you for accidental, good faith violations of this policy;”
- **Safe Harbor:** “Exempt from the Digital Millennium Copyright Act (DMCA), and we will not bring a claim against you for circumvention of technology controls;”
- **Safe Harbor:** “Exempt from restrictions in our Terms &amp; Conditions that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy;”
- **Safe Harbor:** “Lawful, helpful to the overall security of the Internet, and conducted in good faith.”
- **Safe Harbor:** “You are expected, as always, to comply with all applicable laws.”
- **Safe Harbor:** “If at any time you have concerns or are uncertain whether your security research is consistent with this policy, please inquire via Bugcrowd Support before going any further.”
- **Engagement Guidelines:** “Any Stored XSS vulnerabilities found in the MATLAB Online will be considered as P3 unless demonstrated to have wider and more severe impact”
- **Engagement Guidelines:** “Stored XSS vulnerabilities through file names will be considered P3”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
