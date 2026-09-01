# Scope: MATLAB Online - Ongoing Bug Bounty Engagement

> Source: https://bugcrowd.com/engagements/matlab-online
> Captured at: 2026-08-27T05:11:41.627617+00:00
> Scope ID: `scope_bf60df515417448fa46575cdef4b6ac8`

## Program summary

MATLAB Online은 MATLAB 및 Simulink 기능을 클라우드로 확장하는 브라우저 기반 서비스입니다. 지속 진행 중인 버그 바운티이며, 보상은 P1 $3000 – $7000, P2 $1200 – $3000, P3 $550 – $750, P4 $200 – $250입니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| URL | https://matlab.mathworks.com/ | 명시된 In-Scope 대상에서의 테스트만 허가됩니다. @bugcrowdninja.com 계정으로 생성한 콘텐츠에서만 테스트할 수 있으며, 연구원 체험 라이선스 연결 후 이 프로덕션 스택에서 테스트해야 합니다. | P1 | 브라우저 기반 MATLAB Online 프로덕션 환경입니다. 사용자 제공 MATLAB 코드 및 system() 또는 네트워크 지원 함수의 실행 자체는 서버 측 인젝션 취약점으로 인정되지 않습니다. 권한 있는 root 사용자로의 명령 실행 또는 Docker 컨테이너에서 Linux/Amazon EC2 호스트 운영체제로의 탈출이 주요 관심 대상입니다. 보상: P1 $3000 – $7000 · P2 $1200 – $3000 · P3 $550 – $750 · P4 $200 – $250. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Any domain/property of MathWorks not listed explicitly in the targets section is out of scope. This includes any/all subdomains not listed above. | 발견 시 보고는 가능하지만 보상 또는 포인트 보상 대상이 아니며, 같은 보고서를 여러 채널로 제출해서는 안 됩니다. | None | 명시된 대상 외 MathWorks 도메인·자산 및 미기재 하위 도메인은 범위 밖입니다. |

## Allowed activities

- 명시된 In-Scope 대상에서 테스트합니다.
- @bugcrowdninja.com 계정으로 생성한 콘텐츠에서만 테스트합니다.
- XSS, CSRF, SQLi, 인증·인가 문제, 데이터 노출, RCE, Docker 컨테이너 탈출 및 독창적·영향력 있는 문제를 보고할 수 있습니다.
- 명령이 root 권한으로 실행되거나 Docker 컨테이너에서 호스트 운영체제로 탈출하는 취약점을 테스트·보고할 수 있습니다.
- 임시 콘텐츠가 표시되는 테스트는 일반 방문자에게 정상적으로 보이고 악의적이지 않아야 합니다.

## Prohibited activities

- 모든 유형의 서비스 거부(DoS) 공격
- 헤더 및 파라미터를 통한 오픈 리다이렉트 또는 사이트 이탈 시 보안 경고 미비
- 내부 IP 주소 공개
- 비민감 파일·디렉터리 접근 가능 여부(README.TXT, CHANGES.TXT, robots.txt, gitignore 등)
- 사회공학/피싱 공격
- Self XSS
- 텍스트 인젝션
- 설명적 오류 메시지(스택 트레이스, 애플리케이션/서버 오류, 경로 공개 등)
- 일반/공개 서비스의 핑거프린팅 또는 배너 공개
- 클릭재킹으로만 악용 가능한 문제
- 계정 무결성에 영향을 주지 않는 CSRF(로그인·로그아웃, 연락처 양식 및 기타 공개 양식 등)
- 이메일 스푸핑 및 DMARC, SPF 또는 DKIM 구성 부재
- Secure 및 HTTPOnly 쿠키 플래그 부재(중요 시스템은 예외적으로 범위에 포함될 수 있음)
- 로그인·비밀번호 찾기 페이지 무차별 대입, 계정 잠금 미적용 또는 불충분한 비밀번호 강도
- HTTPS 혼합 콘텐츠 스크립트
- 무차별 대입 또는 오류 메시지를 통한 사용자명/이메일 열거(숫자 파라미터 증가 방식 등 예외적 경우는 가능)
- 중대한 경우를 제외한 TLS/SSL 구성 문제, 인증서 핀닝 부재 또는 이론적으로 취약한 암호군 허용
- 최신 Chrome, Firefox, Safari, IE11 및 Edge에서 동작하지 않는 버그
- 구형 소프트웨어 또는 알려진 취약 컴포넌트 사용(실제 악용 증명이 가능한 예외적 경우는 가능)
- 로그인·등록·이메일 생성 양식의 속도 제한 부재
- 1분에 25건을 초과하는 과도한 LLM 요청 전송
- 업로드 파일의 바이러스 스캔 존재
- 인터넷에 존재하는 콘텐츠 관리자 페이지
- 제3자 서비스·애플리케이션의 보안 문제
- 약한 CAPTCHA 또는 CAPTCHA 우회
- 명시된 HTTP 보안 헤더 누락(Strict-Transport-Security, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, CSP 계열)
- BEAST, BREACH, 재협상 공격, Forward Secrecy 미활성화 또는 약한/안전하지 않은 SSL 암호군
- 이미지 EXIF 메타데이터 미제거
- 동일 단계의 Stored XSS를 파일 형식·확장자만 바꾸어 반복 제출하는 행위
- MathWorks 직원에게 연락하는 기능(예: Send feedback) 사용
- 판매 부서 연락
- 버그 보고 또는 기술·고객 지원 연락
- MathWorks Account 프로필의 service request 기능 사용
- 공개적으로 보이고 지속되는 기능에 대한 지속적 테스트
- 생성한 콘텐츠를 5분 이내에 삭제하지 않는 행위
- 사후 악용으로 데이터 수정 또는 파괴가 발생할 수 있는 경우 계속 테스트하는 행위

## Submission requirements

- 저노력 또는 AI 생성 콘텐츠 보고서는 접수하지 않으며, 독창적 분석·문제 이해·실행 가능한 세부사항을 보여야 합니다.
- 테스트 시 사용한 역할(있는 경우), 문제와 보안 영향의 명확한 설명 및 상세 재현 절차를 포함해야 합니다.
- 신뢰성 있게 재현할 수 없는 보고서는 보상 부적격이 될 수 있습니다.
- 보고서당 하나의 취약점만 제출해야 합니다. 영향 입증에 여러 취약점 체인이 필요한 경우 연결 관계를 명확히 설명하면 같은 보고서에 포함할 수 있습니다.
- 여러 경로·엔드포인트·파라미터 또는 환경에서 발견된 동일 취약점은, 영향 또는 악용 방식이 실질적으로 다르지 않으면 중복으로 처리되므로 하나만 제출해야 합니다.
- 이 참여는 공개를 허용하지 않으며, 발견한 취약점 정보를 공개할 수 없습니다.

## Operational constraints

- 모든 요청에 \`X-Request-Purpose: BugcrowdResearch\` 헤더를 포함해야 합니다. 미포함 시 차단될 수 있습니다.
- 선택적으로 \`X-Bugcrowd-Ninja: \[username\]\` 헤더를 포함할 수 있습니다.
- MathWorks Researcher Intake에서 @bugcrowdninja.com 이메일로 만든 MATLAB Online 계정으로 로그인하여 연구원 체험 라이선스를 활성화한 뒤 프로덕션 스택을 사용해야 합니다.
- 잠재적 사후 악용이 데이터 수정 또는 파괴로 이어질 수 있다고 판단되면 즉시 테스트를 중단하고 제출해야 합니다.
- Stored XSS는 더 넓고 심각한 영향을 입증하지 않으면 P3로 간주됩니다.
- 파일 이름을 통한 Stored XSS는 P3로 간주됩니다.
- 독창적·복잡하고 영향력 있는 발견은 재현 단계와 영향을 입증하면 P2로 상향될 수 있습니다.

## Safe harbor

이 정책에 따라 선의로 수행한 연구는 CFAA 및 유사 주법상 승인된 것으로 간주되며, 우발적·선의의 정책 위반에 대해 법적 조치를 시작하거나 지원하지 않습니다. DMCA 기술 통제 우회 청구에서 면제되고, 보안 연구를 방해하는 이용약관 제한은 제한적으로 면제됩니다. 연구는 합법적이고 인터넷 전반의 보안에 도움이 되는 선의의 행위로 간주됩니다. 다만 적용 법률을 준수해야 하며, 정책 부합 여부가 불확실하면 Bugcrowd Support에 문의해야 합니다.

## Ambiguities requiring review

- 범위 표에는 대상 URL 하나만 보이며, 별도의 API·모바일 앱·CIDR 또는 IP 자산은 명시되지 않았습니다.
- 명시된 범위 밖 MathWorks 자산은 보고 가능하나 보상·포인트 보상 부적격입니다.
- 페이지의 검증 통계(10일)는 최근 3개월의 통계이며 공식 응답 SLA로 명시되지는 않았습니다.
- 공개 불가 조건이 있으나 별도의 엠바고 기간 또는 예외 절차는 명시되지 않았습니다.

## Source evidence

- **Targets:** “In Scope In scope Payment reward chart P1 $3000 – $7000 P2 $1200 – $3000 P3 $550 – $750 P4 $200 – $250 Target Overview This is a browser-based version of MATLAB. This platform gives users a MATLAB experience in a browser. As such, it is designed to execute user-supplied MATLAB code. This includes OS commands using the system() or network enabled functions in MATLAB. Executing MATLAB commands at the prompt or within a MATLAB program does not meet the standard for any "Server-Side Injection" vulnerabilities. We are interested in vulnerabilities that allow a user to execute commands as a privileged (root) user. MATLAB Online runs in a Docker container on a Linux host running in Amazon EC2. We are particularly interested in any vulnerabilities that allow a user to escape from the Docker container to the host operating system. The production environment for MATLAB Online is https://matlab.mathworks.com/”
- **Scope restriction:** “Testing is only authorized on the targets listed as In-Scope. Any domain/property of MathWorks not listed explicitly in the targets section is out of scope. This includes any/all subdomains not listed above. If you happen to identify a security vulnerability on a target that is not in-scope, but that demonstrably belongs to MathWorks, it may be reported to this program. However, note that out of scope targets are ineligible for rewards or points-based compensation. Please do not submit the same report through multiple channels.”
- **Engagement Guidelines:** “We do not accept reports that contain low-effort or AI-generated content. Submissions must demonstrate original analysis, clear understanding of the issue, and actionable detail. Reports lacking meaningful human input will be rejected Potential post-exploitation scenarios: If you believe you've identified a vulnerability that may lead to post-exploitation activity including modification or destruction of data please stop testing and submit your finding. We will work with you to evaluate the vulnerability and award you accordingly for the final impact and severity Testing is only allowed on content created by your @bugcrowdninja.com Account Any Stored XSS vulnerabilities found in the MATLAB Online will be considered as P3 unless demonstrated to have wider and more severe impact Stored XSS vulnerabilities through file names will be considered P3 Unique, complex, and impactful findings may be elevated to P2 based on demonstrated steps and impact”
- **Access:** “To ensure uninterrupted access and avoid rate-limiting or blocking during your testing, please include the following custom HTTP header in all of your requests: Required X-Request-Purpose: BugcrowdResearch Optional X-Bugcrowd-Ninja: \[username\] This helps us identify legitimate testing traffic and prevent accidental interference with real users or automated systems. Failure to include this header may result in your requests being blocked.”
- **Credentials:** “\*\* Testing is only allowed on content created by your @bugcrowdninja.com Account\*\* Mathworks offers Researchers Trial Licenses to access the In-scope Targets. In order to activate a trial license, create a MATLAB Online Account with your bugcrowdninja email address and then visit the MathWorks Researcher Intake and sign in using your account which will give you license to access MATLAB Online. Once the license association is complete you should use the production stack (https://matlab.mathworks.com/) for all the testing.”
- **Out of Scope:** “The following finding types are specifically excluded from the bounty: Denial of Service attacks of any type. Open redirects (through headers and parameters) / Lack of security speedbump when leaving the site Internal IP address disclosure Accessible non-sensitive files and directories (e.g., README.TXT, CHANGES.TXT, robots.txt, gitignore, etc.) Social engineering/phishing attacks Self XSS Text injection Descriptive error messages (e.g., stack traces, application/server errors, path disclosure) Fingerprinting/banner disclosure on common/public services. Clickjacking and issues only exploitable through clickjacking. CSRF issues that don't impact the integrity of an account (e.g. login or out, contact forms and other publicly accessible forms) Email spoofing, lack of DMARC, SPF records, or DKIM configuration Lack of Secure and HTTPOnly cookie flags (critical systems may still be in scope). Login or Forgot Password page brute force, account lockout not enforced, or insufficient password strength requirements HTTPS mixed content scripts. Username / email enumeration by brute forcing / error messages (e.g. login / signup / forgotten password). Exceptional cases may still be in scope (e.g. ability to enumerate email addresses via incrementing a numeric parameter). TLS/SSL configuration issues are not in scope unless they are egregious. Lack of pinning or allowing theoretically insecure cipher-suites is not in scope. Bugs that don't work in the latest version of Chrome, Firefox, Safari, IE11, and Edge Out-of-date software or use of a known-vulnerable component (exceptional cases, such as where you are able to provide proof of exploitation, may still be in scope) Lack of rate limiting on login, registration, or email generating forms. Attempt to overwhelm the LLM by sending an excessive number of requests in a short period (exceeding 25 within a minute), you may not receive the anticipated response and will be blocked. The presence of virus scanning on uploaded files Content admin pages present on the Internet. Security issues in 3rd party services, applications. Weak Captcha / Captcha Bypass Missing HTTP security headers, specifically (https://www.owasp.org/index.php/List\_of\_useful\_HTTP\_headers), e.g. Strict-Transport-Security X-Frame-Options X-XSS-Protection X-Content-Type-Options Content-Security-Policy, X-Content-Security-Policy, X-WebKit-CSP Content-Security-Policy-Report-Only The following SSL Issues: SSL Attacks such as BEAST, BREACH, Renegotiation attack SSL Forward secrecy not enabled SSL weak / insecure cipher suites EXIF meta-data not stripped on images Out-of-scope for Stored XSS XSS vulnerabilities that follow the same steps across different file types or extensions will be considered duplicates and are out of scope for additional rewards. For example, using same payload in different file types and opening in different apps within MATLAB Online will be considered as duplicates.”
- **Safe Harbor:** “When conducting vulnerability research according to this policy, we consider this research to be: Authorized in accordance with the Computer Fraud and Abuse Act (CFAA) (and/or similar state laws), and we will not initiate or support legal action against you for accidental, good faith violations of this policy; Exempt from the Digital Millennium Copyright Act (DMCA), and we will not bring a claim against you for circumvention of technology controls; Exempt from restrictions in our Terms &amp; Conditions that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy; and Lawful, helpful to the overall security of the Internet, and conducted in good faith. You are expected, as always, to comply with all applicable laws. If at any time you have concerns or are uncertain whether your security research is consistent with this policy, please inquire via Bugcrowd Support before going any further.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
