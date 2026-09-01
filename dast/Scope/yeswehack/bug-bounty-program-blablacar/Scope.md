# Scope: Bug Bounty Program - BlaBlaCar

> Source: https://yeswehack.com/programs/bug-bounty-program-blablacar
> Captured at: 2026-08-27T05:16:22.072673+00:00
> Scope ID: `scope_11e9e7f989494bf79e80e3fad7758599`

## Program summary

BlaBlaCar는 21개국에서 연간 1억 명 이상의 활성 회원을 연결하는 커뮤니티 기반 여행 네트워크입니다. 모든 명시적 범위 자산의 자산 가치는 Low이며, 보상은 CVSS Low €100 · Medium €200 · High €1,000 · Critical €3,000입니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| API | https://edge.blablacar.(fr\|de\|co.uk\|in\|es\|mx\|be\|hr\|hu\|it\|nl\|pl\|com.br\|pt\|ro\|ru\|com\|tr\|com.ua)) | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | API. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| API | https://auth.blablacar.(fr\|de\|co.uk\|in\|es\|mx\|be\|hr\|hu\|it\|nl\|pl\|com.br\|pt\|ro\|ru\|com\|tr\|com.ua) | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | API. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| URL | https://www.blablacar.(fr\|de\|co.uk\|in\|es\|mx\|be\|hr\|hu\|it\|nl\|pl\|com.br\|pt\|ro\|ru\|com\|tr\|com.ua) | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Web application. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| URL | https://m.blablacar.(fr\|de\|co.uk\|in\|es\|mx\|be\|hr\|hu\|it\|nl\|pl\|com.br\|pt\|ro\|ru\|com\|tr\|com.ua) | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Web application. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| URL | https://booking.blablacar.(fr\|de\|co.uk\|in\|es\|mx\|be\|hr\|hu\|it\|nl\|pl\|com.br\|pt\|ro\|ru\|com\|tr\|com.ua) | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Web application. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.comuto&amp;hl=en | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Mobile application Android. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| MOBILE\_APP | https://itunes.apple.com/fr/app/blablacar-trusted-carpooling/id341329033?l=en&amp;mt=8 | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Mobile application IOS. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| API | https://api.blablalines.com | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | API. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| URL | https://daily.blablacar.fr | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Web application. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| URL | https://blablacardaily.com | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Web application. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| MOBILE\_APP | https://play.google.com/store/apps/details?id=com.blablalines | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Mobile application Android. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |
| MOBILE\_APP | https://apps.apple.com/fr/app/blablalines-covoiturage/id1225543288 | 명시된 범위 자산이며 적격 취약점 및 보상 자격 요건을 충족해야 합니다. | Critical | Mobile application IOS. 자산 가치 Low. 보상: Low €100 · Medium €200 · High €1,000 · Critical €3,000. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Any website that is not listed explicitly in the scope. | 보상 대상이 아닙니다. |  | 명시적으로 범위에 나열되지 않은 모든 웹사이트. |
| OTHER | fraud related reports | 범위 밖입니다. 단, CSRF 익스플로잇으로 가능한 사기 활동은 유효합니다. |  | 보안 취약점을 악용하지 않는 사기 관련 보고 및 버그나 불완전한 비즈니스 규칙 집행으로 가능한 사기 활동. |

## Allowed activities

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Insecure Direct Object Reference (IDOR)
- 수평 및 수직 권한 상승
- 인증 우회 및 취약한 인증
- 실제 보안 영향이 있는 비즈니스 로직 오류
- 로컬 파일 접근 및 조작(LFI, RFI, XXE, SSRF, XSPA)
- 실제 보안 영향이 있는 CORS
- 실제 보안 영향이 있는 CSRF
- Open Redirect
- 조직이 통제하고 하나 이상의 범위에 영향을 미치는 자산에서 노출된 비밀정보·자격 증명·민감 정보

## Prohibited activities

- 명시적 승인 없는 전체·부분 등 모든 취약점 공개
- {{BU\_NAME}} 애플리케이션·서버·네트워크·인프라에 대한 DoS 공격
- 서비스 성능 저하 또는 중단을 일으킬 수 있는 테스트
- 대량 네트워크 트래픽을 발생시키는 자동 스캐너 또는 도구 사용
- 애플리케이션·서버의 사용자 데이터나 파일 유출·복사·조작·파괴
- 취약점 및 보안 영향을 입증하는 PoC가 없는 보고
- 실제 보안 영향이 없는 보안 모범 사례 보고
- 피해자 물리적 접근 또는 사회공학이 필요한 공격 시나리오
- 실질적 익스플로잇 증거가 없는 이론적 보고
- 검증되지 않은 자동 웹 취약점 스캐너 보고
- 최근 공개된 0-day 취약점
- Tabnabbing
- 다른 사용자에게 영향을 줄 수 없는 Self-XSS 또는 XSS
- 낮은 심각도의 CSRF
- "HTTP Host Header" XSS
- 쿠키 플래그 누락
- 직접 악용 및 PoC로 이어지지 않는 보안 HTTP 헤더 누락
- Mixed content 경고
- Clickjacking/UI redressing
- 레이트 리밋·브루트포스·CAPTCHA 미비
- 악용 및 PoC 없는 CVE
- 악용 및 PoC 없는 열린 포트 또는 서비스
- 외부 링크나 JavaScript 삽입 없는 콘텐츠 스푸핑
- SSL/TLS 모범 사례 문제
- HSTS 헤더 누락
- SPF·DKIM·DMARC 등 이메일 보안 레코드 누락
- 신뢰된 제3자 사이트 Referer 헤더를 통한 비밀번호 재설정 토큰 유출
- 웹 폼 autocomplete 속성 존재
- 프로토콜 불일치
- 악용 및 PoC 없는 Blind SSRF
- 자신의 애플리케이션 충돌
- 입증 가능한 공격 벡터와 PoC 없는 취약·오래된 소프트웨어·라이브러리
- UUID4 또는 암호화 형식 대신 정수형 숫자 사용자 ID 노출
- 악용 및 PoC 없는 정보 노출
- 세션 관리 문제
- 피해자 컴퓨터·기기 물리 접근이 필요한 문제
- MITM 또는 피해자 기기 물리 접근이 필요한 보고
- 약한 비밀번호 정책
- Pre-account takeover
- "Archived" Github 저장소의 모든 취약점
- 사용자 스팸 가능성
- 도난 자격 증명 또는 기기 물리 접근을 포함하는 취약점
- 최신 브라우저 또는 현재 앱스토어 버전에서 작동하지 않는 취약점
- SSL Pinning·바이너리 보호·난독화·탈옥·루팅 탐지·안티디버깅 통제 부재
- 일반 Android 또는 iOS 취약점 악용
- 모바일 기기 내부 데이터베이스·환경설정 파일 암호화 부재
- 탈옥·루팅·백업 등 비표준 iOS/Android 사용 사례의 문제
- 메시지 검열 우회
- 가입 시 필수가 아닌 이메일 검증
- 클라이언트 앱 내 API client ID/Secret 포함
- 공개 API 키 노출 또는 잘못된 구성

## Submission requirements

- 발견 즉시 잠재적 보안 문제를 알려야 합니다.
- 동일 취약점을 여러 번 발견하면 하나의 보고서만 만들고 댓글을 사용해야 합니다.
- 보고서에는 취약점·악용 방법·보안 영향·수정 조언의 명확한 설명이 포함되어야 합니다.
- 익스플로잇 수행 및 최종 영향을 보여 주는 스크린샷 PoC를 포함해야 합니다.
- 필요시 코드 스니펫·페이로드·명령을 포함한 완전한 재현 절차를 제공해야 합니다.
- 보상을 받으려면 최초 보고자여야 하며 적격 취약점이어야 합니다.
- 보상을 받으려면 BlaBlaCar 또는 계약업체의 전·현직 직원이 아니어야 합니다.
- 보고서를 제출하려면 hunter 계정으로 로그인해야 합니다.

## Operational constraints

- User-Agent 헤더에 ' BBC-YWH-Bugbounty-&lt;your yeswehack pseudo&gt; ' 값을 추가해야 합니다.

## Safe harbor

명시되지 않음.

## Ambiguities requiring review

- 범위 밖 자산이라도 플랫폼에 영향을 주며 설득력 있고 작동하는 POC가 코드 변경을 유도하면 보상될 수 있다고 명시되어 있어, 해당 예외의 사전 승인·판정 기준은 추가로 명시되지 않았습니다.
- 안전항구(safe harbor) 조항은 명시되어 있지 않습니다.

## Source evidence

- **Scopes:** “Scopes: 12”
- **Scopes:** “https://edge.blablacar.(fr\|de\|co.uk\|in\|es\|mx\|be\|hr\|hu\|it\|nl\|pl\|com.br\|pt\|ro\|ru\|com\|tr\|com.ua)) \| API \| Low \|”
- **Scopes:** “https://apps.apple.com/fr/app/blablalines-covoiturage/id1225543288 \| Mobile application IOS \| Low \|”
- **Out of scopes:** “Any website that is not listed explicitly in the scope.”
- **Reporting &amp; Disclosure Policy:** “Denial of service (DoS) attacks on {{BU\_NAME}} applications, servers, networks or infrastructure are strictly forbidden.”
- **Reward Eligibility:** “You must be the first reporter of a vulnerability.”
- **Hunting requirements:** “Please append to your user-agent header the following value: ' BBC-YWH-Bugbounty-&lt;your yeswehack pseudo&gt; '.”
- **Non-qualifying vulnerabilities:** “Reports without an accompanying proof-of-concept demonstrating vulnerability and security impact”
- **Reports of leaks and exposed credentials:** “Impact is in-scope (e.g. valid credentials on an in-scope asset) \| Eligible \| Eligible \| Not eligible”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
