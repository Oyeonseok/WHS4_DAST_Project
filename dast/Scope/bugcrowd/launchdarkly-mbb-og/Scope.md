# Scope: LaunchDarkly Managed Bug Bounty Engagement

> Source: https://bugcrowd.com/engagements/launchdarkly-mbb-og
> Captured at: 2026-08-27T05:10:21.642628+00:00
> Scope ID: `scope_596f03df6ffd4437ae865d707d4f393c`

## Program summary

LaunchDarkly의 런타임 제어 플랫폼에 대한 진행 중인 공개 버그 바운티 프로그램입니다. 심각도별 보상은 P1 $6500 – $7500, P2 $2500, P3 $1250, P4 $150입니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| URL | app.launchdarkly.com | 명시적으로 In Scope에 열거되어 있습니다. | P1 | LaunchDarkly의 주요 프런트엔드 애플리케이션 및 진입점입니다. 기능 플래그, 컨텍스트 유형, 세그먼트와 조직 설정을 관리합니다. 보상: P1 $6500 – $7500 · P2 $2500 · P3 $1250 · P4 $150. |
| API | app.launchdarkly.com/api/v2/ | 명시적으로 In Scope에 열거되어 있습니다. | P1 | LaunchDarkly 애플리케이션의 백엔드 API입니다. /api/v2/ 및 /internal/ 하위 경로는 유효한 ldso 세션 쿠키 또는 Authorization 헤더의 액세스 토큰이 필요합니다. /private/ API가 비사용자에게 부적절하게 접근 가능한 경우 보고 가치가 있습니다. 보상: P1 $6500 – $7500 · P2 $2500 · P3 $1250 · P4 $150. |
| SOURCE\_CODE | LaunchDarkly Open Source SDKs | SDK 저장소(이름이 -sdk로 끝나는 저장소) 관련 분석에 한해 명시적으로 허용됩니다. | P1 | 고객 애플리케이션에서 기능 플래그를 평가하는 오픈 소스 SDK입니다. 자체 애플리케이션에 SDK를 통합하고 SDK와 LaunchDarkly 서버 간 통신 및 핸들러 로직을 테스트할 수 있습니다. 보상: P1 $6500 – $7500 · P2 $2500 · P3 $1250 · P4 $150. |
| DOMAIN | stream.launchdarkly.com | 명시적으로 In Scope에 열거되어 있습니다. | P1 | 서버 및 클라이언트 SDK에 플래그 정보를 제공하는 Streamer입니다. 다른 사용자용 플래그 정보를 부적절하게 조회하게 하는 플래그 평가 로직 악용이 관심 대상입니다. 보상: P1 $6500 – $7500 · P2 $2500 · P3 $1250 · P4 $150. |
| DOMAIN | events.launchdarkly.com | 명시적으로 In Scope에 열거되어 있습니다. | P1 | SDK의 플래그 평가 이벤트를 수집하는 Event Recorder입니다. 이벤트 기록 메커니즘 악용 가능성이 관심 대상입니다. 보상: P1 $6500 – $7500 · P2 $2500 · P3 $1250 · P4 $150. |
| DOMAIN | docs.launchdarkly.com | 명시적으로 In Scope에 열거되어 있습니다. | P1 | LaunchDarkly 문서를 제공하는 정적 사이트입니다. 검색창 등의 입력 필드의 XSS·주입 취약점과 app.launchdarkly.com에 대한 교차 출처 요청의 CSRF가 관심 대상입니다. 보상: P1 $6500 – $7500 · P2 $2500 · P3 $1250 · P4 $150. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| DOMAIN | blog.launchdarkly.com | 보상 및 포인트 기반 보상 비적격입니다. | N/A | 명시적 Out of Scope 대상입니다. |
| DOMAIN | launchdarkly.com | 보상 및 포인트 기반 보상 비적격입니다. | N/A | 명시적 Out of Scope 대상입니다. |
| DOMAIN | sandbox.launchdarkly.com | 보상 및 포인트 기반 보상 비적격입니다. | N/A | 명시적 Out of Scope 대상입니다. |
| DOMAIN | slack.launchdarkly.com | 보상 및 포인트 기반 보상 비적격입니다. | N/A | 명시적 Out of Scope 대상입니다. |
| DOMAIN | status.launchdarkly.com | 보상 및 포인트 기반 보상 비적격입니다. | N/A | 명시적 Out of Scope 대상입니다. |
| DOMAIN | launchdarkly.atlassian.net | 보상 및 포인트 기반 보상 비적격입니다. | N/A | 명시적 Out of Scope 대상입니다. |

## Allowed activities

- 자체 계정과 자격 증명을 사용하여 명시된 범위 대상만 테스트할 수 있습니다.
- 자체 애플리케이션에 SDK를 통합하고 SDK와 LaunchDarkly 서버 간 통신을 테스트할 수 있습니다.
- SDK 키 또는 클라이언트 ID를 UI에서 생성하여 SDK 연결을 초기화할 수 있습니다.
- 공개된 N-day가 대상에서 악용 가능한 경우 즉시 보고할 수 있으며, 건별로 검토됩니다.
- 서비스의 정당한 운영에 필요한 수준으로 문서 사이트의 입력 필드 및 교차 출처 요청을 테스트할 수 있습니다.

## Prohibited activities

- 범위에 명시되지 않은 모든 LaunchDarkly 도메인·속성 및 나열되지 않은 하위 도메인에 대한 테스트
- 다른 사용자의 데이터 표적화
- 사이트 일부의 삭제·제거·편집
- DoS, DDoS, Network DoS 및 서비스 중단을 유발할 수 있는 활동
- 가용성·볼류메트릭 테스트
- Rate limiting bypass attempts
- 이메일 폭탄 또는 플러딩
- 모든 형태의 사회 공학
- 민감한 작업이 없는 페이지의 클릭재킹
- 인증되지 않았거나 민감한 작업이 없는 양식의 CSRF
- MITM 또는 사용자 기기에 대한 물리적 접근이 필요한 공격
- 작동하는 PoC 없는 기존 공개 취약 라이브러리 보고
- LaunchDarkly 플랫폼 고유 취약점을 입증하지 않은 CSV 주입
- SSL/TLS 구성의 모범 사례 누락
- 공격 벡터 또는 HTML/CSS 수정 가능성 입증 없는 콘텐츠 스푸핑·텍스트 주입
- 비인증 엔드포인트의 rate limiting 또는 무차별 대입 이슈
- CSP 모범 사례 누락
- ldso 쿠키를 제외한 쿠키의 HttpOnly 또는 Secure 플래그 누락
- SPF/DKIM/DMARC 등 이메일 모범 사례 누락
- 최신 안정 버전보다 두 버전 이상 뒤처지지 않은 브라우저에서만 영향을 받는 취약점
- 비일반적 브라우저 확장 프로그램 사용자에게만 영향을 주는 취약점
- 소프트웨어 버전 노출, 배너 식별, 설명적 오류 메시지 또는 헤더
- 공식 패치 후 1개월 미만인 공개 0-day(건별 판단)
- Tabnabbing
- 추가 보안 영향을 입증하지 않은 Open redirect
- 비현실적인 사용자 상호작용이 필요한 이슈
- -sdk로 끝나지 않는 저장소 관련 발견
- 소스 코드의 취약점·의존성 스캔 결과
- 적절히 배포된 애플리케이션에 노출된 클라이언트 측 SDK 키
- 비밀일 필요가 없는 웹사이트 클라이언트 측 키·토큰
- Jira ServiceDesk의 공개 등록
- 검증 이메일 받은편지함 스팸
- 앱 텍스트 필드 또는 애플리케이션 생성 이메일의 HTML 주입
- 이메일 주소 변경 시 비밀번호 재설정 링크가 만료되지 않는 문제
- 오픈 소스 저장소의 취약점·의존성 스캔
- -sdk 접미사가 없는 오픈 소스 GitHub 저장소 발견
- P5 취약점
- 지원팀 인터페이스(챗봇, 양식 또는 이메일·티켓·알림을 생성하는 기타 수단) 테스트
- 제3자 통합 및 엔드포인트 테스트
- 계정 확인 및 비밀번호 찾기 페이지의 rate limiting 이슈

## Submission requirements

- 저효율 또는 AI 생성 콘텐츠는 허용되지 않으며, 제출물은 독창적 분석·이슈 이해·실행 가능한 세부 사항을 보여야 합니다.
- 테스트에 사용한 역할, 이슈와 보안 영향의 명확한 설명, 상세 재현 절차를 포함해야 합니다.
- 보고서당 취약점 하나만 제출해야 합니다. 영향 입증에 여러 취약점 체인이 필요하면 연계성을 명확히 설명하여 같은 보고서에 포함할 수 있습니다.
- 여러 경로·엔드포인트·파라미터 또는 환경에서 발견된 동일 취약점은, 영향 또는 악용 방법이 실질적으로 다르지 않으면 중복으로 취급되므로 하나만 제출해야 합니다.
- SSRF 및 webhook 기반 SSRF 제출에는 대상 엔드포인트 도달 증명과 관련 메타데이터를 포함해야 합니다.
- 이 프로그램은 비공개 공개 정책을 따르므로, 발견한 취약점 정보를 공개해서는 안 됩니다.

## Operational constraints

- 모든 계정은 @bugcrowdninja 이메일 주소 또는 주소에 bugcrowd 부분문자열을 포함한 이메일로 생성해야 합니다.
- 앱 접근을 위해 @bugcrowdninja.com 이메일로 가입해야 합니다.
- /api/v2/ 및 /internal/ API 테스트에는 유효한 ldso 세션 쿠키 또는 Authorization 헤더의 액세스 토큰이 필요합니다.
- 데이터 수정 또는 파괴로 이어질 수 있는 사후 악용 가능성을 식별하면 테스트를 중단하고 보고해야 합니다.
- 프로덕션 환경을 테스트하므로 대상의 안정성 및 무결성을 훼손하는 행위는 금지됩니다.
- 지원팀 인터페이스에 대한 모든 테스트를 중단해야 하며, 계속 테스트하면 프로그램에서 제외될 수 있습니다.

## Safe harbor

정책에 따른 선의의 취약점 연구는 CFAA 및 유사 주법상 승인된 것으로 간주되며, 우발적·선의의 위반에 대해 법적 조치를 시작하거나 지원하지 않습니다. DMCA 기술 통제 우회 청구를 제기하지 않고, 보안 연구를 방해하는 약관 제한을 해당 연구 범위에서 제한적으로 면제하며, 연구를 합법적이고 인터넷 보안에 유익한 선의의 행위로 간주합니다. 단, 모든 적용 법률을 준수해야 합니다.

## Ambiguities requiring review

- 범위 표에는 \`app.launchdarkly.com\`과 \`app.launchdarkly.com/api/v2/\`가 별도로 설명되지만, 가시적인 구조화 표의 표기 방식상 API 경로가 독립 자산인지 앱 자산의 범위 설명인지 완전히 명확하지 않습니다.
- \`LaunchDarkly Open Source SDKs\`는 대상 표에 표시되지만 개별 SDK 저장소·URL 목록은 캡처에 제공되지 않았습니다.
- 각 개별 대상별 최대 심각도는 따로 제시되지 않았으며, 대상 그룹 전체에 대한 P1~P4 보상표만 제공됩니다.
- 범위 밖 LaunchDarkly 자산도 소유가 입증되면 보고는 가능하나 보상 또는 포인트 기반 보상은 받을 수 없습니다.

## Source evidence

- **Targets:** “app.launchdarkly.com”
- **Targets:** “app.launchdarkly.com/api/v2/”
- **Targets:** “LaunchDarkly Open Source SDKs”
- **Targets:** “events.launchdarkly.com”
- **Targets:** “stream.launchdarkly.com”
- **Targets:** “docs.launchdarkly.com”
- **Out of Scope:** “Testing is only authorized on the targets listed as in scope. Any domain/property of LaunchDarkly not listed in the targets section is out of scope. This includes any/all subdomains not listed above.”
- **Engagement Guidelines:** “All accounts must be created using your @bugcrowdninja email address, or otherwise include the substring bugcrowd (eg, your.name+bugcrowd1234@example.com is permissible)”
- **Excluded Submission Types:** “Support team interfaces, such as chat bots, forms, or other methods which generate emails, tickets, or notifications for the LaunchDarkly support teams. There are real people on the other end, and junk requests are a drain on their resources.”
- **Safe Harbor:** “Authorized in accordance with the Computer Fraud and Abuse Act (CFAA) (and/or similar state laws), and we will not initiate or support legal action against you for accidental, good faith violations of this policy;”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
