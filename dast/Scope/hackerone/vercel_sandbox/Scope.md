# Scope: Vercel Sandbox

> Source: https://hackerone.com/vercel_sandbox?type=team
> Captured at: 2026-08-27T09:51:45.420037+00:00
> Scope ID: `scope_e56b956e737b47d69bc504c50b4fd69d`

## Program summary

Vercel Sandbox의 Firecracker microVM 격리 경계, 호스트 측 샌드박스 방화벽, 자격 증명 브로커링 및 샌드박스 제어 플레인 API를 대상으로 하는 기간 한정 공개 버그 바운티 프로그램이다. 캡처에는 구조화된 인스코프 자산 1개가 표시되며, 프로그램 정책·범위·테스트 규칙·세이프 하버 전문이 제공된다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Vercel sandbox | Eligible | Critical | 고객이 격리 환경에서 프로그램을 실행하고, 디스크 스냅샷, 송신 네트워크 연결 제한 및 네트워킹 수준의 자격 증명 브로커링을 수행하는 Vercel Sandbox 제품이다. Firecracker microVM에서 EC2 호스트로의 탈출, 소유하지 않은 다른 테넌트에 대한 읽기·수정·코드 실행, 교차 테넌트 DoS, 구성된 방화벽 우회, Vercel 측 결함에 의한 브로커링 자격 증명 획득, 그리고 다른 테넌트 샌드박스를 제어할 수 있는 샌드박스 제어 플레인 API 결함이 포함된다. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| DOMAIN | vercel.com | Ineligible | N/A | 일반 Vercel 플랫폼 버그는 이 프로그램 범위가 아니며 적절한 별도 Vercel HackerOne 프로그램에 제출해야 한다. |
| OTHER | v0 | Ineligible | N/A | Vercel Sandbox와 무관한 v0 관련 문제는 제외된다. |
| API | Other Vercel REST APIs not associated with Sandbox | Ineligible | N/A | 계정, 팀, 프로젝트, 배포, 대시보드, 청구 및 기타 비-Sandbox 엔드포인트를 포함한 광범위한 Vercel 플랫폼 API는 제외된다. |
| API | Vercel Container Registry (VCR) | Ineligible | N/A | 레지스트리 인증, blob push, OIDC vercel scope 및 VCR 제어 플레인은 제외된다. |
| SOURCE\_CODE | @vercel/sandbox SDK and runtime | Ineligible | N/A | 운영자가 Sandbox API를 생성·구성하는 데 사용하는 클라이언트 측 패키지·런타임의 취약점은 제외되며, 그 서버 측 제어 플레인 API만 포함된다. |

## Allowed activities

- 자신이 소유한 계정에서만 테스트하고, 교차 테넌트 재현은 자신이 소유한 공격자·피해자 계정 두 개 사이에서 수행한다.
- 샌드박스 CLI 또는 @vercel/sandbox를 사용해 샌드박스를 생성·구성·관리하는 서버 측 Sandbox 제어 플레인 API를 테스트한다.
- 실제 Vercel Sandbox에서 동작하는 라이브 PoC로 Firecracker 호스트 탈출, 교차 테넌트 영향 또는 방화벽·자격 증명 제어 우회를 최소한으로 확인한다.
- 공개 Firecracker 취약점이라도 라이브 Sandbox에서 실제 EC2 호스트 탈출 또는 다른 테넌트 영향으로 무기화하여 입증한 경우 제출할 수 있다.

## Prohibited activities

- Firecracker guest OS까지만 도달하는 Linux 컨테이너 네임스페이스 탈출만을 제출한다.
- 자신의 샌드박스에 대한 DoS를 수행하거나 제출한다.
- 제3자 웹사이트가 자격 증명 브로커링 헤더를 반사하는 취약점을 제출한다.
- 문서가 다른 구성을 권고한 알려진 제한사항을 취약점으로 제출한다.
- 버전 일치, 권고문 링크 또는 작동하지 않는 공개 익스플로잇만으로 공개 CVE를 제출한다.
- 운영자가 공급할 수 없는 커스텀 guest kernel 또는 Firecracker build가 필요한 공격을 수행한다.
- Dockerfile·Containerfile 이미지 빌드 단계, 빌드 컨텍스트, 캐시 또는 빌드 시 레지스트리 인증 문제를 테스트한다.
- 정적 분석만으로 보고하며 라이브 PoC를 제공하지 않는다.
- Vercel이 운영하지 않는 Datadog·AWS 등의 제3자 서비스 자체 취약점을 보고한다.
- 다른 테넌트의 계정·프로젝트·샌드박스를 열거하거나 탐색한다. 두 개의 본인 계정으로 재현할 수 없다면 최초 확인 후 중단한다.
- 성공 후 다른 테넌트 또는 호스트의 데이터를 열거·덤프·유출·지속화하거나 추가 탐색한다.
- 개인정보 침해, 데이터 파괴, Vercel 서비스의 중단·성능 저하를 야기한다.
- 영구 백도어를 설치하거나 PoC 이후 접근을 유지한다.
- Vercel 직원·고객·연구자를 대상으로 피싱·비싱·스미싱 등 사회공학을 수행한다.
- Vercel 운영 엔드포인트에 대해 초당 5개 요청을 초과하는 보안 스캐너를 사용하거나 볼류메트릭 DoS를 수행한다.
- 개인 검증 없는 AI 생성 보고서를 제출한다.
- 엠바고 기간 중 재현 단계, PoC, 익스플로잇, 샌드박스·호스트 로그/스크린샷 또는 기술적 재현 세부사항을 외부에 공개·공유한다.

## Submission requirements

- 보고서마다 하나의 취약점만 제출한다. 단, 영향을 입증하기 위해 체인이 필요한 경우는 예외이다.
- 상세 재현 절차와 동작하는 PoC 코드 zip을 제공해야 하며, 재현 불가 보고서는 대상이 아니다.
- 초기 제출에 PoC zip, Vercel Team ID(team\_…), Project ID(prj\_…), Sandbox ID(sbx\_…), 취약점 분류, 심각도 근거 및 심각도 부풀리기 패널티 인정 내용을 포함해야 한다.
- 중복은 동일 근본 원인에 대해 최초의 유효하고 완전 재현 가능한 보고서만 인정되며, 동일 근본 원인의 여러 문제는 하나의 보고서로 통합된다.
- 내부 추적기에 이미 기록된 문제도 중복 처리될 수 있으며, 공개 Known findings에 없더라도 적용된다.
- 보고서는 비공개로 시작하고, 공개 전에는 보고서가 종료되고 2026년 12월 1일이 지난 뒤(또는 Vercel의 조기 서면 승인 후)여야 한다. Critical 또는 High 미패치 건은 서면으로 한 번, 최대 2027년 3월 1일까지 연장될 수 있다.
- 엠바고 후 외부 공개 초안은 게시 7일 전에 Vercel에 보내야 하며, HackerOne 내 공개는 Vercel의 명시적 승인이 필요하다.

## Operational constraints

- 프로그램 기간은 2026년 8월 18일부터 2026년 9월 1일 23:59 UTC까지이며, 종료 후 보고서는 대상이 아니다.
- Vercel 계정은 HackerOne 별칭(username@wearehackerone.com)으로 생성하고 모든 Sandbox API 트래픽에 그 계정을 사용한다.
- 교차 테넌트 테스트는 항상 본인이 소유한 두 계정을 사용한다.
- 교차 테넌트 접근이 확인되면 즉시 중단하고, 필요 이상 데이터를 접근·다운로드하지 않으며 제3자 데이터는 보고서에서 가린다.
- 깨끗한 새 샌드박스에서 재현하고, 정확한 명령·샌드박스 설정·이미지·관찰된 영향·Sandbox/Team/Project ID 및 타임스탬프를 기록한다.
- 관련 법률을 준수해야 한다.

## Safe harbor

이 정책을 선의로 준수한 보안 연구는 CFAA, DMCA 및 유사 법률상 승인된 행위로 간주되며, Vercel은 민사·형사 조치나 중지 요구를 하지 않는다. 다만 제3자에게는 적용되지 않고, 범위 외 자산 테스트, 한 번의 확인을 넘는 타 테넌트 데이터 접근·보유, 볼류메트릭 DoS, 사회공학 및 엠바고된 취약점 세부사항·작동 익스플로잇 공개는 보호 대상이 아니다.

## Ambiguities requiring review

- 구조화된 Scope 표에는 자산 1개만 명시되어 있으며, 개별 API 경로나 호스트 서비스 주소·도메인은 제공되지 않았다. Sandbox 클라이언트가 소비하는 제어 플레인 API라는 기능적 범위로만 정의된다.
- Linux 컨테이너→Firecracker guest OS 탈출과 다수의 post-escape host-side surface 및 헤더 누출 클래스는 알려진 중복이다. 단, 새 EC2 호스트 침해, 교차 테넌트 도달 또는 새 호스트 쓰기 원시기능이라는 실질적으로 새로운 영향은 별도로 가능하다.
- \[모범 기준\] 프로그램은 Gold Standard Safe Harbor 및 AI Research Safe Harbor 준수를 표방한다.
- \[정책 표준 이탈\] HackerOne 기본 공개 가이드라인과 충돌할 경우 이 프로그램의 Limited Coordinated Vulnerability Disclosure 정책이 우선한다.

## Source evidence

- **Scope:** “Vercel sandbox”
- **Scope:** “No customer should be able to perform cross-tenant actions on other customer sandbox, bypass network protections, or fetch credentials that have been configured in credential brokering.”
- **Introduction:** “This is not the Vercel platform bug bounty and not the Vercel open-source program. Do not report vercel.com, v0, dashboard, general platform bugs; or anything unrelated to Vercel Sandbox.”
- **In Scope:** “Escapes from the Firecracker microVM to the EC2 host OS (the actual trust boundary).”
- **In Scope:** “Reads or modifies data belonging to another tenant (a sandbox you do not own), including files, environment, secrets, memory, or network traffic.”
- **In Scope:** “Executes code on the EC2 host or in another tenant's sandbox.”
- **In Scope:** “Crashing or destabilizing other tenants' sandboxes on the same host (cross-tenant denial of service).”
- **In Scope:** “Bypassing the sandbox network firewall (deny-all, domain allowlists, subnets.allow / subnets.deny, CIDR-only allow) to reach destinations the operator did not authorize.”
- **In Scope:** “Retrieving credentials configured through credential brokering (injected OIDC tokens, forwarded auth headers, etc.) without relying on a vulnerability in a third-party website that reflects those headers back.”
- **In Scope:** “The sandbox control plane is in scope as well: the Vercel-operated REST API that the sandbox CLI and @vercel/sandbox call to create, configure, and manage sandboxes.”
- **Out of scope:** “Linux container namespace escapes that only reach the Firecracker guest OS (PID, mount, net, disk, or device namespaces).”
- **Out of scope:** “Denial of service against your own sandbox (crashing, hanging, or exhausting resources in a sandbox you own).”
- **Out of scope:** “Vulnerabilities in third-party websites that reflect credential-brokering headers back to the sandbox.”
- **Out of scope:** “Behavior the documentation tells operators to configure differently.”
- **Out of scope:** “Already-public Firecracker or any other software component CVEs reported as a version match.”
- **Out of scope:** “Custom-kernel or custom-VMM attacks that require a kernel or Firecracker build the operator cannot supply.”
- **Out of scope:** “Build-phase Dockerfile / Containerfile build environment issues (image build, build context, cache, registry auth at build time).”
- **Out of scope:** “Vercel Container Registry (VCR) issues ; registry auth, blob push, OIDC vercel scope, and VCR control plane are out of scope.”
- **Out of scope:** “Static-analysis-only findings. A confirmed report requires a working live PoC against a vercel sandbox.”
- **Out of scope:** “Vulnerabilities in services Vercel does not operate (e.g., Datadog, AWS) even if their credentials are reachable from a sandbox; report the Vercel-side reachability, not the third-party bug.”
- **Out of scope:** “The @vercel/sandbox SDK and runtime that operators use to create and configure sandboxes.”
- **Out of scope:** “Other Vercel REST APIs not associated with Sandbox.”
- **Testing guidelines:** “Test only in accounts you own.”
- **Cross-tenant testing:** “Always use two accounts you own (attacker and victim). Reproduce the cross-tenant access entirely between those accounts.”
- **Spinning up sandboxes:** “Use @vercel/sandbox or the sandbox CLI. Both talk to the same API; pick whichever fits your workflow.”
- **Out of scope:** “If you weaponize one, it is in scope: a public upstream Firecracker vulnerability that you drive to a real escape to the EC2 host or to another tenant on a live Vercel Sandbox is eligible, and is paid at the impact you demonstrate.”
- **Rules of engagement:** “One vulnerability per report, unless you must chain issues to demonstrate impact.”
- **Rules of engagement:** “Provide detailed reproduction steps and a zip of working proof-of-concept code. Reports we cannot reproduce are not eligible.”
- **Submission guidelines:** “A zip file of working PoC code (required ; no PoC, no bounty)”
- **Submission guidelines:** “Vercel Team ID used during testing (team\_…)”
- **Submission guidelines:** “Vercel Project ID used during testing (prj\_…)”
- **Submission guidelines:** “Vercel Sandbox ID where the issue was reproduced (sbx\_…)”
- **Submission guidelines:** “Vulnerability class: Cross-Tenant data access / Networking and Firewall / Denial of Service / Other”
- **Submission guidelines:** “Severity with a rationale that matches this bounty table”
- **Submission guidelines:** “Acknowledgement of the severity-inflation bounty penalty”
- **Rules of engagement:** “Duplicates: we award the first valid, fully reproducible report of a root cause. Later reports of the same root cause are duplicates.”
- **Rules of engagement:** “Internal duplicates: we cross-reference every submission against our internal vulnerability tracker, not only the Known findings published here.”
- **Rules of engagement:** “Root cause consolidation: multiple vulnerabilities caused by one underlying issue receive one bounty.”
- **Overview:** “Window: Tuesday, 18 August 2026 – Tuesday, 1 September 2026 (23:59 UTC), or earlier if the $1,000,000 USD reward pool is exhausted.”
- **Overview:** “Reports after close are not eligible.”
- **Accounts:** “Sign up at vercel.com with your HackerOne alias (username@wearehackerone.com; aliases supported). Use those accounts for all Sandbox API traffic so we can distinguish research from abuse.”
- **Cross-tenant testing:** “Stop at confirmation. If you cannot reproduce with two accounts you own — for example because the vulnerability appears to depend on a target you do not control — stop after a single confirmation.”
- **Rules of engagement:** “Do not access more data than necessary to prove the vulnerability. Stop immediately if you encounter personal data or secrets that are not yours; do not download them; redact them from the report.”
- **Reproducing:** “Reproduce in a fresh sandbox. Confirm from a clean sandbox create.”
- **Reproducing:** “Capture a live PoC. Record the exact commands, sandbox config, image, and observed impact. Include sandbox IDs, team IDs, project IDs, timestamps.”
- **Rules of engagement:** “All testing must comply with applicable law.”
- **Rules of engagement:** “Do not install persistent backdoors. Do not maintain access after you have a PoC. Do not modify host or tenant state beyond what is required to demonstrate impact.”
- **Rules of engagement:** “No social engineering (phishing, vishing, smishing) of Vercel employees, customers, or researchers.”
- **Rules of engagement:** “Security scanners against Vercel-operated endpoints: cap at 5 queries per second. No volumetric DoS.”
- **Rules of engagement:** “Do not submit AI-generated reports without personally verifying a working PoC and real impact.”
- **Disclosure policy:** “Before the embargo ends, you may not publish or share with anyone outside this HackerOne report:”
- **Embargo:** “1 December 2026 has passed (90 days after program close on 1 September 2026), or Vercel has written to you that this report is cleared for disclosure earlier.”
- **Embargo:** “If the finding is Critical or High and still unpatched in production on 1 December 2026, Vercel may extend the embargo once, in writing on the report, by up to 90 days (no later than 1 March 2027).”
- **After the embargo:** “External (blog, talk, research paper, video) ; allowed after the embargo. Send Vercel the draft 7 days before publishing”
- **Disclosure policy:** “On-platform disclosure on HackerOne requires explicit Vercel approval (mutual agreement).”
- **Safe Harbor:** “We consider security research conducted in accordance with this policy as authorized conduct under applicable anti-hacking laws, including the Computer Fraud and Abuse Act, the DMCA, and similar laws.”
- **Safe Harbor:** “We will not pursue civil or criminal action, or send a cease-and-desist, against researchers who follow this policy in good faith.”
- **Safe Harbor:** “Safe Harbor does not cover: testing out-of-scope assets, accessing or retaining another tenant's data beyond a single confirmation, volumetric DoS, social engineering, or public disclosure of embargoed vulnerability details or working exploits.”
- **Program highlights:** “Gold Standard Safe Harbor”
- **Program highlights:** “AI Research Safe Harbor”
- **Conflicts:** “If this section conflicts with HackerOne's default disclosure guidelines, this section wins.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
