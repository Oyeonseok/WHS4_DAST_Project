# Scope: Vercel Sandbox

> Source: https://hackerone.com/vercel_sandbox?type=team
> Captured at: 2026-08-27T05:08:53.198736+00:00
> Scope ID: `scope_968dd41491204aa19c207875b85563a9`

## Program summary

Vercel Sandbox의 격리 경계( Firecracker microVM, 호스트 측 sandbox firewall, credential brokering, sandbox control plane API)에 한정된 기간제 공개 버그바운티입니다. 기간은 2026년 8월 18일~9월 1일 23:59 UTC(또는 $1,000,000 USD 풀 소진 시 조기 종료)이며, 종료 후 보고서는 보상 대상이 아닙니다. 보상은 Low $1,000–$5,000 · Medium $5,000–$10,000 · High $10,000–$25,000 · Critical $25,000–$50,000이고, 보고서당 최대 $50,000 USD입니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Vercel sandbox | Eligible | Critical | 고객이 격리 환경에서 프로그램 실행, 디스크 스냅샷, egress 네트워크 제한, 네트워크 수준 credential brokering을 수행하는 Sandbox 제품입니다. Firecracker microVM→EC2 호스트 탈출, 본인 소유가 아닌 테넌트 데이터 읽기·수정 또는 코드 실행, 동일 호스트의 다른 테넌트 대상 DoS, 설정된 firewall 우회, Vercel 측 결함을 통한 brokered credential 회수, 그리고 sandbox CLI/@vercel/sandbox가 사용하는 서버 측 sandbox control plane REST API의 권한 우회·IDOR 등이 포함됩니다. 최대 심각도: Critical. 보상 대상: Eligible. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Linux container namespace escapes that only reach the Firecracker guest OS | Ineligible | N/A | EC2 호스트·다른 테넌트·firewall/credential control에 도달하지 않고 Firecracker guest OS까지만 탈출하는 컨테이너 namespace 탈출은 제외됩니다. |
| OTHER | Vercel Container Registry (VCR) | Ineligible | N/A | registry auth, blob push, OIDC vercel scope 및 VCR control plane 이슈는 제외됩니다. |
| SOURCE\_CODE | The @vercel/sandbox SDK and runtime | Ineligible | N/A | 운영자가 Sandbox API를 만들고 구성하는 client-side package/runtime 자체의 취약점은 제외되며, 이 클라이언트가 호출하는 서버 측 sandbox control plane API만 포함됩니다. |
| API | Other Vercel REST APIs not associated with Sandbox | Ineligible | N/A | 계정, team, project, deployment, dashboard, billing 및 기타 비-Sandbox endpoint를 포함한 광범위한 Vercel platform API는 이 챌린지 범위 밖입니다. |

## Allowed activities

- 본인 소유 계정에서만 테스트합니다.
- 교차 테넌트 테스트는 본인이 소유한 공격자·피해자 두 계정 사이에서만 재현합니다.
- Firecracker microVM→EC2 호스트 탈출, 타 테넌트 데이터/코드 접근, 설정된 sandbox firewall 우회, Vercel 측 credential-brokering 결함, sandbox control plane의 권한 우회·IDOR을 라이브 PoC로 검증할 수 있습니다.
- 한 번의 교차 테넌트 접근 확인 후 즉시 중단하고 관찰 내용을 기록·제출합니다.
- Vercel 운영 endpoint 대상 보안 스캐너는 초당 5 queries 이하로 사용할 수 있습니다.

## Prohibited activities

- EC2 호스트·다른 테넌트·firewall/credential control에 닿지 않는 Linux container namespace escape만 보고하는 행위.
- 본인 sandbox만 크래시·정지·자원 고갈시키는 DoS.
- 제3자 웹사이트가 credential-brokering header를 반사하는 취약점을 이용한 credential retrieval.
- 문서가 다른 설정을 지시한 알려진 제한사항을 취약점으로 제출하는 행위(예: domain allowlist와 subnets.allow 조합, CIDR-only 정책으로 DNS 제한).
- 라이브 Sandbox에서 실제 탈출을 입증하지 않은 공개 CVE 버전 매칭, advisory 링크, 공개 exploit code 제출.
- 운영자가 공급할 수 없는 malicious custom kernel 또는 custom Firecracker build가 필요한 공격.
- Dockerfile/Containerfile build phase, build context, cache, registry auth 관련 이슈.
- static-analysis-only 보고서.
- Vercel이 운영하지 않는 Datadog·AWS 등 제3자 서비스 자체의 취약점.
- 본인 소유가 아닌 계정·project·sandbox를 테스트, 열거 또는 탐색하는 행위(정해진 교차 테넌트 절차 제외).
- 타 테넌트/호스트 접근 성공 후 데이터 열거·덤프·반출·영속화·추가 탐색 또는 악의적 행위.
- 개인정보나 타인의 secret를 필요한 수준 이상 접근·다운로드·보관하는 행위.
- persistent backdoor 설치 또는 PoC 후 접근 유지.
- Vercel 직원·고객·연구자 대상 phishing, vishing, smishing 등 social engineering.
- Vercel 또는 HackerOne 직원 협박.
- volumetric DoS.
- 개인 검증 없는 AI 생성 보고서 제출.
- 법률 위반 테스트.
- 다음 알려진 root cause의 중복 보고: writable /proc/sys/kernel/core\_pattern과 /volumes/opt/vercel bind mount, 모든 41 Linux capabilities, host /dev bind mount, ActAllow seccomp 및 bypassable AF\_VSOCK, mknod+mount로 /dev/vda 마운트, writable modprobe/uevent\_helper와 /opt/vercel bind mount.
- 다음 알려진 post-escape surface만을 새 host-compromise primitive 없이 보고: vsock 2050 unauthenticated host service, containerd.sock/ipc.sock/APM·metrics sockets, sibling container spawn, CAP\_SYS\_ADMIN+unrestricted /proc/sys writes, DogStatsD/metrics vsock injection, sandbox-init Ed25519 key extraction.
- Vercel 측 결함 없이 sandbox workload에서 x-vercel-oidc-token, x-vercel-protection-bypass, x-vercel-proxy-signature를 단순 획득하거나 제3자 반사 채널로 유출하는 행위.
- 정책상 차단은 유지됐으나 logging/audit trail이 없는 경우, sandbox-internal endpoint version banner, security header 부재, 보안 결과 없는 verbose error/opaque status, 도달 가능성 없는 capability/config inventory, 문서·best-practice 제안, raw scanner output 제출.
- 임바고 종료 전 PoC·exploit·payload·재현 절차·sandbox/host/tenant 로그나 식별자를 공개 또는 외부 공유하는 행위.
- 임바고 후에도 타 Vercel 고객 데이터·식별자, production credential·brokered OIDC token·forwarded auth header·cookie·private key, 또는 중단 의무가 있던 타 테넌트 데이터를 공개하는 행위.

## Submission requirements

- 보고서당 하나의 취약점만 제출합니다. 영향 입증에 필요한 경우에만 체이닝합니다.
- 재현 가능한 상세 단계와 작동하는 PoC 코드 zip을 제공합니다. 재현 불가 보고서는 보상 대상이 아닙니다.
- 초기 제출에 PoC zip을 포함하거나 요청 시 신속히 제공합니다. 이론적 설명, source-code-only 분석, ‘필요하면 PoC 제공’은 대상이 아닙니다.
- Vercel Team ID(team\_…), Project ID(prj\_…), 재현 Sandbox ID(sbx\_…)를 포함합니다.
- 취약점 분류(Cross-Tenant data access / Networking and Firewall / Denial of Service / Other), bounty table에 맞춘 severity 및 근거, severity-inflation bounty penalty 인지를 포함합니다.
- 보고서는 비공개로 시작하며, HackerOne 내 공개는 Vercel의 명시적 승인이 필요합니다.
- 외부 공개는 보고서가 닫힌 뒤 2026년 12월 1일 이후(또는 Vercel의 조기 서면 허가 후)에만 가능하며, Critical/High 미패치 건은 서면으로 최대 2027년 3월 1일까지 한 차례 연장될 수 있습니다.
- 임바고 후 외부 글·발표는 공개 7일 전에 Vercel에 초안을 보내야 합니다.
- Vercel은 제출 후 첫 응답 1 business day, triage 5 business days, triage 후 bounty decision 10 business days를 최선 노력으로 목표로 합니다.

## Operational constraints

- HackerOne alias(username@wearehackerone.com)로 Vercel 계정을 만들고 해당 계정으로 모든 Sandbox API 트래픽을 수행합니다.
- Hobby 플랜으로 시작할 수 있고 Pro 플랜은 더 높은 sandbox quota를 제공합니다.
- Sandbox는 @vercel/sandbox 또는 sandbox CLI로 생성·관리합니다.
- custom image는 linux/amd64 OCI image를 Vercel Container Registry에 push한 뒤 사용합니다.
- 기본 및 hardened mode에서 network firewall(deny-all, domain allowlists, subnets.allow/subnets.deny, CIDR-only allow), credential brokering, lifecycle, host-facing service를 검증합니다.
- 각 결과는 fresh sandbox에서 재현하고, 정확한 명령·sandbox configuration·image·observed impact·sandbox/team/project ID·timestamp를 기록합니다.
- 타인 데이터에 우발적으로 닿으면 보고서에서 redact하고 확인 즉시 중단합니다.
- 범위가 불명확하면 프로그램 토론 또는 sandbox-escapes@vercel.com으로 사전 확인합니다.

## Safe harbor

정책을 선의로 준수한 보안 연구는 CFAA, DMCA 및 유사 법률상 승인된 행위로 간주하며, Vercel은 민형사 조치나 cease-and-desist를 취하지 않습니다. 다만 이 보호는 제3자에게는 적용되지 않으며, 범위 밖 asset 테스트, 단일 확인을 넘는 타 테넌트 데이터 접근·보관, volumetric DoS, social engineering, 임바고된 취약점 세부사항 또는 작동 exploit의 공개에는 적용되지 않습니다.

## Ambiguities requiring review

- 구조화된 scope 표에는 단일 자산 ‘Vercel sandbox’만 명시되어 있습니다. sandbox control plane의 개별 endpoint는 열거하지 않아도, sandbox client가 소비하는 endpoint라면 범위에 포함된다고 정책이 설명합니다.
- 프로그램은 종료 후 보고서를 보상 비대상으로 정하지만, 종료 전에 제출한 보고서의 triage는 2026년 10월 1일까지 진행한다고 명시합니다.
- \[모범 기준\] Gold Standard Safe Harbor, AI Research Safe Harbor 및 Platform Standards 준수를 표기합니다.
- \[모범 기준\] Fast Payment로 취약점 보고 접수 후 1개월 이내 지급을 표기합니다.
- 알려진 primitive는 중복이지만, 새로운 EC2 host compromise·cross-tenant reach·새 host write primitive 또는 새 영향이 입증되면 새 영향 tier에서 보상될 수 있습니다.
- 내부 tracker에 이미 기록됐으나 페이지에 공개되지 않은 동일 finding도 duplicate 처리될 수 있습니다.

## Source evidence

- **Introduction:** “This is a time-boxed public bug bounty focused on the Sandbox isolation boundary: the Firecracker microVM, the host-side sandbox firewall, credential brokering, and the sandbox control plane API.”
- **Scope:** “Vercel sandbox allows customers to run programs on an isolated environment, take disk snapshots, limit egress network connections and perform credential brokering at the networking level.”
- **In Scope:** “The sandbox control plane is in scope as well: the Vercel-operated REST API that the sandbox CLI and @vercel/sandbox call to create, configure, and manage sandboxes.”
- **Out of scope:** “Linux container namespace escapes that only reach the Firecracker guest OS (PID, mount, net, disk, or device namespaces).”
- **Rules of engagement:** “Provide detailed reproduction steps and a zip of working proof-of-concept code. Reports we cannot reproduce are not eligible.”
- **Testing guidelines:** “Always use two accounts you own (attacker and victim). Reproduce the cross-tenant access entirely between those accounts.”
- **Submission guidelines:** “A zip file of working PoC code (required ; no PoC, no bounty)”
- **Safe Harbor:** “We consider security research conducted in accordance with this policy as authorized conduct under applicable anti-hacking laws, including the Computer Fraud and Abuse Act, the DMCA, and similar laws.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
