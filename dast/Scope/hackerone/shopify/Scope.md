# Scope: Shopify

> Source: https://hackerone.com/shopify?type=team
> Captured at: 2026-08-27T04:05:32.040681+00:00
> Scope ID: `scope_0634ed9dd59c4484bd671abd0d0f67f8`

## Program summary

Shopify의 버그 바운티 프로그램으로, 플랫폼 보안에 영향을 주는 취약점 제보에 대해 최대 $200,000의 보상을 제공합니다. 명시된 범위 외 자산의 유효한 취약점은 접수될 수 있으나 보상 대상이 아닙니다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| DOMAIN | your-store.myshopify.com | Eligible | Critical | \*.myshopify.com에 호스팅되는 본인의 개발 스토어입니다. https://partners.shopify.com/에서 개발 스토어를 생성해야 합니다. |
| DOMAIN | shopify.plus | Eligible | Critical | Environment: Core |
| OTHER | Shopify Mobile Applications | Eligible | Critical | Android 및 iOS Shopify 모바일 애플리케이션입니다. 제3자 운영 서비스는 Shopify 사용자 영향의 PoC 없이는 보상 대상이 아닐 수 있습니다. |
| DOMAIN | shop.app | Eligible | Critical | Environment: Core |
| DOMAIN | partners.shopify.com | Eligible | Critical | Environment: Core |
| OTHER | Authentication &amp; ATO | Eligible | Critical | Environment: Core |
| DOMAIN | arrive-server.shopifycloud.com | Eligible | Critical | Environment: Core |
| DOMAIN | admin.shopify.com | Eligible | Critical | Environment: Core |
| DOMAIN | accounts.shopify.com | Eligible | Critical | Environment: Core |
| WILDCARD | \*.shopifycs.com | Eligible | Critical | PCI 준수 방식으로 신용카드 데이터를 처리하는 Shopify 서비스입니다. |
| WILDCARD | \*.pci.shopifyinc.com | Eligible | Critical | Environment: Core |
| DOMAIN | shopifyinbox.com | Eligible | Medium | Environment: Non-core |
| OTHER | Shopify Third Party Store | Ineligible | Medium | 본인이 생성한 상점에 대해서만 테스트할 수 있습니다. |
| OTHER | Shopify Third Party Apps | Ineligible | Medium | 제3자 Shopify 앱 취약점은 책임 개발자에게 보고해야 하며, 만족스러운 응답을 받지 못한 경우에만 이 프로그램으로 보고할 수 있습니다. |
| OTHER | Shopify Developed Apps | Eligible | Medium | https://apps.shopify.com/collections/made-by-shopify 에 설치되는 Shopify 앱 및 판매 채널입니다. |
| DOMAIN | linkpop.com | Eligible | Medium | Environment: Non-core |
| SOURCE\_CODE | https://github.com/Shopify/\* | Eligible | Medium | Shopify GitHub 조직의 공개 저장소입니다. |
| WILDCARD | \*.shopifykloud.com | Eligible | Medium | 개발자 테스트 또는 제3자 애플리케이션이 포함될 수 있습니다. 테스트 앱처럼 보이는 하위 도메인은 조사 전에 프로그램에 문의해야 합니다. |
| WILDCARD | \*.shopifycloud.com | Eligible | Medium | 개발자 테스트 또는 제3자 앱이 포함될 수 있으며, 예시로 제시된 테스트성 도메인은 범위에 포함되지 않습니다. 불확실한 테스트성 도메인은 사전에 문의해야 합니다. |
| WILDCARD | \*.shopify.io | Eligible | Medium | 개발자 테스트 또는 제3자 애플리케이션이 포함될 수 있습니다. 테스트 또는 제3자 앱처럼 보이는 경우 사전에 문의해야 합니다. |
| WILDCARD | \*.shopify.com | Eligible | Medium | .shopify.com 관련 보고는 보상 적격성을 사안별로 검토합니다. 제3자 운영 서비스는 .myshopify.com 사용자 영향 PoC 없이는 보상 대상이 아닐 수 있습니다. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | supplier-portal.shopifycloud.com | Ineligible | None | invoices.shopify.io, factures.shopify.io, invoices.shopify.cn, invoices.shopify.de, invoices.shopify.fr, invoices.shopify.jp를 포함합니다. |
| OTHER | Other | Ineligible | None | 명시적으로 기타 자산은 범위 밖입니다. |
| DOMAIN | livechat.shopify.com | Ineligible | None | HackerOne 보고서 관련하여 Shopify Support에 채팅, 이메일 또는 전화로 연락하는 것은 허용되지 않습니다. |
| DOMAIN | investors.shopify.com | Ineligible | None | 제3자가 운영합니다. |
| DOMAIN | community.shopify.dev | Ineligible | None | 제3자 서비스이며 테스트해서는 안 됩니다. |
| DOMAIN | community.shopify.com | Ineligible | None | 제3자 서비스이며 테스트해서는 안 됩니다. |
| DOMAIN | cdn.shopify.com | Ineligible | None | 판매자가 임의 파일을 업로드할 수 있으며, 파일 업로드 가능 자체는 의도된 기능입니다. |
| DOMAIN | academy.shopify.com | Ineligible | None | 제3자가 운영합니다. |
| WILDCARD | \*.email.shopify.com | Ineligible | None | 제3자가 운영합니다. |

## Allowed activities

- HackerOne YOURHANDLE @ wearehackerone.com 등록 이메일로 생성한 스토어만 테스트합니다.
- 유출 자격 증명은 인증 후 즉시 로그아웃하는 범위에서만 유효성을 확인할 수 있습니다.
- Shopify 제3자 앱은 책임 개발자에게 먼저 보고하고 만족스러운 응답을 받지 못한 경우에만 이 프로그램에 보고합니다.

## Prohibited activities

- 본인이 생성하지 않은 스토어에 접근하거나 상호작용해서는 안 됩니다.
- 해결 전 또는 허가 없이 이슈를 공개해서는 안 됩니다.
- 테스트 또는 포상 관련 문의, 사전 검증, 상태 확인을 위해 Shopify Support에 연락해서는 안 됩니다.
- 유출 자격 증명으로 인증 이외의 기능을 실행하거나, 보고서 외의 다른 사람에게 자격 증명을 공유해서는 안 됩니다.
- 법률을 위반하거나 본인 소유가 아닌 데이터를 방해 또는 손상시키는 테스트를 해서는 안 됩니다.

## Submission requirements

- 취약점을 검증한 즉시 Shopify에 보고해야 합니다.
- Shopify, Shop 사용자, 파트너 또는 판매자에 대한 관련 CVSS 영향을 보여주는 기능적 PoC를 제출해야 합니다.
- 모든 보고 규칙을 따라야 합니다.
- 제출 콘텐츠는 본인의 원저작물이어야 하며 필요한 권리를 보유해야 합니다.

## Operational constraints

- 보상은 범위 페이지에 명시된 자산으로 제한됩니다.
- 동일한 근본 원인의 복수 보고서는 Duplicate로 처리됩니다.
- 근본 원인이 Shopify의 통제 하에 있는 경우에만 트리아지 및 보상합니다.
- IDOR은 식별자 예측 가능성, 접근 데이터 및 전체 서비스 영향을 고려해 평가합니다.
- Non-core 자산은 기밀성·무결성·가용성 요구사항을 Low로 설정하여 점수화합니다.
- Shopify는 규칙 또는 제출을 변경·무효화하거나 프로그램을 예고 없이 취소할 수 있습니다.

## Safe harbor

Gold Standard Safe Harbor를 준수한다고 표시되어 있습니다. 다만 캡처에는 세부 세이프하버 조항이 포함되어 있지 않습니다.

## Ambiguities requiring review

- Gold Standard Safe Harbor의 구체적 보호 범위와 조건은 캡처에 제공되지 않았습니다.
- 범위 외 자산의 유효한 취약점은 접수될 수 있으나 보상 비적격이라고만 명시되어 있으며, 트리아지 여부는 명확하지 않습니다.
- \*.shopify.com 및 일부 wildcard 자산은 테스트·제3자 서비스에 대해 개별 판단 또는 사전 문의를 요구하므로, 개별 하위 도메인의 적격성은 확정할 수 없습니다.

## Source evidence

- **Scope:** “1-30 of 30”
- **Eligibility:** “The scope of the bug bounty program is limited to the assets listed on the scope page for this program. Valid vulnerabilities on any asset not explicitly listed in scope may be accepted but are ineligible for a reward.”
- **Getting started:** “You must test only against stores you have created. Testing against live merchants is prohibited and can result in reports being closed as Not Applicable and/or your disqualification from the Shopify bug bounty program.”
- **Rules for participation:** “Only test against stores you created using your HackerOne YOURHANDLE @ wearehackerone.com registered email.”
- **Vulnerability Reporting:** “You must report any discovered vulnerability to Shopify as soon as you have validated the vulnerability.”
- **Leaked Credentials:** “Hackers should submit the leaked credentials to the program and should not test their validity beyond authenticating and then immediately deauthenticating - without exercising any functionality.”
- **Scope:** “Reports involving .shopify.com are reviewed on a per case basis for bounty eligibility, this includes shopifycompass.com. Any services operated by a third party without a proof of concept demonstrating impact on .myshopify.com users will likely be ineligible for a bounty.”
- **Scope exclusions:** “Core Ineligible Findings are out of scope.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
