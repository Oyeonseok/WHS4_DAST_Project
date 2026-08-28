# Scope: Safety Bug Bounty

> Source: https://bugcrowd.com/engagements/openai-safety
> Captured at: 2026-08-27T04:46:10.149821+00:00
> Scope ID: `scope_8dab0530e244438e81eb2884ac3134f8`

## Program summary

OpenAI 사용자의 위험을 초래하는 안전·악용 이슈를 보상하는 프로그램이다. 활성 OpenAI 제품의 설계 또는 구현 문제로 공격자가 물질적 피해를 유발할 수 있어야 하며, 명확하고 실행 가능한 완화 조치가 있어야 한다. 각 인스코프 대상의 보상은 P1 $5500 – $7500, P2 $2500 – $3500, P3 $750 – $1500, P4 $250 – $500로 표시된다.

## In-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | Agentic Tools Including MCP | 버그헌터가 소유한 ‘피해자’ 테스트 계정에서 간접/제3자 프롬프트 인젝션 또는 신뢰할 수 없는 콘텐츠 공격으로 Connector/MCP 도구가 민감 데이터를 접근·유출·변환하거나 유해한 작업을 수행하게 하는 경우, 권한 범위를 넘는 접근·작업, 또는 고영향 작업에 대해 사용자 이해·확인이 부적절하거나 실질적으로 오해를 유발하는 경우가 적격이다. 사람 상호작용 없이 OpenAI 사용자 계정을 최소 10개 대량 생성하는 악용도 포함된다. | P1 | Atlas Browser, Codex, Operator, Connectors 및 기타 에이전틱 ChatGPT 도구를 포함한다. OpenAI 시스템·구성·권한·확인 UX·통합 로직의 취약점으로 민감 데이터 무단 접근, 테넌트 간 노출 또는 피해자 계정의 유해한 작업이 발생하는 경우가 대상이다. 보상: P1 $5500 – $7500 · P2 $2500 – $3500 · P3 $750 – $1500 · P4 $250 – $500. |
| OTHER | OpenAI Proprietary Information | 실제 취약점 또는 모델 이슈가 OpenAI 내부 정보, 지식재산 또는 기타 기밀 데이터를 반환해야 한다. 다른 OpenAI 독점 정보 노출 취약점은 기존 Security Bug Bounty를 통해 보고하도록 안내된다. | P1 | 추론 관련 독점 정보(예: 전체 비요약 Chain of Thought)를 반환하는 취약점이 대상이다. 보상: P1 $5500 – $7500 · P2 $2500 – $3500 · P3 $750 – $1500 · P4 $250 – $500. |
| WILDCARD | \*.openai.com | 의도된 한도를 크게 넘는 지속적·대규모 사용을 가능하게 하는 의미 있는 OpenAI 속도 제한 또는 플랫폼 제어 우회를 입증해야 한다. 대화 속도 제한 우회는 최신 모델 세대의 Sol 모델(추론 수준 무관)에서 하루 5개 이하 계정으로 최소 1,000 completions를 입증해야 한다. OpenAI 계정 대량 생성 자동화도 포함된다. | P1 | 플랫폼의 악용 방지 보호장치 우회 및 계정/플랫폼 무결성 신호 취약점 대상이다. 보상: P1 $5500 – $7500 · P2 $2500 – $3500 · P3 $750 – $1500 · P4 $250 – $500. |
| DOMAIN | openai.com | 직접적인 사용자 피해 경로 및 개별적으로 실행 가능한 개선 조치를 제시하는 경우에 한해 사례별 보상 검토 대상이다. | P1 | 명시된 사례 외에도 사용자 피해로 이어지는 직접 경로와 실행 가능하고 구체적인 완화 조치를 포함한 신규 악용 결함은 사례별로 고려될 수 있다. 보상: P1 $5500 – $7500 · P2 $2500 – $3500 · P3 $750 – $1500 · P4 $250 – $500. |

## Out-of-scope assets

| Type | Asset | Eligibility | Maximum severity | Description |
|---|---|---|---|---|
| OTHER | OpenAI models | Out of scope | N/A | OpenAI의 금지 콘텐츠 정책을 위반하는 모델 응답 생성 이슈는 범위 밖이다. 모든 콘텐츠/모델 응답 이슈는 전통적 보안 수정으로 해결하기 어렵다고 명시되어 범위 밖이다. |

## Allowed activities

- 버그헌터가 소유한 테스트 ‘피해자’ 계정에서 Connector 또는 MCP 관련 취약점을 재현하고 증거를 수집하는 활동
- 권한·워크스페이스·앱 통합 권한을 초과하는 Connector/MCP 접근 또는 작업, 교차 워크스페이스·테넌트 노출을 입증하는 활동
- 사용자 이해·확인이 부적절하거나 실제 동작과 실질적으로 다른 확인 UX를 입증하는 활동
- 사람 상호작용 없이 OpenAI 사용자 계정을 최소 10개 생성하는 에이전틱 도구 악용을 입증하는 활동
- 하루 5개 이하 계정에서 Sol 최신 모델 세대의 최소 1,000 completions를 보여 주는 확장 가능한 대화 속도 제한 우회를 입증하는 활동

## Prohibited activities

- 타인 소유 계정·자산·서비스에 영향을 주는 테스트
- 실제 사용자 또는 에이전트가 발견할 수 있는 공개 표면에 프롬프트 인젝션 텍스트를 호스팅하는 등 실제 계정 손상 또는 피해 위험이 있는 테스트
- OpenAI 측 수정으로 이어지지 않는 제3자 서비스에만 존재하는 이슈 보고
- 명시적 테스트 권한이 없는 계정·테넌트·데이터 접근
- 명백히 악성 또는 위험한 명령을 피해자가 실행해야 하는 프롬프트 인젝션 보고
- 모델 응답이 내부 독점 정보를 노출하는 것처럼 보이기만 하는 보고
- CoT를 제외한 시스템 프롬프트 또는 추론 시점 모델 컨텍스트 창의 기타 정보 보고
- 의도된 한도를 크게 넘는 지속적·대규모 사용을 입증하지 못하는 속도 제한 우회 보고
- 지리적 접근 제한 제어 회피
- 실제 사기를 조장하거나 소셜 엔지니어링이 필요한 테스트(예: 허위 OpenAI Startup Fund 계정 생성)
- OpenAI 금지 콘텐츠 정책을 위반하는 콘텐츠를 생성한다는 모델 응답 이슈

## Submission requirements

- 적격 이슈는 활성 OpenAI 제품의 설계 또는 구현 문제여야 하며 공격자가 물질적 피해를 유발할 수 있어야 한다.
- 명확한 권장 조치 또는 완화 단계가 있어야 하며, 일반적 제품 개선 요청은 보상 대상이 아니다.
- 일반적 조건에서 신뢰성 있게 재현할 수 있는 충분한 절차와 증거를 제공해야 한다. 부분적·확률적 익스플로잇은 고영향임을 입증하는 경우에만 검토될 수 있다.
- 이미 OpenAI에 제출된 이슈는 보상하지 않는다.
- 조정 공개에는 제출 시 공개 요청 옵션을 선택한 명시적 허가가 필요하다.

## Operational constraints

- 피해자 역할의 모든 계정은 연구자 소유 테스트 계정이어야 한다.
- 개인 계정의 문제를 피하기 위해 버그헌팅에는 테스트 계정을 사용해야 한다.
- 자동 취약점 스캐너는 속도 제한·차단·계정 정지를 유발할 수 있으며, 차단된 계정 또는 IP는 만료될 때까지 기다려야 한다. 수동 해제는 제공되지 않는다.
- 계정 업그레이드 또는 구매 비용은 환급되지 않는다.
- 승인된 테스트라도 OpenAI 이용약관 전체에서 면제되는 것은 아니며, 서비스 악용은 제한·차단·정지로 이어질 수 있다.
- 정책 적합성이 불확실하면 진행 전에 support@bugcrowd.com으로 문의해야 한다.

## Safe harbor

정책을 선의로 준수하는 연구자에 대해 OpenAI는 법적 조치를 위협하거나 제기하지 않으며, 적격 서비스·애플리케이션의 기술적 보호조치 우회와 관련한 DMCA 청구도 포함한다. 정책 준수 시 해당 연구는 CFAA 및 유사 주법상 ‘authorized’로 간주되고, 안전·보안 연구라는 제한된 목적에 한해 참여를 금지하는 이용약관·사용 정책 제한을 면제한다. 다만 OpenAI는 제3자 시스템에 대한 연구를 승인하거나 제3자의 법적 조치로부터 방어·면책을 보장할 수 없다.

## Ambiguities requiring review

- 제공된 캡처에는 각 대상의 구체적인 URL·API 엔드포인트 또는 제품별 세부 자산 목록이 없으며, Target Group 이름 수준의 범위만 확인된다.
- ‘Other Novel Abuse’는 사례별 검토 대상이므로 사전 확정된 적격성 또는 보상을 보장하지 않는다.
- 기존 Security Bug Bounty 범위로 안내된 다른 OpenAI 독점 정보 노출 및 권한 초과 기능·데이터 접근의 구체적 대상 범위는 이 캡처에 포함되지 않았다.
- 안전 이슈의 최종 보상 결정 및 금액은 OpenAI 재량이라고 명시되어 있다.

## Source evidence

- **Overview:** “The OpenAI Safety Bug Bounty Program is designed to complement our existing Security Bug Bounty Program by rewarding for safety and abuse issues that pose risks to OpenAI users.”
- **Program Rules:** “Qualifying issues must represent a design or implementation issue in an active OpenAI product that can be abused by an attacker to cause material harm.”
- **Program Rules:** “Any accounts used as victims must be test accounts owned by the researcher. Any testing that affects accounts, assets, or services owned by others is strictly prohibited.”
- **Agentic Tools Including MCP:** “In Scope: Indirect / third-party prompt injection or untrusted-content attacks that cause an agent to misuse a Connector or MCP tool to access, exfiltrate, or transform sensitive data from a bughunter-owned “victim” account, or to take a harmful action under that account.”
- **OpenAI Proprietary Information:** “In Scope: Vulnerabilities that return proprietary information related to reasoning (e.g., full unsummarized Chain of Thought).”
- **Account and Platform Integrity:** “Rate limit bypass issues must demonstrate at least 1,000 completions from the latest model generation across no more than five accounts within one day on our Sol model (any reasoning level).”
- **Content Issues:** “All content/model response issues are out of scope — these issues are complex and not addressable through traditional security fixes.”
- **Safe Harbor:** “OpenAI will not threaten or bring any legal action against anyone who makes a good faith effort to comply with this bug bounty policy.”

---
승인하기 전에 원본 프로그램 페이지와 이 문서를 대조해 검토하세요.
