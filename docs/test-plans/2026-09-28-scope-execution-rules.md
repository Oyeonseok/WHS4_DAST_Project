# Scope execution requirements implementation plan

> For agentic workers: use subagent-driven-development. Preserve all existing uncommitted work, including generic headers and concurrent Recon improvements. No commits or server restarts.

**Goal:** AI interprets approved policy text into grounded executable restrictions and operator prerequisites; CLI, dashboard and all outbound transports apply them without regex interpretation of policy prose.

**Architecture:** Extend the approved Scope analysis with nullable structured execution rules. A digest/version-bound resolver interprets legacy approved captures into a separate cache, returning both required headers and execution rules. Execution option values are validated against supported capabilities, intersected with existing permissions/caps and persisted into TargetPolicy. A shared durable SQLite governor charges outbound requests across targets and Recon/Attack/Validation, retaining program/target periodic limits across scans.

**Stack:** Existing Pydantic/Python/SQLite transports and React/TypeScript dashboard. No dependencies.

**Spec:** The design and public contracts below are authoritative. The user's authorization is to extend the existing AI-interpreted header behavior to request limits and other policy-dependent execution options/prerequisites.

## Global constraints

- AI decides the meaning of natural-language policy requirements. Python validates supported fields and exact source evidence; no policy prose regex/name matching determines requirements.
- Existing approved Scope JSON/Markdown/Approval/Manifest and historical scan policies/DBs remain unchanged. No target requests, exploit scan, server restart, commit or external message.
- New fields are nullable only to load legacy documents; explicit empty rules mean AI decided no additional requirements. Failure/unresolved interpretation blocks new launch; catalog reads never call models.
- Option application can only narrow host/method/authorization/tool permissions and numeric caps. Missing mandatory operator inputs/confirmations and unsupported mandatory controls block launch.
- Existing generic header names/templates/inputs and credential/origin boundaries remain supported.
- Fresh launches get a shared scan budget and request governor. Old saved policies without a governor binding retain their old transport behavior; do not rewrite them.
- Tests inject model responses/transports/clocks and never contact a real model or target.

## Frozen contracts

`ScopeAnalysis.execution_rules: ScopeExecutionRules | None` (default null). Add to fresh Scope collection and approval review.

```json
{
  "request_limits": [{
    "maximum": 10,
    "period_seconds": 1,
    "scope": "program",
    "source_quote": "Keep requests to 10 per second or lower."
  }],
  "option_limits": [{
    "field": "concurrency",
    "value": 1,
    "source_quote": "Use only one concurrent request."
  }],
  "allowed_methods": null,
  "allowed_target_assets": null,
  "required_inputs": [{
    "key": "testing_email",
    "label": "Testing account email",
    "kind": "email",
    "allowed_email_domains": ["wearehackerone.com"],
    "target_assets": [],
    "source_quote": "Use @wearehackerone.com email addresses for testing."
  }],
  "required_confirmations": [{
    "key": "production_contact",
    "label": "I contacted the program before production testing.",
    "target_assets": ["https://production.example/"],
    "source_quote": "Contact us before testing production."
  }],
  "blocking_requirements": []
}
```

- `RequestLimit`: maximum positive integer bounded, period_seconds positive finite number or null; scope `scan|program|target`; exact nonblank source_quote. Null period means total/lifetime quota for the declared scope; periodic program/target quotas persist across scans.
- `OptionLimit`: supported field `concurrency|timeout_seconds|max_depth|max_requests|max_scan_seconds|playwright_interaction|form_submission|katana_headless|ffuf_enabled|ffuf_recursion|mitm_capture_bodies`; value numeric or bool according to field, source_quote. Numeric values must meet existing policy bounds; max_scan_seconds <=86400. Booleans are restrictions: false disables, true does not widen a disabled permission.
- Allowed methods/targets carry their own exact quote (structured object `{values: [...], source_quote: ...}`), must be subsets of approved capabilities/assets; an empty permission intersection blocks execution.
- Required inputs reuse bounded key/label/text/username/email conventions; allowed_email_domains only for email, no arbitrary regex. `target_assets=[]` means all selected targets. Every nonempty target binding must be an exact approved asset. Same input key must have compatible declarations.
- Confirmations have bounded key/label, exact source_quote, optional exact target_assets. Manual obligations are explicitly acknowledged, never claimed automatically performed. Unknown mandatory controls are `{label, source_quote, reason, target_assets: []}` blocking requirements. Empty target_assets applies globally; otherwise reject only launches selecting an exact bound approved asset. Conditional unsupported requirements must retain their condition rather than blocking unrelated targets.
- AI must keep optional advice distinct from mandatory restrictions; contradictions/ambiguous mandatory controls become blockers. It must not invent optional setting requirements from incidental numbers in program prose.
- Source quotes must occur in captured approved text and be grounded in Scope source evidence. Schema validates types/ranges and duplicates.

`ScopeExecutionInterpretation` contains `required_request_headers` plus `execution_rules`, both non-null. `ScopeExecutionResolver(cache_dir, interpreter=None).cached/resolve(document)` returns an in-memory ScopeAnalysis, never modifies approval files. Capture/response/runtime bounds, digest plus interpretation version, atomic cache writes, corrupt cache => pending. Keep existing header resolver API for tests/compatibility; web/CLI use combined resolver.

Execution requirements API retains existing fields and adds:

```json
{
  "execution_requirements_status": "ready",
  "execution_rules": {},
  "policy_inputs": [],
  "policy_confirmations": [],
  "policy_blockers": []
}
```

`header_requirements_status` remains a compatibility readiness field and is ready only when the combined interpretation is ready. Existing `required_headers/header_inputs` remain. Profile `limits` expose effective conservative bounds. `scope_max_requests_per_second` derives from structured periodic limits (maximum/period), never policy-text regex. Display raw window quotas and their scope separately from app request budget.

POST `/api/v1/scopes/{scope_id}/execution-requirements` resolves combined legacy requirements, same-origin required, returns `{scope: publicScope}`. Keep `/header-requirements` route as compatibility alias. No model calls on catalog polls.

Launch adds `policy_values:{key:value}`, `policy_confirmations:[key]`. CLI adds repeatable `--policy-input KEY=VALUE`, `--confirm-policy KEY`. Validate only prerequisites applicable to selected exact assets, enforce email domains, reject unknown/conflicting declarations, and fail before any new target request. Existing authorization confirmation and identity_values remain.

New TargetPolicy optional `request_governor` binding is an object containing:

```json
{
  "ledger_path": "/trusted/result/.policy-budgets/<program_id>.db",
  "scan_id": "scan_...",
  "program_id": "<stable canonical program hash>",
  "scan_max_requests": 500,
  "scan_max_seconds": null,
  "requests_per_second": 0.5,
  "concurrency": 1,
  "request_limits": []
}
```

Binding validates paths/IDs/numbers, is generated by application code after policy verification (not model proposals). Ledger namespace is stable for the canonical program URL. Per-scan app budget applies across all targets/stages; per-target legacy policy caps remain additional bounds. Program/target periodic limits use stable program/origin buckets across scans. The same binding is copied to Handoff policies and proxy rules; resume reuses it.

Governor contract: `RequestGovernor(binding, clock=..., sleeper=...).reserve(url, units=1, timeout_seconds=...) -> permit`; `permit.wait()` ensures actual dispatch does not precede scheduled time; `permit.complete(outcome=...)` releases active capacity without refunding charged units. SQLite immediate transactions serialize process/thread reservations; unknown/failed outcomes remain charged. Batch transport units cannot cross scan/period quotas. Stale bounded concurrency leases expire without refund; elapsed scan timeout includes wait. Unavailable/invalid ledger fails closed. No binding => compatibility no-op. Expose a small dependency-free module that the standalone proxy can load.

## Task 1: Policy interpretation, binding and launch

Owners: scope/models.py, new scope/execution_rules.py, target-policy skill, recon/policy.py + profiles.py, cli.py, web/requirements.py + launch.py + server.py + scope_workflow.py, related backend tests. Do not edit transport/governor files or WebUI.

- [x] Add failing structured-model/resolver tests: Neon-style `10 per second` without text regex, requests/minute/day, shared operator prerequisites, conditional production acknowledgement, exact evidence, contradictions, malformed cache, model failure and immutable source.
- [x] Implement frozen contracts, fresh AI prompts and combined resolver, approval rendering and API. Keep existing generic-header behavior.
- [x] Apply restrictions to TargetPolicy, require relevant operator values/confirmations, compile application-owned governor bindings for new executed scans. Persist inputs/confirmation evidence without credentials; preserve fields across handoff/resume.
- [x] Remove text-regex rate inference; launch/profile values use structured rules. User overrides cannot exceed policy caps and may only lower them.
- [x] Adapt offline fixtures to explicit empty rules or injected combined interpreters. Run affected suites, write report. No commits.

## Task 2: Shared outbound request enforcement

Owners: new core/request_governor.py, core/request_broker.py, attack/request_cli.py, validation/execution/request_broker.py + transport_broker.py (+ playwright_browser.py only if necessary), recon/tools/mitm_addon.py (+ mitm_proxy.py if needed), related tests. Do not edit Task1 model/CLI/web files or WebUI.

- [x] Write failing behavioral tests for two stages/targets sharing scan budget, program quotas across scans, window rollover, normalized origins, process/thread concurrency, fail-closed ledger and delayed dispatch. Use fake clocks/sleepers and temp DBs.
- [x] Implement dependency-free shared governor accepting the binding dictionary contract. Preserve charged units on failure/unknown outcome and safe lease cleanup.
- [x] Integrate every actual outbound Recon HTTP/proxy/browser and Attack/Validation HTTP/browser/transport request, including redirects and batched request units. Avoid counting one physical request twice; browser Validation already uses ValidationRequestBroker ledger.
- [x] Reserve only after scope/credential/task validation. Wait before dispatch; complete/release on success and error; proxy releases in response/error hooks. Fail closed, including malformed explicit binding. Existing policies without binding retain compatibility.
- [x] Run affected offline transport/budget suites and report. No real target/model calls, commits or extra features.

## Task 3: Dashboard policy options and operator prerequisites

Owners: WebUI only. Consume frozen contract; no backend edits.

- [x] Add failing helpers/rendering tests for structured request limits/window labels, policy caps, conditional email input, target-bound confirmation, pending/blocked interpretation and launch payload.
- [x] Extend types and combined resolver endpoint. Display policy limits and exact evidence, distinguish app scan budget from policy quotas, and show auto-applied option restrictions.
- [x] Render applicable policy_inputs and policy_confirmations dynamically; block missing/invalid/unsupported requirements and pending results. Send policy_values/policy_confirmations alongside identity_values. Clear on Scope changes; target changes reevaluate applicability.
- [x] Show collected execution rules and prerequisites in detail/draft approval views. Keep old payloads supported as pending; no guessed requirements.
- [x] Node24 UI tests/build, report, no commits.

## Task 4: Fresh AI adapters and approval evidence

Owners: agents/main.py, agents/native_pipeline.py, orchestration/scope.py, Scope skill and new focused AI/approval tests. Task1 supplies models/resolver, this task adds interpret_scope_execution_requirements(ProgramPage)->ScopeExecutionInterpretation and fresh collection prompts/validation. No CLI/web/transport/WebUI edits.

- [x] TDD structured interpretation, exact captured grounding, non-null fresh rules and approval Markdown visibility.
- [x] Use bounded existing structured adapters with no browser tools for legacy interpretation; no natural-language policy regex inference.
- [x] Fresh Scope collection describes all supported requirements/options and includes non-null execution_rules; reject missing decisions, verify quotations/target bindings.
- [x] Approval Markdown renders executable limits and operator prerequisites with exact evidence. Preserve legacy files.
- [x] Run focused offline adapter/Scope suites and report; no commits/model/target calls.

## Integration verification (controller)

- [x] Independent task reviews and one integrated review; fix blockers through implementers.
- [x] Affected combined suites and full offline pytest with loopback privileges when needed; Node24 UI tests/build.
- [x] Real AI interpretation of immutable approved Neon capture into combined cache, inspect non-secret metadata only; no target requests. Verify exact 10/sec program ceiling and relevant email/production conditions.
- [x] Offline normal transport integration proves compiled shared scan budget/rate/inputs and header behavior; preserve original approval artifacts and historical DB/policy hashes.
- [x] Update docs/test-results/09.28/SUMMARY.md and add supported-option inventory to docs/OPERATIONS.md. No backend restart or scan launch.

## Task 5: Conditional unsupported requirements follow-up

Actual immutable Neon interpretation demonstrated production-only and non-executable extension requirements becoming global blockers. Task1 supplies optional exact target_assets on blockers and version2 cache. Consumer owner updates UI gating/evidence, generic AI instructions and approval Markdown without changing backend/governor.

- [x] Add failing applicability, global blocker, approval binding and prompt contract tests.
- [x] Preserve conditional blocker exact target bindings across AI, dashboard and approval.
- [x] Run Node24 UI tests/build and focused AI/backend tests; independent spec/quality review.
