# Generic AI policy exclusions implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Execute tasks in order, with task review and a final integrated review. Steps use checkbox syntax.

**Goal:** Interpret arbitrary program exclusions with AI, bind semantic conditions to captured resources, and enforce exclusion decisions before every supported request across Recon, Attack and Validation.

**Architecture:** Scope contains quoted, bounded exclusion expressions. An offline AI binder classifies immutable application-generated request candidates using associated captured evidence; a dependency-free evaluator returns continue, deny or hold. Scope, evidence and complete request identity bind cached results; absent or stale evidence never permits a request.

**Tech Stack:** Existing Python/Pydantic/SQLite/Playwright and React/TypeScript; no new dependencies.

**Spec:** The Design and contracts in this document are the authoritative specification approved by the user in chat.

## Global constraints

- Preserve all preexisting dirty work. Work in this feature checkout because dependent generic-header/governor changes are uncommitted here; take task-local snapshots for reviews. No commits, git resets, merges, external messages, backend restart, real target traffic or real model calls during implementation/testing.
- AI interprets natural-language requirements and semantic resource categories; no Neon names, prose regex or program-specific feature lists determine policy.
- Quotes must be exact contiguous source spans. Binding citations must identify immutable, associated application-supplied evidence. AI never supplies a free destination, broadens authorization, or invents operator/account ownership facts.
- A restriction expression is evaluated with three-valued logic. True means deny; potentially applicable unknown means hold; false merely continues existing host/method/authorization/budget checks. True global blockers remain launch blockers.
- Unsupported condition nodes remain unknown. No arbitrary regex, Python, SQL or executable expressions. Expressions have depth <=8, nodes <=128 and predicates/strings/counts are bounded.
- Missing/null exclusion interpretation is legacy and needs explicit capture-only reinterpretation before new launch. Explicit [] means AI reviewed and found no exclusions. Existing saved policies without the new guard retain their behavior; historical approvals/policies/DBs remain byte-identical.
- Semantic snapshots expire at most 86400 seconds after their oldest supporting evidence. Missing/future/expired capture timestamps cannot support a usable semantic binding; direct predicates need no resource evidence.
- Bound semantic classifications never generalize to changed URL, method, query, headers, request body or identity. No model calls occur in per-request admission or catalog GET. Classified captures are probabilistic semantic judgments; provenance validation is not mathematical proof of semantic truth.
- Evidence preparation reads existing local captures only. Unknown seeds hold before login/executor/network. No Recon/bootstrap exception fetches the resource whose policy status is unknown.
- Keep the simplified scan form: no new consent checkbox lists or long policy explanations. Compact condition/held status and full details in Scope review are sufficient.
- Worker reports include exact files, TDD red/green evidence, verification commands/results, and limitations. Do not spawn worker subagents.

## Design and frozen contracts

### Models

Create `src/aidast/scope/exclusions.py` for exclusion and binding Pydantic models; it does not import scope.models/recon.policy.

`ExclusionPredicate`: `key` bounded identifier; `field` = host|path|method|query|json_body|form_body|semantic|unsupported; `operator` = equals|prefix|present; optional bounded `name`, `value` strings. Prefix is supported only for a segment-bounded path. Query/form use an exact parameter name; JSON body uses a bounded JSON pointer. Semantic predicates use their key as an opaque category ID and a value describing the category, determined by AI. Unsupported predicates preserve the unexpressible condition text. No arbitrary headers, regex or executable grammar in this release; semantic predicates can represent additional researcher/resource conditions only with sufficient evidence, otherwise unknown.

`ExclusionExpression`: `operator` = predicate|all|any|not; optional predicate and children list; validate arity, recursive depth/node limits and unique predicate IDs per rule. `ScopeExclusion`: key,label,source_quote,target_assets,condition. Scope rule keys are unique. All nonempty target bindings are exact approved assets. Concrete host/path/method/query/body predicate values need source grounding; derived feature locations use semantic binding rather than fabricated direct predicates.

`ScopeExecutionRules.exclusions: list[ScopeExclusion] | None = None`; quoted_requirements includes non-null exclusions. Legacy model loading remains valid; fresh AI results must contain non-null exclusions ([] accepted).

`ResourceCandidate`: application-generated candidate_id, request_key SHA256, url,method, sanitized public_headers, body_sha256, bounded body_preview or null, evidence_ids. `ResourceEvidence`: evidence_id, candidate_ids, source_url, kind (html/javascript/api/captured_response), content_sha256, bounded excerpt and optional captured_at epoch timestamp. The producer retains source identity and verifies bytes/associations before issuing records; arbitrary file names/annotations alone are not evidence.

`ResourceClassification`: decisions list. Each decision has candidate_id, rule_key, predicate_key, classification match|nonmatch|unknown, reason and citations[{evidence_id,quote}]. Citations must be associated with that candidate and verbatim spans of its supplied excerpt; match/nonmatch require affirmative evidence. Missing/duplicate/wrong-ID/invalid-quote decisions become unknown or reject the batch safely. Absence of a keyword or a response body never proves nonmatch.

`CompiledExclusionPolicy`: schema_version '1', scope_digest, rule_digest, evidence_digest, target_asset, rules list, semantic_bindings list and optional expires_at finite epoch timestamp. Usable semantic bindings require unexpired expires_at; absent expiry holds. Each binding contains request_key, rule_key,predicate_key, classification, evidence_ids. Validate SHA256 identities and rule membership. rule_digest covers rules; evidence_digest is generated from the immutable evidence snapshot. A classification never grants host/method permissions.

### Dependency-free gate

Create `src/aidast/core/exclusion_guard.py`, stdlib-only and loadable via runpy in mitmproxy's Python.

- `request_key(url, method, headers=None, body=None, context=None) -> str`: complete canonical method/origin/path/query plus sorted case-insensitive header values, full body hash and bounded trusted operation/context metadata. Context distinguishes WS handshake from frames/control operations and gRPC wire semantics. Do not persist raw credential/body values. Reject malformed URL/userinfo/fragment and conflicting case-insensitive duplicate headers.
- `validate_exclusion_policy(data) -> dict`: recursively validate bounded shape, digests, IDs, supported operators and bindings without Pydantic.
- `evaluate_exclusions(data, *, url, method='GET', headers=None, body=None, body_available=False, context=None, now=None) -> dict`: {decision:'continue'|'deny'|'hold',rule_keys:[...],reason:str}. None is legacy continue. Malformed present data holds. Full physical requests pass body_available=True even for an empty body; unavailable data produces unknown only where relevant. A true exclusion dominates other unknown rules.
- Logical tables: false AND unknown=false; true AND unknown=unknown; true OR unknown=true; false OR unknown=unknown; NOT unknown=unknown. Unknown semantic bindings never default to nonmatch.
- Canonical path handling must avoid percent-encoded separators/traversal ambiguity; query/body duplicate keys and parse errors are unknown where relevant. JSON scalars/nested pointers and form encodings are bounded.

`TargetPolicy.request_exclusions: CompiledExclusionPolicy | None` default null, omit legacy null serialization when appropriate. `TargetPolicy.check_request_exclusions(url, *, method, headers=None, body=None, body_available=False, context=None, now=None) -> dict` delegates to shared evaluator. Existing URL checks remain baseline scope boundaries and must not be confused with full-context admission. `mitm_rules()` serializes the exact guard snapshot. Every physical path must explicitly evaluate the full-context gate after preparing final headers/body and before reserve/dispatch; URL-only checks cannot approve an unknown body-dependent operation.

### Offline binding and preparation

`ExclusionBindingResolver(cache_dir, interpreter=None).resolve(*, scope_digest, target_asset, rules, candidates, evidence) -> CompiledExclusionPolicy` uses a digest-keyed atomic sidecar. Cache identity includes grammar/binding versions, Scope digest, selected target, rule digest, complete candidates/request keys and evidence IDs/content hashes/excerpts/associations. Bound/cache reads never call a model. Empty rules/direct-only rules need no semantic model call.

Both agent adapters expose `classify_exclusion_resources(context: dict) -> ResourceClassification`, browsing/tool disabled, bounded request/response/time and explicit untrusted evidence framing. Shared prompt-building/response-validation lives in the exclusion module or a focused helper to avoid prose duplication. The batch includes every relevant candidate/predicate pair; missing results stay unknown. Binder verifies app-owned IDs, coverage, quotes and evidence association before producing usable bindings.

`ScopeExecutionResolver` version becomes 3. cached() must prefer a valid current sidecar over incomplete embedded rules; embedded rules are complete only with exclusions not null. Merely bumping the cache version is insufficient. CLI checks completeness through the resolver on every new execution; catalog GET returns pending for incomplete legacy rules without model calls. Fresh Scope validation requires non-null exclusions and exact source grounding; update central fixtures meaningfully for the new contract.

A shared preparation helper builds requests from actual selected start URLs and verified local Recon/Pipeline captures tied to the approved Scope and target origin. It reads SQLite in read-only mode, does not mutate captures, and sanitizes evidence before model use. Candidate headers include effective researcher identity headers when known; missing credentials/context cannot inherit a previous authenticated decision. Only actually observed request descriptors get a semantic binding; endpoint templates or annotations cannot fabricate one. Candidate count/bytes are bounded. Direct exclusions require no capture to enforce.

Attach the compiled snapshot to newly generated policies after the existing caps/identity/governor intersection. Unmanaged system-browser login is unsupported when exclusions are nonempty and must hold before opening that browser; loading an existing session bundle is still possible without target IO. Evaluate essential start requests before login preparation, executor creation and target I/O; deny/hold yields an actionable error with rule keys, not raw secret context. Unknown future requests are held by runtime; a subsequent explicit offline preparation can refresh the snapshot using newly available evidence, never by fetching an unknown resource. New launches and dashboard preparation use the same helper; no separate policy meaning in frontend. Maintain explicit policy-only/offline inspection and expose counts/reasons of unresolved resources.

### Transport completeness

Recon core broker, Playwright route fetch/fallback/browser-support requests, mitmproxy requests, Attack guarded_request, Validation HTTP inner transport, Validation browser routes, and explicit WS/gRPC transport operations all intersect the same guard. Recheck redirects and final merged headers/body. URL observation and endpoint recording may retain evidence about excluded resources, but observation does not authorize dispatch. Unsupported wire/body/action semantics in WS/gRPC are held whenever they are needed by a rule. Concurrent/group transports cannot reserve or send a partially disallowed group.

## Task 1: Models and shared exclusion evaluator

**Files:** Create scope/exclusions.py, core/exclusion_guard.py, tests/test_policy_exclusion_guard.py; modify scope/models.py and recon/policy.py.
**Consumes:** Existing ScopeAnalysis grounding and TargetPolicy baseline boundaries.
**Produces:** Frozen models, request_key, validate_exclusion_policy, evaluate_exclusions, TargetPolicy.check_request_exclusions and mitm serialization.

- [x] Write meaningful failing tests for generic renamed/localized exclusions, OR/all/not tri-state, method/path/query/body predicates, duplicate key ambiguity, URL encoding/traversal, malformed guard, stale rule digest and semantic exact-context identity. Example:
```python
assert evaluate_exclusions(compiled_semantic_rule, url='https://example.test/api', method='POST', headers={}, body=b'{"operation":"feedback"}', body_available=True)['decision'] == 'hold'
assert evaluate_exclusions(direct_path_exclusion, url='https://example.test/support', method='GET')['decision'] == 'deny'
```
- [x] Run focused tests and retain the red output.
- [x] Implement the frozen contracts. Keep stdlib evaluator independent of aidast/Pydantic imports and validate runpy behavior.
- [x] Run new tests plus scope execution rules/recon policy tests, self-review and write report. No commit; controller snapshots this task delta.

## Task 2: AI interpretation, evidence binding and legacy freshness

**Files:** Create scope/exclusion_binding.py and tests/test_policy_exclusion_binding.py; modify agents/main.py, agents/native_pipeline.py, scope/execution_rules.py, orchestration/scope.py, scope skill text; scope/exclusions.py only if additive fixes needed; update relevant central fixtures/tests for fresh exclusions [].
**Consumes:** Task 1 models and request_key/evaluator.
**Produces:** ExclusionBindingResolver, classify_exclusion_resources in both adapters, current version-aware Scope resolver and capture-only complete interpretations.

- [x] Write failing tests for AI generic exclusion interpretation, invented/noncontiguous source quotes, embedded v2 rules upgrade, v3 sidecar precedence and unchanged approval bytes.
- [x] Write binding tests with literal candidate/evidence IDs: one semantic category matches several unrelated endpoint names; unrelated citations or absence of words cannot authorize; changed request headers/body invalidates bindings; missing pairs are unknown; corrupt/stale sidecar holds; no model calls for cache reads/direct rules. Assert behavior, not prompt string presence.
- [x] Implement shared bounded offline AI prompt/validation, models and digest-bound sidecars. Fresh interpretation always declares exclusions; never reclassify old blockers by label string matching.
- [x] Run covering tests for both adapters/cache/approval workflow and report red/green evidence and capabilities. No commit.

## Task 3: Shared preparation, CLI/dashboard launch and captured evidence

**Files:** Create scope/exclusion_preparation.py, tests/test_policy_exclusion_preparation.py; modify cli.py,web/launch.py,web/requirements.py,web/server.py,scope/execution_rules.py, Scope/UI types and Scope review component. Update scope execution/dashboard/pipeline tests as needed.
**Consumes:** Current complete Scope resolver, binder and evaluator.
**Produces:** Verified readonly evidence loader, shared preparation helper, compiled policy snapshots and pre-network seed holds for CLI/dashboard; compact exclusion/held diagnostics.

- [x] Write failing tests for actual temporary SQLite captures tied to Scope/target, wrong Scope/origin and symlink rejection, body/capture size limits, redaction, fabricated annotations and unknown seed held before login/executor.
- [x] Write shared CLI/web tests for direct exclusions applied automatically, semantic candidates prepared offline with injected interpreter, unchanged original artifacts, existing input/confirmation/global blocker enforcement, cache-only GET and fresh readiness.
- [x] Implement snapshot preparation and attach guards to new policies. Use selected actual starts; no invented destinations or passive/bootstrap bypass. Move login work only as necessary so held seeds cannot cause preparatory target requests.
- [x] Preserve simplified UI and show full interpreted exclusion rules in Scope review; no extra consent list. Policy-only/offline inspection must expose denied/held resources without requests.
- [x] Run focused preparation/CLI/web/UI tests and build; report evidence and unresolved capability limits. No commit.

## Task 4: Enforce every physical transport and integrated regression

**Files:** Modify core/request_broker.py,core/http_safety.py,recon/tools/playwright_driver.py,recon/tools/mitm_addon.py,attack/request_cli.py,validation/execution/request_broker.py,validation/execution/playwright_browser.py,validation/execution/transport_broker.py and adapters only if required; create tests/test_policy_exclusion_transports.py, update affected transport tests and docs/OPERATIONS.md.
**Consumes:** Task 1 guard and Task 3 persisted policy snapshots.
**Produces:** Final merged request admission across all supported transports and documentation of conservative unknown handling.

- [x] Write failing tests with real local/fake physical transports recording calls: direct and semantic excluded requests send zero calls; known nonmatch sends exactly one; header/query/body/method changes hold; redirects into excluded destinations do not send; browser support cannot bypass; proxy runpy has no package dependencies; WS/gRPC missing required context holds; concurrent groups reject before any reservation/send.
- [x] Implement full-context checks before budget/reservation and actual send. Preserve identity header, auth, method and shared governor behavior. Inspect actual WS/gRPC wire versus policy_url, and all direct transport fallback paths.
- [x] Run covering tests, broader Recon/Attack/Validation suites and UI build; document the difference between AI semantic judgment and deterministic enforcement, supported predicates, immutable cache/provenance and fresh-seed limitations.
- [x] Report exact changed files and results; root performs final integrated verification/review. No commit or real scan.
