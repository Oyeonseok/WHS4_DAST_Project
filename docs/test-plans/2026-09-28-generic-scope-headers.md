# AI-interpreted Scope request headers

> Implementation uses subagent-driven-development. This document includes the approved design and the executable plan. Do not commit or overwrite unrelated pending changes.

**Goal:** Apply the required researcher identification headers described by any approved program, without a header-name allowlist or regex policy interpreter.

**Design:** The user requested natural-language policy interpretation by AI. Scope AI returns generic header requirements containing a valid HTTP header name, value template, explicitly declared user input slots and exact source quote. Python validates the structured result and fills input values; it does not decide requirements from text. Requirements are approved with the Scope. Existing approved Scopes lacking this new structure get a separate AI interpretation from the unchanged approved captured text, cached by the approved Scope digest. No target requests or scope recollection are needed for this conversion.

**Contracts:**

```json
{
  "required_request_headers": [{
    "name": "X-Research-Identity",
    "value_template": "bounty-{researcher_username}",
    "inputs": [{"key": "researcher_username", "label": "Researcher username", "kind": "username"}],
    "source_quote": "Send X-Research-Identity: bounty-<your username> in every request."
  }]
}
```

`ScopeAnalysis.required_request_headers` is nullable for old persisted Scopes; `[]` means AI determined there are no required headers. Header input kinds: `text`, `username`, `email`. Templates permit only declared simple `{key}` fields, with no attributes, indexes or format expressions. Header names use HTTP token syntax. Identification requirements cannot overwrite routing/hop-by-hop/framing or credential headers such as Host, Cookie and Authorization, or internal AI-DAST capabilities. Values are bounded and cannot contain control characters. Preserve existing approved Scope files and the previous Pipeline.db User-Agent change.

Execution requirements API extends its existing fields:

```json
{
  "header_requirements_status": "ready",
  "required_headers": [],
  "header_inputs": [],
  "required_header": null,
  "scope_max_requests_per_second": 1.0,
  "operational_constraints": [],
  "profiles": []
}
```

`required_headers` contains the structured header specifications. `header_inputs` deduplicates their input declarations. `required_header` is a compatibility field; the new UI uses the lists. Old Scopes are `pending` until interpreted or cached. Listing scopes must not invoke models. `POST /api/v1/scopes/{scope_id}/header-requirements` resolves an old selected Scope and returns `{"scope": <ApprovedScope.public()>}`. Model failure must keep the Scope visible and block launch with a useful error; it must not imply no requirements.

Launch accepts `identity_values: {input_key: value}`. CLI supports repeatable `--header-input KEY=VALUE`. Existing `--hackerone-username` and `--intigriti-username` are aliases for those slot keys. The generated TargetPolicy stores the resolved `required_identity_headers` map. Recon, Attack, HTTP/browser Validation and proxy-mediated Recon apply those exact names and values after untrusted runtime/credential headers. Do not widen host, method or rate permissions. Preserve the behavior of old policies with no generic map.

## Task 1: Backend and AI contract

Files: `scope/models.py`, `scope/identity_headers.py`, `agents/main.py`, `agents/native_pipeline.py`, Scope skill, `orchestration/scope.py`, `web/requirements.py`, `web/launch.py`, `web/server.py`, `cli.py`, `core/http_safety.py`, request transports, supporting tests.

- [x] Replace the temporary name-specific tests with tests exercising structured AI output, not textual regex matching. Example assertion:

```python
headers = resolve_scope_identity_headers(
    analysis_with_custom_header,
    identity_values={"researcher_username": "alice"},
)
assert headers == {"X-Research-Identity": "bounty-alice"}
```

- [x] Watch failures for arbitrary names, multiple inputs, fixed values, missing inputs, exact evidence, unresolved old Scope, cache reuse and policy override.
- [x] Implement the contracts above. Put legacy AI interpretation in a bounded, injectable resolver; cache only validated results tied to the approved digest. No regex or supported-name iteration may determine policy requirements.
- [x] Run offline backend regression suites. Use injected model responses for deterministic contract tests; do not contact a target or model from tests.
- [x] Record changed files, tests and any remaining limitations. No commit.
- [x] Review the task against this spec and resolve blocking findings.

## Task 2: Dashboard dynamic inputs

Files: `WebUI/src/lib/scan.ts`, `WebUI/src/App.tsx`, new UI logic tests.

- [x] Add tests for two unfamiliar header names, a shared slot, literal values needing no input, missing required values, and pending requirements. Example:

```js
assert.equal(canLaunchWithHeaderInputs({header_requirements_status:'pending',header_inputs:[]}, {}), false);
```

- [x] Extend types using the contracts above. Render the names and value templates from the requirement list, and inputs from `header_inputs` using their labels/kinds. No known-header branching.
- [x] When the selected Scope is pending, call the resolution endpoint once, show a loading/error state, and update the selected Scope from the returned public object. Do not allow launch until ready.
- [x] Send `identity_values` in the launch request. Keep input validation and clearing on Scope changes. Existing typed platform flags may remain compatible but must not drive generic UI behavior.
- [x] Run UI tests and build with installed Node 24. No commit.
- [x] Review the task against this spec and resolve blocking findings.

## Task 3: Integration verification

- [x] Run combined backend suites, UI tests and build after integration.
- [x] Review the complete task changes against generic naming, grounding, missing-input behavior, policy enforcement and source preservation.
- [x] Interpret the existing approved Neon Scope through the real AI adapter into the separate cache; inspect only non-secret requirement metadata. Confirm original approved files remain byte-identical.
- [x] Perform at most one benign authenticated GET to the approved staging `/app/`, using a cloned diagnostic DB and separately compiled policy. Do not explicitly put identification headers or User-Agent into the payload: both must come from the normal pipeline code. Verify the request fingerprint and 200/no1010 response; preserve original scan DB.
- [x] Add findings and verification evidence to `docs/test-results/09.28/SUMMARY.md`, keeping its existing consolidated layout.

No broad scan, exploit payload, production deployment, Scope rewrite, commit or external message is authorized by this plan.
