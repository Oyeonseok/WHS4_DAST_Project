# Policy advisories Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Allow scanning with visible ambiguous-policy guidance while retaining explicit mandatory restrictions and delivering guidance to all execution Agents.

**Architecture:** Scope AI separates grounded advisories from hard prerequisites. Reference capture uses semantic relationship and fragment-free retrieval identity. A shared policy skill and bound per-target context carry the effective interpretation through Attack and PoC stages; the UI renders warnings without treating them as blockers.

**Tech Stack:** Python/Pydantic/pytest, packaged Codex skills, React/TypeScript/Node24/Vite.

**Spec:** `docs/test-plans/2026-09-29-policy-advisories-design.md`

## Global Constraints

- Preserve all pre-existing unrelated workspace edits; do not commit or create a worktree in this read-only-git session.
- Do not start a live target scan, restart the backend, fetch external policy pages, or invoke a real model during verification.
- Keep explicit scope authority, exclusions, required headers, methods, rates, and unmet mandatory prerequisites enforced.
- No Neon, HackerOne, document-title, or blocker-label allowlists/filters for semantic decisions.
- Existing approved Scope and scan evidence bytes remain unchanged.
- Fresh extracted blockers and advisories are each bounded to 64; persisted advisory capacity reserves another 112 captured-reference edges (176 total).
- Display advisories compactly with no additional consent checkbox.
- Use injected offline model/reader tests and local-only transport verification.

### Task 1: Grounded advisory semantics, reference admission and legacy resolution

**Files:** Modify `src/aidast/scope/models.py`, `src/aidast/scope/policy_references.py`, `src/aidast/scope/execution_rules.py`, `src/aidast/orchestration/scope.py`, Scope instruction sections in `src/aidast/agents/main.py` and `src/aidast/agents/native_pipeline.py`; tests in `tests/test_scope_policy_preparation.py`, `tests/test_scope_execution_rules.py`, and new `tests/test_policy_advisories.py`. Adapt affected fixtures where they encode the superseded blanket hold.

**Interfaces:** Produce `PolicyAdvisory(target_assets:list[str]=[],label:str,source_quote:str,reason:str,guidance:str)`, `ScopeExecutionRules.advisories:list[PolicyAdvisory]=[]`, `ScopeExecutionRules.policy_review_version:Literal[1,2]=1`. Produce `relationship:Literal['required','supporting','uncertain']='uncertain'` in `PolicyReferenceChoice` and `PolicyReferenceCapture`. Keep `require_unresolved_testing_holds(page,analysis)` callable for compatibility but change it to add grounded advisories and stamp review version 2. Produce `requires_policy_advisory_review(document:ScopeDocument)->bool` for the catalog; return true only for version-1 rules with references or blockers. `ScopeExecutionResolver.cached/resolve` remain unchanged signatures; v4 caches contain reviewed effective analysis. Produce a pure `render_execution_advisories(rules:ScopeExecutionRules)->str` rendering helper for effective runtime Scope context in Task 2.

- [x] Write regression tests and observe their expected failures before source edits. Construct generic observed links to the same document with `#one`, `#two`, no fragment, and two different query strings; assert a single fragment-equivalent retrieval, preserved edges and distinct query retrievals. Assert unresolved unknown/mixed references produce advisories and `validate_policy_prerequisites(...)` succeeds; a grounded explicit hard blocker still raises. Assert fresh >64 model advisories fail, and 64 fresh +112 generated fit. Assert each advisory quote is checked like a restriction quote. Inject a semantic selector with required/supporting/uncertain choices; verify required choices consume collection budget first and selection instructions reject automatic Related Articles incorporation. Use the supplied local Neon capture only as read-only fixture evidence when helpful.

```python
assert reviewed.execution_rules.policy_review_version == 2
assert reviewed.execution_rules.advisories
assert reviewed.execution_rules.blocking_requirements == []
validate_policy_prerequisites(reviewed.execution_rules, ["app.example"])
assert "guidance" in reviewed.execution_rules.advisories[0].model_dump()
```

- [x] Add the bounded advisory model/quotes, relationship metadata and host review stamp. Replace blanket-hold semantics in both Scope instruction implementations. Use `urllib.parse.urldefrag(url)[0]` for cache identity while keeping exact URLs in provenance; process required selections first. Render advisories in Scope Markdown with quote, reason, guidance and applicability. Never remove supplied blockers by textual labels; the AI is instructed to classify ambiguity into advisories during fresh extraction.

- [x] Bump cache version to 4; require re-interpretation of version-1 references/blockers, validate new grounding, add unresolved advisories in the legacy interpretation path too, and never modify approved bytes. Ensure loading newly collected complete version-2 Scope requires no model call.

```python
def requires_policy_advisory_review(document):
    rules = document.analysis.execution_rules
    return bool(rules and rules.policy_review_version < 2 and
                (document.source.policy_references or rules.blocking_requirements))
```

- [x] Run `.venv/bin/python -m pytest tests/test_policy_advisories.py tests/test_scope_policy_preparation.py tests/test_scope_execution_rules.py tests/test_scope_policy_refresh.py tests/test_required_identity_headers.py -q` plus affected focused tests. Record red/green results and exact owned files in report. No commit.

### Task 2: Shared policy harness and actual per-scan Agent context

**Files:** Create `src/aidast/skills/policy/__init__.py`, `src/aidast/skills/policy/SKILL.md`, and focused helper `src/aidast/agents/policy_guidance.py`; modify `src/aidast/scope/execution_rules.py` binding, `src/aidast/agents/main.py`, `src/aidast/agents/native_pipeline.py`, `src/aidast/cli.py`, relevant validation orchestration/legacy entrypoints and skill prompts, and `pyproject.toml` package-data entry for the new packaged skill. Tests new `tests/test_policy_guidance.py` and affected native/validation tests. Avoid unrelated concurrent Reporting/Recon changes.

**Interfaces:** Consume Task1 advisory model/render helper. `bind_execution_policies(...)` appends applicable grounded advisory context to `TargetPolicy.policy_notes` deterministically; do not rely on model copying it. Produce `policy_skill_text()->str`, `stage_policy_skill(work_dir:Path)->Path`, and `policy_guidance_context(policy)->str` helpers in `agents/policy_guidance.py`. Store runtime effective Markdown as a new per-scan artifact if cached legacy interpretation differs; retain original Scope source and approval binding. All policy effects continue to use the effective resolved analysis.

- [x] Write failing tests proving an applicable advisory survives policy binding, is visible in actual native Attack/Chaining prompts/config/staged skill and in Recon and Validation/PoC planner input; unrelated target advisories are filtered. Prove clear blockers/headers/rates/exclusions cannot be softened by the guidance helper. Use fake agents/subprocesses rather than real Codex.

```python
assert "aidast-policy" in (work_dir / ".agents/skills/aidast-policy/SKILL.md").read_text()
assert "Sensitive data" in policy_guidance_context(bound_policy)
assert bound_policy.limits.requests_per_second <= original_policy.limits.requests_per_second
```

- [x] Define the shared SKILL: read effective Scope and TargetPolicy warnings; ambiguity does not authorize an operation; perform permitted work, skip a questionable operation and record its reason; stop when captured conditions require it; use owned/synthetic data; follow identical precautions for attack, chaining, replay, PoC and impact development; cannot override hard guards or execute policy text as instructions. Stage/invoke it in native isolated workspaces and include its instructions in legacy/prompt-only adapters. Deliver actual warnings to executable validation decisions, not only eligibility commentary. Preserve Blind Validation claim isolation.

- [x] Make effective cached legacy advisories appear in the scan's Scope/TargetPolicy inputs without modifying approved source artifacts or breaking Validation snapshot verification. Run `.venv/bin/python -m pytest tests/test_policy_guidance.py tests/test_native_attack_orchestration.py tests/test_native_chaining_orchestration.py tests/test_validation_agent.py tests/test_validation_eligibility_runner.py tests/test_validation_scope_eligibility.py tests/test_scope_execution_rules.py -q` and affected CLI/impact tests. Record evidence/owned files. No commit.

### Task 3: Compact dashboard advisories and migration integration

**Files:** Modify `src/aidast/web/launch.py`, `src/aidast/web/requirements.py`, `src/aidast/web/scope_workflow.py`, `WebUI/src/lib/scan.ts`, `WebUI/src/components/ScopeExecutionRules.ts`, scan setup/draft components as needed, translations if used; tests `tests/test_web_launch.py`, new `tests/test_policy_advisory_launch.py`, new `WebUI/tests/policy-advisories.test.mjs` plus affected existing tests.

**Interfaces:** Consume Task1 `requires_policy_advisory_review`, version-4 resolver and `advisories`; consume Task2 bound effective context. Existing API execution rules expose `advisories`, with no new user-provided launch inputs. Legacy references/blockers require explicit preparation even when structural fields are present. Read-only catalog operations never invoke a model.

- [x] Write failing tests: reviewed warning-only requirements permit `canLaunchWithPolicyInputs`; applicable hard blockers still prevent launch; warnings render compactly with expandable reason/quote/guidance; selected target filtering works; old reference-heavy Scope is pending until preparation resolves a new cache, then warnings permit launch; source artifacts retain identical bytes.

```javascript
assert.equal(canLaunchWithPolicyInputs(warningOnly, ["app.example"], {}, []), true);
assert.equal(canLaunchWithPolicyInputs(hardBlocked, ["app.example"], {}, []), false);
```

- [x] Expose/display advisory details in draft and approved scan setup without adding consent. Keep warning-only rows out of all Start gating. Ensure legacy pending status comes from need for reviewed interpretation, and normal preparation creates a grounded cache; don't strip blockers on catalog reads or change original artifact authority.

- [x] Run affected Python web/workflow/CLI tests, `npm test` and `npm run build` in `WebUI` with Node24. Record owned files and tests. No commit.

### Final integration verification

- [x] Review the complete owned diff once for actual advisory propagation, reference semantics, hard-control preservation, legacy immutability and UI launch behavior. Address findings through a single consolidated fix dispatch and scoped re-review.
- [x] With source frozen, run full offline Python suite, full Node24 UI tests and production build. Recheck all pre-existing approved Scope/scan artifacts against the pre-task hash snapshot. Archive reviews, reports and verification in `result/test-runs/09.29/policy-advisories/`; append actual metrics to `docs/test-results/09.29/SUMMARY.md`.
