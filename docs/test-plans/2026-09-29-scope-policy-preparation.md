# Scope-time referenced-policy preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement the integrated task. Steps use checkbox syntax.

**Goal:** Prepare referenced policy evidence and executable rules at Scope creation so scans apply saved requirements immediately.

**Architecture:** Observe actual program links, select references with offline collection-time AI, fetch through a separate bounded public reader, and interpret combined evidence before draft save. Preserve primary-only asset authority and testing/reporting/disclosure distinctions; complete approved scopes need no launch-time AI.

**Tech Stack:** Python, Pydantic, stdlib HTTPS/HTML parsing, existing Playwright/model adapters, pytest.

**Spec:** docs/test-plans/2026-09-29-scope-policy-preparation-design.md (approved chat design plus clarified preparation timing).

## Global Constraints

- Preserve all preexisting dirty work and use snapshots in the current feature checkout. No commits, git resets, merges, backend restarts, actual target/model calls or scans during implementation/testing.
- Keep ProgramPage.text and its original content_sha256 intact; Scope/manifest hashes include reference evidence. Never mutate historical approved Scope/Approval/Manifest/policy/DB files.
- Real observed candidate IDs and contiguous source quotes bind AI selections; no service-specific names, prose regex policy decisions, invented URLs/values or asset authorization from external text.
- Public isolated HTTPS GET reference transport only; no authenticated session/credentials/proxy; validate every redirect and pin validated public addresses with original TLS hostname verification.
- Bound observations to 128 links per page, selection to 8 documents total, recursion to depth 2, redirects to 3, each raw response to 1 MiB, total combined evidence to 120000 characters, per-request timeout to 15 seconds.
- Fresh Scope must include explicit required_request_headers and execution_rules.exclusions before draft approval. Offline saved interpretation is consumed at scan launch; request-specific semantic resource binding retains existing guards.
- Testing controls stay execution requirements; reporting/public disclosure duties stay submission requirements. Missing/ambiguous potentially applicable testing controls remain held. Never clear blockers by their label.
- Keep existing aggregate authorization UI; no additional consent lists. Worker must not spawn agents; root provides reviews.

## Task 1: Integrated collection-time preparation

**Files:**
- Create: src/aidast/scope/policy_references.py (bounded schema/selection orchestration and isolated transport; split transport into a small sibling if needed).
- Modify: src/aidast/scope/models.py (observed links/reference evidence, combined accessor, collection-result defaults).
- Modify: src/aidast/scope/reader.py (actual link observations per primary view, both readers).
- Modify: src/aidast/agents/main.py and src/aidast/agents/native_pipeline.py (offline reference selector, structured native observations, combined capture interpretation/grounding, phase semantics).
- Modify: src/aidast/orchestration/scope.py (enrich before final analysis, completeness, reference provenance Markdown).
- Modify: src/aidast/scope/execution_rules.py (shared evidence quote validation for legacy compatible resolver).
- Modify: src/aidast/skills/scope/SKILL.md (collection vs interpretation boundaries and phases).
- Modify only if necessary: src/aidast/cli.py, src/aidast/web/scope_workflow.py (wire production dependencies, progress messages).
- Create: tests/test_scope_policy_preparation.py; add actual regressions in existing relevant scope/AI/web tests.
- Documentation: docs/OPERATIONS.md, preserve unrelated hunks; root owns result SUMMARY.

**Interfaces:**
- Consumes existing ProgramPage, ScopeCollector, ScopeCoordinator.collect_draft/collect, ScopeExecutionResolver.cached/resolve, native/public/runtime-browser collection modes.
- Produces legacy-compatible bounded observed links and reference records on ProgramPage, a shared combined evidence accessor, an offline select_policy_references contract consuming only supplied candidates, and an injectable collection-time enrichment helper. The implementer freezes exact signatures in its report before dependent tests/review; no per-request AI API or new launch-time fetch.

- [x] Write meaningful failing tests using actual temporary draft/approval files plus injected selector/reader and fake pinned HTTPS transport. Example behavior: observed candidate id 7 points to an arbitrary guide; selection quote is present; reference body says `Requests must stay at or below 3 per second.`; final analyst sees primary and reference text; saved request_limits has maximum3, period_seconds1; original assets remain primary only; approved complete resolver uses no interpreter or network.
- [x] Run those tests against pre-implementation source and retain actual behavioral RED output (import failures alone insufficient); never restore baseline files over the live workspace.
- [x] Implement the spec end-to-end with one cohesive common enrichment path, explicit provenance/failure records, bounded offline selection and secure public transport. Keep source-authority checks separate from combined restriction grounding. No program-specific workaround.
- [x] Add negative regressions for nonexistent/duplicate IDs, noncontiguous quotes, external-only assets, failed mandatory testing refs, disclosure-only duties, legacy defaults, unknown/over-budget recursive refs, headers/cookies/auth/proxy leaks, DNS/IP/private redirect, response bounds and strict fresh completeness.
- [x] Run focused covering scope/model/reader/CLI/web tests with offline Codex sentinel; if local sockets need access, use precise local-only escalation. Update older fake fresh-analysis fixtures truthfully with explicit empty headers/exclusions; do not weaken new requirements. Self-review and write task-1-report.md plus task-1-owned-files.json, exact red/green commands/counts, public signatures and limitations. No full suite (root handles), no commits.
- [x] Root task-scoped spec/quality review, fixes if needed, final broad feature review, independent integrated tests and historical artifact hashes; append results and limits to test-results SUMMARY without overwriting existing sections.

## Task 2: Safe recollection and dashboard evidence review

**Files:**
- Modify: src/aidast/web/scope_workflow.py (explicit refresh request, app-owned output revision path on jobs, worker/approval/review lookup consistency, full execution/reference review payload).
- Modify: src/aidast/web/launch.py (catalog discover verified revisions as well as original scopes under the same program identity).
- Modify: WebUI/src/App.tsx (Collect again actually requests refresh, compact reference evidence status and existing execution rule review, correct newly approved scope selection).
- Create: tests/test_scope_policy_refresh.py; add focused WebUI regression tests following existing harness.
- Documentation: docs/OPERATIONS.md (recollect/review/new scan without deleting old artifacts).

**Interfaces:**
- Consumes Task1 persisted reference evidence and complete Scope execution fields; uses existing ScopeDecisionRequest and immutable ScopeCoordinator approval.
- Produces ScopeCollectionRequest.refresh:bool=False, additive nullable application-owned output_path job column (legacy jobs retain canonical path), fresh revisions under canonical_program_dir/revisions/<scopejob_id>, and catalog discovery of those verified revision directories. No user-selected filesystem path.

- [x] Write behavioral RED for an existing approved Scope: refresh collection must make a new reviewed draft; decision yes publishes a distinct new scope, old Scope/Approval/Manifest file bytes remain identical, catalog returns both with original program identity, approved_scope returns the new approved revision, complete revised rules launch without interpretation. Initial default start remains idempotent; pending/rejected/failed recollection does not destroy the original.
- [x] Add fake isolated-worker coverage: start persists the same app-owned output path that run_worker and decide use; no recomputation based on changing filesystem state. Legacy DB rows migrate safely. Validate expected revision paths and symlinks; concurrent/active jobs cannot be bypassed by refresh.
- [x] Implement the smallest explicit refresh flow. If a verified canonical Scope exists and refresh is true, output is a new revision path; if no canonical Scope exists, keep normal canonical creation. Approval remains explicit through the existing Scope review. Catalog uses bounded root-relative pattern discovery and verifies each approval/hash; revisions keep original platform/program identity. Do not overwrite any original approved artifacts.
- [x] Add existing approved-program Collect again action/request handling and select/view the new approved scope after approval. Review payload includes execution_rules and compact reference URL/status/applicability/failure info; show those in existing detailed Scope review, with no extra consent checklist.
- [x] Run focused refresh/workflow/catalog/web tests and UI tests/build. Record authoritative behavioral RED/GREEN, exact owned files/public changes and limits in task-2-report.md + task-2-owned-files.json. No full suite (root handles); no actual collection/model/backend restart or production DB changes.
- [x] Root task-scoped spec/quality gate and final whole-feature review/integration verification.
