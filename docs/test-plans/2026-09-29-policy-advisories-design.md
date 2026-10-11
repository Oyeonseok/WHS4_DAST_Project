# Policy advisories and shared Agent guidance

The user approved correcting over-selected policy references and explicitly requested that ambiguous policy language be visible guidance rather than a reason to prevent the entire scan. This supersedes the earlier blanket hold for unresolved testing references.

## Behavior

Scope-time AI distinguishes explicit mandatory execution prerequisites from policy uncertainty. Only an evidenced mandatory prerequisite that cannot be satisfied by supported controls belongs in `blocking_requirements`. Unclear applicability, missing reference capture, legal/reporting interpretation and incomplete contextual guidance belong in `execution_rules.advisories`. An advisory contains `target_assets`, `label`, `source_quote`, `reason`, and `guidance`; all quotes are grounded in captured evidence. Applicable advisories do not enter launch prerequisite validation. Clear asset, exclusion, method, header and rate restrictions continue to be enforced.

Agents receive the advisories through immutable Scope Markdown and application-bound TargetPolicy context. A shared packaged `aidast-policy` SKILL defines how to proceed within explicit authorization, avoid a questionable individual operation, stop on captured explicit conditions such as sensitive PII, and record the reason. This guidance must reach Recon, Attack, Chaining, Validation and PoC reproduction/planning. A shared static skill alone is insufficient: the actual applicable per-scan warnings must reach the relevant Agent inputs.

## Reference collection

AI chooses observed candidates by the parent text's relationship to the linked document, not titles or service-specific keywords. `relationship` is `required`, `supporting`, or `uncertain`, with legacy default `uncertain`, in both selection and capture. General navigation and optional background links are not automatically incorporated requirements. Required links are processed before supporting links from each selection. Preserve exact parent quotes and requested URLs. Retrieval identity ignores only URL fragments; queries remain distinct. Reused captures preserve every edge's attribution and classification. Missing captures yield advisories, never new testing authority. Preserve bounded public HTTPS transport and collection budgets.

## Compatibility

`ScopeExecutionRules.advisories` defaults to an empty list for old artifacts. `policy_review_version` defaults to 1; host-validated fresh extraction/interpretation stamps 2. Bump execution cache format from 3 to 4. Old documents with policy references or blockers and review version 1 require a fresh grounded AI interpretation in the separate digest-bound cache. Do not reclassify old blockers by matching prose, or rewrite approved Scope JSON/Markdown/Approval manifests. Old complete documents with no references or blockers may retain compatible controls. Listing stays read-only; preparation/resolution performs the model call. Effective review results must reach generated execution Scope Markdown and all Agent contexts without changing the approved revision.

## Global Constraints

- Preserve all pre-existing unrelated workspace edits; do not commit or create a worktree in this read-only-git session.
- Do not start a live target scan, restart the backend, fetch external policy pages, or invoke a real model during verification.
- Keep explicit scope authority, exclusions, required headers, methods, rates, and unmet mandatory prerequisites enforced.
- No Neon, HackerOne, document-title, or blocker-label allowlists/filters for semantic decisions.
- Existing approved Scope and scan evidence bytes remain unchanged.
- Fresh extracted blockers and advisories are each bounded to 64; persisted advisory capacity reserves another 112 captured-reference edges (176 total).
- Display advisories compactly with no additional consent checkbox.
- Use injected offline model/reader tests and local-only transport verification.
