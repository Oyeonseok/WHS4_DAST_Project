# Stateful UI Exploration After Katana

Status: design for user review, 2026-09-30.

## Goal and observed limit

Recon should collect endpoints by exploring an authenticated application's normal UI across screens and multi-step workflows. The browser should continue while useful, in-scope work remains, then send every stored observation through the existing AI annotation stage before later pipeline stages use it.

The current initial AI pass and post-Katana follow-up each allow four model decisions. The follow-up visits at most three Katana pages, and `FunctionalUIAgent` forgets attempted controls between calls. It chooses clicks and navigation but does not fill form fields. In the recent local Juice Shop run under the Neon policy, both AI passes stopped at their step limits. These limits explain the shallow traversal; raising them alone does not add memory or form workflows.

## Approach

| Option | Benefit | Limitation |
| --- | --- | --- |
| Increase the current limits | Small code change | Repeated controls, fragmented state and unfilled forms remain. |
| One post-Katana explorer with a persistent frontier | Tracks screens and workflows, spends one budget on useful actions | Needs bounded screen identity, backtracking and guarded form actions. |
| Unrestricted browser agent | Broad freedom | Cannot rely on the existing Scope boundary or reproduce decisions. |

Use the persistent frontier. Keep PlaywrightDriver as the sole browser executor and the existing egress policy and request governor as the authority for every actual request. The model selects from host-generated action candidates; it cannot supply arbitrary URLs, scripts, selectors or HTTP requests.

## Where Scope is enforced

The approved Scope is interpreted into a `TargetPolicy` for each execution target; Recon passes its `mitm_rules()` snapshot to mitmproxy. There is no AI call or reread of Scope.md for each request. Before a browser action, the explorer filters candidates using that policy so it avoids predictable blocks. PlaywrightDriver also checks each browser request at its route boundary. For proxied traffic, the mitmproxy addon is the final egress gate: it checks the physical request's destination, path, method, exclusions, browser workflow evidence and shared request allowance before forwarding it. Katana and ffuf use this same proxy. For a direct browser transport, which does not pass through the addon, PlaywrightDriver performs request admission and reserves the shared governor allowance itself. Each forwarded request consumes the allowance at its active egress gate, not once per check.

Thus the explorer does not add another independent Scope interpretation. Its candidate check prevents waste and unsafe UI choices; the existing transport gate decides whether the actual HTTP request can leave. A click can cause several requests, and a redirect can target a different URL, so checking only the chosen button would be insufficient.

## Recon sequence

1. Restore or establish the approved authenticated browser session. Record bootstrap requests and responses. Defer the current initial AI pass and the initial generic interaction pass so neither spends exploration or page allowance before Katana.
2. Run standard and permitted headless Katana modes and merge their observations.
3. Start one AI explorer with the current in-scope page and Katana-observed, successful HTML GET pages as seeds. Include later same-origin HTML pages and navigation controls discovered through the browser.
4. Persist browser observations during exploration, after each settled action or small bounded group, with the existing source, context, request and response provenance. Feed those observations to the remaining browser, adaptive JS, API and ffuf discovery stages through the existing endpoint pipeline. Run ffuf after AI exploration.
5. Once Recon finishes, run the existing `tag_pending_observations` stage on all untagged observations. The dashboard's combined `aidast run` path already enables this stage. Keep the explicit `--tag-after` behavior for standalone `aidast recon`; document when standalone runs need it. Complete the pending tag pass before Attack and downstream review consume annotations.

The existing generic Playwright interaction pass may still cover controls the AI does not choose. Schedule one generic pass after the AI explorer and share its page/action tracking so it does not consume the explorer's page allowance first. Preserve the existing observation merge and later discovery stages.

## Explorer state and action contract

An `ExplorerState` owns one deadline, remaining decision count, a frontier, visited screen keys, attempted action keys and progress counters for the entire post-Katana pass. A screen key combines a canonical in-scope URL with a bounded fingerprint of visible control and field identities. This distinguishes tabs, panels and SPA states on one URL without sending raw DOM or values to the model. An action key uses the screen key, stable candidate identity and action type; changing DOM indices alone must not make an old action new.

Each iteration inventories the current rendered screen and offers only host-created candidates: navigate to an observed in-scope GET page, click an eligible control, fill/select an eligible field, or submit an eligible form. The planner sees sanitized labels, field types, a short screen summary, remaining budget and aggregate progress. It returns a candidate ID and bounded task goal. Before execution, the host checks that the candidate still exists on the current screen. PlaywrightDriver then performs exactly that action through its existing guarded transport.

The frontier favors unvisited screens and unattempted workflows. The live browser can continue through newly opened panels and routes. To try an alternative branch, the executor can revisit an observed GET page or use browser history when safe. It must not replay a state-changing action merely to reconstruct a screen. An inaccessible branch is recorded as skipped with a reason. The explorer retains its state across page visits; individual page visits do not create a fresh four-step allowance.

## Form workflows

The browser may fill ordinary search, filter and synthetic test-data fields. It may submit forms, including a project-creation flow, only when the approved Scope permits the resulting method and the existing `form_submission` and account-workflow checks permit the action. Use bounded synthetic values derived from the scan identifier and field metadata; do not copy credentials, personal data or raw page text into generated values. Skip password changes, invitations, payments, destructive controls, uploads and ambiguous submissions. Do not submit the same state-changing action twice in one scan.

Candidate approval is preliminary. Every browser request, including background requests, redirects and form submissions, remains subject to the current origin/path/method/exclusion rules and shared request budget. A read-only Scope can still inventory forms but cannot send a disallowed POST. The authenticated session and guarded transport requirements remain in force. Authentication pages and expired sessions stop the affected exploration path.

## Budgets, stopping and diagnostics

The default post-Katana budget is 10 minutes and 50 AI decisions per target, with the existing policy's request budget and the driver's page allowance as additional ceilings. The explorer may stop earlier when its frontier is exhausted. One failed candidate removes that candidate and continues to other eligible work; a model error, lost authentication, exhausted request allowance or policy boundary has an explicit stop reason. A user pause suspends the scan process and therefore the explorer; cancellation stops it with the scan.

Record unique screens, pages visited, decisions, attempted and completed actions, eligible and blocked forms, new observed endpoint keys, remaining frontier size and stop reason. Dashboard activity must distinguish `frontier_exhausted`, `decision_limit`, `time_limit`, `request_limit`, `authentication_lost`, `policy_boundary` and execution errors. Reaching a budget is reported as limited coverage, never as complete exploration.

## AI tagging order

Tagging remains sequential at the end of Recon. `ObservationRecorder` already commits each observation before tagging, and the current SQLite schema uses `journal_mode=DELETE` with a sequential execution assumption. Concurrent model calls and a second writer would require a separate connection, retry and worker lifecycle design. That change is outside this exploration plan, as allowed by the user's fallback instruction.

The explorer's observations use the existing recorder and sanitized tagging payload. `tag_pending_observations` selects all observations without annotations, so both old Recon observations and newly explored UI observations enter the same taxonomy and audit trail. A tagging failure preserves observations and follows the existing pipeline failure behavior; it does not silently count an observation as tagged. No tagging result is required to steer the explorer in this design.

## Validation and acceptance

- In a local multi-screen SPA, the explorer crosses more than three screens, opens a transient panel, performs a multi-step search or creation workflow, and records new requests with response evidence. It stops when the frontier is exhausted or a named budget is reached.
- A repeated URL with a different visible state is explored once per meaningful screen; reordered DOM indices and revisits do not repeat an already attempted action. Failed candidates do not prevent unrelated eligible actions.
- A read-only Scope prevents POST delivery to the local server. An explicitly permitted synthetic creation occurs once, and its endpoint observation retains the originating UI context. Authentication, out-of-scope navigation and blocked controls do not expand permissions.
- At the end of a combined scan, the existing tag worker processes the explorer's observations as well as those from other Recon tools, including non-2xx responses when recorded. Progress and failed batch counts reflect the actual untagged backlog. Later stages begin only after the existing tag gate completes.
- Tests use local fixtures and fake planners for deterministic decisions. A local browser integration test verifies real request/response observation. No external target is needed for design validation.

## Implementation boundaries

The likely change points are `src/aidast/ui_testing/agent.py` or a focused explorer module for state and planning; `src/aidast/recon/tools/playwright_driver.py` for form candidate inventory and guarded execution; `src/aidast/recon/tools/endpoint_discovery.py` for stage ordering, seeds and observation drains; and existing activity rendering for progress. Reuse `src/aidast/recon/annotations.py`, `src/aidast/recon/policy.py`, the shared governor and the current `aidast run` final tagging stage. Do not introduce a second policy source, a new direct network client, or a concurrent tagging worker in this plan.
