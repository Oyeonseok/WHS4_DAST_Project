# Endpoint-based Attack coverage

Normal CLI and dashboard scans review every included Recon endpoint before Attack.
The AI planner uses ordinary page/function/data-role annotations, parameter schemas,
observed URLs/statuses, header names and origin technology context. It selects among
installed vulnerability Hunt Skills and proposes hypotheses for a specific endpoint,
input location/name and authentication baseline. Tags are evidence of functionality,
not vulnerability findings. Missing evidence and inapplicable endpoints receive an
explicit disposition rather than a negative test result.

The planner streams evidence through batches of up to 16 endpoints. Each endpoint's
bounded evidence window reports its original counts and whether evidence was truncated.
The backend rejects invented endpoints, foreign annotations, unobserved input fields
and unavailable Skills. Invalid proposals receive the captured evidence and structured
validation feedback for at most two correction rounds. Independently valid hypotheses
are retained across responses and saved before another model call; incomplete endpoint
reviews remain resumable after provider failures. Corrective retries cannot turn an
unobserved parameter into an endpoint-wide test just to satisfy validation. Remaining
invalid proposals are recorded as unexecuted with their input location/name and reason,
while valid hypotheses proceed. The dashboard reports correction progress and unresolved
proposals separately from actual tests. Historical diagnostics stay in the Pipeline;
a new complete endpoint review supersedes previous unresolved diagnostics.

Planning-only `attack_hypothesis` annotations and endpoint
reviews are stored in the writable Pipeline copy; the original Recon DB stays immutable.
Existing source/benchmark coverage is retained.

Execution drains the durable coverage queue in batches of eight. Eight limits one
batch, not the scan's vulnerability types or URLs. All existing Scope, required-header,
authentication, exclusion, request-rate and request-budget controls still apply.
A normal run has at most 1,000 execution batches (with up to three retries per item);
if work remains at that limit, the run fails explicitly and retains the pending queue.

The dashboard shows the current batch, total hypotheses, actual tests, unfinished
work, authentication/policy/budget blockers and evidence gaps. Skipped work counts as
a resolved disposition, not an actual test. Exact task URLs come from captured evidence;
credentials and query values are omitted. Gap previews show the first 200 entries and
state when more entries exist; complete records remain in Pipeline.db.

Negative results require completed same-task HTTP evidence. Planning hypotheses also
require the exact endpoint/method and actual credential baseline. Findings require
compatible reproduction inputs and source attempt/request bindings, including when
adopting prior findings after a retry. Independent Validation remains authoritative.
A completed execution batch is resumable while coverage or endpoint reviews remain
unfinished, so interruption between batches cannot advance directly to Chaining.

The behavior applies to newly started scans and unfinished Attack retries. Completed
historic scans are not automatically attacked again.
