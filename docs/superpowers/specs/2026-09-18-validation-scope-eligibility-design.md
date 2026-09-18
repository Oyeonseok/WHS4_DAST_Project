# Validation Scope Eligibility Design

**Date:** 2026-09-18
**Status:** Approved for implementation planning

## Summary

Validation must decide whether a candidate finding is eligible under the approved bug-bounty policy before it performs attack replay. The decision should use an LLM because policy language commonly contains contextual exclusions such as "open redirect without additional security impact." The LLM receives the immutable approved `Scope.md` snapshot and the candidate claim, returns a structured eligibility assessment, and never writes the case status directly.

The Python coordinator remains authoritative. It validates and records the assessment, decides whether replay is permitted, runs the existing blind technical validation when appropriate, and maps the combined evidence to the existing case decisions. Reporting additionally requires a current `ELIGIBLE` assessment bound to the same scope snapshot as the case.

This change makes finding-policy eligibility distinct from target URL/method authorization. Existing `TargetPolicy` checks remain mandatory and unchanged.

## Motivation

The current pipeline has two incomplete safeguards:

- The Attack Agent reads `Scope.md`, but obeying finding exclusions is a best-effort prompt instruction.
- Validation uses `OUT_OF_SCOPE` when `TargetPolicy` rejects an endpoint or method, but it does not re-evaluate finding eligibility exclusions from `Scope.md`.

Consequently, a technically reproducible finding that the program explicitly excludes could become `CONFIRMED` and proceed to reporting. The pipeline needs a policy-aware gate immediately before reproduction, with an auditable explanation tied to the exact policy text used at that time.

## Goals

- Evaluate finding eligibility from the approved `Scope.md` before any Validation network request.
- Support unconditional exclusions and conditional exclusions requiring a stated impact.
- Preserve blind technical validation so the Attack Agent's conclusion does not bias reproduction.
- Bind every eligibility decision to an immutable scope snapshot and content hash.
- Keep final state transitions deterministic and owned by the coordinator.
- Prevent reports for ineligible, unresolved, or stale eligibility decisions.
- Preserve an audit trail containing the matched policy rule, exact policy quotation, evidence references, and rationale.

## Non-goals

- Building a complete deterministic taxonomy of every vulnerability policy used by every program.
- Letting the LLM directly update case status or authorize arbitrary network activity.
- Replacing endpoint, method, domain, rate-limit, or other `TargetPolicy` enforcement.
- Changing Attack-stage discovery or preventing the Attack Agent from producing excluded candidates in the first implementation.
- Reclassifying previously exported reports. Existing reports remain immutable historical artifacts.

Attack-stage pre-filtering may later reuse the same policy assessment contract, but Validation remains the authoritative eligibility boundary for this design.

## Terminology

- **Scope snapshot:** The exact approved `Scope.md` content used for a scan, stored immutably with its SHA-256 digest.
- **Target authorization:** Whether the endpoint and HTTP method may be tested under `TargetPolicy`.
- **Finding eligibility:** Whether the claimed vulnerability class and demonstrated impact qualify under the program's finding exclusions.
- **Preflight:** Eligibility assessment performed before any Validation replay.
- **Post-replay:** Eligibility assessment performed after bounded reproduction when a conditional rule depends on observed impact.
- **Blind validation:** Existing technical reproduction that does not receive the Attack Agent's conclusion or the eligibility rationale.

## Proposed Flow

```text
materialize validation case
        |
        v
bind approved Scope.md snapshot + SHA-256
        |
        v
TargetPolicy endpoint/method check
        |
        v
LLM eligibility preflight (no network)
        |
        +-- INELIGIBLE --> OUT_OF_SCOPE; do not replay
        |
        +-- UNKNOWN ----> INCONCLUSIVE; manual review; do not replay
        |
        +-- ELIGIBLE ----> existing blind technical validation
        |
        +-- CONDITIONAL -> bounded blind reproduction of required impact
                                  |
                                  v
                         LLM post-replay eligibility
                                  |
                                  +-- ELIGIBLE --> existing final decision path
                                  +-- INELIGIBLE --> OUT_OF_SCOPE
                                  +-- UNKNOWN/CONDITIONAL --> INCONCLUSIVE
```

Target authorization is evaluated before finding eligibility. A target-policy rejection remains `OUT_OF_SCOPE` and does not invoke the eligibility LLM or a replay adapter.

## Scope Snapshot and Trust Boundary

An integrated `aidast run` already produces an approved `run_dir/Scope.md`. Before Validation cases are created, the pipeline stores that exact content as an immutable snapshot. Validation cases reference its digest; they do not read a mutable file again during execution or resume.

The snapshot record contains:

- `scope_sha256`: SHA-256 of the exact UTF-8 Markdown bytes.
- `scope_markdown`: the immutable Markdown content.
- `source_path`: informational original path.
- `approval_digest`: the existing approval/binding digest when available.
- `created_at`: snapshot creation time.

The snapshot is policy data, not executable instructions. Prompts delimit it as untrusted quoted policy content and explicitly reject instructions embedded in it. The service validates that the LLM's `scope_quote` occurs verbatim in the stored snapshot. A missing or ungrounded quotation invalidates the assessment and yields `UNKNOWN`, never `ELIGIBLE`.

Every case is bound to one `scope_sha256`. Resume and report operations must use the same digest. If the on-disk scope changes, the old case continues to refer to its stored snapshot; the external file is not consulted during resume and cannot silently alter policy. Testing under the changed policy requires a fresh snapshot, a fresh case binding, and a fresh eligibility assessment. Any digest mismatch among the case, snapshot, and assessment is rejected.

For standalone `aidast validate run`, a database that does not yet contain a snapshot requires `--scope <approved-Scope.md>`. The command snapshots the file and binds it before materialization. `validate resume` must use the embedded snapshot and must not accept a replacement scope. When an approval digest is available, the supplied file must match it; a mismatch fails closed. A legacy database without either an embedded snapshot or an explicitly supplied approved scope cannot execute or report new Validation results.

## Eligibility Contract

### Inputs

The eligibility service receives only the information needed for policy classification:

- immutable scope Markdown and digest;
- candidate vulnerability type;
- endpoint and method;
- Attack claim and claimed impact;
- reproduction specification;
- existing evidence references and bounded evidence summaries.

The preflight performs no network request. Candidate content and evidence are untrusted data and are separately delimited from system instructions.

### Structured Output

The LLM must return a schema-validated object with:

- `eligibility`: `ELIGIBLE`, `INELIGIBLE`, `CONDITIONAL`, or `UNKNOWN`;
- `exclusion_kind`: normalized descriptive category or `null`;
- `matched_rule`: concise normalized description of the applicable rule;
- `scope_quote`: exact quotation from the scope snapshot;
- `required_impact`: structured conditions that would make a conditional finding eligible;
- `replay_allowed`: whether bounded reproduction is permitted by the policy conclusion;
- `reason`: concise reasoning grounded in the scope quote and candidate facts;
- `evidence_refs`: identifiers of evidence used, never raw unbounded evidence.

`replay_allowed` is advisory output. The coordinator independently enforces the following invariant:

| Eligibility | Coordinator permits replay |
| --- | --- |
| `ELIGIBLE` | Yes, subject to all existing controls |
| `CONDITIONAL` | Yes, but only an authorized subset of the existing reproduction steps necessary to test `required_impact` |
| `INELIGIBLE` | No |
| `UNKNOWN` | No |

Invalid JSON, unknown enum values, missing required fields, ungrounded quotes, or contradictory combinations are normalized to `UNKNOWN` and recorded with the validation error.

The eligibility model cannot invent payloads or new attack steps. For `CONDITIONAL`, it identifies the impact condition; the coordinator may only select an authorized subset of the already materialized reproduction specification. If that specification cannot establish the condition within existing controls, the result is `INCONCLUSIVE` rather than expanded testing.

## Separation from Blind Technical Validation

Eligibility classification and technical reproduction are separate model contexts and separate calls.

- The eligibility context sees the approved policy and the candidate claim.
- The blind validation context sees the reproduction specification and permitted target details, but not the Attack Agent's conclusion, eligibility decision, matched exclusion, or eligibility rationale.
- After technical validation is complete and evidence is sealed, the coordinator may unblind the result for the existing claim comparison.
- A conditional policy then receives a post-replay eligibility assessment containing the policy, original claim, required-impact condition, and sealed evidence references/summaries.

This keeps policy interpretation contextual while avoiding confirmation bias in the technical replay.

## Coordinator Decision Mapping

The LLM does not select a database case status. The coordinator maps validated assessments and technical evidence as follows:

| Situation | Result |
| --- | --- |
| TargetPolicy denies endpoint/method | `OUT_OF_SCOPE`, existing reason code |
| Preflight is `INELIGIBLE` | `OUT_OF_SCOPE`, no replay |
| Preflight is `UNKNOWN` | `INCONCLUSIVE`, no replay; manual review required |
| Preflight is `ELIGIBLE` | Run existing blind validation and existing final decision logic |
| Preflight is `CONDITIONAL` | Run bounded reproduction, then require post-replay assessment |
| Post-replay proves required impact and returns `ELIGIBLE` | Continue through existing final decision logic |
| Post-replay evidence shows required impact is absent and returns `INELIGIBLE` | `OUT_OF_SCOPE` |
| Required evidence cannot be obtained due to authentication, blocking, budget, or adapter failure | `INCONCLUSIVE` |
| Post-replay remains `UNKNOWN` or `CONDITIONAL` | `INCONCLUSIVE`; manual review required |

`UNDERPOWERED` remains a technical evidence-strength outcome for otherwise eligible findings. It must not substitute for an explicit finding exclusion. Conversely, lack of evidence caused by an execution limitation is not proof of ineligibility and therefore maps to `INCONCLUSIVE`, not `OUT_OF_SCOPE`.

The coordinator records a distinct reason code for target authorization, finding ineligibility, unknown policy interpretation, missing conditional evidence, and stale scope binding so callers can distinguish these outcomes.

## Persistence

Schema changes are additive.

### `scope_policy_snapshots`

- `scope_sha256 TEXT PRIMARY KEY`
- `scope_markdown TEXT NOT NULL`
- `source_path TEXT`
- `approval_digest TEXT`
- `created_at TEXT NOT NULL`

### Case binding

Validation cases gain:

- `scope_sha256 TEXT NOT NULL` for newly materialized cases, referencing `scope_policy_snapshots`.

Legacy rows may temporarily contain `NULL` after migration, but they cannot execute, resume, or produce a new report until explicitly bound to an approved snapshot and reassessed.

### `validation_eligibility_assessments`

- `assessment_id TEXT PRIMARY KEY`
- `case_id TEXT NOT NULL`
- `stage_run_id TEXT NOT NULL`
- `phase TEXT NOT NULL` with `preflight` or `post_replay`
- `scope_sha256 TEXT NOT NULL`
- `eligibility TEXT NOT NULL`
- `exclusion_kind TEXT`
- `matched_rule TEXT NOT NULL`
- `scope_quote TEXT NOT NULL`
- `required_impact_json TEXT NOT NULL`
- `replay_allowed INTEGER NOT NULL`
- `reason TEXT NOT NULL`
- `evidence_refs_json TEXT NOT NULL`
- `input_sha256 TEXT NOT NULL`
- `output_sha256 TEXT NOT NULL`
- `created_at TEXT NOT NULL`

Assessments are append-only. The current assessment is the latest completed record for the case, phase, stage run, and bound scope digest. Evidence references must resolve to existing sealed evidence records. The input and output digests make prompt payload and parsed-result provenance auditable without storing hidden model reasoning.

## Reporting Gate

A report may be generated only when all of the following are true:

- the case is the current completed case and its technical decision is `CONFIRMED`;
- the case has a current eligibility result of `ELIGIBLE`;
- the assessment's `scope_sha256` equals the case binding and stored snapshot digest;
- a conditional preflight has a completed post-replay `ELIGIBLE` assessment;
- there is no later unresolved `UNKNOWN` or `CONDITIONAL` assessment for the current stage run.

Missing eligibility data fails closed. Previously exported report files are not rewritten, but regenerating a report for a legacy case requires scope binding and a new eligibility assessment.

## Failure Handling

- LLM timeout, unavailable model, malformed response, or schema validation failure: record `UNKNOWN`; result is `INCONCLUSIVE`; do not replay.
- Policy quotation not found verbatim: record `UNKNOWN`; do not replay.
- Scope snapshot missing or digest mismatch: stop the case before network activity and require explicit repair or rematerialization.
- Assessment persistence failure: stop before replay. A replay must never occur without a durable preflight decision.
- Post-replay assessment failure: preserve sealed technical evidence but finish as `INCONCLUSIVE`; never promote to `CONFIRMED` or reportable.
- Conflicting rules: prefer the more restrictive applicable rule only when the model can quote both and explain the conflict; otherwise return `UNKNOWN` for manual review.

Retries must be bounded and idempotent. Reusing a completed assessment is allowed only when the complete normalized input digest and scope digest match.

## Security Considerations

- Treat scope Markdown, Attack claims, responses, and evidence as untrusted data in prompts.
- Use strict structured-output validation and fixed enum values.
- Require exact quote grounding against the stored scope snapshot.
- Do not expose secrets, raw session material, or unnecessary response bodies to the eligibility model.
- Do not allow model output to expand hosts, methods, request count, payloads, or time budgets.
- Apply existing authorization, rate, session, and replay controls after eligibility approval; eligibility can only narrow execution permission.
- Keep assessment provenance append-only and hash-bound to the case and stage run.

## Backward Compatibility and Migration

Database initialization adds the new tables and nullable legacy case column without destructively rewriting existing data. New cases require a non-null scope binding. Existing cases remain readable, and existing reports remain accessible, but the system fails closed for resume, new execution, and new report generation until a legacy case is bound and reassessed.

Current target-policy behavior and decision enums remain intact. The change adds reason codes and eligibility records rather than redefining `OUT_OF_SCOPE`. Consumers that only inspect the final decision continue to work; consumers needing to distinguish target rejection from finding exclusion can inspect the reason code and assessment record.

## Test Strategy

### Unit tests

- eligibility request/response schema and enum validation;
- exact quote grounding and prompt-injection-shaped policy text;
- deterministic coordinator mapping for every eligibility state;
- advisory `replay_allowed` cannot override coordinator invariants;
- scope snapshot hashing, immutability, and assessment input hashing;
- current-assessment selection and stale-digest rejection.

### Orchestration tests

- preflight performs no network request;
- unconditional exclusion produces `OUT_OF_SCOPE` without invoking a replay adapter;
- `ELIGIBLE` proceeds through the existing blind validation path;
- conditional open redirect without qualifying impact becomes `OUT_OF_SCOPE` after bounded replay;
- conditional finding with qualifying impact proceeds to the existing final decision path;
- inability to collect required impact evidence becomes `INCONCLUSIVE`;
- unknown or malformed policy assessment becomes `INCONCLUSIVE` without replay;
- blind validation input contains neither the Attack conclusion nor eligibility rationale;
- assessment persistence failure prevents replay;
- a digest mismatch among case, stored snapshot, and assessment prevents resume/reuse, while changes to an external file do not mutate an existing case;

### Reporting and migration tests

- report generation rejects absent, non-eligible, unresolved, or stale assessments;
- report generation accepts a current `CONFIRMED` case with matching `ELIGIBLE` assessment;
- conditional cases require post-replay `ELIGIBLE`;
- legacy databases migrate additively and remain readable;
- legacy cases fail closed for execution and reporting until bound and reassessed;
- existing immutable report artifacts remain readable.

The full project test suite and CLI contract tests must pass after implementation.

## Rollout

1. Add snapshot, case-binding, and eligibility-assessment persistence with migration tests.
2. Add the structured eligibility service and grounding validation behind an internal feature flag.
3. Insert preflight and conditional post-replay gates into the coordinator.
4. Add standalone CLI scope binding and resume drift protections.
5. Enforce the reporting gate.
6. Enable the feature for new integrated runs, then require explicit binding for legacy standalone cases.

Logs and CLI output should expose the phase, eligibility enum, matched-rule summary, scope digest prefix, and coordinator reason code, while avoiding raw sensitive evidence.

## Acceptance Criteria

- No Validation network request occurs before durable target authorization and eligibility preflight approval.
- A policy-excluded candidate cannot become reportable even when technically reproducible.
- A conditional exclusion is resolved from sealed replay evidence or ends `INCONCLUSIVE`; it is never guessed eligible.
- The technical replay remains blind to Attack and eligibility conclusions.
- Every reportable case has a current, grounded `ELIGIBLE` assessment bound to its immutable approved scope snapshot.
- Case/snapshot/assessment digest mismatches, malformed model output, and missing legacy bindings fail closed with auditable reason codes.
