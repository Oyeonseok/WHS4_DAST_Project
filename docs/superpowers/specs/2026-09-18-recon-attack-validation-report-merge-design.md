# Recon/Attack and Validation/Report Merge Design

**Date:** 2026-09-18

**Status:** Approved for implementation planning

## Objective

Merge the Recon and Attack capabilities present in the `AI-DAST-ALL` working
tree into the current branch while preserving the current branch's newer
security boundaries, Validation implementation, Reporting implementation, and
shared pipeline schema.

The result must expose one coherent pipeline:

```text
Scope/Auth/Policy
    -> Recon
    -> verified Handoff
    -> Pipeline.db schema v10
    -> Attack
    -> Shared Validation
    -> case-based Report
```

## Source Baselines

### `AI-DAST-ALL`

`AI-DAST-ALL/` is a separate Git repository embedded as an untracked directory
in the current repository. Its checked-out commit is `15a8ee0`, but the source
of the desired Recon and Attack behavior is its modified working tree, not that
commit alone. The working tree contains both modified tracked files and new,
untracked Attack modules.

Before implementation, record the relative path and SHA-256 of every source,
test, Skill, and packaging file selected from `AI-DAST-ALL`. Recompute the
inventory before each import task. Stop if a selected source changes during
the merge so that the implementation never silently combines different
snapshots.

Do not import generated or local runtime material:

- `.venv/`
- `result/`
- `*.db` and SQLite sidecars
- `__pycache__/`
- `*.pyc`
- Git metadata

Normalize source line endings to LF. Line-ending-only differences are not
behavioral changes.

### Current branch

The current branch `feat/recon_minseok_validate` at design time is based on
commit `c44489e`. It owns the newer safety, Validation, Reporting, and pipeline
contracts. Existing unrelated working-tree content must be preserved.

## Ownership Rules

| Area | Functional baseline | Merge rule |
|---|---|---|
| Scope and Auth | Current branch | Preserve current implementation and public CLI behavior |
| Core policy and request safety | Current branch | Preserve or strengthen; never relax to match `AI-DAST-ALL` |
| Recon | `AI-DAST-ALL`, reconciled with current safety fixes | Import only behavior not already present and not in conflict with current safety |
| Attack | `AI-DAST-ALL` working tree | Import missing execution modules, then adapt them to current contracts |
| Pipeline materialization and schema | Current branch | Keep schema v10 and immutable Recon-to-pipeline provenance |
| Validation | Current branch | Keep package structure and all current runtime capabilities |
| Reporting | Current branch | Keep case-based reporting and evidence-reference separation |
| CLI | Shared integration boundary | Merge commands and options semantically rather than replacing the file |

When both trees implement the same behavior differently, the safer current
behavior wins unless the `AI-DAST-ALL` implementation is demonstrably stricter
and remains compatible with the current downstream contracts.

## Recon Design

The current Recon implementation already descends from the same code line as
`AI-DAST-ALL` and contains newer changes. Therefore, Recon is not replaced as a
directory. Each behavioral delta is classified as one of:

1. capability missing from the current branch and safe to import;
2. equivalent behavior already present;
3. formatting or line-ending noise;
4. a regression against a current safety or integration guarantee.

Current behavior that must remain includes:

- authentication endpoint provenance;
- authenticated and runtime-browser Scope collection;
- Intigriti identification headers when required by approved Scope text;
- `AIDAST_RESULT_ROOT` handling;
- Scope-derived host, scheme, port, path, method, and exclusion enforcement;
- request header propagation through the guarded Recon transports;
- fail-closed handling of missing endpoint annotations before Attack;
- blocking downstream Attack when Recon has task failures;
- the current browser, redirect, credential, and secret-handling boundaries.

The following `AI-DAST-ALL` behaviors are explicitly rejected because they
weaken current guarantees:

- continuing into Attack with untagged observations;
- allowing a `completed_with_errors` Recon scan to enter Attack;
- removing current request-header propagation;
- removing authentication provenance checks;
- replacing result-root configuration with a hard-coded `result/` path;
- broadening non-URL target schemes or ports beyond the current validation.

Progress output or batching changes may be imported only if they leave the
transaction, completeness, and downstream gates unchanged.

## Attack Design

The following modules exist only in the `AI-DAST-ALL` working tree and form the
primary Attack import set:

- `src/aidast/attack/ed25519_authorization.py`
- `src/aidast/attack/executor_factory.py`
- `src/aidast/attack/idor.py`
- `src/aidast/attack/intent_manifest.py`
- `src/aidast/attack/intent_resolver.py`
- `src/aidast/attack/launcher.py`
- `src/aidast/attack/local_workflow.py`
- `src/aidast/attack/playwright_transport.py`
- `src/aidast/attack/policy_executor.py`
- `src/aidast/attack/service_factory.py`
- `src/aidast/attack/session_binding.py`
- `src/aidast/attack/session_pool.py`

These modules provide local Ed25519 authorization, intent manifests and
resolution, policy-bound executors, dual-identity IDOR execution, persistent
browser sessions, session binding, launcher construction, and a local Codex
Skill workflow.

The import also requires semantic edits to existing Attack integration files:

- `attack/__init__.py` exports the reviewed public API;
- `attack/authorization.py` supplies the signing and verification primitives;
- `attack/store.py` records attempts before dispatch, completes attempts, and
  coordinates local and external authorization revocation;
- `attack/runtime.py` exposes required execution wiring without accepting
  incomplete Recon scans;
- `attack/db_cli.py` keeps the current Validation v10 reproduction contract;
- `attack/request_cli.py`, `attack/skill_agent.py`, and
  `attack/skill_selector.py` receive only compatibility changes required by
  the imported execution path;
- `cli.py` integrates user-facing entry points without losing current Scope,
  Recon, Validation, Report, update, or result-root behavior.

The imported modules currently have no dedicated test coverage for their
public classes and functions. Each module must receive focused tests before it
is considered integrated.

## Validation and Schema Compatibility

The current Validation implementation remains authoritative:

- `validation/contracts/`
- `validation/core/`
- `validation/execution/`
- `validation/orchestration/`
- `validation/persistence/`
- the current Validation catalog, per-hunt contracts, and Skills

The current `pipeline/live_schema.py` schema v10 remains authoritative. The
merge must not remove or weaken:

- protocol-specific multipart, WebSocket, gRPC, and concurrent contracts;
- durable transport-operation accounting;
- impact-development contracts and hypothesis state;
- `validation_attempts.impact_hypothesis_id`;
- Validation evidence and observation integrity fields;
- `finding_reproduction_specs` runtime, development, and impact-development
  contract fields;
- existing provenance and immutability triggers.

Old flat imports used by `AI-DAST-ALL` Attack code must be changed to the
current public `aidast.validation` API where that API intentionally exports the
symbol. A direct subpackage import is allowed only for an internal type that is
not part of the public API and whose ownership is clear. Do not add a broad
compatibility shim that recreates the former flat module layout.

Attack finding commits must validate all supplied reproduction contracts
against the resolved current Validation profile before inserting them. A
contract that widens endpoints, methods, identities, runtime kinds, or impact
paths is rejected atomically.

## Reporting Design

The current case-based Reporting implementation is retained. Reports are
generated only from eligible Validation cases and remain local drafts; the
merge adds no platform submission behavior.

The current evidence-reference distinction must remain: Validation evidence
references are not conflated with arbitrary nested Attack evidence fields.
Report creation fails if referenced Validation evidence is absent or belongs
to a different case, scan, or stage.

## End-to-End Data Flow

1. Current Scope and Auth code creates and verifies approved program scope.
2. Current guarded Recon executes the reconciled Recon capability set.
3. Recon completes only when required work and annotations satisfy current
   downstream gates.
4. Handoff hashes and SQLite state are verified before materialization.
5. `materialize.py` creates a writable `Pipeline.db` from the immutable Recon
   source and records its provenance.
6. `live_schema.py` upgrades only the writable copy to schema v10.
7. Attack resolves observed intents from the pipeline, binds them to an
   authorization, selects a policy-aware executor, and records an attempt
   before dispatch.
8. Every Attack request passes the current Scope/TargetPolicy, authorization,
   budget, identity, and session boundaries.
9. Confirmed Attack findings include a Validation-compatible reproduction
   specification.
10. Current Shared Validation verifies integrity, replays the applicable
    runtime contract, develops bounded impact where authorized, and records an
    evidence-backed decision.
11. Current Reporting reads an eligible case and renders a local platform
    draft with validated evidence references.

## Failure and Recovery Rules

- Source inventory drift stops the merge task before files are imported.
- Missing or invalid authorization, intent binding, policy binding, identity,
  or session binding rejects an Attack request before network dispatch.
- Attempt reservation is durable and precedes dispatch. An interrupted attempt
  remains reviewable and is never silently replayed as new work.
- External authorization is revoked before the local run is marked revoked.
  Retrying revocation is idempotent.
- Recon failure or annotation incompleteness prevents Attack startup.
- A schema version lower than 10 or missing required v10 columns fails closed;
  Attack never downgrades or recreates the shared schema.
- Invalid reproduction contracts roll back the finding commit.
- Insufficient Validation proof cannot produce `CONFIRMED`.
- Invalid Report evidence references prevent draft creation.
- Existing resumability is retained at stage boundaries; recovery does not
  bypass policy, authorization, integrity, or evidence checks.

## Testing Strategy

### Source and import tests

- Assert the recorded source inventory matches the imported snapshot.
- Verify all imported Attack modules import without optional network activity.
- Verify package exports and wheel package data include the intended modules
  and Skills.

### Attack unit tests

- Ed25519 key generation, signing, verification, expiry, and tamper rejection.
- Intent manifest canonicalization, digest binding, unknown intent rejection,
  and duplicate handling.
- observed endpoint-to-intent resolution without target widening.
- session binding by run, identity, target, scheme, host, port, and path.
- persistent session isolation and deterministic cleanup.
- executor selection, unsupported test rejection, dual-identity enforcement,
  and policy rejection before transport.
- attempt reservation, completion, idempotency, and coordinated revocation.

### Contract tests

- Attack finding commits against schema v10 with HTTP, browser, OOB,
  multipart, WebSocket, gRPC, concurrent, development, and impact-development
  contracts as applicable.
- rejection of runtime kinds and impact paths outside the Validation profile.
- preservation of current Validation and Reporting evidence semantics.

### Recon regression tests

- authenticated endpoint provenance and Intigriti header propagation.
- result-root behavior and Scope exclusions.
- annotation incompleteness blocks Attack.
- failed Recon tasks block Attack handoff consumption.
- redirects, browser requests, and tool traffic retain current policy guards.

### Integrated verification

- offline `Recon -> Handoff -> Pipeline.db -> Attack -> Validation -> Report`
  test with fake transports and deterministic agents;
- focused test groups after each independently reviewable merge task;
- full offline test suite;
- `git diff --check`;
- package build and installed-package import/resource smoke tests.

The checked-in `.venv` directories are not usable test environments: their
Python launchers are zero-byte, non-executable files. Verification must create
or select a clean Python 3.13-or-newer environment without modifying or relying
on those directories.

## Out of Scope

- weakening Scope or authorization rules to preserve old behavior;
- downgrading pipeline schema v10;
- restoring the former flat Validation source layout;
- automatically submitting reports to bounty platforms;
- importing local databases, sessions, credentials, results, caches, or Git
  history from `AI-DAST-ALL`;
- unrelated refactoring of current Validation, Reporting, Recon, or CLI code.

## Acceptance Criteria

The design is implemented when:

1. the reviewed `AI-DAST-ALL` Attack execution capabilities are available from
   the current package;
2. safe, non-duplicated Recon capabilities are reconciled without losing any
   named current safety guarantee;
3. the current Validation package and schema v10 remain authoritative;
4. the current case-based Report and evidence separation remain authoritative;
5. every new Attack execution path has focused test coverage;
6. the offline end-to-end pipeline succeeds for valid inputs and fails closed
   at each specified boundary;
7. the full offline suite, diff checks, and package smoke tests pass in a clean
   supported environment.
