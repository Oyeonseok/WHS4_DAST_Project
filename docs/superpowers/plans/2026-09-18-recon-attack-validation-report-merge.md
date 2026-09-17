# Recon/Attack and Validation/Report Merge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the reviewed `AI-DAST-ALL` Recon and Attack capabilities into the current package without weakening the current Recon safety boundaries, Validation schema v10, or case-based Reporting contracts.

**Architecture:** Treat the current branch as the integration root and `AI-DAST-ALL` as a hash-pinned source snapshot. Import the missing Attack execution units in dependency order, adapt them to the current public Validation and pipeline contracts, and reconcile Recon behavior semantically instead of replacing the current Recon tree. Keep all real transports behind existing policy, authorization, budget, identity, and session boundaries.

**Tech Stack:** Python 3.13+, Pydantic 2, SQLite, Playwright, cryptography/Ed25519, pytest, setuptools/uv.

**Spec:** `docs/superpowers/specs/2026-09-18-recon-attack-validation-report-merge-design.md`

## Global Constraints

- `AI-DAST-ALL` working-tree content, not only commit `15a8ee0`, is the Recon/Attack source baseline.
- Stop an import task if any selected source hash differs from the recorded manifest.
- Never import `.venv`, `result`, SQLite files or sidecars, `__pycache__`, `*.pyc`, or nested Git metadata.
- Preserve current Scope/Auth behavior, Intigriti headers, `AIDAST_RESULT_ROOT`, authentication provenance, request guards, and fail-closed Recon gates.
- Preserve `Pipeline.db` schema v10; never run a v9 downgrade or remove current Validation columns, tables, triggers, or indexes.
- Preserve the current package-based Validation layout and case-based Reporting evidence separation.
- No report submission, implicit credentials, default live transport, or automatic authorization generation is added.
- Use LF line endings for imported source.
- Existing user content under the untracked `AI-DAST-ALL/` directory is read-only input and must not be modified.
- Run tests in a clean Python 3.13-or-newer environment outside the checked-in zero-byte `.venv` directories.

## Target File Map

### New source files

- `src/aidast/attack/ed25519_authorization.py`: local signed authorization envelope and provider.
- `src/aidast/attack/intent_manifest.py`: immutable intent manifest serialization and digest binding.
- `src/aidast/attack/intent_resolver.py`: Recon-grounded `RequestIntent` construction.
- `src/aidast/attack/session_binding.py`: explicit target/identity storage-state lookup.
- `src/aidast/attack/policy_executor.py`: `PolicyService` adapter for ordinary tests.
- `src/aidast/attack/idor.py`: dual-identity IDOR comparison executor.
- `src/aidast/attack/executor_factory.py`: explicit ordinary/IDOR executor selection.
- `src/aidast/attack/service_factory.py`: current authorization-to-`PolicyService` wiring.
- `src/aidast/attack/playwright_transport.py`: bounded single-session browser transport.
- `src/aidast/attack/session_pool.py`: target/identity-isolated persistent browser context pool.
- `src/aidast/attack/launcher.py`: approved session-aware executor construction.
- `src/aidast/attack/local_workflow.py`: trusted local planner/provider workflow composition.
- `scripts/merge_source_inventory.py`: deterministic source snapshot and verification helper.
- `docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json`: generated hash manifest of selected inputs.
- `docs/changes/RECON_ATTACK_SOURCE_RECONCILIATION.md`: per-delta accept/reject record.

### Existing files modified

- `src/aidast/attack/__init__.py`: reviewed exports for imported capabilities.
- `src/aidast/attack/authorization.py`: Ed25519 verification helper used by the current `PolicyService`.
- `src/aidast/attack/store.py`: pre-dispatch attempt persistence and coordinated revocation.
- `src/aidast/attack/runtime.py`: retain completed-only Recon acceptance while exposing required wiring.
- `src/aidast/attack/db_cli.py`: retain and test schema v10 reproduction contracts.
- `src/aidast/cli.py`: preserve the injected trusted-workflow boundary and current options.
- `README.md`: document the trusted embedding boundary and imported capabilities.

### Tests created or extended

- Create `tests/test_merge_source_inventory.py`.
- Create `tests/test_attack_local_authorization.py`.
- Create `tests/test_attack_intent_session.py`.
- Create `tests/test_attack_policy_execution.py`.
- Create `tests/test_attack_session_transport.py`.
- Create `tests/test_attack_local_workflow.py`.
- Create `tests/test_recon_merge_boundaries.py`.
- Modify `tests/test_attack_store.py`.
- Modify `tests/test_attack_cli.py`.
- Modify `tests/test_shared_validation_cli.py`.
- Modify `tests/test_merged_pipeline_e2e.py`.
- Modify `tests/test_shared_validation_reporting.py` only if a new mixed-evidence regression case is needed; do not rewrite existing assertions.

---

## Preparation: Create the Test Environment and Capture Baseline

- [ ] **Step 1: Create a clean temporary environment**

```bash
UV_CACHE_DIR=/tmp/aidast-merge-uv-cache uv venv /tmp/aidast-merge-venv --python 3.13
UV_CACHE_DIR=/tmp/aidast-merge-uv-cache UV_PROJECT_ENVIRONMENT=/tmp/aidast-merge-venv uv sync --group dev
```

Expected: `/tmp/aidast-merge-venv/bin/python --version` reports Python 3.13.x or newer. Do not repair or depend on either checked-in `.venv` directory.

- [ ] **Step 2: Run the unmodified baseline suite**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest -q`

Expected: PASS. If it does not pass, record the exact pre-existing failures before changing production code and stop to investigate rather than attributing them to the merge.

---

### Task 1: Pin the `AI-DAST-ALL` Working-Tree Source

**Files:**
- Create: `scripts/merge_source_inventory.py`
- Create: `tests/test_merge_source_inventory.py`
- Create: `docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json`
- Create: `docs/changes/RECON_ATTACK_SOURCE_RECONCILIATION.md`

**Interfaces:**
- Consumes: repository root and nested `AI-DAST-ALL` directory.
- Produces: `snapshot(source_root: Path, paths: Sequence[str]) -> dict[str, str]`, `verify(source_root: Path, manifest: Mapping[str, str]) -> None`, and a committed JSON map of relative paths to lowercase SHA-256 digests.

- [ ] **Step 1: Write failing inventory tests**

```python
from pathlib import Path

import pytest

from scripts.merge_source_inventory import SourceDriftError, snapshot, verify


def test_snapshot_is_sorted_and_ignores_generated_files(tmp_path: Path) -> None:
    source = tmp_path / "AI-DAST-ALL"
    (source / "src/aidast/attack").mkdir(parents=True)
    (source / "src/aidast/attack/b.py").write_text("b\n", encoding="utf-8")
    (source / "src/aidast/attack/a.py").write_text("a\n", encoding="utf-8")
    result = snapshot(source, ["src/aidast/attack/b.py", "src/aidast/attack/a.py"])
    assert list(result) == ["src/aidast/attack/a.py", "src/aidast/attack/b.py"]
    assert all(len(value) == 64 for value in result.values())


def test_verify_rejects_changed_or_missing_source(tmp_path: Path) -> None:
    source = tmp_path / "AI-DAST-ALL"
    source.mkdir()
    selected = source / "selected.py"
    selected.write_text("before\n", encoding="utf-8")
    manifest = snapshot(source, ["selected.py"])
    selected.write_text("after\n", encoding="utf-8")
    with pytest.raises(SourceDriftError, match="selected.py"):
        verify(source, manifest)
```

- [ ] **Step 2: Run the tests and confirm the module is missing**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_merge_source_inventory.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'scripts.merge_source_inventory'`.

- [ ] **Step 3: Implement the deterministic inventory helper**

```python
class SourceDriftError(RuntimeError):
    pass


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(source_root: Path, paths: Sequence[str]) -> dict[str, str]:
    root = source_root.resolve(strict=True)
    result: dict[str, str] = {}
    for relative in sorted(set(paths)):
        path = (root / relative).resolve(strict=True)
        if root not in path.parents or not path.is_file():
            raise SourceDriftError(f"invalid selected source: {relative}")
        if any(part in {".git", ".venv", "result", "__pycache__"} for part in path.parts):
            raise SourceDriftError(f"generated source is forbidden: {relative}")
        if path.suffix in {".pyc", ".db"}:
            raise SourceDriftError(f"generated source is forbidden: {relative}")
        result[relative] = _digest(path)
    return result


def verify(source_root: Path, manifest: Mapping[str, str]) -> None:
    actual = snapshot(source_root, tuple(manifest))
    changed = [name for name, digest in manifest.items() if actual.get(name) != digest]
    if changed:
        raise SourceDriftError("source drift: " + ", ".join(sorted(changed)))
```

The CLI accepts exactly `snapshot SOURCE MANIFEST PATH...` and `verify SOURCE MANIFEST`. JSON output uses `indent=2`, `sort_keys=True`, a trailing newline, and UTF-8.

- [ ] **Step 4: Generate and verify the source manifest**

Include the 12 new Attack files, every common changed Recon/Attack file identified in the design investigation, `src/aidast/cli.py`, `src/aidast/pipeline/live_schema.py`, and relevant `AI-DAST-ALL/tests/test_*.py` files. Do not include cache files.

Run:

```bash
/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py snapshot AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json \
  src/aidast/attack/ed25519_authorization.py \
  src/aidast/attack/executor_factory.py \
  src/aidast/attack/idor.py \
  src/aidast/attack/intent_manifest.py \
  src/aidast/attack/intent_resolver.py \
  src/aidast/attack/launcher.py \
  src/aidast/attack/local_workflow.py \
  src/aidast/attack/playwright_transport.py \
  src/aidast/attack/policy_executor.py \
  src/aidast/attack/service_factory.py \
  src/aidast/attack/session_binding.py \
  src/aidast/attack/session_pool.py \
  src/aidast/attack/authorization.py \
  src/aidast/attack/store.py \
  src/aidast/attack/runtime.py \
  src/aidast/attack/db_cli.py \
  src/aidast/attack/request_cli.py \
  src/aidast/recon/annotations.py \
  src/aidast/recon/executor.py \
  src/aidast/recon/policy.py \
  src/aidast/recon/tools/endpoint_discovery.py \
  src/aidast/recon/tools/playwright_driver.py \
  src/aidast/cli.py \
  src/aidast/pipeline/live_schema.py
/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py verify AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json
```

Expected: both commands exit 0; the manifest contains only selected files and 64-character hashes.

- [ ] **Step 5: Record the Recon/Attack delta decisions**

Write a table with columns `Source file`, `Behavioral delta`, `Decision`, `Current replacement`, and `Required regression test`. It must explicitly reject partial annotation continuation, `completed_with_errors` Attack entry, request-header removal, authentication-provenance removal, hard-coded result root, schema v9, and broad evidence traversal.

- [ ] **Step 6: Run focused verification**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_merge_source_inventory.py -q`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add scripts/merge_source_inventory.py tests/test_merge_source_inventory.py docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json docs/changes/RECON_ATTACK_SOURCE_RECONCILIATION.md
git commit -m "chore: pin AI-DAST-ALL merge source"
```

---

### Task 2: Import Authorization, Intent, and Session-Binding Contracts

**Files:**
- Create: `src/aidast/attack/ed25519_authorization.py`
- Create: `src/aidast/attack/intent_manifest.py`
- Create: `src/aidast/attack/intent_resolver.py`
- Create: `src/aidast/attack/session_binding.py`
- Create: `tests/test_attack_local_authorization.py`
- Create: `tests/test_attack_intent_session.py`
- Modify: `src/aidast/attack/authorization.py`

**Interfaces:**
- Consumes: current `RunAuthorization`, `RequestIntent`, `AttackStore`, and Recon schema.
- Produces: `generate_keypair`, `sign_authorization`, `load_verified`, `to_run_authorization`, `LocalEd25519AuthorizationProvider`, `new_document`, `intent_digest`, `write_intent_manifest`, `load_intent_manifest`, `bind_intents_to_authorization`, `ObservedIntentResolver`, `SessionBindings`, and `SessionBindingError`.

- [ ] **Step 1: Write failing Ed25519 envelope tests**

```python
def test_signed_authorization_round_trips_and_rejects_tampering(tmp_path: Path) -> None:
    private = tmp_path / "private.key"
    public = tmp_path / "public.key"
    envelope = tmp_path / "Authorization.json"
    generate_keypair(private, public)
    document = valid_authorization_document()
    sign_authorization(document, private, envelope)
    assert load_verified(envelope) == document
    changed = json.loads(envelope.read_text(encoding="utf-8"))
    changed["document"]["approver"] = "attacker"
    envelope.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="signature verification failed"):
        load_verified(envelope)
```

Also test invalid typed documents, future `not_before`, expired documents, reviewer mismatch, run-binding mismatch, and absence of an external revoker.

- [ ] **Step 2: Write failing intent and session tests**

```python
def test_observed_intent_resolver_refuses_mutation_and_cross_scan_endpoint(pipeline_db: Path) -> None:
    resolver = ObservedIntentResolver(pipeline_db, bindings=authorization_bindings("scan-a"))
    with pytest.raises(ValueError, match="in-scope Recon observation"):
        resolver(authorized_test(endpoint_id="endpoint-from-scan-b"), "hypothesis")
    mark_endpoint_method(pipeline_db, "endpoint-a", "POST")
    with pytest.raises(ValueError, match="explicit approved Attack intent"):
        resolver(authorized_test(endpoint_id="endpoint-a"), "hypothesis")


def test_session_binding_requires_regular_file_for_exact_host_and_identity(tmp_path: Path) -> None:
    state = tmp_path / "identity-a.json"
    state.write_text('{"cookies":[]}', encoding="utf-8")
    bindings = SessionBindings({"example.test": {"identity_a": str(state)}})
    assert bindings.resolve("https://example.test/app", "identity_a") == state.resolve()
    with pytest.raises(SessionBindingError, match="no session"):
        bindings.resolve("https://other.test", "identity_a")
```

- [ ] **Step 3: Run tests to verify missing imports**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_attack_local_authorization.py tests/test_attack_intent_session.py -q`

Expected: collection fails because the four modules do not yet exist.

- [ ] **Step 4: Verify the pinned source and import the four modules**

Run: `/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py verify AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json`

Import the reviewed implementations with LF endings. In `authorization.py`, retain current Pydantic models and add only the exact Ed25519 signing/verification functions required by `service_factory.py`:

```python
def verify_ed25519(authorization: RunAuthorization, public_key: bytes) -> bool:
    signature = authorization.signature
    if not signature:
        return False
    document = authorization.model_copy(update={"signature": None})
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _decode_signature(signature), canonical_bytes(document)
        )
    except (ValueError, InvalidSignature):
        return False
    return True
```

Use the current canonical serialization helper; do not introduce a second digest format for `RunAuthorization`.

- [ ] **Step 5: Run focused tests and current authorization regressions**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_attack_local_authorization.py \
  tests/test_attack_intent_session.py \
  tests/test_attack_authorization.py \
  tests/test_policy_service.py -q
```

Expected: PASS with no transport calls in rejection cases.

- [ ] **Step 6: Commit**

```bash
git add src/aidast/attack/authorization.py src/aidast/attack/ed25519_authorization.py src/aidast/attack/intent_manifest.py src/aidast/attack/intent_resolver.py src/aidast/attack/session_binding.py tests/test_attack_local_authorization.py tests/test_attack_intent_session.py
git commit -m "feat: add bounded attack authorization contracts"
```

---

### Task 3: Import Policy Executors and Session Transports

**Files:**
- Create: `src/aidast/attack/policy_executor.py`
- Create: `src/aidast/attack/idor.py`
- Create: `src/aidast/attack/executor_factory.py`
- Create: `src/aidast/attack/service_factory.py`
- Create: `src/aidast/attack/playwright_transport.py`
- Create: `src/aidast/attack/session_pool.py`
- Create: `tests/test_attack_policy_execution.py`
- Create: `tests/test_attack_session_transport.py`

**Interfaces:**
- Consumes: `PolicyService`, `SQLiteBudgetLedger`, `TargetPolicy`, `AuthorizedTest`, exact `RequestIntent` resolvers, and explicit Playwright storage-state paths.
- Produces: `PolicyServiceAttackExecutor`, `DualIdentityIdorExecutor`, `select_executor`, `build_policy_service`, `PlaywrightSessionTransport`, and `PersistentSessionPool`.

- [ ] **Step 1: Write failing policy executor tests**

```python
def test_policy_executor_uses_exact_resolved_intent() -> None:
    service = Mock()
    service.request.return_value = (broker_response(200, body=b"ok"), Mock())
    intent = request_intent(method="HEAD", url="https://example.test/item/1")
    executor = PolicyServiceAttackExecutor(
        service, lambda test, hypothesis: intent, lambda task, skills: (),
    )
    result = executor.execute(authorized_test(), hypothesis_id="hypothesis")
    service.request.assert_called_once_with(intent)
    assert (result.outcome, result.method, result.url) == (
        "supports", "HEAD", "https://example.test/item/1"
    )


def test_idor_requires_two_services_and_body_or_denial_signal() -> None:
    with pytest.raises(ValueError, match="requires two approved identity services"):
        select_executor(
            skill_id="hunt-idor", service=Mock(), test_provider=Mock(),
            intent_resolver=Mock(),
        )
```

Add table-driven IDOR cases for `(A=403,B=200) -> supports`, equal successful bodies -> supports, and unequal successful bodies -> refutes. Assert identity B is explicitly recorded.

- [ ] **Step 2: Write failing session-transport tests with fake Playwright objects**

Test exact storage-state use, host isolation, identity isolation, context reuse for the same key, deterministic `close()`, redirect rejection, response-size enforcement, and the absence of any default browser or network creation at import time.

```python
def test_session_pool_isolates_target_and_identity(fake_playwright, session_files) -> None:
    pool = PersistentSessionPool(playwright_factory=lambda: fake_playwright)
    first = pool.transport("https://a.test", "identity_a", session_files["a"])
    again = pool.transport("https://a.test", "identity_a", session_files["a"])
    other = pool.transport("https://a.test", "identity_b", session_files["b"])
    assert first is again
    assert other is not first
    pool.close()
    assert fake_playwright.stop.called
```

- [ ] **Step 3: Run tests to verify missing modules**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_attack_policy_execution.py tests/test_attack_session_transport.py -q`

Expected: collection fails on the new module imports.

- [ ] **Step 4: Verify source hashes and import the six modules**

Run: `/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py verify AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json`

Keep the executor decision explicit:

```python
if "idor" in skill_id.casefold():
    if identity_a is None or identity_b is None or idor_intent_resolver is None:
        raise ValueError("IDOR execution requires two approved identity services")
    return DualIdentityIdorExecutor(
        identity_a, identity_b, idor_intent_resolver, test_provider
    )
return PolicyServiceAttackExecutor(service, intent_resolver, test_provider)
```

`build_policy_service` must use current `AuthorizationBindings` and `verify_ed25519`, and must require injected `policy`, durable `ledger`, `transport`, `public_key`, and exact `intents`; it must not supply defaults.

- [ ] **Step 5: Run focused and broker regression tests**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_attack_policy_execution.py \
  tests/test_attack_session_transport.py \
  tests/test_policy_service.py \
  tests/test_request_broker.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/aidast/attack/policy_executor.py src/aidast/attack/idor.py src/aidast/attack/executor_factory.py src/aidast/attack/service_factory.py src/aidast/attack/playwright_transport.py src/aidast/attack/session_pool.py tests/test_attack_policy_execution.py tests/test_attack_session_transport.py
git commit -m "feat: add policy-bound attack executors"
```

---

### Task 4: Wire the Trusted Local Attack Workflow

**Files:**
- Create: `src/aidast/attack/launcher.py`
- Create: `src/aidast/attack/local_workflow.py`
- Create: `tests/test_attack_local_workflow.py`
- Modify: `src/aidast/attack/__init__.py`
- Modify: `tests/test_attack_cli.py`

**Interfaces:**
- Consumes: explicit Main Agent, executor factory, policy map, signed authorization, intent manifest, session bindings, and durable Attack store.
- Produces: `SessionAttackLauncher`, `CodexSkillAttackPlanner`, `build_local_skill_workflow`, and reviewed `aidast.attack` exports.

- [ ] **Step 1: Write failing workflow composition tests**

```python
def test_local_workflow_requires_injected_executor_factory() -> None:
    workflow = build_local_skill_workflow(
        main_agent=fake_main_agent(),
        executor_factory=lambda authorization, store: fake_executor(),
    )
    assert isinstance(workflow, SkillAttackWorkflow)


def test_default_cli_still_refuses_uninjected_live_execution(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["attack", "execute", str(tmp_path / "Pipeline.db"),
              "--authorization", str(tmp_path / "Authorization.json")])
```

Also test that the planner accepts only the current `HypothesisBatch` and `FindingAssessment` schemas, and that the launcher rejects an authorization whose intent manifest, policy, or session identity is absent.

- [ ] **Step 2: Run tests to verify missing workflow symbols**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_attack_local_workflow.py tests/test_attack_cli.py -q`

Expected: new workflow tests fail on missing imports; existing CLI refusal tests continue to pass.

- [ ] **Step 3: Verify hashes and import launcher/workflow**

Run: `/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py verify AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json`

Expose only reviewed names from `attack/__init__.py`:

```python
from .ed25519_authorization import LocalEd25519AuthorizationProvider
from .executor_factory import select_executor
from .intent_manifest import load_intent_manifest, write_intent_manifest
from .launcher import SessionAttackLauncher
from .local_workflow import CodexSkillAttackPlanner, build_local_skill_workflow
from .session_binding import SessionBindingError, SessionBindings
```

Do not make the normal CLI automatically construct a live workflow. `_run_attack(..., workflow=None)` must keep rejecting `approve` and `execute`. Trusted embedding code can inject the newly constructed workflow through the existing protocol.

- [ ] **Step 4: Run workflow, package-export, and CLI tests**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_attack_local_workflow.py \
  tests/test_attack_cli.py \
  tests/test_merged_cli_contract.py -q
```

Expected: PASS; no live browser or network starts.

- [ ] **Step 5: Commit**

```bash
git add src/aidast/attack/launcher.py src/aidast/attack/local_workflow.py src/aidast/attack/__init__.py tests/test_attack_local_workflow.py tests/test_attack_cli.py
git commit -m "feat: wire trusted local attack workflow"
```

---

### Task 5: Add Durable Attack Attempt and Revocation State

**Files:**
- Modify: `src/aidast/attack/store.py`
- Modify: `tests/test_attack_store.py`
- Modify: `src/aidast/attack/workflow.py`

**Interfaces:**
- Consumes: current `AttackStore` run/scan binding and external authorization revoker.
- Produces: `record_attempt(..., status="started") -> WriteResult`, `complete_attempt(..., outcome, response_status=None) -> WriteResult`, and `revoke_run(reason, revoke_authorization=None) -> int`.

- [ ] **Step 1: Write failing persistence tests**

```python
def test_attempt_is_idempotently_reserved_before_completion(store: AttackStore) -> None:
    inserted = store.record_attempt(
        attempt_id="attempt", task_id="task", endpoint_id="endpoint",
        skill_name="hunt-idor", test_id="test", hypothesis_id="hypothesis",
    )
    duplicate = store.record_attempt(
        attempt_id="attempt", task_id="task", endpoint_id="endpoint",
        skill_name="hunt-idor", test_id="test", hypothesis_id="hypothesis",
    )
    assert (inserted.status, duplicate.status) == ("inserted", "duplicate")
    assert store.complete_attempt("attempt", outcome="confirmed", response_status=200).status == "updated"


def test_external_revocation_precedes_local_revocation(store: AttackStore) -> None:
    events: list[str] = []
    generation = store.revoke_run(
        "operator revoked", revoke_authorization=lambda authorization_id: events.append(authorization_id)
    )
    assert events == ["authorization"]
    assert generation == 1
```

Test wrong endpoint, conflicting duplicate attempt ID, invalid response status, foreign run, missing attempt, and external revoker failure leaving the local run unchanged.

- [ ] **Step 2: Run focused tests and confirm missing methods**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_attack_store.py -q`

Expected: new tests fail with missing keyword/method errors.

- [ ] **Step 3: Merge the reviewed store behavior**

Persist the attempt fingerprint as the canonical SHA-256 of `{"test_id": ..., "hypothesis_id": ...}`. Validate identifiers and endpoint ownership before insert. The revocation order must remain:

```python
current = self.get_run()
authorization_id = current.get("authorization_id")
if revoke_authorization is not None and authorization_id:
    revoke_authorization(authorization_id)
with self.conn:
    # increment generation, clear authorization, and append audit state
```

Keep `SkillAttackWorkflow.revoke()` passing `self.authorization_provider.revoke` into `store.revoke_run()`.

- [ ] **Step 4: Run persistence and workflow regressions**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_attack_store.py \
  tests/test_attack_agent.py \
  tests/test_attack_local_workflow.py \
  tests/test_attack_cli.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aidast/attack/store.py src/aidast/attack/workflow.py tests/test_attack_store.py
git commit -m "feat: persist bounded attack attempts"
```

---

### Task 6: Preserve Validation Schema v10 at the Attack Boundary

**Files:**
- Modify: `tests/test_shared_validation_cli.py`
- Modify: `src/aidast/attack/db_cli.py` only if a failing test exposes a compatibility defect.
- Modify: `src/aidast/pipeline/live_schema.py` only if a failing test exposes a missing additive migration; never copy v9 from `AI-DAST-ALL`.

**Interfaces:**
- Consumes: `commit_finding(db_path, scan_id, payload_path) -> dict`, current `SkillProfileResolver`, and current runtime/development/impact-development contracts.
- Produces: atomic schema-v10 finding commits with canonical reproduction hashes.

- [ ] **Step 1: Add schema-v10 compatibility tests**

```python
def test_attack_commit_preserves_all_validation_v10_contracts(pipeline_db: Path, payload_path: Path) -> None:
    payload = finding_payload(
        runtime_contract=valid_http_runtime_contract(),
        development_contract=valid_development_contract(),
        impact_development_contract=valid_impact_development_contract(),
    )
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    result = commit_finding(pipeline_db, "scan", payload_path)
    assert result["finding_id"] == payload["finding_id"]
    with sqlite3.connect(pipeline_db) as connection:
        row = connection.execute(
            "SELECT runtime_contract_sha256,development_contract_sha256,"
            "impact_development_contract_sha256,spec_sha256 "
            "FROM finding_reproduction_specs WHERE finding_id=?",
            (payload["finding_id"],),
        ).fetchone()
        assert all(value and len(value) == 64 for value in row)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
```

Add rejection tests for a runtime kind outside the resolved profile, an undeclared identity role, a widened endpoint/method, and an impact path not owned by Validation. Assert no finding, requests, or reproduction spec remains after each rejection.

- [ ] **Step 2: Run the compatibility tests before modifying code**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_shared_validation_cli.py -q`

Expected: existing current behavior may already pass. If it passes, make no production change in this task; the passing test is the deliverable. If it fails, the failure must identify a current v10 compatibility defect, not a reason to remove v10 fields.

- [ ] **Step 3: Apply only the minimal v10 fix if required**

The accepted insert shape retains all current fields:

```sql
INSERT INTO finding_reproduction_specs (
    finding_id, attack_skill_name, endpoint_id, method, endpoint_template,
    injection_location, parameter_name, payload_template_json,
    required_identity_roles_json, source_attempt_ids_json,
    source_request_ids_json, payload_structure_sha256, source_policy_sha256,
    runtime_contract_json, runtime_contract_sha256,
    development_contract_json, development_contract_sha256,
    impact_development_contract_json, impact_development_contract_sha256,
    spec_sha256
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
```

- [ ] **Step 4: Run Validation protocol and schema regressions**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_shared_validation_cli.py \
  tests/test_validation_contracts.py \
  tests/test_validation_runtime_contract.py \
  tests/test_validation_impact_development.py \
  tests/test_validation_multipart_runtime.py \
  tests/test_validation_websocket_runtime.py \
  tests/test_validation_grpc_runtime.py \
  tests/test_validation_concurrent_runtime.py \
  tests/test_validation_transport_broker.py -q
```

Expected: PASS and every created pipeline reports `PRAGMA user_version=10`.

- [ ] **Step 5: Commit**

```bash
git add tests/test_shared_validation_cli.py src/aidast/attack/db_cli.py src/aidast/pipeline/live_schema.py
git commit -m "test: lock attack to validation schema v10"
```

Stage only files actually changed; omit production files when the existing implementation already passes.

---

### Task 7: Reconcile Recon Without Safety Regression

**Files:**
- Create: `tests/test_recon_merge_boundaries.py`
- Modify: `src/aidast/recon/annotations.py` only for non-semantic progress output if desired.
- Modify: `src/aidast/recon/tools/endpoint_discovery.py` or `playwright_driver.py` only for a capability documented as accepted in `RECON_ATTACK_SOURCE_RECONCILIATION.md`.
- Modify: `src/aidast/cli.py` only if an accepted capability needs wiring.

**Interfaces:**
- Consumes: current Recon executor, annotation worker, CLI parser, Scope document, request headers, and handoff preparation.
- Produces: documented parity with accepted `AI-DAST-ALL` Recon behavior while retaining every current fail-closed gate.

- [ ] **Step 1: Write regression tests for every rejected relaxation**

```python
def test_failed_deferred_annotation_blocks_attack_handoff(monkeypatch, approved_scope) -> None:
    monkeypatch.setattr("aidast.cli.tag_pending_observations", lambda *args, **kwargs: (3, 1))
    with pytest.raises(ReconExecutionError, match="could not be tagged"):
        run_recon_fixture(approved_scope, prepare_attack=True)


def test_completed_with_errors_scan_is_not_accepted_by_attack_store(handoff_fixture) -> None:
    handoff_fixture.set_scan_status("completed_with_errors")
    with pytest.raises(AttackStoreError, match="completed scan"):
        AttackStore.create(handoff_fixture.manifest, handoff_fixture.output)
```

Also assert Intigriti headers reach guarded Recon transports, authentication provenance remains passive and secret-free, `AIDAST_RESULT_ROOT` affects all default output roots, and non-URL policies cannot broaden HTTPS/443.

- [ ] **Step 2: Run the new tests before Recon changes**

Run: `/tmp/aidast-merge-venv/bin/python -m pytest tests/test_recon_merge_boundaries.py -q`

Expected: safety tests PASS against the current branch. Any failure is fixed before importing optional Recon behavior.

- [ ] **Step 3: Verify the source manifest and inspect accepted deltas only**

Run: `/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py verify AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json`

For each accepted row in the reconciliation document, add one failing capability test, implement only that behavior, and rerun the focused test. Do not copy entire Recon files. If the reconciliation finds no safe missing behavior, leave production Recon unchanged and commit the regression tests and decision record only.

- [ ] **Step 4: Run the full Recon/Auth/Scope boundary group**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_recon_merge_boundaries.py \
  tests/test_recon_workflow.py \
  tests/test_recon_policy.py \
  tests/test_recon_browser_transport.py \
  tests/test_deferred_annotation_evidence.py \
  tests/test_auth.py \
  tests/test_auth_endpoints.py \
  tests/test_scope_workflow.py \
  tests/test_pipeline_cli.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/test_recon_merge_boundaries.py docs/changes/RECON_ATTACK_SOURCE_RECONCILIATION.md src/aidast/recon/annotations.py src/aidast/recon/tools/endpoint_discovery.py src/aidast/recon/tools/playwright_driver.py src/aidast/cli.py
git commit -m "test: preserve recon boundaries during source merge"
```

Stage only files actually changed.

---

### Task 8: Prove the Full Pipeline and Package Boundary

**Files:**
- Modify: `tests/test_merged_pipeline_e2e.py`
- Modify: `tests/test_shared_validation_reporting.py` only for an additional evidence-namespace case.
- Modify: `README.md`

**Interfaces:**
- Consumes: immutable Recon snapshot, v10 materialization, imported Attack workflow with fake transports, current Shared Validation, and current case-based Report.
- Produces: an offline proof that the merged stages interoperate without mutating Recon or weakening report evidence checks.

- [ ] **Step 1: Extend the offline E2E test with one bounded finding**

Use a deterministic fake planner and fake `PolicyService` transport. The test must:

```python
source_before = recon_path.read_bytes()
pipeline_path = materialize_pipeline(handoff_path, root / "Pipeline.db")
attack_result = trusted_attack_workflow.execute(
    pipeline_path, run_id=run_id, authorization=authorization_path,
)
validation_result = validation_coordinator.run("scan")
report_result = report_agent.run(
    pipeline_path, root / "report", platform="hackerone",
    case_id=validation_result.case_ids[0],
)
assert attack_result["status"] == "completed"
assert validation_result.status == "completed"
assert report_result["status"] in {"prepared", "drafted"}
assert recon_path.read_bytes() == source_before
with sqlite3.connect(pipeline_path) as connection:
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
```

The fake transport must be injected explicitly and must assert that the received URL, method, identity, and intent digest equal the signed authorization. No external host is contacted.

- [ ] **Step 2: Add failure-path E2E assertions**

In parameterized cases, tamper with one of: Handoff hash, authorization signature, intent digest, session identity, reproduction contract, Validation evidence ID, and Report case ID. Assert the failure occurs before the next stage and that no downstream terminal success record is created.

- [ ] **Step 3: Run the integrated tests**

Run:

```bash
/tmp/aidast-merge-venv/bin/python -m pytest \
  tests/test_merged_pipeline_e2e.py \
  tests/test_merged_policy_boundaries.py \
  tests/test_shared_validation_reporting.py \
  tests/test_reporting_integration.py -q
```

Expected: PASS with zero live network calls.

- [ ] **Step 4: Update operator documentation**

Document that:

- the imported Attack code is available through `aidast.attack`;
- `aidast attack approve/execute` still requires a trusted injected workflow;
- authorization, intents, policy, durable budget, and session bindings are mandatory;
- Validation and Report continue to use `Pipeline.db` schema v10;
- reports remain local drafts.

- [ ] **Step 5: Run final verification**

Run:

```bash
/tmp/aidast-merge-venv/bin/python scripts/merge_source_inventory.py verify AI-DAST-ALL docs/changes/AI_DAST_ALL_SOURCE_MANIFEST.json
/tmp/aidast-merge-venv/bin/python -m pytest -q
git diff --check
UV_CACHE_DIR=/tmp/aidast-merge-uv-cache uv build
/tmp/aidast-merge-venv/bin/python -c "import aidast.attack, aidast.validation, aidast.reporting; assert hasattr(aidast.attack, 'SessionAttackLauncher')"
```

Expected: source verification exits 0, the entire suite passes, `git diff --check` is silent, build succeeds, and the import smoke test exits 0.

- [ ] **Step 6: Commit**

```bash
git add tests/test_merged_pipeline_e2e.py tests/test_shared_validation_reporting.py README.md
git commit -m "test: prove merged AI DAST pipeline"
```

Stage only files actually changed.

## Final Review Checklist

- [ ] Compare every spec requirement with at least one completed task above.
- [ ] Confirm no selected `AI-DAST-ALL` source hash changed during implementation.
- [ ] Confirm no generated/local file from the nested repository was imported.
- [ ] Confirm current Recon safety tests still fail closed.
- [ ] Confirm `PRAGMA user_version` remains 10 in all pipeline fixtures.
- [ ] Confirm current protocol-runtime and impact-development suites pass.
- [ ] Confirm Report ignores nested Attack evidence namespaces and rejects foreign Validation evidence.
- [ ] Confirm normal CLI invocation cannot create a trusted live workflow from untrusted command-line data.
- [ ] Confirm the full test suite, diff check, build, and installed import smoke test pass.
