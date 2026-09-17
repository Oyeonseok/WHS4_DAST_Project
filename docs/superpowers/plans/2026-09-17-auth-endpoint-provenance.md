# Authentication Endpoint Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve sanitized login endpoint metadata across session creation and restoration so Recon assigns stable endpoint IDs without replaying authentication requests.

**Architecture:** A small authentication-endpoint value object validates and deduplicates passive request coordinates. Both system-browser login transports emit those coordinates into `Session.json`; `TargetSession` exposes them to `ReconExecutor`, which imports same-origin entries through `ObservationRecorder` and emits a diagnostic for legacy bundles. Runtime-browser reauthentication uses the same recorder before policy handlers are installed, while active Recon request methods remain unchanged.

**Tech Stack:** Python 3.13, Playwright sync API/CDP, PowerShell CDP transport, SQLite, pytest/unittest

**Spec:** `docs/superpowers/specs/2026-09-17-auth-endpoint-provenance-design.md`

## Global Constraints

- Never persist passwords, tokens, cookies, authorization headers, query strings, request bodies, or response bodies as authentication endpoint metadata.
- Do not replay login requests when restoring a session.
- Keep active Recon methods limited to `GET`, `HEAD`, and `OPTIONS`.
- Keep legacy bundles valid and distinguish an absent metadata field from a present empty array.
- Do not weaken the Attack requirement for a Recon-backed endpoint ID.
- Import only same-target endpoints into the target Recon origin; configured external authentication hosts remain bootstrap context, not target endpoints.

## File map

- Create `src/aidast/auth/endpoints.py`: immutable endpoint type, URL sanitization, strict bundle parsing, and deduplication.
- Create `tests/test_auth_endpoints.py`: pure contract tests for the new module.
- Modify `src/aidast/auth/browser.py`: session bundle serialization/loading and native Chrome request observation.
- Modify `src/aidast/auth/browser_login_windows.ps1`: Windows CDP request observation and sanitized export.
- Modify `src/aidast/cli.py`: pass configured authentication bootstrap boundaries into session collection.
- Modify `src/aidast/recon/executor.py`: import restored authentication endpoints and report legacy provenance.
- Modify `src/aidast/recon/tools/playwright_driver.py`: attach a passive request observer before manual login and reauthentication.
- Modify `tests/test_auth.py`: Windows script contract.
- Modify `tests/test_recon_browser_transport.py`: runtime login observation sequencing and safe filtering.
- Modify `tests/test_recon_workflow.py`: restored-session import and legacy diagnostics.
- Modify `tests/test_attack_request_guard.py`: imported endpoint can ground an Attack request/finding path.

---

### Task 1: Authentication endpoint value object

**Files:**
- Create: `src/aidast/auth/endpoints.py`
- Create: `tests/test_auth_endpoints.py`

**Interfaces:**
- Produces: `AuthenticationEndpoint(method: str, origin: str, path: str, source: str = "auth_bootstrap", observed_at: str | None = None)`
- Produces: `AuthenticationEndpoint.from_request(method: str, url: str, *, target_origin: str, allowed_bootstrap_origins: frozenset[str] = frozenset(), observed_at: str | None = None) -> AuthenticationEndpoint | None`
- Produces: `parse_authentication_endpoints(raw: object, *, target_origin: str, allowed_bootstrap_origins: frozenset[str] = frozenset()) -> tuple[AuthenticationEndpoint, ...]`
- Produces: `serialize_authentication_endpoints(items: Iterable[AuthenticationEndpoint]) -> list[dict[str, str]]`

- [ ] **Step 1: Write failing sanitization and deduplication tests**

```python
def test_request_metadata_discards_query_fragment_and_deduplicates():
    first = AuthenticationEndpoint.from_request(
        "post", "https://example.test/rest/user/login?token=secret#fragment",
        target_origin="https://example.test",
        observed_at="2026-09-17T01:02:03Z",
    )
    second = AuthenticationEndpoint.from_request(
        "POST", "https://example.test/rest/user/login?password=other",
        target_origin="https://example.test",
    )
    parsed = parse_authentication_endpoints(
        [first.to_bundle_dict(), second.to_bundle_dict()],
        target_origin="https://example.test",
    )
    assert [(item.method, item.origin, item.path) for item in parsed] == [
        ("POST", "https://example.test", "/rest/user/login")
    ]
    assert "secret" not in json.dumps(serialize_authentication_endpoints(parsed))


@pytest.mark.parametrize("raw", [
    [{"method": "POST", "origin": "https://example.test", "path": "/login?x=1", "source": "auth_bootstrap"}],
    [{"method": "POST", "origin": "https://user@example.test", "path": "/login", "source": "auth_bootstrap"}],
    [{"method": "POST", "origin": "file://example.test", "path": "/login", "source": "auth_bootstrap"}],
    [{"method": "POST", "origin": "https://evil.test", "path": "/login", "source": "auth_bootstrap"}],
    [{"method": "POST", "origin": "https://example.test", "path": "/login", "source": "auth_bootstrap", "body": "secret"}],
])
def test_bundle_parser_rejects_unsafe_or_unknown_fields(raw):
    with pytest.raises(AuthenticationEndpointError):
        parse_authentication_endpoints(raw, target_origin="https://example.test")
```

- [ ] **Step 2: Run the tests and confirm RED**

Run: `uv run pytest -q tests/test_auth_endpoints.py`

Expected: collection fails because `aidast.auth.endpoints` does not exist.

- [ ] **Step 3: Implement the immutable validated contract**

```python
_FIELDS = {"method", "origin", "path", "source", "observed_at"}

@dataclass(frozen=True, slots=True)
class AuthenticationEndpoint:
    method: str
    origin: str
    path: str
    source: str = "auth_bootstrap"
    observed_at: str | None = None

    @classmethod
    def from_request(cls, method, url, *, target_origin,
                     allowed_bootstrap_origins=frozenset(), observed_at=None):
        parsed = urlsplit(url)
        candidate_origin = normalize_origin(url)
        if candidate_origin not in {target_origin, *allowed_bootstrap_origins}:
            return None
        return cls(method.upper(), candidate_origin, parsed.path or "/",
                   observed_at=observed_at)

    def to_bundle_dict(self) -> dict[str, str]:
        result = {"method": self.method, "origin": self.origin,
                  "path": self.path, "source": self.source}
        if self.observed_at is not None:
            result["observed_at"] = self.observed_at
        return result
```

Add strict method/origin/path/source validation, reject unknown fields, normalize default ports, and return deterministic deduplicated tuples keyed by `(method, origin, path)`.

- [ ] **Step 4: Run the focused tests and confirm GREEN**

Run: `uv run pytest -q tests/test_auth_endpoints.py`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/aidast/auth/endpoints.py tests/test_auth_endpoints.py
git commit -m "feat(auth): define authentication endpoint metadata"
```

---

### Task 2: Session bundle metadata contract

**Files:**
- Modify: `src/aidast/auth/browser.py:65-112,189-242`
- Modify: `tests/test_auth_endpoints.py`

**Interfaces:**
- Consumes: `parse_authentication_endpoints(...)` and `serialize_authentication_endpoints(...)` from Task 1.
- Produces: `TargetSession.authentication_endpoints: tuple[AuthenticationEndpoint, ...]`
- Produces: `TargetSession.has_authentication_endpoint_provenance: bool`
- Produces: `TargetSession.replace_authentication_endpoints(items: Iterable[AuthenticationEndpoint]) -> None`
- Changes: capture callables return storage-state keys plus optional `authentication_endpoints`.

- [ ] **Step 1: Write failing new-bundle, legacy-bundle, and refresh tests**

```python
def test_collect_session_persists_sanitized_authentication_endpoints(tmp_path):
    raw = storage_state()
    raw["authentication_endpoints"] = [
        {"method": "POST", "url": "https://example.test/rest/user/login?token=secret",
         "observed_at": "2026-09-17T01:02:03Z"}
    ]
    sessions = collect_target_sessions(
        [target("https://example.test")], scope_id="scope", run_id="run",
        identity="primary", start_urls={("URL", "https://example.test"): "https://example.test"},
        root=tmp_path, capture=lambda *_: raw,
    )
    session = next(iter(sessions.values()))
    assert session.has_authentication_endpoint_provenance is True
    assert session.authentication_endpoints[0].path == "/rest/user/login"
    assert "secret" not in session.bundle_path.read_text()


def test_legacy_bundle_loads_without_endpoint_provenance(tmp_path):
    bundle = write_legacy_bundle(tmp_path)
    session = load_session(bundle, scope_id="scope", asset_type="URL",
                           asset="https://example.test", identity="primary")
    assert session.has_authentication_endpoint_provenance is False
    assert session.authentication_endpoints == ()


def test_reauthentication_replaces_bundle_endpoint_set(tmp_path):
    session = write_session(tmp_path, endpoints=[post("/old-login")])
    session.replace_authentication_endpoints([post("/rest/user/login")])
    reloaded = load_session(session.bundle_path, scope_id="scope", asset_type="URL",
                            asset="https://example.test", identity="primary")
    assert [item.path for item in reloaded.authentication_endpoints] == ["/rest/user/login"]
```

- [ ] **Step 2: Run the tests and confirm RED**

Run: `uv run pytest -q tests/test_auth_endpoints.py`

Expected: failures show missing `TargetSession` endpoint properties and bundle serialization.

- [ ] **Step 3: Implement bundle load, save, and atomic refresh**

Extend `TargetSession` with the immutable endpoint tuple and a provenance boolean. Parse the optional field in `load_session()` and `TargetSession.verify()`. In `collect_target_sessions()`, transform raw `{method, url, observed_at}` records through `AuthenticationEndpoint.from_request()` before writing:

```python
bundle_doc = {
    "schema_version": "1.1",
    # existing binding and sha256 fields
    "authentication_endpoints": serialize_authentication_endpoints(endpoints),
}
```

Implement refresh as a read-validate-rewrite using the existing `_write()` function so permissions remain `0600`. Preserve all unrelated bundle keys and replace only `authentication_endpoints`.

- [ ] **Step 4: Run focused bundle tests and existing session tests**

Run: `uv run pytest -q tests/test_auth_endpoints.py tests/test_recon_browser_transport.py -k 'session or authentication_endpoint'`

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/aidast/auth/browser.py tests/test_auth_endpoints.py
git commit -m "feat(auth): persist login endpoint provenance"
```

---

### Task 3: Observe login requests in both system-browser transports

**Files:**
- Modify: `src/aidast/auth/browser.py:121-187`
- Modify: `src/aidast/auth/browser_login_windows.ps1`
- Modify: `src/aidast/cli.py:683-699`
- Modify: `tests/test_auth.py`
- Modify: `tests/test_auth_endpoints.py`

**Interfaces:**
- Consumes: `AuthenticationEndpoint.from_request(...)` from Task 1.
- Produces: raw capture document field `authentication_endpoints: list[{method, origin, path, source, observed_at?}]`; request URLs exist only in observer memory and are sanitized before capture output is returned.

- [ ] **Step 1: Write failing native sequencing and Windows contract tests**

```python
def test_native_capture_observes_requests_before_operator_confirmation(tmp_path):
    events = []
    context = fake_cdp_context(events)
    with patched_native_chrome(context, input_fn=lambda _: events.append("confirm")):
        raw = _capture_native("https://example.test", tmp_path / "login-export.json")
    assert events.index("request-listener-installed") < events.index("confirm")
    assert raw["authentication_endpoints"] == [
        {"method": "POST", "url": "https://example.test/rest/user/login",
         "observed_at": ANY_TIMESTAMP}
    ]


def test_windows_login_records_network_requests_before_read_host():
    script = files("aidast.auth").joinpath("browser_login_windows.ps1").read_text()
    assert "Network.enable" in script
    assert "Network.requestWillBeSent" in script
    assert script.index("Network.enable") < script.index("Read-Host")
    assert "authentication_endpoints" in script
```

- [ ] **Step 2: Run the tests and confirm RED**

Run: `uv run pytest -q tests/test_auth.py tests/test_auth_endpoints.py -k 'native_capture or windows_login'`

Expected: native listener and Windows network capture assertions fail.

- [ ] **Step 3: Attach the native observer before login**

Move CDP readiness and `connect_over_cdp()` before the input prompt. Register `context.on("request", callback)` before the operator interacts. The callback appends only `method`, `url`, and UTC `observed_at` to an in-memory list. Do not install routes, a proxy, or request mutation. After storage export, return the list under `authentication_endpoints`; `collect_target_sessions()` immediately sanitizes it.

- [ ] **Step 4: Attach the Windows CDP observer before login**

Before `Read-Host`, enable target auto-attach and `Network.enable` for page sessions. Extend the CDP receive loop so `Network.requestWillBeSent` events append only method, URL, and timestamp to `$authenticationEndpoints`; continue routing command responses by ID. Export that array with cookies/origins/session storage. Do not export event headers or post data.

- [ ] **Step 5: Verify target-origin filtering and policy tests**

Confirm both browser transports discard external identity-provider coordinates
from target endpoint provenance. Authentication bootstrap configuration remains
available for browser navigation but does not turn another origin into a target
Recon endpoint.

Run: `uv run pytest -q tests/test_auth.py tests/test_auth_endpoints.py tests/test_recon_policy.py`

Expected: all tests pass and policy tests still show safe active methods.

- [ ] **Step 6: Commit**

```bash
git add src/aidast/auth/browser.py src/aidast/auth/browser_login_windows.ps1 src/aidast/cli.py tests/test_auth.py tests/test_auth_endpoints.py
git commit -m "feat(auth): observe login endpoint metadata"
```

---

### Task 4: Import restored and runtime authentication endpoints into Recon

**Files:**
- Modify: `src/aidast/recon/executor.py:342-362,561-665`
- Modify: `src/aidast/recon/tools/playwright_driver.py:1198-1230,1231-1270`
- Modify: `src/aidast/recon/tools/endpoint_discovery.py:1683-1723`
- Modify: `tests/test_recon_workflow.py`
- Modify: `tests/test_recon_browser_transport.py`

**Interfaces:**
- Consumes: `TargetSession.authentication_endpoints` and provenance boolean from Task 2.
- Produces: `ReconExecutor._import_authentication_endpoints(task, origin_id, session) -> int`.
- Produces: Playwright result rows with `source="auth_bootstrap"`, `discovery_kind="passive_login_observation"`, and `browser_supporting_request=True`.
- Changes: runtime reauthentication passes observed rows back to `TargetSession.replace_authentication_endpoints()` after successful session save.

- [ ] **Step 1: Write failing restored-session import tests**

```python
def test_origin_discovery_imports_login_endpoint_without_sending_request(tmp_path):
    executor, task, session = executor_with_session(
        tmp_path, endpoints=[post("/rest/user/login")]
    )
    executor._handle_origin_discovery(task)
    row = executor.conn.execute(
        "SELECT method,normalized_path,source_tools FROM endpoints"
    ).fetchone()
    assert row == ("POST", "/rest/user/login", "auth_bootstrap")
    observation = executor.conn.execute(
        "SELECT discovery_kind,source_tool FROM endpoint_observations"
    ).fetchone()
    assert observation == ("passive_login_observation", "auth_bootstrap")
    executor.http_client.assert_not_called()


def test_legacy_session_emits_missing_provenance_diagnostic(tmp_path):
    executor, task, _ = executor_with_legacy_session(tmp_path)
    executor._handle_origin_discovery(task)
    assert diagnostic_events(executor, "auth_endpoint_provenance_missing") == [{
        "task_id": task.task_id,
        "target": task.target.asset,
    }]
```

- [ ] **Step 2: Run the workflow tests and confirm RED**

Run: `uv run pytest -q tests/test_recon_workflow.py -k 'login_endpoint or provenance'`

Expected: no imported endpoint or diagnostic exists.

- [ ] **Step 3: Implement idempotent Recon import**

After origin creation and before endpoint discovery, call `ObservationRecorder.record("auth_bootstrap", items)` for entries whose origin equals the execution origin. Each item must use:

```python
{
    "method": endpoint.method,
    "path": endpoint.path,
    "url": endpoint.origin + endpoint.path,
    "source": "auth_bootstrap",
    "discovery_kind": "passive_login_observation",
    "observed_at": endpoint.observed_at,
    "context": {"association_method": "session_bundle", "auth_state": "authenticated"},
}
```

If the bundle field is absent, emit `auth_endpoint_provenance_missing`. Do not emit this diagnostic for a present empty array. Rely on endpoint uniqueness for idempotence.

- [ ] **Step 4: Write failing runtime reauthentication tests**

Update the expected manual-login sequence so `_attach_manual_browser()` and a passive request listener are installed before `_wait_for_manual_login()`. Simulate a POST login request containing a secret query value and assert `get_http_results()` exposes only the normalized path and safe metadata. Assert successful reauthentication replaces bundle metadata through a supplied refresh callback; cancelled or failed login does not refresh it.

- [ ] **Step 5: Run runtime tests and confirm RED**

Run: `uv run pytest -q tests/test_recon_browser_transport.py -k 'manual_session or reauthentication or login_endpoint'`

Expected: the current attachment order and missing refresh callback fail.

- [ ] **Step 6: Implement passive runtime observation and refresh**

Attach the CDP browser before waiting for the operator, but install only the new passive request callback during `_phase == "login"`; install routing and active policy handlers only after login succeeds. Emit sanitized authentication result rows. Add an optional `authentication_endpoint_callback` to `ManualSessionConfig`; `ReconExecutor` supplies `session.replace_authentication_endpoints` for restored sessions. Invoke it only after `save_session()` succeeds.

- [ ] **Step 7: Verify Recon behavior**

Run: `uv run pytest -q tests/test_recon_workflow.py tests/test_recon_browser_transport.py tests/test_recon_annotations.py tests/test_recon_policy.py`

Expected: all tests pass; the safe-method policy assertions remain unchanged.

- [ ] **Step 8: Commit**

```bash
git add src/aidast/recon/executor.py src/aidast/recon/tools/playwright_driver.py src/aidast/recon/tools/endpoint_discovery.py tests/test_recon_workflow.py tests/test_recon_browser_transport.py
git commit -m "feat(recon): import authentication endpoint provenance"
```

---

### Task 5: Attack grounding regression and full verification

**Files:**
- Modify: `tests/test_attack_request_guard.py`
- Modify: `docs/superpowers/plans/2026-09-17-auth-endpoint-provenance.md` (check completed steps only)

**Interfaces:**
- Consumes: the normal Recon `endpoints.endpoint_id` created by Task 4.
- Verifies: existing Attack request authorization, attempt persistence, and finding commit paths require no production-code relaxation.

- [ ] **Step 1: Write the failing end-to-end persistence regression**

Create a completed Recon scan with a restored session containing `POST /rest/user/login`, run the Recon import, then use the existing Attack DB/request helpers. Assert the request is recorded as `network_observed` with the imported endpoint ID, a lead uses the same ID, and `commit_finding()` promotes the lead without `a finding reproduction requires endpoint_id` or endpoint mismatch errors.

```python
assert request_row["endpoint_provenance"] == "network_observed"
assert request_row["endpoint_reference_id"] == imported_endpoint_id
assert attempt_row["endpoint_id"] == imported_endpoint_id
assert finding_row["endpoint_id"] == imported_endpoint_id
```

- [ ] **Step 2: Run the regression test and confirm RED if integration wiring is incomplete**

Run: `uv run pytest -q tests/test_attack_request_guard.py -k 'authentication_endpoint_provenance'`

Expected before any necessary wiring adjustment: failure identifies the exact missing endpoint association. If it passes immediately, remove any proposed Attack production change because existing grounding already consumes the Recon endpoint correctly.

- [ ] **Step 3: Make only the minimal integration adjustment, if RED requires one**

Do not relax `commit_finding()`. Any required change must be limited to resolving the existing `(method, normalized_path, origin)` endpoint row in the request guard. If Step 2 passes, make no production change in this step.

- [ ] **Step 4: Run focused security and persistence tests**

Run: `uv run pytest -q tests/test_auth_endpoints.py tests/test_auth.py tests/test_recon_workflow.py tests/test_recon_browser_transport.py tests/test_recon_annotations.py tests/test_recon_policy.py tests/test_attack_request_guard.py tests/test_attack_cli.py`

Expected: all selected tests pass with no warnings or errors.

- [ ] **Step 5: Run formatting and full regression verification**

Run: `git diff --check`

Expected: no output and exit code 0.

Run: `uv run pytest -q`

Expected: the complete suite passes; only the repository's documented intentional skips may remain.

- [ ] **Step 6: Commit**

```bash
git add tests/test_attack_request_guard.py docs/superpowers/plans/2026-09-17-auth-endpoint-provenance.md
git commit -m "test(attack): cover restored login endpoint grounding"
```
