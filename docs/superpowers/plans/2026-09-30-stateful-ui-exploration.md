# Stateful Post-Katana UI Exploration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the two shallow AI UI passes with one stateful post-Katana explorer that follows ordinary workflows, records real endpoint observations, and leaves AI tagging in its existing final Recon stage.

**Architecture:** A pure frontier tracks screen and action identity across the whole pass. PlaywrightDriver inventories and executes only host-generated, policy-guarded UI candidates; a structured planner chooses candidate numbers but cannot issue requests. Recon seeds the explorer from the authenticated page and Katana HTML observations, persists each settled action's network evidence, then continues through the existing browser, API, ffuf and final tagging stages.

**Tech Stack:** Python 3, Pydantic, Playwright, SQLite, pytest, TypeScript dashboard, Node test runner.

**Spec:** [Stateful UI exploration design](../specs/2026-09-30-stateful-ui-exploration-design.md).

## Global Constraints

- Default explorer ceiling: 600 elapsed seconds and 50 structured AI decisions per target; the existing 30-page driver allowance and approved request budget also apply.
- Approved Scope is compiled per target. Candidate preflight cannot expand it; proxied requests remain governed by mitmproxy, direct browser requests by PlaywrightDriver's route guard and the same request governor.
- Model input contains bounded sanitized labels and metadata, never raw DOM, cookies, tokens, form values or arbitrary page instructions. Model output selects only a listed candidate number.
- Project creation and other state-changing submissions require the existing account-workflow/form controls and execution policy; read-only Scope must prevent the physical POST. No destructive, payment, invitation, credential or upload workflows.
- Persist browser observations before the later Recon phases. Combined `aidast run` keeps `tag_pending_observations` after Recon; standalone `aidast recon` retains its explicit `--tag-after` behavior. Do not add concurrent tagging.
- Preserve the dirty worktree, including currently untracked UI modules and tests that this plan builds on. Execute against this checkout; inspect `git diff --cached` before each commit and use patch staging for mixed files. Do not include unrelated preexisting hunks in a task commit. Tests use local fixtures, not external targets.

## File map

- Create `src/aidast/ui_testing/frontier.py`: pure screen/action identity, page frontier and attempt tracking.
- Create `src/aidast/ui_testing/forms.py`: bounded synthetic field values and field eligibility.
- Create `src/aidast/ui_testing/explorer.py`: one budgeted model loop and result counters.
- Modify `src/aidast/core/request_governor.py`: read-only remaining scan allowance query for truthful explorer stopping; request admission stays unchanged.
- Modify `src/aidast/recon/tools/playwright_driver.py`: candidate inventory, stable keys and guarded field/action execution; reuse existing request route and workflow checks.
- Modify `src/aidast/recon/tools/endpoint_discovery.py`: replace active pre-Katana AI/priority passes with one post-Katana explorer, persist per-step observations, retain later phases.
- Modify `src/aidast/recon/activity.py` and `WebUI/src/lib/activity.ts` / `activityMessages.ts`: one truthful explorer phase with counters and stop reason.
- Modify focused Python and WebUI tests named below. Keep `src/aidast/recon/annotations.py`, Scope policy and mitmproxy enforcement unchanged unless a failing integration test proves a contract defect.

---

### Task 1: Stable frontier across screens

**Files:**
- Create: `src/aidast/ui_testing/frontier.py`
- Create: `tests/test_ui_explorer_frontier.py`

**Interfaces:**
- Consumes: `canonical_visit_key(url)` from `aidast.recon.tools.page_identity` and candidate dictionaries with `key`, `kind`, `label`.
- Produces: `screen_key(url: str, candidates: list[dict]) -> str`, `ExplorerFrontier(max_pages: int)`, `add_page(url: str) -> bool`, `next_page() -> str | None`, `untried(screen: str, candidates: list[dict]) -> list[dict]`, `mark_attempted(screen: str, candidate_key: str) -> None`, `retire_screen(screen: str) -> None`, and `queued_count: int`.

- [ ] **Step 1: Write failing pure-state tests.** Cover one URL with a newly opened panel, reordered DOM indices, repeated candidates and bounded queue size. Use stable candidate keys, not array positions:

```python
from aidast.ui_testing.frontier import ExplorerFrontier, screen_key

def test_screen_and_attempt_keys_survive_dom_reorder():
    state = ExplorerFrontier(max_pages=30)
    a = [{'index': 3, 'key': 'button:projects', 'kind': 'click', 'label': 'Projects'}]
    b = [{'index': 17, 'key': 'button:projects', 'kind': 'click', 'label': 'Projects'}]
    first = screen_key('https://app.test/work', a)
    assert first == screen_key('https://app.test/work', b)
    state.mark_attempted(first, 'button:projects')
    assert state.untried(first, b) == []
    assert first != screen_key('https://app.test/work', b + [
        {'index': 18, 'key': 'button:new-project', 'kind': 'click', 'label': 'New project'}])
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_ui_explorer_frontier.py -q`; expect import failure for the new module.
- [ ] **Step 3: Implement the pure frontier.** Hash canonical URL plus sorted bounded candidate keys; reject empty/oversized keys; cap queued page URLs at 30 and deduplicate canonical URLs. Store attempts by `(screen, candidate_key)`:

```python
def screen_key(url: str, candidates: list[dict]) -> str:
    keys = sorted({item['key'] for item in candidates[:80] if isinstance(item.get('key'), str)})
    payload = json.dumps([canonical_visit_key(url), keys], separators=(',', ':'))
    return hashlib.sha256(payload.encode()).hexdigest()

def untried(self, screen: str, candidates: list[dict]) -> list[dict]:
    if screen in self.retired_screens:
        return []
    return [item for item in candidates if (screen, item['key']) not in self.attempted]

def retire_screen(self, screen: str) -> None:
    self.retired_screens.add(screen)
```

- [ ] **Step 4: Run** the focused test again; expect all frontier tests to pass, including same-URL panel and queue bounds.
- [ ] **Step 5: Commit only** `frontier.py` and `test_ui_explorer_frontier.py` as `feat: track stateful UI exploration frontier`.

### Task 2: Guarded browser candidate inventory and form fields

**Files:**
- Create: `src/aidast/ui_testing/forms.py`
- Modify: `src/aidast/recon/tools/playwright_driver.py`
- Test: `tests/test_functional_ui_browser.py`
- Test: `tests/test_recon_workflow_browser.py`

**Interfaces:**
- Consumes: existing `list_functional_controls()`, `trigger_safe_actions()`, `visit_path()`, `InteractionConfig.allow_form_submission`, `TargetPolicy` and account-workflow guards.
- Produces: `PlaywrightDriver.list_explorer_candidates() -> list[dict]` with `index`, stable `key`, `label`, `kind` (`click`, `navigation`, `fill`, `select`, `submit`), and host-only handle/path metadata; `PlaywrightDriver.execute_explorer_candidate(*, index: int, key: str, screen: str, deadline: float) -> bool`; `PlaywrightDriver.explorer_form_counts() -> tuple[int, int]` returning unique eligible and blocked form counts; `synthetic_value(field: dict, scan_id: str) -> str | None`.

- [ ] **Step 1: Add failing local browser tests.** A panel reveals an empty required project-name field and a submit button; the candidate inventory offers fill, then submit. Assert the created body uses a scan-specific synthetic name, only one POST reaches the local handler, and read-only policy sends zero POSTs. Assert a stale `key` after rerender performs no action:

```python
fields = driver.list_explorer_candidates()
fill = next(item for item in fields if item['kind'] == 'fill')
screen = screen_key(driver.page.url, fields)
assert driver.execute_explorer_candidate(index=fill['index'], key=fill['key'],
                                         screen=screen, deadline=time.monotonic() + 5)
assert driver.page.locator('input[name="name"]').input_value().startswith('AI-Dast-')
assert not driver.execute_explorer_candidate(index=fill['index'], key='stale',
                                             screen=screen, deadline=time.monotonic() + 5)
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_functional_ui_browser.py -q` with the browser opt-in environment enabled; expect the new inventory method to be missing.
- [ ] **Step 3: Add field eligibility and values in `forms.py`.** Permit visible enabled search/text/select fields with bounded metadata; decline password, file, payment, invitation and ambiguous controls. Generate a bounded project name from the scan ID, never from model text or page contents:

```python
def synthetic_value(field: dict, scan_id: str) -> str | None:
    if field.get('type') in {'password', 'file', 'hidden'} or field.get('sensitive'):
        return None
    if field.get('role') == 'project_name':
        return 'AI-Dast-' + re.sub(r'[^a-zA-Z0-9]', '', scan_id)[:20]
    if field.get('role') == 'search':
        return 'test'
    return None
```

- [ ] **Step 4: Add driver inventory and executor.** Assign stable keys from role, label, field name/form identity, nearest resource/card identity or observed navigation path; suppress only candidates that remain indistinguishable. Derive `project_name` and `search` roles from bounded field name/type/label and the containing form's already classified action. Number existing controls as they are today and fields from index 2000 upward. Count distinct eligible/blocked forms by canonical page URL plus form identity. Offer form fields and submit only when `InteractionConfig.allow_form_submission` and the existing policy/workflow checks permit them; never infer permission from a label. Re-inventory before every action, compare `screen_key` and candidate key, then call existing click/navigation methods or Playwright `fill`/`select_option`. Select only a visible enabled non-placeholder option. Submit through the existing `trigger_safe_actions` validity and workflow checks, retaining its `_workflow_attempted_controls` set so a rerender cannot repeat one creation; never invoke `page.evaluate()` to dispatch a network request:

```python
current = self.list_explorer_candidates()
if screen_key(self._ensure_page().url, current) != screen:
    return False
chosen = next((item for item in current if item['index'] == index and item['key'] == key), None)
if chosen is None or time.monotonic() >= deadline:
    return False
if chosen['kind'] in {'click', 'submit'}:
    return bool(self.trigger_safe_actions(candidate_index=index,
        candidate_label=chosen['label'], candidate_handle=chosen.get('handle'),
        max_actions=1, deadline=deadline))
```

- [ ] **Step 5: Run** browser tests with `AIDAST_WORKFLOW_BROWSER_TEST=1`, plus `tests/test_recon_workflow_browser.py`; require local server evidence that blocked POSTs never arrive and allowed creation arrives once.
- [ ] **Step 6: Commit only** `forms.py`, the driver change and focused tests as `feat: offer guarded UI form actions`.

### Task 3: One budgeted explorer loop

**Files:**
- Create: `src/aidast/ui_testing/explorer.py`
- Modify: `src/aidast/core/request_governor.py`
- Test: `tests/test_ui_explorer.py`
- Test: `tests/test_request_governor.py`
- Test: `tests/test_functional_ui_agent.py`

**Interfaces:**
- Consumes: `ExplorerFrontier`, `screen_key`, `UIPlanner.propose(context) -> UIChoice`, driver methods from Task 2, and `after_step: Callable[[], list[dict]]` supplied by Recon.
- Produces: `RequestGovernor.remaining_scan_requests() -> int`; `StatefulUIExplorer(planner).run(driver, *, seed_urls: list[str], after_step: Callable[[], list[dict]], max_decisions: int = 50, max_seconds: float = 600) -> ExplorerResult`; result fields `pages`, `screens`, `actions`, `decisions`, `completed_forms`, `eligible_forms`, `blocked_forms`, `new_endpoints`, `frontier_remaining`, `stop_reason`.

- [ ] **Step 1: Write failing deterministic tests.** A fake driver starts on a shell, navigates across four HTML pages, opens a same-URL panel and exposes a field. Assert one shared 50-decision allowance, no repeat after index reorder, current-page retry after delayed SPA hydration, no URL or secret in planner input, and continuation after one failed candidate:

```python
result = StatefulUIExplorer(planner).run(
    driver, seed_urls=['https://app.test/work/a', 'https://app.test/work/b',
                       'https://app.test/work/c', 'https://app.test/work/d'],
    after_step=lambda: [], max_decisions=50, max_seconds=600)
assert result.pages >= 4
assert result.decisions <= 50
assert result.stop_reason == 'frontier_exhausted'
assert all('Cookie' not in str(value) for value in planner.contexts)
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_ui_explorer.py tests/test_request_governor.py -q`; expect import failure for `StatefulUIExplorer` and failure of the new read-only allowance assertion.
- [ ] **Step 3: Add a read-only governor allowance query.** Sum charged units for the current program and scan from the existing ledger and subtract from `scan_max_requests`; do not reserve, charge or alter request admission. Raise `GovernorError` if the ledger cannot be read:

```python
def remaining_scan_requests(self) -> int:
    b = self.binding
    if b is None:
        raise GovernorError('shared governor required')
    try:
        with sqlite3.connect(Path(self.path).as_uri() + '?mode=ro',
                             uri=True, timeout=5) as conn:
            used = conn.execute(
                'SELECT coalesce(sum(units),0) FROM governor_requests WHERE program=? AND scan=?',
                (b['program_id'], b['scan_id'])).fetchone()[0]
    except sqlite3.Error as exc:
        raise GovernorError('shared governor ledger unavailable') from exc
    return max(0, b['scan_max_requests'] - used)
```

- [ ] **Step 4: Implement the explorer loop.** Reuse the current `FunctionalUIAgent` checks for authenticated actor and guarded transport. Add only host-vetted current/Katana URLs to `ExplorerFrontier(max_pages=driver.interaction_config.max_pages - driver._interaction_page_count)`; count the current page once if eligible. On each successful navigation, add its canonical URL to `driver._interaction_visited` and increment `driver._interaction_page_count` only for a new page so the later generic pass shares the allowance. Wait at most three seconds for an empty SPA shell. Each iteration checks deadline, 50-decision cap and `RequestGovernor(driver.target_policy.request_governor).remaining_scan_requests()`. Inventory once per screen, offer at most 60 sanitized candidates, count every model call, and mark the stable key before execution. A planner `stop` retires the current screen, then the runner tries another queued GET page. After every visit or action, call `after_step()` and enqueue only observed GET 2xx HTML URLs that pass the same-origin, authentication-page, dangerous-path and TargetPolicy checks:

```python
page_key = canonical_visit_key(driver._ensure_page().url)
if page_key not in driver._interaction_visited:
    driver._interaction_visited.add(page_key)
    driver._interaction_page_count += 1
    pages += 1
inventory = driver.list_explorer_candidates()
current_screen = screen_key(driver._ensure_page().url, inventory)
offered = frontier.untried(current_screen, inventory)[:60]
if offered:
    context = {'controls': [{'index': x['index'], 'label': x['label'],
                             'kind': x['kind']} for x in offered],
               'remaining_steps': max_decisions - decisions,
               'remaining_seconds': max(0, deadline - time.monotonic())}
    choice = UIChoice.model_validate(self.planner.propose(context))
    decisions += 1
    if choice.stop:
        frontier.retire_screen(current_screen)
    else:
        chosen = next((x for x in offered if x['index'] == choice.candidate_index), None)
        if chosen is None:
            return ExplorerResult(
                pages=pages, screens=len(seen_screens), actions=actions,
                decisions=decisions, completed_forms=completed_forms,
                eligible_forms=driver.explorer_form_counts()[0],
                blocked_forms=driver.explorer_form_counts()[1],
                new_endpoints=len(seen_endpoints),
                frontier_remaining=frontier.queued_count + len(
                    frontier.untried(current_screen, inventory)),
                stop_reason='invalid_choice')
        frontier.mark_attempted(current_screen, chosen['key'])
        actions += int(driver.execute_explorer_candidate(
            index=chosen['index'], key=chosen['key'], screen=current_screen,
            deadline=deadline))
    observed = after_step()
```

- [ ] **Step 5: Complete the loop's explicit exits and counters.** Build `ExplorerResult` with all fields from the interface. Count unique method/path keys from `observed`; use `driver.explorer_form_counts()` for eligible/blocked forms and increment completed forms only on successful submit. Define `frontier_remaining` as queued page URLs plus currently offered untried actions; use zero only when both are exhausted. Stop with `frontier_exhausted`, `decision_limit`, `time_limit`, `page_limit`, `request_limit`, `authentication_lost`, `policy_boundary`, `planner_error`, `invalid_choice` or `observation_error`. A single failed candidate is skipped while other candidates remain. Neither a model decision nor a failed candidate can create a fresh budget.

```python
for row in observed:
    if row.get('path'):
        seen_endpoints.add((str(row.get('method', 'GET')).upper(), row['path']))
    status = (row.get('evidence') or {}).get('response_status')
    if (row.get('method') == 'GET' and type(status) is int
            and 200 <= status < 300
            and 'html' in str(row.get('content_type', '')).lower()):
        url = urljoin(driver.base_url.rstrip('/') + '/', row['path'])
        if (driver._same_origin(url) and driver.target_policy.allows_url(url)
                and not is_authentication_page_url(url)
                and not driver._path_looks_dangerous(urlparse(url).path)):
            frontier.add_page(url)
```
- [ ] **Step 6: Run** `tests/test_ui_explorer.py tests/test_request_governor.py tests/test_functional_ui_agent.py`; require exact stop reasons for frontier exhaustion, 50 decisions, 600 seconds, auth loss, request exhaustion and policy boundary. The old bounded agent API stays callable for compatibility tests.
- [ ] **Step 7: Commit only** `explorer.py`, `request_governor.py` and focused tests as `feat: explore UI with one persistent budget`.

### Task 4: Place the explorer after Katana and persist evidence

**Files:**
- Modify: `src/aidast/recon/tools/endpoint_discovery.py`
- Test: `tests/test_recon_workflow_integration.py`
- Test: `tests/test_functional_ui_agent.py`

**Interfaces:**
- Consumes: `StatefulUIExplorer.run(driver, *, seed_urls, after_step, max_decisions, max_seconds)`, Katana `katana_page_urls`/merged results, `observe_browser(phase)` and the current authenticated `PlaywrightDriver`.
- Produces: `run_scoped_ui_exploration(driver, katana_results, *, visit_urls=None, planner=None, model=None, after_step=None) -> ExplorerResult | None` and `playwright_ai_exploration` phase diagnostics.

- [ ] **Step 1: Write failing ordering and persistence tests.** Patch the explorer with a deterministic fake and capture phase calls. Assert `katana_merge < playwright_ai_exploration < playwright_interaction < ffuf`; assert the current page runs even when Katana has no valid HTML seed; assert a browser-observed API is recorded before ffuf seeds are built:

```python
assert phases.index('katana_merge') < phases.index('playwright_ai_exploration')
assert phases.index('playwright_ai_exploration') < phases.index('ffuf')
assert any(item['path'] == '/work/api/from-ui' for item in recorded_observations)
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_recon_workflow_integration.py tests/test_functional_ui_agent.py -q`; expect the new phase and wrapper assertions to fail.
- [ ] **Step 3: Add the wrapper and stage ordering.** Retain passive browser bootstrap, remove calls to the initial four-step AI pass and pre-Katana generic interaction pass, then invoke the new explorer after Katana merge whether or not Katana returned HTML. Filter observed GET 2xx HTML seeds through the existing same-origin, dangerous-path, authentication-page and TargetPolicy checks. Make `observe()` and `observe_browser()` return their filtered observations while preserving their recording side effects; pass `lambda: observe_browser('playwright_ai_exploration')` as `after_step`. The wrapper uses `lambda: []` only for direct test callers that omit `after_step`. Run the generic interaction pass afterward and keep ffuf seeded by browser observations:

```python
diagnose('phase_started', phase='playwright_ai_exploration')
result = run_scoped_ui_exploration(
    driver, katana_results, visit_urls=katana_page_urls, model=recon_model,
    after_step=lambda: observe_browser('playwright_ai_exploration'))
observe_browser('playwright_ai_exploration')
if result is None:
    diagnose('phase_skipped', phase='playwright_ai_exploration',
             reason='guarded_authenticated_scope_required')
else:
    diagnose('phase_completed', phase='playwright_ai_exploration',
             pages=result.pages, screens=result.screens, actions=result.actions,
             decisions=result.decisions, completed_forms=result.completed_forms,
             eligible_forms=result.eligible_forms, blocked_forms=result.blocked_forms,
             new_endpoints=result.new_endpoints,
             frontier_remaining=result.frontier_remaining, reason=result.stop_reason)
```

- [ ] **Step 4: Run** focused workflow, browser transport and Recon policy tests. Verify proxy and direct transports still use their existing request guards and that browser observations survive both drains and final merge.
- [ ] **Step 5: Commit only** endpoint discovery and focused tests as `feat: run stateful UI explorer after Katana`.

### Task 5: Report truthful progress and preserve final tagging

**Files:**
- Modify: `src/aidast/recon/activity.py`
- Modify: `WebUI/src/lib/activity.ts`
- Modify: `WebUI/src/lib/activityMessages.ts`
- Test: `tests/test_recon_diagnostics.py`
- Test: `tests/test_deferred_annotation_evidence.py`
- Test: `tests/test_pipeline_cli.py`
- Test: `WebUI/tests/events.test.mjs`

**Interfaces:**
- Consumes: Task 4 `playwright_ai_exploration` diagnostics and existing final `tag_pending_observations` stage.
- Produces: allowlisted activity fields `pages`, `screens`, `actions`, `decisions`, `completed_forms`, `eligible_forms`, `blocked_forms`, `new_endpoints`, `frontier_remaining` and reasons `frontier_exhausted`, `decision_limit`, `time_limit`, `page_limit`, `request_limit`, `authentication_lost`, `policy_boundary`, `planner_error`, `invalid_choice`, `observation_error`.

- [ ] **Step 1: Write failing activity and tagging tests.** Assert that new counts/reasons survive sanitization without leaking labels or URLs. Store an explorer-phase observation and another tool observation; run `tag_pending_observations` with a fake annotation agent after Recon and assert both are tagged, without a model call during `ObservationRecorder.record`. In the existing combined-run CLI fixture assert event order `recon execute finished < recon tagging started < main review started`:

```python
activity = activity_from_diagnostic('phase_completed', {
    'phase': 'playwright_ai_exploration', 'screens': 5, 'decisions': 12,
    'frontier_remaining': 3, 'reason': 'decision_limit', 'secret': 'drop-me'})
assert activity == {'phase': 'playwright_ai_exploration', 'state': 'finished',
                    'screens': 5, 'decisions': 12, 'frontier_remaining': 3,
                    'reason': 'decision_limit'}

agent = RecordingAgent()
recorder = ObservationRecorder(connection, origin_id=origin_id, scan_id='scan', agent=None)
recorder.record('playwright_ai_exploration', [{
    'method': 'GET', 'path': '/work/api/from-ui',
    'source': 'playwright_ai_exploration',
    'evidence': {'response_status': 200},
}])
recorder.record('ffuf', [{
    'method': 'GET', 'path': '/work/api/from-ffuf',
    'source': 'ffuf', 'evidence': {'response_status': 404},
}])
assert not hasattr(agent, 'prompt')
done, failed = tag_pending_observations(connection, scan_id='scan', agent=agent)
assert (done, failed) == (2, 0)
assert '/work/api/from-ui' in agent.prompt

sequence = [(event['payload']['message_params']['agent'],
             event['payload']['message_params']['step'],
             event['payload']['message_params']['state']) for event in progress]
assert sequence.index(('recon', 'execute', 'finished')) < sequence.index(
    ('recon', 'tagging', 'started')) < sequence.index(('main', 'review', 'started'))
```

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_recon_diagnostics.py tests/test_deferred_annotation_evidence.py tests/test_pipeline_cli.py -q` and `npm test --prefix WebUI`; expect new phase assertions to fail.
- [ ] **Step 3: Add the phase and allowlists.** Include the new phase in both `activity_from_diagnostic` and `validated_activity` AI-reason selection. Display unique screens, actions, decisions, remaining frontier and explicit limit reason in Korean and English. Keep `observation_tagging` after Recon and preserve existing progress/count logic. Do not place tagging inside the explorer:

```python
TOOL_PHASES = TOOL_PHASES | {'playwright_ai_exploration'}
REASON_PHASES = REASON_PHASES | {'playwright_ai_exploration'}
ACTIVITY_COUNTS = ACTIVITY_COUNTS + ('screens', 'completed_forms', 'eligible_forms',
                                     'blocked_forms', 'new_endpoints', 'frontier_remaining')
AI_STOP_REASONS = AI_STOP_REASONS | {'frontier_exhausted', 'decision_limit',
                                     'request_limit', 'authentication_lost', 'policy_boundary',
                                     'observation_error'}
allowed_reasons = (AI_STOP_REASONS if phase == 'playwright_ai_exploration'
                   or phase.startswith('playwright_functional_ai') else STOP_REASONS)
```

- [ ] **Step 4: Run** the Python activity/tagging/CLI tests, `npm test --prefix WebUI` and `npm run build --prefix WebUI`; require passing output and the recorded execute/tagging/review order.
- [ ] **Step 5: Commit only** the activity/frontend/test files as `feat: show stateful UI exploration progress`.

### Task 6: Local end-to-end acceptance and regression

**Files:**
- Test: `tests/test_functional_ui_browser.py`
- Test: `tests/test_recon_workflow_proxy.py`
- Modify: `docs/OPERATIONS.md`

**Interfaces:**
- Consumes: Tasks 1-5 as one integrated Recon run; no new production interface.
- Produces: reproducible local evidence for four-screen exploration, one permitted synthetic creation, blocked read-only POST, observation provenance, final tagging and named budget stops.

- [ ] **Step 1: Add a local multi-screen fixture test.** Serve `/work`, four linked HTML screens, a same-URL modal, search GET and project-creation POST. Use a deterministic planner that chooses visible candidate numbers; assert at least four unique screens and the observed search and creation endpoints. Run the same fixture under a read-only policy and assert the server receives no POST:

```python
assert result.screens >= 4
assert ('GET', '/work/search?q=test') in received
assert received.count(('POST', '/work/projects')) == (0 if read_only else 1)
assert any(row['path'] == '/work/projects' and row['method'] == 'POST'
           for row in driver.get_http_results()) is (not read_only)
```

- [ ] **Step 2: Run** `AIDAST_WORKFLOW_BROWSER_TEST=1 .venv/bin/python -m pytest tests/test_functional_ui_browser.py tests/test_recon_workflow_proxy.py -q`; require the integrated case to pass after Tasks 1-5. If it fails, return to the task that owns the failing contract before completing this acceptance task.
- [ ] **Step 3: Document** the 600-second/50-decision default, Scope egress ownership, read-only form behavior, final tagging and restart requirement for an already running scan in `docs/OPERATIONS.md`. Use a concrete operator note:

```markdown
Katana 이후 AI UI 탐색은 대상당 최대 10분 또는 AI 선택 50회까지 진행합니다.
실제 요청은 프록시 경로에서 mitmproxy addon, 직접 브라우저 경로에서
Playwright 요청 가드가 승인된 Scope와 공유 요청 예산으로 검사합니다.
관측 AI 태깅은 Recon 종료 후 실행합니다. 실행 중인 스캔은 새 코드가
적용되지 않으므로 새 스캔을 시작해야 합니다.
```
- [ ] **Step 4: Run** `AIDAST_WORKFLOW_BROWSER_TEST=1 .venv/bin/python -m pytest tests/test_recon*.py tests/test_functional_ui*.py tests/test_ui_explorer*.py -q`, then `npm test --prefix WebUI` and `npm run build --prefix WebUI`. If sandboxed Chromium cannot launch, rerun only that browser command with the required local permission and record both outcomes.
- [ ] **Step 5: Review** `git diff --check` and the exact changed-file list; commit only the acceptance test and operations note as `test: verify stateful UI exploration locally`.

## Self-review checklist for the implementer

- Every model decision selects an offered candidate; the host validates its stable key after rerender.
- One target gets one 600-second/50-decision allowance and does not stop after three pages unless another limit applies.
- Every actual request stays on the existing policy path; blocked POSTs are absent from the local server log.
- Observations generated during exploration are recorded before ffuf and included in final AI tagging after Recon.
- Limit stops show remaining frontier so the dashboard does not imply complete coverage.
- Existing uncommitted work is not staged or committed by task commits.
