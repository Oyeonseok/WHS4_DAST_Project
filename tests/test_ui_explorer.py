"""The explorer shares one budget across screens and follows live UI state."""
from types import SimpleNamespace

from aidast.recon.policy import RequestGovernorBinding, TargetPolicy
from aidast.scope.models import AssetType
from aidast.ui_testing.agent import UIChoice
from aidast.ui_testing.explorer import StatefulUIExplorer
from aidast.core.request_governor import RequestGovernor


class Driver:
    def __init__(self, tmp_path):
        self.base_url = 'https://example.test/work'
        self.page = SimpleNamespace(url=self.base_url, wait_for_timeout=lambda _ms: None)
        self.target_policy = TargetPolicy(
            scope_id='scope', policy_id='policy', asset_type=AssetType.URL,
            asset=self.base_url, allowed_hosts=['example.test'],
            allowed_path_prefixes=['/work'],
            request_governor=RequestGovernorBinding(
                ledger_path=str(tmp_path / 'ledger.db'), scan_id='scan',
                program_id='program', scan_max_requests=100,
                requests_per_second=10, concurrency=2, request_limits=[]))
        self.interaction_config = SimpleNamespace(max_pages=30)
        self._interaction_page_count = 0
        self._interaction_visited = set()
        self._browser_transport = 'direct'
        self._direct_workers_blocked = True
        self.preauthenticated = True
        self._auth_expired = False
        self.panel = False
        self.executed = []

    def _ensure_page(self): return self.page
    def _same_origin(self, url): return url.startswith('https://example.test/')
    def _path_looks_dangerous(self, path): return False
    def get_auth_headers(self): return {'Cookie': 'sid=secret'}
    def explorer_form_counts(self): return (0, 0)

    def list_explorer_candidates(self):
        if self.page.url.endswith('/work') and not self.panel:
            return [{'index': 0, 'key': 'open-panel', 'kind': 'click', 'label': 'Open panel'}]
        if self.panel and self.page.url.endswith('/work'):
            return [{'index': 8, 'key': 'open-panel', 'kind': 'click', 'label': 'Open panel'},
                    {'index': 9, 'key': 'panel-field', 'kind': 'fill', 'label': 'Search'}]
        return [{'index': 0, 'key': 'visit-action', 'kind': 'click', 'label': 'View details'}]

    def execute_explorer_candidate(self, *, index, key, screen, deadline):
        self.executed.append((self.page.url, key))
        if key == 'open-panel': self.panel = True
        return True

    def visit_path(self, path, **_kwargs):
        self.page.url = 'https://example.test' + path
        return True


class Planner:
    def __init__(self): self.contexts = []
    def propose(self, context):
        self.contexts.append(context)
        return UIChoice(candidate_index=context['controls'][0]['index'], goal='task', stop=False)


def test_one_explorer_visits_four_pages_and_same_url_panel_without_leaking_auth(tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    result = StatefulUIExplorer(planner).run(driver,
        seed_urls=[f'https://example.test/work/{i}' for i in range(4)],
        after_step=lambda: [], max_decisions=50)
    assert result.pages == 5
    assert result.screens >= 6
    assert result.stop_reason == 'frontier_exhausted'
    assert ('https://example.test/work', 'panel-field') in driver.executed
    assert result.decisions <= 50
    assert 'secret' not in str(planner.contexts)
    assert 'example.test' not in str(planner.contexts)


def test_one_shared_decision_limit_reports_remaining_frontier(tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    result = StatefulUIExplorer(planner).run(driver,
        seed_urls=[f'https://example.test/work/{i}' for i in range(4)],
        after_step=lambda: [], max_decisions=2)
    assert result.decisions == 2
    assert result.stop_reason == 'decision_limit'
    assert result.frontier_remaining > 0


def test_observed_html_get_adds_a_new_page_to_the_same_frontier(tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    batches = iter([[{'method': 'GET', 'path': '/work/discovered',
        'content_type': 'text/html', 'evidence': {'response_status': 200}}], []])
    result = StatefulUIExplorer(planner).run(driver, seed_urls=[],
        after_step=lambda: next(batches, []))
    assert result.pages == 2
    assert ('https://example.test/work/discovered', 'visit-action') in driver.executed
    assert result.new_endpoints == 1


def test_failed_candidate_does_not_abort_other_candidates(tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    original = driver.execute_explorer_candidate
    driver.execute_explorer_candidate = lambda **kwargs: (
        False if kwargs['key'] == 'open-panel' else original(**kwargs))
    result = StatefulUIExplorer(planner).run(driver, seed_urls=[], after_step=lambda: [])
    assert result.stop_reason == 'frontier_exhausted'
    assert result.actions == 0


def test_default_fifty_choices_is_one_shared_ceiling(tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    state = {'screen': 0}
    driver.list_explorer_candidates = lambda: [{
        'index': 0, 'key': f'button-{state["screen"]}',
        'kind': 'click', 'label': 'Continue'}]
    def execute(**_kwargs):
        state['screen'] += 1
        return True
    driver.execute_explorer_candidate = execute
    result = StatefulUIExplorer(planner).run(driver, seed_urls=[], after_step=lambda: [])
    assert (result.decisions, result.actions, result.stop_reason) == (50, 50, 'decision_limit')
    assert result.frontier_remaining == 1


def test_request_exhaustion_and_auth_loss_have_distinct_stops(tmp_path):
    driver = Driver(tmp_path)
    binding = driver.target_policy.request_governor
    permit = RequestGovernor(binding).reserve(driver.base_url, units=100)
    permit.complete()
    stopped = StatefulUIExplorer(Planner()).run(driver, seed_urls=[], after_step=lambda: [])
    assert stopped.stop_reason == 'request_limit'
    driver._auth_expired = True
    stopped = StatefulUIExplorer(Planner()).run(driver, seed_urls=[], after_step=lambda: [])
    assert stopped.stop_reason == 'authentication_lost'


def test_current_page_outside_scope_stops_before_a_model_choice(tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    driver.page.url = 'https://outside.test/work'
    result = StatefulUIExplorer(planner).run(driver, seed_urls=[], after_step=lambda: [])
    assert result.stop_reason == 'policy_boundary'
    assert planner.contexts == []


def test_six_hundred_second_ceiling_stops_before_another_choice(monkeypatch, tmp_path):
    driver, planner = Driver(tmp_path), Planner()
    ticks = iter([0.0, 601.0])
    monkeypatch.setattr('aidast.ui_testing.explorer.time.monotonic', lambda: next(ticks))
    result = StatefulUIExplorer(planner).run(driver, seed_urls=[],
        after_step=lambda: [], max_seconds=600)
    assert result.stop_reason == 'time_limit'
    assert result.decisions == 0
