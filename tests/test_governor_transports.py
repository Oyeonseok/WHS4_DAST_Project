import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from test_request_governor import binding, Clock
import test_validation_request_broker as http_fixture
import test_validation_transport_broker as transport_fixture
import test_request_broker as proxy_fixture
from test_attack_request_guard import fixture, FakeOpener
from aidast.attack.request_cli import guarded_request
from aidast.validation.execution.transport_broker import TransportDispatchResult


def setup_fixture(cls):
    f = cls(); f.setUp()
    return f


def test_validation_http_and_browser_share_governor_and_count_once():
    f = setup_fixture(http_fixture.ValidationRequestBrokerTests)
    try:
        f.policy = type(f.policy).model_validate(f.policy.model_dump() | {'request_governor': binding(Path(f.temp.name), scan_max_requests=1)})
        f.broker().request('https://test/items/1', method='GET')
        with sqlite3.connect(Path(f.temp.name) / 'budget.db') as c:
            assert c.execute('SELECT sum(units) FROM governor_requests').fetchone()[0] == 1
        with pytest.raises(ValueError, match='budget'):
            f.broker().begin_observed_request('https://test/items/2', method='GET')
    finally: f.doCleanups()


def test_validation_transport_governor_charges_before_sender():
    f = setup_fixture(transport_fixture.ValidationTransportBrokerTests)
    try:
        f.policy = type(f.policy).model_validate(f.policy.model_dump() | {'request_governor': binding(Path(f.temp.name), scan_max_requests=1)})
        b = f.broker(); calls = []
        b.dispatch(f.spec(), lambda timeout: (calls.append(timeout), TransportDispatchResult('ok', 0))[1])
        with pytest.raises(ValueError, match='budget'):
            b.dispatch(f.spec(1), lambda timeout: calls.append(timeout))
        assert len(calls) == 1
    finally: f.doCleanups()


def test_attack_obeys_shared_budget_before_io(tmp_path):
    database, p, payload, stage, task = fixture(tmp_path, max_requests=5)
    doc = json.loads(p.read_text()); doc['policies'][0]['request_governor'] = binding(tmp_path, scan_max_requests=1)
    p.write_text(json.dumps(doc)); payload.write_text(json.dumps({'url':'https://example.test/api/profile'}))
    opener = FakeOpener()
    with patch('aidast.attack.request_cli.build_opener', return_value=opener):
        guarded_request(database, scan_id='scan', stage_run_id=stage, task_id=task, policy_path=p, payload_path=payload)
        with pytest.raises(ValueError, match='budget'):
            guarded_request(database, scan_id='scan', stage_run_id=stage, task_id=task, policy_path=p, payload_path=payload)
    assert len(opener.calls) == 1


def test_proxy_shared_concurrency_releases_on_error_and_response():
    f = setup_fixture(proxy_fixture.ProxyBoundaryTests)
    try:
        rules = proxy_fixture.policy().mitm_rules(); rules['request_governor'] = binding(f.root, concurrency=1, requests_per_second=50)
        f.configure_rules(rules)
        async def exercise():
            first = f.flow(); await f.addon.request(first)
            second = f.flow()
            pending = asyncio.create_task(f.addon.request(second))
            await asyncio.sleep(0.02)
            assert not pending.done()
            await f.addon.error(first)
            await asyncio.wait_for(pending, 1)
            assert not second.metadata.get('aidast_policy_blocked')
            await f.addon.response(second)
        asyncio.run(exercise())
        with sqlite3.connect(f.root / 'budget.db') as c:
            assert c.execute("SELECT count(*) FROM governor_requests WHERE state='complete'").fetchone()[0] == 2
    finally: f.doCleanups()


def test_validation_redirect_releases_each_body_before_next_hop():
    from test_validation_request_broker import Response
    f = setup_fixture(http_fixture.ValidationRequestBrokerTests)
    try:
        value = binding(Path(f.temp.name), scan_max_requests=2, concurrency=1)
        f.policy = type(f.policy).model_validate(f.policy.model_dump() | {'request_governor': value})
        b = f.broker(); clock = Clock(); b.clock = clock; b.sleeper = clock.sleep
        from aidast.core.request_governor import RequestGovernor, GovernorError
        b.governor = RequestGovernor(value, clock=clock, sleeper=clock.sleep)
        class Body(Response):
            def __init__(self, status, headers): self.status, self.headers = status, headers
            def read(self, maximum):
                with pytest.raises(GovernorError, match='budget|concurrency'):
                    b.governor.reserve('https://test/items/3')
                return b'ok'
        responses = iter([Body(302, {'Location': '/items/2'}), Body(200, {})])
        b.transport = lambda request, timeout: next(responses)
        assert b.request('https://test/items/1', method='GET').body == b'ok'
        with sqlite3.connect(value['ledger_path']) as c:
            assert c.execute("SELECT count(*) FROM governor_requests WHERE state='complete'").fetchone()[0] == 2
    finally: f.doCleanups()


def test_malformed_proxy_binding_blocks_even_observation_mode():
    f = setup_fixture(proxy_fixture.ProxyBoundaryTests)
    try:
        rules = proxy_fixture.policy().mitm_rules(); rules['request_governor'] = {}
        f.addon.enforcement_required = False
        f.configure_rules(rules)
        flow = f.flow(); asyncio.run(f.addon.request(flow))
        assert flow.metadata.get('aidast_policy_blocked')
    finally: f.doCleanups()


def test_playwright_capacity_remains_held_until_physical_fetch_finishes():
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from aidast.core.request_governor import RequestGovernor, GovernorError
    from aidast.validation.execution.playwright_browser import PlaywrightBrowserExecutor
    f = setup_fixture(http_fixture.ValidationRequestBrokerTests)
    try:
        value = binding(Path(f.temp.name), concurrency=1)
        f.policy = type(f.policy).model_validate(f.policy.model_dump() | {'request_governor': value})
        callbacks = {}; context = MagicMock(); page = context.new_page.return_value
        page.url = 'https://test/items/1'
        context.on.side_effect = lambda name, fn: callbacks.update({name: fn})
        context.route.side_effect = lambda pattern, fn: callbacks.update({'route': fn})
        request = SimpleNamespace(url=page.url, method='GET', headers={}, post_data_buffer=None, is_navigation_request=lambda: True)
        def navigate(*args, **kwargs):
            route = MagicMock()
            fetched = MagicMock(status=200, headers={})
            def fetch(**kwargs):
                assert kwargs['max_redirects'] == kwargs['max_retries'] == 0
                with pytest.raises(GovernorError, match='concurrency'):
                    RequestGovernor(value).reserve('https://test/items/2')
                return fetched
            route.fetch.side_effect = fetch
            callbacks['route'](route, request)
            route.continue_.assert_not_called()
            route.fulfill.assert_called_once_with(response=fetched)
            fetched.dispose.assert_called_once()
        page.goto.side_effect = navigate
        playwright = MagicMock(); playwright.chromium.launch.return_value.new_context.return_value = context
        manager = MagicMock(); manager.__enter__.return_value = playwright
        with patch('playwright.sync_api.sync_playwright', return_value=manager):
            result = PlaywrightBrowserExecutor()(url=page.url, headers={}, wait_ms=0,
                selectors=(), attributes={}, policy=f.policy, db_path=f.path, scan_id='scan',
                stage_run_id='stage', case_id='case', attempt_id='attempt')
        assert len(result.request_ids) == 1
        RequestGovernor(value).reserve('https://test/items/2').complete()
    finally: f.doCleanups()
