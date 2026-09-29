"""Exercise the shared limits used by dashboard Recon, across broker and proxy."""
import asyncio
import inspect
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from aidast.core.request_broker import RequestBroker, RequestPolicyError
from aidast.core.request_governor import RequestGovernor, GovernorError
from aidast.recon.tools.api_secondary_discovery import _request_broker
import test_request_broker as proxy_fixture
from test_request_governor import binding


@pytest.fixture
def proxy():
    fixture = proxy_fixture.ProxyBoundaryTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.doCleanups()


def configure(proxy, **changes):
    value = binding(proxy.root, **(dict(concurrency=1, requests_per_second=50,
                    scan_max_requests=100) | changes))
    target = type(proxy_fixture.policy()).model_validate(proxy_fixture.policy().model_dump() | {'request_governor': value})
    proxy.configure_rules(target.mitm_rules())
    return target, value


def charges(value):
    with sqlite3.connect(value['ledger_path']) as conn:
        return conn.execute('SELECT sum(units),sum(capacity) FROM governor_requests').fetchone()


def run_request(addon, flow):
    result = addon.request(flow)
    if inspect.isawaitable(result):
        asyncio.run(result)


def test_api_broker_through_proxy_charges_one_request_at_concurrency_one(proxy):
    target, value = configure(proxy)
    statuses = []

    def send(request, timeout):
        flow = proxy.flow()
        flow.request.pretty_url = request.full_url
        flow.request.headers = dict(request.header_items())
        run_request(proxy.addon, flow)
        status = 403 if flow.metadata.get('aidast_policy_blocked') else 200
        statuses.append(status)
        asyncio.run(proxy.addon.error(flow))
        return proxy_fixture.response(status, {'Content-Type': 'application/json'}, b'{"items":[]}')

    with patch('aidast.recon.tools.api_secondary_discovery.build_opener') as opener:
        opener.return_value.open.side_effect = send
        result = _request_broker(target, 'http://127.0.0.1:8080').request(
            'https://example.com/app/items')
    assert result.status_code == 200
    assert statuses == [200]
    assert charges(value) == (1, 1)


def test_direct_broker_keeps_shared_budget_and_scope_checks(proxy):
    target, value = configure(proxy, scan_max_requests=1)
    sent = []

    def send(request, timeout):
        sent.append(request.full_url)
        return proxy_fixture.response()

    broker = RequestBroker(target, transport=send)
    broker.request('https://example.com/app')
    with pytest.raises(RequestPolicyError, match='budget'):
        broker.request('https://example.com/app/second')
    with pytest.raises(RequestPolicyError, match='destination'):
        broker.request('https://foreign.example/app')
    assert len(sent) == 1
    assert charges(value) == (1, 1)


def test_browser_burst_waits_without_blocking_proxy_response_hooks(proxy):
    _target, value = configure(proxy)
    assert inspect.iscoroutinefunction(proxy.addon.request)
    admitted, active = [], 0
    peak = 0

    async def send(index):
        nonlocal active, peak
        flow = proxy.flow()
        flow.request.pretty_url += f'/items/{index}'
        await proxy.addon.request(flow)
        assert not flow.metadata.get('aidast_policy_blocked')
        active += 1
        peak = max(peak, active)
        admitted.append(index)
        await asyncio.sleep(0.015)
        active -= 1
        await proxy.addon.response(flow)

    async def burst():
        await asyncio.wait_for(asyncio.gather(*(send(i) for i in range(4))), 2)

    asyncio.run(burst())
    assert len(admitted) == 4
    assert peak == 1
    assert proxy.addon.request_count == 4
    assert proxy.addon.blocked_request_count == 0
    assert charges(value) == (4, 4)


def test_async_admission_waits_for_rolling_quota(proxy):
    _target, value = configure(proxy, request_limits=[dict(
        maximum=1, period_seconds=0.08, scope='program', source_quote='one per window')])
    assert inspect.iscoroutinefunction(proxy.addon.request)
    times = []

    async def send(index):
        flow = proxy.flow()
        flow.request.pretty_url += f'/items/{index}'
        await proxy.addon.request(flow)
        assert not flow.metadata.get('aidast_policy_blocked')
        times.append(time.monotonic())
        await proxy.addon.response(flow)

    async def burst():
        await asyncio.wait_for(asyncio.gather(send(1), send(2), send(3)), 2)

    asyncio.run(burst())
    assert len(times) == 3
    # Measure the ledger's dispatch times. Recording a coroutine's return can
    # be delayed by unrelated CPU scheduling after its permit is dispatched.
    with sqlite3.connect(value['ledger_path']) as conn:
        dispatched = [row[0] for row in conn.execute('SELECT charged FROM governor_requests ORDER BY charged')]
    assert all(right - left >= 0.075 for left, right in zip(dispatched, dispatched[1:]))
    assert charges(value) == (3, 3)


def test_queued_proxy_requests_recheck_priority_budget(proxy):
    _target, value = configure(proxy)
    proxy.addon.rules.update(max_requests=2, budget_total=2)
    assert inspect.iscoroutinefunction(proxy.addon.request)
    forwarded = []

    async def send(index):
        flow = proxy.flow()
        flow.request.pretty_url += f'/items/{index}'
        await proxy.addon.request(flow)
        if not flow.metadata.get('aidast_policy_blocked'):
            forwarded.append(index)
            await asyncio.sleep(0.015)
            await proxy.addon.response(flow)

    async def burst():
        occupied = proxy.addon.governor.reserve('https://example.com/app')
        occupied.wait()
        tasks = [asyncio.create_task(send(i)) for i in (1, 2, 3)]
        await asyncio.sleep(0.03)
        await occupied.complete_async()
        await asyncio.wait_for(asyncio.gather(*tasks), 2)

    asyncio.run(burst())
    assert len(forwarded) == 1  # One unit remains reserved for browser traffic.
    assert proxy.addon.request_count == 1
    assert proxy.addon.blocked_request_count == 2
    assert charges(value) == (2, 2)  # Occupied permit plus one physical request.


def test_cancelled_async_pacing_releases_reserved_capacity(tmp_path):
    value = binding(tmp_path, concurrency=1, requests_per_second=1, scan_max_requests=10)
    governor = RequestGovernor(value)
    assert callable(getattr(governor, 'acquire_async', None))
    first = governor.reserve('https://example.com/app')
    first.wait()
    first.complete()

    async def cancel():
        task = asyncio.create_task(governor.acquire_async('https://example.com/app', timeout_seconds=1))
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    with sqlite3.connect(value['ledger_path']) as conn:
        assert conn.execute("SELECT count(*) FROM governor_requests WHERE state!='complete'").fetchone()[0] == 0


def test_async_capacity_wait_is_bounded_and_does_not_spend_budget(tmp_path):
    value = binding(tmp_path, concurrency=1)
    governor = RequestGovernor(value)
    assert callable(getattr(governor, 'acquire_async', None))
    first = governor.reserve('https://example.com/app')
    first.wait()
    start = time.monotonic()
    try:
        with pytest.raises(GovernorError, match='deadline|timeout'):
            asyncio.run(governor.acquire_async('https://example.com/app', timeout_seconds=0.05))
    finally:
        first.complete()
    assert time.monotonic() - start < 0.5
    assert charges(value) == (1, 1)


def test_async_permanent_quota_rejects_without_waiting(tmp_path):
    value = binding(tmp_path, request_limits=[dict(maximum=1, period_seconds=None,
                    scope='program', source_quote='one total')])
    governor = RequestGovernor(value)
    assert callable(getattr(governor, 'acquire_async', None))
    first = governor.reserve('https://example.com/app')
    first.wait()
    first.complete()
    start = time.monotonic()
    with pytest.raises(GovernorError, match='quota'):
        asyncio.run(governor.acquire_async('https://example.com/app', timeout_seconds=1))
    assert time.monotonic() - start < 0.2


def test_web_launch_accepts_unlimited_ffuf_runtime_without_changing_request_caps():
    from aidast.web.launch import ScanLaunchRequest
    request = ScanLaunchRequest(scope_id='test', targets=['example.test'],
                               authorization_confirmed=True, ffuf_max_time_seconds=0)
    assert request.ffuf_max_time_seconds == 0
    assert request.max_requests == 500
    with pytest.raises(ValueError):
        ScanLaunchRequest(scope_id='test', targets=['example.test'], authorization_confirmed=True,
                          ffuf_max_time_seconds=-1)


def test_policy_proxy_receives_the_configured_request_timeout(proxy):
    target, _ = configure(proxy)
    assert target.mitm_rules()['timeout_seconds'] == target.limits.timeout_seconds


def test_async_admission_remains_responsive_during_an_external_ledger_lock(tmp_path):
    value = binding(tmp_path, concurrency=1)
    governor = RequestGovernor(value)
    first = governor.reserve('https://example.com/app'); first.wait(); first.complete()
    lock = sqlite3.connect(value['ledger_path'], isolation_level=None)
    lock.execute('BEGIN IMMEDIATE')
    ticks = []
    async def exercise():
        async def heartbeat():
            for _ in range(4):
                await asyncio.sleep(0.005)
                ticks.append(time.monotonic())
        task = asyncio.create_task(heartbeat())
        with pytest.raises(GovernorError, match='deadline|timeout'):
            await governor.acquire_async('https://example.com/app', timeout_seconds=0.03)
        await task
    started = time.monotonic()
    try:
        asyncio.run(exercise())
    finally:
        lock.rollback(); lock.close()
    assert time.monotonic() - started < 0.2
    assert len(ticks) == 4
