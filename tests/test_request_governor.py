from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest

from aidast.core.request_governor import RequestGovernor, GovernorError


class Clock:
    def __init__(self): self.now = 1000.0
    def __call__(self): return self.now
    def sleep(self, delay): self.now += delay


def binding(tmp_path, **changes):
    return dict(ledger_path=str(tmp_path / 'budget.db'), scan_id='scan_one',
                program_id='program_one', scan_max_requests=3, scan_max_seconds=None,
                requests_per_second=2.0, concurrency=2, request_limits=[]) | changes


def governor(value, clock):
    return RequestGovernor(value, clock=clock, sleeper=clock.sleep)


def test_shared_stages_targets_and_failures_remain_charged(tmp_path):
    clock = Clock()
    for host in ['a.example', 'b.example', 'a.example']:
        permit = governor(binding(tmp_path), clock).reserve('https://' + host)
        permit.wait()
        permit.complete(outcome='unknown')
    with pytest.raises(GovernorError, match='budget'):
        governor(binding(tmp_path), clock).reserve('https://b.example')


def test_program_window_persists_across_scans(tmp_path):
    clock = Clock()
    rules = [dict(maximum=1, period_seconds=60, scope='program', source_quote='one/minute')]
    first = governor(binding(tmp_path, request_limits=rules), clock).reserve('https://a.example')
    first.wait(); first.complete()
    other = governor(binding(tmp_path, scan_id='scan_two', request_limits=rules), clock)
    with pytest.raises(GovernorError, match='quota'):
        other.reserve('https://b.example')
    clock.now += 60
    other.reserve('https://b.example').wait()


def test_sync_acquire_waits_for_temporary_program_window(tmp_path):
    clock = Clock()
    rules = [dict(maximum=1, period_seconds=2, scope='program', source_quote='half per second')]
    g = governor(binding(tmp_path, scan_max_requests=10, request_limits=rules), clock)
    first = g.acquire('https://example.com'); first.wait(); first.complete()
    second = g.acquire('https://example.com', timeout_seconds=5)

    assert clock.now == 1002.0
    assert second.timeout_seconds == 5
    second.wait(); second.complete()


def test_sync_admission_deadline_also_bounds_rate_pacing(tmp_path):
    clock = Clock()
    g = governor(binding(tmp_path, requests_per_second=0.5), clock)
    first = g.acquire('https://example.com', timeout_seconds=1)
    first.wait(); first.complete()
    second = g.acquire('https://example.com', timeout_seconds=1)
    try:
        with pytest.raises(GovernorError, match='deadline.*pacing'):
            second.wait()
    finally:
        second.complete()
    assert clock.now == 1000.0
    with sqlite3.connect(tmp_path / 'budget.db') as conn:
        assert conn.execute('SELECT sum(units) FROM governor_requests').fetchone()[0] == 2


def test_target_budget_normalizes_origin_and_resets_only_for_a_new_scan(tmp_path):
    clock = Clock()
    rules = [dict(maximum=1, period_seconds=None, scope='target', source_quote='once per target per scan')]
    first = governor(binding(tmp_path, request_limits=rules), clock)
    p = first.reserve('https://EXAMPLE.com.:443/a'); p.wait(); p.complete()
    # Recreating a governor or using another path cannot reset this scan's budget.
    with pytest.raises(GovernorError, match='quota'):
        governor(binding(tmp_path, request_limits=rules), clock).reserve('https://example.com/b')
    first.reserve('https://example.com:444/b').wait()
    # A new scan gets its own target budget even at the same normalized origin.
    other = governor(binding(tmp_path, scan_id='scan_two', request_limits=rules), clock)
    p = other.reserve('https://example.com/b'); p.wait(); p.complete()
    with pytest.raises(GovernorError, match='quota'):
        other.reserve('https://EXAMPLE.com.:443/c')
    other.reserve('https://example.com:444/b').wait()
    with sqlite3.connect(tmp_path / 'budget.db') as conn:
        assert conn.execute('SELECT scan,sum(units) FROM governor_requests GROUP BY scan ORDER BY scan').fetchall() == [
            ('scan_one', 2), ('scan_two', 2)]


def test_periodic_target_quota_persists_across_scans_and_normalizes_origin(tmp_path):
    clock = Clock()
    rules = [dict(maximum=1, period_seconds=60, scope='target', source_quote='one per target per minute')]
    p = governor(binding(tmp_path, request_limits=rules), clock).reserve('https://EXAMPLE.com.:443/a')
    p.wait(); p.complete()
    other = governor(binding(tmp_path, scan_id='scan_two', request_limits=rules), clock)
    with pytest.raises(GovernorError, match='quota'):
        other.reserve('https://example.com/b')
    p = other.reserve('https://other.example/a'); p.wait(); p.complete()
    clock.now += 60
    p = other.reserve('https://example.com/b'); p.wait(); p.complete()


def test_nonperiodic_program_quota_remains_cross_scan(tmp_path):
    clock = Clock()
    rules = [dict(maximum=1, period_seconds=None, scope='program', source_quote='one program total')]
    p = governor(binding(tmp_path, request_limits=rules), clock).reserve('https://a.example')
    p.wait(); p.complete()
    other = governor(binding(tmp_path, scan_id='scan_two', request_limits=rules), clock)
    with pytest.raises(GovernorError, match='quota'):
        other.reserve('https://b.example')


def test_nonperiodic_scan_quota_is_shared_by_targets_and_resets_for_a_new_scan(tmp_path):
    clock = Clock()
    rules = [dict(maximum=1, period_seconds=None, scope='scan', source_quote='one request per scan')]
    p = governor(binding(tmp_path, request_limits=rules), clock).reserve('https://a.example')
    p.wait(); p.complete()
    first = governor(binding(tmp_path, request_limits=rules), clock)
    with pytest.raises(GovernorError, match='quota'):
        first.reserve('https://b.example')
    p = governor(binding(tmp_path, scan_id='scan_two', request_limits=rules), clock).reserve('https://a.example')
    p.wait(); p.complete()


def test_target_budget_batch_and_failed_outcome_do_not_refund_or_leak_between_scans(tmp_path):
    clock = Clock()
    rules = [dict(maximum=2, period_seconds=None, scope='target', source_quote='two per target per scan')]
    first = governor(binding(tmp_path, scan_max_requests=10, request_limits=rules), clock)
    with pytest.raises(GovernorError, match='quota'):
        first.reserve('https://example.com', units=3)
    p = first.reserve('https://example.com', units=2); p.wait(); p.complete(outcome='failed')
    with pytest.raises(GovernorError, match='quota'):
        first.reserve('https://example.com')
    other = governor(binding(tmp_path, scan_id='scan_two', scan_max_requests=10, request_limits=rules), clock)
    p = other.reserve('https://example.com', units=2); p.wait(); p.complete()
    with pytest.raises(GovernorError, match='quota'):
        other.reserve('https://example.com')
    with sqlite3.connect(tmp_path / 'budget.db') as conn:
        assert conn.execute('SELECT scan,sum(units) FROM governor_requests GROUP BY scan ORDER BY scan').fetchall() == [
            ('scan_one', 2), ('scan_two', 2)]


def test_wait_paces_actual_dispatch_and_batch_units(tmp_path):
    clock = Clock(); g = governor(binding(tmp_path, scan_max_requests=10), clock)
    one = g.reserve('https://example.com'); two = g.reserve('https://example.com', units=2)
    clock.now += 10
    one.wait(); one.complete()
    two.wait(); two.complete()
    assert clock.now == 1011
    three = g.reserve('https://example.com'); three.wait()
    assert clock.now == 1011.5


def test_concurrency_shared_threads_and_expired_lease(tmp_path):
    clock = Clock(); value = binding(tmp_path, concurrency=1)
    first = governor(value, clock).reserve('https://example.com', timeout_seconds=1)
    first.wait()
    with ThreadPoolExecutor() as pool:
        with pytest.raises(GovernorError, match='concurrency'):
            pool.submit(lambda: governor(value, clock).reserve('https://other.example')).result()
    clock.now += 32
    governor(value, clock).reserve('https://other.example')
    with pytest.raises(GovernorError): first.wait()


def test_deadline_includes_rate_wait(tmp_path):
    clock = Clock(); g = governor(binding(tmp_path, scan_max_seconds=1, requests_per_second=0.5), clock)
    first = g.reserve('https://example.com'); first.wait(); first.complete()
    second = g.reserve('https://example.com')
    with pytest.raises(GovernorError, match='deadline'): second.wait()


def test_explicit_invalid_or_unavailable_binding_fails_closed(tmp_path):
    for value in [{}, binding(tmp_path, concurrency=True), binding(tmp_path, requests_per_second=float('nan')),
                  binding(tmp_path, ledger_path=str(tmp_path / 'absent' / 'budget.db'))]:
        with pytest.raises(GovernorError): RequestGovernor(value).reserve('https://example.com')
    (tmp_path / 'budget.db').write_text('invalid database')
    with pytest.raises(GovernorError): RequestGovernor(binding(tmp_path)).reserve('https://example.com')


def test_no_binding_is_compatibility_noop():
    permit = RequestGovernor(None).reserve('https://example.com'); permit.wait(); permit.complete()


def test_batch_cannot_cross_quota(tmp_path):
    clock = Clock()
    rules = [dict(maximum=2, period_seconds=10, scope='program', source_quote='two')]
    g = governor(binding(tmp_path, request_limits=rules), clock)
    with pytest.raises(GovernorError, match='quota'): g.reserve('https://example.com', units=3)
    p = g.reserve('https://example.com', units=2); p.wait(); p.complete()
    with pytest.raises(GovernorError): g.reserve('https://example.com')


def test_core_broker_redirects_charge_shared_budget_and_release(tmp_path):
    from tests.test_request_broker import policy, response
    from aidast.core.request_broker import RequestBroker
    from unittest.mock import Mock
    p = policy().model_copy(update={'request_governor': binding(tmp_path, scan_max_requests=1)})
    transport = Mock(return_value=response(302, {'Location': '/app/child'}))
    with pytest.raises(ValueError, match='budget'):
        RequestBroker(p, transport=transport).request('https://example.com/app')
    assert transport.call_count == 1
    with sqlite3.connect(tmp_path / 'budget.db') as conn:
        assert conn.execute("SELECT count(*) FROM governor_requests WHERE state='complete'").fetchone()[0] == 1


def test_core_broker_scope_rejection_does_not_charge(tmp_path):
    from tests.test_request_broker import policy
    from aidast.core.request_broker import RequestBroker
    p = policy().model_copy(update={'request_governor': binding(tmp_path)})
    with pytest.raises(ValueError): RequestBroker(p).request('https://outside.example/')
    assert not (tmp_path / 'budget.db').exists()


def _process_reserve(value, barrier, result):
    barrier.wait()
    try:
        permit = RequestGovernor(value).reserve('https://example.com')
        permit.wait()
        result.put('allowed')
        # Keep permit live until both processes have attempted reservation.
        barrier.wait()
        permit.complete()
    except GovernorError:
        result.put('blocked')
        barrier.wait()


def test_independent_processes_share_capacity(tmp_path):
    import multiprocessing
    ctx = multiprocessing.get_context('spawn')
    gate, results = ctx.Barrier(2), ctx.Queue()
    value = binding(tmp_path, concurrency=1)
    processes = [ctx.Process(target=_process_reserve, args=(value, gate, results)) for _ in range(2)]
    try:
        for process in processes: process.start()
        outcomes = [results.get(timeout=10) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        assert sorted(outcomes) == ['allowed', 'blocked']
        with sqlite3.connect(value['ledger_path']) as conn:
            assert conn.execute('SELECT sum(units) FROM governor_requests').fetchone()[0] == 1
    finally:
        for process in processes:
            if process.is_alive(): process.terminate(); process.join()


def test_nested_transport_units_do_not_claim_another_connection(tmp_path):
    clock = Clock(); g = governor(binding(tmp_path, concurrency=1), clock)
    connection = g.reserve('https://example.com'); connection.wait()
    controls = g.reserve('https://example.com', units=2, concurrency_units=0)
    controls.wait(); controls.complete()
    with pytest.raises(GovernorError): g.reserve('https://example.com')
    connection.complete()


def test_dispatch_timeout_is_clamped_to_remaining_scan_deadline(tmp_path):
    clock = Clock(); g = governor(binding(tmp_path, scan_max_seconds=5), clock)
    p = g.reserve('https://example.com', timeout_seconds=30)
    clock.now += 2
    p.wait()
    assert p.timeout_seconds == 3


def delay_transaction_entry(g, clock, delay):
    from contextlib import contextmanager
    original = g._transaction
    @contextmanager
    def delayed(**kwargs):
        with original(**kwargs) as conn:
            clock.now += delay
            yield conn
    g._transaction = delayed


@pytest.mark.parametrize('operation', ['reserve', 'wait'])
def test_lock_wait_counts_toward_scan_deadline(tmp_path, operation):
    clock = Clock(); g = governor(binding(tmp_path, scan_max_seconds=1), clock)
    permit = g.reserve('https://example.com')
    delay_transaction_entry(g, clock, 2)
    with pytest.raises(GovernorError, match='deadline'):
        if operation == 'reserve': g.reserve('https://example.com')
        else: permit.wait()


def test_lock_wait_counts_toward_lease_expiry(tmp_path):
    clock = Clock(); g = governor(binding(tmp_path), clock)
    permit = g.reserve('https://example.com', timeout_seconds=1)
    delay_transaction_entry(g, clock, 32)
    with pytest.raises(GovernorError, match='expired'): permit.wait()


def test_lock_delay_timestamp_cannot_compress_next_dispatch_spacing(tmp_path):
    clock = Clock(); g = governor(binding(tmp_path, requests_per_second=1), clock)
    first = g.reserve('https://example.com'); second = g.reserve('https://example.com')
    original = g._transaction
    delay_transaction_entry(g, clock, 2)
    first.wait()
    first_at = clock.now
    g._transaction = original
    second.wait()
    assert clock.now - first_at >= 1
