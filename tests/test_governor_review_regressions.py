"""Offline and inert loopback regressions for shared admission boundaries."""
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import test_validation_request_broker as request_fixture
from test_request_governor import binding


def fixture(cls=request_fixture.ValidationRequestBrokerTests):
    value = cls(); value.setUp()
    return value


def test_concurrent_adapter_actual_senders_remain_paced_after_barrier():
    from aidast.validation.contracts.concurrent_contract import ConcurrentRuntimeContract
    from aidast.validation.execution.concurrent_adapter import ConcurrentReproductionPort
    from test_validation_concurrent_runtime import _attempt
    f = fixture()
    try:
        child = _attempt('target') | {'request': {'path_parameters': {'id': 'inert'}}}
        runtime = ConcurrentRuntimeContract(runtime_kind='concurrent', schema_version=1,
            workers=2, repeat_count=1, release_strategy='simultaneous', barrier_timeout_seconds=3,
            target=child, positive_control=child, negative_control=child)
        blind = f.blind.model_copy(update={'credential_references': (), 'signal_types': ('timing',),
            'runtime_contract': runtime.model_dump(mode='json')})
        policy = type(f.policy).model_validate(f.policy.model_dump() | {
            'request_governor': binding(Path(f.temp.name), requests_per_second=2, concurrency=2)})
        sent = []
        def transport(request, timeout):
            sent.append(time.monotonic())
            return request_fixture.Response()
        ConcurrentReproductionPort(transport=transport).execute(blind, attempt_kind='target',
            batch_no=1, ordinal=1, attempt_id='attempt', db_path=f.path, scan_id='scan',
            stage_run_id='stage', case_id='case', policy=policy)
        assert len(sent) == 2
        assert abs(sent[1] - sent[0]) >= 0.45
    finally: f.doCleanups()


def test_websocket_connector_watchdog_receive_and_close_use_shared_deadline():
    import test_validation_websocket_runtime as ws
    f = fixture(ws.WebSocketAdapterTests)
    try:
        f.policy = type(f.policy).model_validate(f.policy.model_dump() | {
            'request_governor': binding(Path(f.temp.name), scan_max_seconds=0.3,
                scan_max_requests=100, requests_per_second=50)})
        doc = ws.runtime_document()
        for name in ('target', 'positive_control', 'negative_control'):
            doc[name]['max_received_frames'] = 1
        connection = ws.ScriptedConnection(['{"message":"target"}']); observed = {}
        def connector(*args, **kwargs): observed.update(kwargs); return connection
        with patch('aidast.validation.execution.websocket_adapter.Timer') as timer:
            f.execute(connector, document=doc)
        assert 0 < observed['open_timeout'] <= 0.3
        assert 0 < observed['close_timeout'] <= 0.3
        assert 0 < timer.call_args.args[0] <= 0.3
        assert connection.timeouts and max(connection.timeouts) <= 0.3
        assert connection.closed and connection.close_timeout <= 0.3
    finally: f.doCleanups()


def test_grpc_io_and_cleanup_use_shared_remaining_deadline():
    import test_validation_grpc_runtime as grpc_fixture
    f = fixture(grpc_fixture.GrpcAdapterTests)
    try:
        f.policy = type(f.policy).model_validate(f.policy.model_dump() | {
            'request_governor': binding(Path(f.temp.name), scan_max_seconds=0.3,
                requests_per_second=50)})
        channel = grpc_fixture.ScriptedChannel()
        f.execute(channel)
        assert len(channel.calls) == 1
        assert 0 < channel.calls[0][2] <= 0.3
        assert channel.closed
    finally: f.doCleanups()


@pytest.mark.parametrize('ledger_failure', [False, True])
def test_browser_closes_transport_before_abandoning_rows_even_if_ledger_fails(ledger_failure):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from aidast.validation.execution.playwright_browser import PlaywrightBrowserExecutor
    f = fixture()
    try:
        callbacks = {}; events = []; context = MagicMock(); browser = MagicMock()
        page = context.new_page.return_value
        page.url = 'https://test/items/1'
        context.route.side_effect = lambda pattern, fn: callbacks.update(route=fn)
        context.close.side_effect = lambda: events.append('context_closed')
        browser.close.side_effect = lambda: events.append('browser_closed')
        browser.new_context.return_value = context
        request = SimpleNamespace(url=page.url, method='GET', headers={}, post_data_buffer=None)
        def navigate(*args, **kwargs):
            route = MagicMock(); route.continue_.side_effect = RuntimeError('interrupted')
            callbacks['route'](route, request)
        page.goto.side_effect = navigate
        ledger = MagicMock(); ledger.begin_observed_request.return_value = 'request_one'
        def fail(*args, **kwargs):
            events.append('ledger_release')
            if ledger_failure: raise OSError('ledger unavailable')
        ledger.fail_observed_request.side_effect = fail
        playwright = MagicMock(); playwright.chromium.launch.return_value = browser
        manager = MagicMock(); manager.__enter__.return_value = playwright
        with patch('playwright.sync_api.sync_playwright', return_value=manager), patch(
            'aidast.validation.execution.playwright_browser.ValidationRequestBroker', return_value=ledger):
            with pytest.raises((RuntimeError, OSError)):
                PlaywrightBrowserExecutor()(url=page.url, headers={}, wait_ms=0, selectors=(), attributes={},
                    policy=f.policy, db_path=f.path, scan_id='scan', stage_run_id='stage', case_id='case', attempt_id='attempt')
        assert events == ['context_closed', 'browser_closed', 'ledger_release']
    finally: f.doCleanups()


@pytest.mark.parametrize('scenario', ['redirect', 'normal', 'websocket'])
def test_real_loopback_playwright_redirect_cannot_spend_beyond_shared_budget(scenario):
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
    from threading import Thread
    from aidast.validation.execution.playwright_browser import PlaywrightBrowserExecutor, BrowserExecutionError
    f = fixture(); served = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            served.append(self.path)
            if self.path == '/items/start' and scenario == 'redirect':
                self.send_response(302); self.send_header('Location', '/items/end'); self.end_headers()
            else:
                data = b'<html><link rel="icon" href="data:,">inert fixture</html>'
                if scenario == 'websocket':
                    data += b'<script>new WebSocket("ws://"+location.host+"/ambient");</script>'
                self.send_response(200); self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self, *args): pass
    server = None
    try:
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True); thread.start()
        url = f'http://127.0.0.1:{server.server_port}/items/start'
        policy = type(f.policy).model_validate(f.policy.model_dump() | {
            'allowed_schemes': ['http'], 'allowed_hosts': ['127.0.0.1'], 'allowed_ports': [server.server_port],
            'request_governor': binding(Path(f.temp.name), scan_max_requests=1)})
        error = None
        try:
            PlaywrightBrowserExecutor()(url=url, headers={}, wait_ms=100, selectors=(), attributes={},
                policy=policy, db_path=f.path, scan_id='scan', stage_run_id='stage', case_id='case', attempt_id='attempt')
        except BrowserExecutionError as exc:
            error = exc
        assert (error is None) == (scenario == 'normal')
        assert served == ['/items/start']
    finally:
        if server is not None: server.shutdown(); server.server_close()
        f.doCleanups()


@pytest.mark.parametrize('mode,method,url', [
    ('same-origin', 'POST', 'https://example.com/app'),
    ('passive', 'HEAD', 'https://assets.example.net/resource'),
])
def test_proxy_execution_method_ceiling_precedes_browser_support(mode, method, url):
    import test_request_broker as proxy_fixture
    from aidast.core.http_safety import BROWSER_MODE_HEADER, BROWSER_TOKEN_HEADER
    f = fixture(proxy_fixture.ProxyBoundaryTests)
    try:
        rules = proxy_fixture.policy().mitm_rules()
        rules.update(execution_allowed_methods=['GET'], browser_context_token='x' * 32)
        f.configure_rules(rules)
        flow = f.flow(); flow.request.method = method; flow.request.pretty_url = url
        flow.request.headers.update({BROWSER_MODE_HEADER: mode, BROWSER_TOKEN_HEADER: 'x' * 32})
        f.addon.request(flow)
        assert flow.metadata.get('aidast_policy_blocked')
    finally: f.doCleanups()


@pytest.mark.parametrize('governed', [False, True])
def test_browser_serviceworker_and_websocket_controls_preserve_legacy(governed):
    from unittest.mock import MagicMock
    from aidast.validation.execution.playwright_browser import PlaywrightBrowserExecutor
    f = fixture()
    try:
        policy = type(f.policy).model_validate(f.policy.model_dump() | {
            'request_governor': binding(Path(f.temp.name)) if governed else None})
        context = MagicMock(); context.new_page.return_value.url = 'https://test/items/1'
        context.new_page.return_value.goto.side_effect = RuntimeError('inert interruption')
        browser = MagicMock(); browser.new_context.return_value = context
        playwright = MagicMock(); playwright.chromium.launch.return_value = browser
        manager = MagicMock(); manager.__enter__.return_value = playwright
        with patch('playwright.sync_api.sync_playwright', return_value=manager), pytest.raises(RuntimeError, match='navigation failed'):
            PlaywrightBrowserExecutor()(url='https://test/items/1', headers={}, wait_ms=0,
                selectors=(), attributes={}, policy=policy, db_path=f.path, scan_id='scan',
                stage_run_id='stage', case_id='case', attempt_id='attempt')
        if governed:
            assert browser.new_context.call_args.kwargs['service_workers'] == 'block'
            assert context.route_web_socket.call_args.args[0] == '**/*'
            route = MagicMock(); context.route_web_socket.call_args.args[1](route)
            route.close.assert_not_called(); route.connect_to_server.assert_not_called()
            context.close.assert_called_once()
        else:
            assert 'service_workers' not in browser.new_context.call_args.kwargs
            context.route_web_socket.assert_not_called()
    finally: f.doCleanups()


def test_missing_browser_websocket_guard_fails_closed_and_closes_context():
    from unittest.mock import MagicMock
    from aidast.validation.execution.playwright_browser import PlaywrightBrowserExecutor, BrowserExecutionError
    f = fixture()
    try:
        policy = type(f.policy).model_validate(f.policy.model_dump() | {'request_governor': binding(Path(f.temp.name))})
        context = MagicMock(); context.route_web_socket = None
        browser = MagicMock(); browser.new_context.return_value = context
        playwright = MagicMock(); playwright.chromium.launch.return_value = browser
        manager = MagicMock(); manager.__enter__.return_value = playwright
        with patch('playwright.sync_api.sync_playwright', return_value=manager):
            with pytest.raises(BrowserExecutionError, match='WebSocket interception'):
                PlaywrightBrowserExecutor()(url='https://test/items/1', headers={}, wait_ms=0,
                    selectors=(), attributes={}, policy=policy, db_path=f.path, scan_id='scan',
                    stage_run_id='stage', case_id='case', attempt_id='attempt')
        context.new_page.assert_not_called(); context.close.assert_called_once(); browser.close.assert_called_once()
    finally: f.doCleanups()
