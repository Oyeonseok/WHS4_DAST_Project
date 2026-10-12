from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
from unittest.mock import Mock, patch

import httpx
import pytest

from aidast.auth.manual_login import ManualLoginGate, ManualLoginStore
from aidast.recon.tools.playwright_driver import ManualSessionConfig, PlaywrightDriver
from aidast.web.server import create_app


def await_status(store, scan_id, status):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        value = store.read(scan_id)
        if value and value['status'] == status:
            return value
        time.sleep(0.005)
    raise AssertionError(f'login request never reached {status}')


def test_gate_requires_click_and_rechecks_browser_after_each_confirmation(tmp_path):
    store = ManualLoginStore(tmp_path)
    gate = ManualLoginGate(store, 'scan_test', 'https://example.com', timeout_seconds=3,
                           poll_interval=0.005)
    check = Mock(side_effect=['invite_required', None])
    with ThreadPoolExecutor() as executor:
        future = executor.submit(gate.wait, check)
        first = await_status(store, 'scan_test', 'waiting')
        assert not future.done()
        check.assert_not_called()
        store.confirm('scan_test', first['request_id'])
        while (second := await_status(store, 'scan_test', 'waiting')).get('problem') is None:
            time.sleep(0.005)
        assert second['problem'] == 'invite_required'
        assert not future.done()
        store.confirm('scan_test', second['request_id'])
        assert future.result(timeout=3) is True
    accepted = store.read('scan_test')
    assert accepted['status'] == 'accepted'
    assert accepted['auth_state'] == 'operator_confirmed'
    assert 'server_verified' not in str(accepted)


def test_no_click_expires_without_automatic_handoff(tmp_path):
    store = ManualLoginStore(tmp_path)
    gate = ManualLoginGate(store, 'scan_test', 'https://example.com', timeout_seconds=0.02,
                           poll_interval=0.005)
    check = Mock(return_value=None)
    with pytest.raises(RuntimeError, match='operator confirmation timed out'):
        gate.wait(check)
    check.assert_not_called()
    request = store.read('scan_test')
    assert request['status'] == 'expired'
    with pytest.raises(ValueError):
        store.confirm('scan_test', request['request_id'])


def test_confirmation_cannot_cross_scans_or_reuse_an_old_request(tmp_path):
    store = ManualLoginStore(tmp_path)
    old = store.begin('scan_one', 'https://example.com', 30)
    other = store.begin('scan_two', 'https://other.test', 30)
    new = store.begin('scan_one', 'https://example.com', 30)
    for scan_id, request_id in [('scan_two', new['request_id']), ('scan_one', old['request_id'])]:
        with pytest.raises(ValueError):
            store.confirm(scan_id, request_id)
    assert store.read('scan_two')['request_id'] == other['request_id']
    assert store.read('scan_one')['status'] == 'waiting'
    with pytest.raises(ValueError):
        store.finish('scan_one', old['request_id'], 'accepted')


@pytest.mark.parametrize('scan_status', ['running', 'failed', 'cancelled', 'paused'])
def test_confirmation_api_requires_active_scan_same_origin_and_current_request(tmp_path, scan_status):
    app = create_app(result_root=tmp_path)
    store = ManualLoginStore(tmp_path)
    current = store.begin('scan_test', 'https://example.com', 30)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
            endpoint = '/api/v1/scans/scan_test/manual-login'
            response = await client.get(endpoint)
            assert response.status_code == 200
            assert response.json()['manual_login']['request_id'] == current['request_id']
            body = {'request_id': current['request_id']}
            assert (await client.post(endpoint + '/confirm', json=body)).status_code == 403
            assert (await client.post(endpoint + '/confirm', json=body,
                                      headers={'Origin': 'https://outside.test'})).status_code == 403
            response = await client.post(endpoint + '/confirm', json=body, headers={'Origin': 'http://testserver'})
            assert response.status_code == (200 if scan_status == 'running' else 409)

    with patch.object(app.state.projector, 'snapshot', return_value={'status': scan_status}):
        asyncio.run(run())


def test_operator_confirmed_cookie_session_continues_without_api_success(tmp_path):
    observed_checks = []
    def confirm(check):
        observed_checks.append(check())
        return True
    config = ManualSessionConfig(login_url='https://example.com/', session_file=str(tmp_path / 'session.json'),
                                 operator_confirmation=confirm, auth_check_url='/restricted-api')
    driver = PlaywrightDriver('https://example.com/', config)
    page = Mock(url=driver.base_url)
    page.is_closed.return_value = False
    page.locator.return_value.count.return_value = 0
    page.locator.return_value.inner_text.return_value = 'Projects Create project'
    driver.context = Mock(pages=[page])
    with patch.object(driver, '_launch_manual_browser'), patch.object(driver, '_attach_manual_browser'), patch.object(
        driver, '_register_authentication_observer'
    ), patch.object(driver, '_page_indicates_login_required', return_value=False), patch.object(
        driver, 'save_session', return_value=True
    ), patch.object(driver, 'get_auth_headers', return_value={'Cookie': 'sid=synthetic'}), patch.object(
        driver, 'session_is_valid', return_value=False
    ) as api_check, patch.object(driver, '_remember_authenticated_state'), patch.object(
        driver, '_register_context_handlers'
    ), patch.object(driver, '_register_page_handlers'):
        driver.capture_and_start()
        with patch.object(driver, 'restore_runtime'), patch.object(driver, 'capture_and_start') as relogin:
            driver.ensure_session()
            relogin.assert_not_called()
    assert observed_checks == [None]
    api_check.assert_not_called()
    assert driver.automatic_auth_marker_path.exists()
    assert driver._phase == 'runtime'


@pytest.mark.parametrize('url, password_count, text, expected', [
    ('https://other.test/', 0, '', 'target_page_missing'),
    ('https://example.com/', 1, '', 'login_form_visible'),
    ('https://example.com/login', 0, 'Sign in to your account. Continue with Google.', 'login_form_visible'),
    ('https://example.com/', 0, 'Use the invitation code to get access to Neon', 'invite_required'),
    ('https://example.com/', 0, 'Projects Create project', None),
])
def test_manual_browser_check_distinguishes_target_login_and_invitation(tmp_path, url, password_count, text, expected):
    driver = PlaywrightDriver('https://example.com/', ManualSessionConfig(
        login_url='https://example.com/', session_file=str(tmp_path / 'session.json')))
    page = Mock(url=url)
    page.is_closed.return_value = False
    page.locator.return_value.count.return_value = password_count
    page.locator.return_value.inner_text.return_value = text
    driver.context = Mock(pages=[page])
    assert driver._manual_login_problem() == expected
    driver.context.cookies.assert_called_once()


def test_dashboard_endpoint_discovery_wires_confirmation_gate(tmp_path, monkeypatch):
    from aidast.recon.tools.endpoint_discovery import discover_endpoints
    monkeypatch.setenv('AIDAST_DASHBOARD_MANUAL_LOGIN', '1')
    with patch('aidast.recon.tools.endpoint_discovery.RESULT_ROOT', tmp_path), patch(
        'aidast.recon.tools.endpoint_discovery.PlaywrightDriver'
    ) as driver:
        driver.return_value.capture_and_start.side_effect = RuntimeError('stop before network')
        with pytest.raises(RuntimeError, match='stop before network'):
            discover_endpoints('https://example.com/', run_id='scan_test', interactive_login=True)
        assert callable(driver.call_args.args[1].operator_confirmation)


def test_dashboard_login_gate_pumps_managed_browser_events(tmp_path, monkeypatch):
    from aidast.recon.tools.endpoint_discovery import discover_endpoints

    monkeypatch.setenv('AIDAST_DASHBOARD_MANUAL_LOGIN', '1')
    with patch('aidast.recon.tools.endpoint_discovery.RESULT_ROOT', tmp_path), patch(
        'aidast.recon.tools.endpoint_discovery.PlaywrightDriver'
    ) as driver, patch.object(ManualLoginGate, 'wait', return_value=True) as wait:
        page = driver.return_value.page = Mock()

        def capture():
            confirmation = driver.call_args.args[1].operator_confirmation
            assert confirmation(lambda: None) is True
            raise RuntimeError('stop after confirmation wiring')

        driver.return_value.capture_and_start.side_effect = capture
        with pytest.raises(RuntimeError, match='stop after confirmation wiring'):
            discover_endpoints('https://example.com/', run_id='scan_test', interactive_login=True)

        pump = wait.call_args.kwargs['poll_browser']
        pump()
        page.wait_for_timeout.assert_called_once_with(50)
