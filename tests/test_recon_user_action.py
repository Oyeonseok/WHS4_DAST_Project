"""Runtime HITL keeps the visible browser session and never solves challenges."""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from aidast.auth.manual_login import ManualLoginGate, ManualLoginStore
from aidast.recon.tools.playwright_driver import ManualSessionConfig, PlaywrightDriver
from aidast.recon.tools.user_action import visible_user_action

BASE = 'https://example.test/'


def page_fixture(*, mfa=0, captcha=0, password=0, text='Account settings', path='account', submit_labels=()):
    page = Mock(url=BASE + path)
    page.is_closed.return_value = False
    def locator(selector):
        result = Mock()
        result.count.return_value = (mfa if 'one-time-code' in selector else captcha if 'iframe' in selector
                                     else password if 'password' in selector else 0)
        result.inner_text.return_value = text
        result.evaluate_all.return_value = list(submit_labels)
        return result
    page.locator.side_effect = locator
    return page


@pytest.mark.parametrize('options,include_login,expected', [
    ({'mfa': 1}, False, 'mfa_required'), ({'captcha': 1}, False, 'captcha_required'),
    ({'text': 'Verify you are human'}, False, 'captcha_required'),
    ({'password': 1, 'path': 'login'}, True, 'login_form_visible'),
    ({'password': 1, 'submit_labels': ('Sign In',)}, True, 'login_form_visible'),
    ({'password': 1}, True, None), ({'password': 1}, False, None),
    ({'text': 'Sign in to continue'}, False, 'login_form_visible'),
    ({'text': 'Home Products Sign in Help'}, True, None),
])
def test_explicit_visible_evidence_detects_user_only_ui(options, include_login, expected):
    assert visible_user_action(page_fixture(**options), include_login=include_login) == expected


def test_registration_password_form_is_not_misclassified_as_expired_login():
    assert visible_user_action(
        page_fixture(password=1, path='register', submit_labels=('Create Account',)),
        include_login=True,
    ) is None


def test_store_migrates_legacy_login_database_and_keeps_old_default(tmp_path):
    path = tmp_path / '.webui' / 'manual_login.db'
    path.parent.mkdir()
    with sqlite3.connect(path) as connection:
        connection.execute('''CREATE TABLE manual_login (
            scan_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, target_origin TEXT NOT NULL,
            status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
            confirmed_at REAL, auth_state TEXT, problem TEXT)''')
    store = ManualLoginStore(tmp_path)
    assert store.begin('scan_one', BASE, 30)['action_kind'] == 'login'
    request = store.begin('scan_one', BASE, 30, action_kind='mfa', problem='mfa_required')
    assert request['status'] == 'waiting' and request['problem'] == 'mfa_required'
    assert request['action_kind'] == 'mfa'


def test_runtime_gate_pumps_browser_events_but_requires_confirmation_and_clear_ui(tmp_path):
    store = ManualLoginStore(tmp_path)
    gate = ManualLoginGate(store, 'scan_one', BASE, timeout_seconds=3, poll_interval=0.005)
    pump, check = Mock(), Mock(return_value=None)
    with ThreadPoolExecutor() as executor:
        future = executor.submit(gate.wait, check, action_kind='captcha', problem='captcha_required', poll_browser=pump)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            request = store.read('scan_one')
            if request and pump.call_count:
                break
            time.sleep(0.005)
        assert request['status'] == 'waiting' and request['problem'] == 'captcha_required'
        assert pump.call_count > 0 and not future.done()
        check.assert_not_called()
        store.confirm('scan_one', request['request_id'])
        assert future.result(timeout=2) is True
    assert store.read('scan_one')['status'] == 'accepted'


def test_runtime_mfa_confirmation_keeps_same_context_and_resumes_safe_actions(tmp_path):
    page = page_fixture(mfa=1)
    context = Mock(pages=[page])
    reasons = []
    def confirmation(problem, validate, pump):
        reasons.append(problem)
        assert validate() == 'mfa_required'
        assert callable(pump)
        pump()
        page.locator.side_effect = page_fixture().locator.side_effect
        assert validate() is None
        return True
    driver = PlaywrightDriver(BASE, ManualSessionConfig(login_url=BASE,
        session_file=str(tmp_path / 'session.json'), operator_action_confirmation=confirmation))
    driver.context, driver.page, driver._browser_kind = context, page, 'cdp'
    with patch.object(driver, 'save_session', return_value=True) as save, patch.object(
        driver, '_launch_manual_browser') as launch, patch.object(driver, '_shutdown_runtime') as shutdown:
        assert driver.trigger_safe_actions() == 0
        assert reasons == ['mfa_required']
        assert driver.context is context and driver.page is page
        save.assert_called_once()
        launch.assert_not_called()
        shutdown.assert_not_called()
        context.unroute.assert_not_called()


def test_expired_runtime_confirmation_skips_page_without_closing_browser(tmp_path):
    confirmation = Mock(side_effect=RuntimeError('operator confirmation timed out'))
    driver = PlaywrightDriver(BASE, ManualSessionConfig(login_url=BASE,
        session_file=str(tmp_path / 'session.json'), operator_action_confirmation=confirmation))
    driver.page = page_fixture(captcha=1)
    driver.context, driver._browser_kind = Mock(), 'cdp'
    context = driver.context
    with patch.object(driver, '_shutdown_runtime') as shutdown:
        assert driver.trigger_safe_actions() == 0
        assert driver.trigger_safe_actions() == 0
    confirmation.assert_called_once()
    assert driver.context is context
    shutdown.assert_not_called()


def test_headless_runtime_reports_limitation_without_launching_gui(tmp_path):
    confirmation = Mock(return_value=False)
    driver = PlaywrightDriver(BASE, ManualSessionConfig(login_url=BASE,
        session_file=str(tmp_path / 'session.json'), operator_action_confirmation=confirmation))
    driver.page = page_fixture(text='Sign in to continue')
    driver.context, driver._browser_kind = Mock(), 'managed'
    with patch.object(driver, '_launch_manual_browser') as launch:
        assert driver.trigger_safe_actions() == 0
    assert confirmation.call_args.args[0] == 'login_form_visible'
    assert confirmation.call_args.args[2] is None
    launch.assert_not_called()


def test_dashboard_runtime_gate_wiring_records_actionable_unavailable_request(tmp_path, monkeypatch):
    from aidast.recon.tools.endpoint_discovery import discover_endpoints
    monkeypatch.setenv('AIDAST_DASHBOARD_MANUAL_LOGIN', '1')
    with patch('aidast.recon.tools.endpoint_discovery.RESULT_ROOT', tmp_path), patch(
        'aidast.recon.tools.endpoint_discovery.PlaywrightDriver') as constructor:
        constructor.return_value.capture_and_start.side_effect = RuntimeError('stop before network')
        with pytest.raises(RuntimeError, match='stop before network'):
            discover_endpoints(BASE, run_id='scan_one', interactive_login=True)
        callback = constructor.call_args.args[1].operator_action_confirmation
        assert callback('captcha_required', lambda: None, None) is False
    request = ManualLoginStore(tmp_path).read('scan_one')
    assert request['action_kind'] == 'captcha'
    assert request['status'] == 'failed' and request['problem'] == 'runtime_browser_required'


def test_real_dom_mfa_resume_uses_the_same_browser_context(tmp_path):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).exists():
            pytest.skip('Chromium is not installed')
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        # A local intercepted fixture supplies the origin; no target request
        # or real MFA/CAPTCHA operation is performed by this test.
        page.route(BASE + 'account', lambda route: route.fulfill(content_type='text/html', body='''
            <input id="otp" autocomplete="one-time-code">
            <button aria-controls="details" onclick="document.body.dataset.opened='yes'">Menu</button>'''))
        page.goto(BASE + 'account')
        reasons = []
        def confirm(problem, validate, pump):
            reasons.append(problem)
            assert validate() == 'mfa_required'
            pump()
            page.locator('#otp').evaluate('(input) => input.remove()')
            return True
        driver = PlaywrightDriver(BASE, ManualSessionConfig(login_url=BASE,
            session_file=str(tmp_path / 'session.json'), operator_action_confirmation=confirm))
        driver.context, driver.page = context, page
        # The production path only provides an event pump for an existing
        # visible CDP runtime. The fixture injects that capability locally.
        driver._browser_kind = 'cdp'
        try:
            assert driver.trigger_safe_actions() == 1
            assert reasons == ['mfa_required']
            assert driver.context is context and driver.page is page
            assert page.locator('body').get_attribute('data-opened') == 'yes'
        finally:
            browser.close()
