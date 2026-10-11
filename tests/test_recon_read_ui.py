"""Exercise read-only UI discovery against actual Chromium DOM behavior."""
from pathlib import Path
import pytest
from playwright.sync_api import sync_playwright
from aidast.recon.tools.playwright_driver import PlaywrightDriver, ManualSessionConfig, InteractionConfig


@pytest.fixture
def read_page():
    with sync_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).exists():
            pytest.skip('Chromium is not installed')
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content('''<div id="details" hidden>Product details</div>
          <button type="button" aria-label="View product details"
            onclick="document.querySelector('#details').hidden=false">Details</button>
          <div role="button" tabindex="0" aria-label="Click for more information about the product"
            onclick="document.body.dataset.info='opened'">Product</div>
          <button type="button" title="View and buy product"
            onclick="document.body.dataset.purchase='yes'">Buy</button>
          <button type="button" title="Do something"
            onclick="document.body.dataset.unknown='yes'">Unknown</button>
          <form><button type="button" title="View form details"
            onclick="document.body.dataset.form='yes'">Form</button></form>''')
        driver = PlaywrightDriver('https://example.test/', ManualSessionConfig(
            login_url='https://example.test/', session_file='unused.json'),
            interaction_config=InteractionConfig(allow_form_submission=False, action_wait_ms=0, expand_read_controls=True))
        driver.page = page
        yield driver, page
        browser.close()


def test_read_controls_open_details_and_information(read_page):
    driver, page = read_page
    assert driver.trigger_safe_actions() == 2
    assert page.locator('#details').is_visible()
    assert page.locator('body').get_attribute('data-info') == 'opened'


def test_expanded_ui_keeps_purchase_unknown_and_form_actions_blocked(read_page):
    driver, page = read_page
    driver.trigger_safe_actions()
    assert page.locator('body').get_attribute('data-purchase') is None
    assert page.locator('body').get_attribute('data-unknown') is None
    assert page.locator('body').get_attribute('data-form') is None


def test_read_dialog_closes_before_next_navigation(read_page):
    driver, page = read_page
    page.set_content('''<button type="button" aria-label="View details"
       onclick="document.body.dataset.opened='yes';document.querySelector('dialog').showModal()">Details</button>
       <button type="button" aria-controls="navigation" onclick="document.body.dataset.nav='yes'">Menu</button>
       <dialog><p>Read-only details</p><button type="button" aria-label="Close details"
       onclick="this.closest('dialog').close()">Close</button></dialog>''')
    driver.trigger_safe_actions()
    assert page.locator('body').get_attribute('data-nav') == 'yes'
    assert page.locator('body').get_attribute('data-opened') == 'yes'
    assert not page.locator('dialog').is_visible()


def test_generic_read_controls_inside_form_are_blocked(read_page):
    driver, page = read_page
    page.set_content('''<form><div role="button" tabindex="0" aria-label="View form information"
       onclick="document.body.dataset.form='yes'">Form action</div></form>''')
    driver.trigger_safe_actions()
    assert page.locator('body').get_attribute('data-form') is None


def test_read_expansion_can_be_disabled_without_clicking_details(read_page):
    driver, page = read_page
    driver.interaction_config.expand_read_controls = False
    assert driver.trigger_safe_actions() == 0
    assert not page.locator('#details').is_visible()


def test_identifier_does_not_make_unknown_action_read_only(read_page):
    driver, page = read_page
    page.set_content('''<button id="view-control" type="button" aria-label="Do something"
       onclick="document.body.dataset.unknown='yes'">Unknown</button>''')
    driver.trigger_safe_actions()
    assert page.locator('body').get_attribute('data-unknown') is None
