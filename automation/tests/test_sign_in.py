"""Interactive sign-in: the browser as it is when Enter is pressed decides, never a stale snapshot."""
from __future__ import annotations

import json
import time

import pytest
from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright

import lcs_jit_automation as lcs
from automation_support import AutomationError, Config
from helpers import fast_lcs_timings, profile

pytestmark = pytest.mark.chromium
LOGIN = 'https://login.microsoftonline.com/common/oauth2/authorize'
SIGN_IN_FORM = '<form><input type="email" name="loginfmt"></form>'
ENVIRONMENT = '<h1>contoso-sandbox</h1><section id="x_ManageEnvironmentSection">Database Accounts</section>'


def make_config(tmp_path, monkeypatch):
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    config = Config.load(profile(tmp_path))
    config.state_path = tmp_path / 'auth.enc'
    config.auth_key_path = None
    # An existing (expired) sign-in lets the browser start headless; bootstrap replaces it.
    config.state_path.write_bytes(lcs.cipher().encrypt(json.dumps({'cookies': [], 'origins': []}).encode()))
    return config


def go_to(url, delay_ms=0):
    return '<script>setTimeout(()=>location.href=' + json.dumps(url) + f',{delay_ms})</script>'


def offline_adapter(config, tmp_path, playwright, sign_in_body, *, signs_in=True):
    """A browser that reaches only these fixture pages, left on Microsoft sign-in.

    Unsigned LCS sends the browser to sign-in with a script (a fulfilled HTTP redirect
    would bypass routing). Serving the sign-in page signs the session in unless
    signs_in is False. The routes are Python callbacks, so a navigation the browser
    starts while Python waits at the prompt completes only after the prompt returns.
    """
    state = {'signed_in': False}
    instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
    instance.context.route('**/*', lambda route: route.abort())  # Nothing reaches the internet.

    def lcs_page(route):
        route.fulfill(content_type='text/html', body=ENVIRONMENT if state['signed_in'] else go_to(LOGIN))

    def sign_in_page(route):
        state['signed_in'] = state['signed_in'] or signs_in
        route.fulfill(content_type='text/html', body=sign_in_body)

    instance.context.route('https://lcs.dynamics.com/**', lcs_page)
    instance.context.route('https://login.microsoftonline.com/**', sign_in_page)
    # Where an expired session is when the prompt appears: LCS redirected it to Microsoft sign-in.
    instance.page.goto(LOGIN)
    return instance


def test_sign_in_completed_while_waiting_for_enter_is_saved(tmp_path, monkeypatch):
    """The reported failure: sign-in finished, Enter was pressed, and the run still said it had not.

    The address read right after Enter used to be the one from before the prompt.
    """
    fast_lcs_timings(monkeypatch)
    config = make_config(tmp_path, monkeypatch)
    before = config.state_path.read_bytes()
    presses = []
    monkeypatch.setattr('builtins.input', lambda: presses.append(1) or time.sleep(1.5) or '')
    with sync_playwright() as playwright:
        instance = offline_adapter(config, tmp_path, playwright, go_to(config.environment_url, 200))
        try:
            instance.bootstrap(navigate_first=False)
        finally:
            instance.close()
    assert presses == [1]
    assert config.state_path.read_bytes() != before
    assert config.environment_id == 'contoso-sandbox'


def test_enter_pressed_before_sign_in_finished_asks_again(tmp_path, monkeypatch, capsys):
    fast_lcs_timings(monkeypatch)
    config = make_config(tmp_path, monkeypatch)
    before = config.state_path.read_bytes()
    presses = []
    with sync_playwright() as playwright:
        instance = offline_adapter(config, tmp_path, playwright, SIGN_IN_FORM)

        def press_enter():
            presses.append(1)
            if len(presses) == 2:  # The user finished signing in before pressing Enter again.
                instance.page.evaluate('url => setTimeout(() => { location.href = url }, 100)', config.environment_url)
                time.sleep(1)
            return ''

        monkeypatch.setattr('builtins.input', press_enter)
        try:
            instance.bootstrap(navigate_first=False)
        finally:
            instance.close()
    assert len(presses) == 2
    assert config.state_path.read_bytes() != before
    prompts = capsys.readouterr().err
    assert 'shows login.microsoftonline.com, not LCS' in prompts and 'press Enter again' in prompts


def test_sign_in_that_never_finishes_fails_after_the_last_prompt(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch)
    monkeypatch.setattr(lcs.LCSAutomation, 'SIGN_IN_PROMPTS', 2)
    config = make_config(tmp_path, monkeypatch)
    before = config.state_path.read_bytes()
    presses = []
    monkeypatch.setattr('builtins.input', lambda: presses.append(1) or '')
    with sync_playwright() as playwright:
        instance = offline_adapter(config, tmp_path, playwright, SIGN_IN_FORM, signs_in=False)
        try:
            with pytest.raises(AutomationError) as raised:
                instance.bootstrap(navigate_first=False)
        finally:
            instance.close()
    assert len(presses) == 2
    assert raised.value.step == 'authentication'
    assert 'still shows login.microsoftonline.com, not LCS' in raised.value.message
    assert 'window this tool opened' in raised.value.message
    assert config.state_path.read_bytes() == before


def test_lcs_opened_in_another_tab_is_found(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch)
    config = make_config(tmp_path, monkeypatch)
    before = config.state_path.read_bytes()
    presses = []
    monkeypatch.setattr('builtins.input', lambda: presses.append(1) or time.sleep(1.5) or '')
    opener = '<script>setTimeout(()=>window.open(' + json.dumps(config.environment_url) + '),200)</script>'
    with sync_playwright() as playwright:
        instance = offline_adapter(config, tmp_path, playwright, opener)
        try:
            instance.bootstrap(navigate_first=False)
        finally:
            instance.close()
    assert presses == [1]
    assert config.state_path.read_bytes() != before


def test_microsoft_sign_in_error_code_is_named(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch, SIGN_IN_GRACE_MS=300)
    monkeypatch.setattr(lcs.LCSAutomation, 'SIGN_IN_PROMPTS', 1)
    config = make_config(tmp_path, monkeypatch)
    monkeypatch.setattr('builtins.input', lambda: '')
    error_page = ('<h2>You cannot access this right now</h2><p>Signed in as reader@contoso.example</p>'
                  '<p>AADSTS53003: Access has been blocked by Conditional Access policies.</p>')
    with sync_playwright() as playwright:
        instance = offline_adapter(config, tmp_path, playwright, error_page, signs_in=False)
        try:
            with pytest.raises(AutomationError) as raised:
                instance.bootstrap(navigate_first=False)
        finally:
            instance.close()
    message = raised.value.message
    assert 'AADSTS53003' in message and 'login.microsoftonline.com/error?code=53003' in message and 'sign-in policies' in message
    assert 'reader@contoso.example' not in message


@pytest.mark.parametrize('closed', ['tab', 'browser'])
def test_window_closed_before_enter_is_explained(tmp_path, monkeypatch, closed):
    fast_lcs_timings(monkeypatch)
    config = make_config(tmp_path, monkeypatch)
    with sync_playwright() as playwright:
        instance = offline_adapter(config, tmp_path, playwright, SIGN_IN_FORM)
        target = instance.page if closed == 'tab' else instance.context
        monkeypatch.setattr('builtins.input', lambda: target.close() or '')
        try:
            with pytest.raises(AutomationError) as raised:
                instance.bootstrap(navigate_first=False)
        finally:
            instance.close()
    assert raised.value.step == 'authentication'
    assert 'browser window was closed' in raised.value.message


def test_enter_presses_typed_before_the_prompt_are_discarded(monkeypatch):
    calls = []

    class Console:
        def isatty(self):
            return True

    monkeypatch.setattr(lcs.sys, 'stdin', Console())
    monkeypatch.setattr(lcs, '_discard_typed_ahead', lambda: calls.append('discard'))
    monkeypatch.setattr('builtins.input', lambda: calls.append('read') or '')
    lcs.wait_for_enter('Press Enter')
    assert calls == ['discard', 'read']
