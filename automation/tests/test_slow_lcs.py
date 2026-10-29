"""A slow LCS: late grid rows, late dialogs and late credentials are awaited, never guessed."""
from __future__ import annotations

import json
import time
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright

import lcs_jit_automation as lcs
from automation_support import AutomationError, Config, utcnow
from helpers import fast_lcs_timings, profile

pytestmark = pytest.mark.chromium
HEADING = '<h1>contoso-sandbox</h1>'


def make_config(tmp_path, monkeypatch):
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    config = Config.load(profile(tmp_path))
    config.state_path = tmp_path / 'auth.enc'
    config.auth_key_path = None
    config.state_path.write_bytes(lcs.cipher().encrypt(json.dumps({'cookies': [], 'origins': []}).encode()))
    return config


def rule_row(name, ip='8.8.8.8', hours=7):
    expiry = (utcnow() + timedelta(hours=hours)).strftime('%m/%d/%Y %I:%M %p')
    return (f'<div class="rowTemplate"><input name="NetworkSecurityRuleName" value="{name}">'
            f'<input name="NetworkSecurityRuleIpOrCidr" value="{ip}"><input name="NetworkSecurityGroupService" value="AzureSQL">'
            f'<input name="NetworkSecurityGroupRuleExpiration" value="{expiry}">'
            '<button role="checkbox" aria-checked="false" onclick="this.setAttribute(\'aria-checked\', '
            'this.getAttribute(\'aria-checked\')===\'true\'?\'false\':\'true\')">Select</button></div>')


def grid_page(rows_html, *, rows_delay_ms=0, confirm_delay_ms=None):
    """Firewall grid whose rows bind rows_delay_ms after the dialog opens."""
    bind = json.dumps(rows_html)
    delete = ("fetch('/delete',{method:'POST'})" if confirm_delay_ms is None else
              f"setTimeout(()=>document.querySelector('#confirm').hidden=false,{confirm_delay_ms})")
    return f'''{HEADING}<section id="x_ManageEnvironmentSection">Database Accounts</section>
      <button id="x_MaintainEnvironment_button">Maintain</button>
      <button id="NetworkSecurityGroupModify" onclick="document.querySelector('#grid-dialog').hidden=false;
        setTimeout(()=>document.querySelector('#x_NetworkSecurityRuleList').innerHTML={bind.replace('"', '&quot;')},{rows_delay_ms})">Enable access</button>
      <div role="dialog" id="grid-dialog" hidden>
        <div id="x_NetworkSecurityRuleList" style="min-height:20px"></div>
        <button id="x_AddRule" onclick="fetch('/add',{{method:'POST'}})">Add</button>
        <button id="x_DeleteRules" onclick="{delete}">Delete</button>
        <button id="x_CloseButton" onclick="this.parentNode.hidden=true">Close</button>
      </div>
      <div role="dialog" id="confirm" hidden><p>Delete the selected rule?</p>
        <button onclick="fetch('/delete',{{method:'POST'}}).then(()=>this.parentNode.hidden=true)">Yes</button></div>'''


def serve(instance, state, page):
    def route(request_route):
        url = request_route.request.url
        if url.endswith('/add'):
            state['adds'] += 1
            request_route.fulfill(body='ok')
        elif url.endswith('/delete'):
            state['deletes'] += 1
            state['rule'] = False
            request_route.fulfill(body='ok')
        else:
            request_route.fulfill(content_type='text/html', body=page())
    instance.context.route('https://lcs.dynamics.com/**', route)


@pytest.mark.parametrize('late_row', ['someone-else', 'validation'])
def test_late_grid_rows_are_awaited_so_no_duplicate_rule_is_created(tmp_path, monkeypatch, late_row):
    fast_lcs_timings(monkeypatch, GRID_EMPTY_SETTLE_MS=4500)
    config = make_config(tmp_path, monkeypatch)
    state = {'adds': 0, 'deletes': 0, 'rule': True}
    # 'someone-else': an unexpired rule for this IP (reused, not owned).
    # 'validation': this run's rule name for another IP (conflict, not overwritten).
    row = rule_row(late_row, ip='8.8.8.8' if late_row == 'someone-else' else '1.1.1.1')
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        serve(instance, state, lambda: grid_page(row, rows_delay_ms=3000))  # old code waited a fixed 2 s
        try:
            instance.navigate()
            if late_row == 'someone-else':
                instance.enable_ip('8.8.8.8')
                assert instance.ip_rule_attempted is False and instance.rule_created is False
            else:
                with pytest.raises(AutomationError, match='Firewall rule validation already exists') as raised:
                    instance.enable_ip('8.8.8.8')
                assert raised.value.step == 'ip_rule'
        finally:
            instance.close()
    assert state['adds'] == 0


def test_late_delete_confirmation_is_clicked(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch, CONFIRM_TIMEOUT_MS=5000)
    config = make_config(tmp_path, monkeypatch)
    state = {'adds': 0, 'deletes': 0, 'rule': True}
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        serve(instance, state, lambda: grid_page(rule_row('validation') if state['rule'] else '', confirm_delay_ms=1500))
        try:
            instance.navigate()
            instance.public_ip, instance.rule_name, instance.ip_rule_attempted = '8.8.8.8', 'validation', True
            instance.disable_ip()
        finally:
            instance.close()
    assert state['deletes'] == 1
    assert instance.rule_created is False


def credential_page(granted):
    expiry = (utcnow() + timedelta(hours=7)).strftime('%m/%d/%Y %I:%M %p')
    row = f'''<div class="rowTemplate"><input name="ServerDbName" value="test\\AxDB"><input name="SqlUserName" value="reader">
      <div data-colindex="4"><input name="SqlPasswordText" value="FIXTURE_PASSWORD"></div>
      <div data-colindex="5"><input name="ReasonForAccess" value="{expiry}"></div>
      <div data-colindex="6"><input name="ReasonForAccessDetails" value="AX  troubleshooting (read-only to AX)"></div>
      <div data-colindex="7"><input name="SqlPasswordText" value="Approved validation "></div></div>''' if granted else ''
    return f'''{HEADING}<section id="x_ManageEnvironmentSection">
      <input id="JITOptionDropdownCustomerView_input" onclick="document.querySelector('#JITOptionDropdownCustomerView_list').hidden=false">
      <ul id="JITOptionDropdownCustomerView_list" hidden><li role="option"
        onclick="document.querySelector('#JITOptionDropdownCustomerView_input').value=this.textContent;this.parentNode.hidden=true">AX troubleshooting (read-only to AX)</li></ul>
      <input id="JITInput_input">
      <button id="JITRequestAccessButtonCustomerView" onclick="fetch('/grant',{{method:'POST'}})">Request access</button>
      <div id="x_SqlAccountTable">{row}</div></section>'''


def test_credentials_found_on_a_later_poll_with_a_single_grant(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch, CREDENTIAL_POLL_SECONDS=20)
    config = make_config(tmp_path, monkeypatch)
    state = {'grants': 0, 'reloads_after_grant': 0}

    def route(request_route):
        if request_route.request.url.endswith('/grant'):
            state['grants'] += 1
            request_route.fulfill(body='ok')
            return
        if state['grants']:
            state['reloads_after_grant'] += 1
        request_route.fulfill(content_type='text/html', body=credential_page(state['reloads_after_grant'] >= 4))

    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        instance.context.route('https://lcs.dynamics.com/**', route)
        try:
            instance.navigate()
            instance.firewall_expires_at = utcnow() + timedelta(hours=8)  # as after enable_ip
            credentials = instance.request_access()
        finally:
            instance.close()
    assert state['grants'] == 1
    assert state['reloads_after_grant'] == 4
    assert credentials.password == 'FIXTURE_PASSWORD' and credentials.username == 'reader'


def test_missing_accounts_section_reports_slow_lcs_or_permission(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch)
    monkeypatch.setattr(lcs.LCSAutomation, 'NAVIGATION_TIMEOUT_MS', 1500)
    config = make_config(tmp_path, monkeypatch)
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        instance.context.route('https://lcs.dynamics.com/**', lambda r: r.fulfill(content_type='text/html', body=f'{HEADING}<p>Loading</p>'))
        try:
            with pytest.raises(AutomationError) as raised:
                instance.navigate()
        finally:
            instance.close()
    assert raised.value.step == 'environment'
    assert 'did not appear within 1.5 s' in raised.value.message and 'permission' in raised.value.message


def test_federated_sign_in_redirect_fails_fast_as_authentication(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch)
    config = make_config(tmp_path, monkeypatch)
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        instance.context.route('https://lcs.dynamics.com/**', lambda r: r.fulfill(
            content_type='text/html', body="<script>location.href='https://adfs.contoso.example/adfs/ls/?wa=signin'</script>"))
        instance.context.route('https://adfs.contoso.example/**', lambda r: r.fulfill(
            content_type='text/html', body='<form>Sign in <input type="email" name="UserName"><input type="password"></form>'))
        started = time.monotonic()
        try:
            with pytest.raises(AutomationError) as raised:
                instance.navigate()
        finally:
            instance.close()
    assert raised.value.step == 'authentication'
    assert 'adfs.contoso.example' in raised.value.message
    assert time.monotonic() - started < 15  # not three full page-load limits


def test_silent_single_sign_on_hop_is_not_mistaken_for_expired_login(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch, SIGN_IN_GRACE_MS=5000)
    config = make_config(tmp_path, monkeypatch)
    state = {'lcs_requests': 0}

    def lcs_route(request_route):
        state['lcs_requests'] += 1
        if state['lcs_requests'] == 1:  # first visit bounces through Entra
            body = "<script>location.href='https://login.microsoftonline.com/common/oauth2/authorize'</script>"
        else:
            body = f'{HEADING}<section id="x_ManageEnvironmentSection">Database Accounts</section>'
        request_route.fulfill(content_type='text/html', body=body)

    back = "<script>setTimeout(()=>location.href=" + json.dumps(config.environment_url) + ",700)</script>"
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        instance.context.route('https://lcs.dynamics.com/**', lcs_route)
        instance.context.route('https://login.microsoftonline.com/**', lambda r: r.fulfill(content_type='text/html', body=back))
        try:
            instance.navigate()
        finally:
            instance.close()
    assert config.environment_id == 'contoso-sandbox'
    assert state['lcs_requests'] == 2


def test_slow_auto_submit_hop_longer_than_the_grace_still_succeeds(tmp_path, monkeypatch):
    # An identity page that only posts back to LCS (form_post) shows no prompt.
    fast_lcs_timings(monkeypatch, SIGN_IN_GRACE_MS=800)
    config = make_config(tmp_path, monkeypatch)
    state = {'lcs_requests': 0}

    def lcs_route(request_route):
        state['lcs_requests'] += 1
        body = ("<script>location.href='https://login.microsoftonline.com/common/oauth2/authorize'</script>" if state['lcs_requests'] == 1
                else f'{HEADING}<section id="x_ManageEnvironmentSection">Database Accounts</section>')
        request_route.fulfill(content_type='text/html', body=body)

    hop = '<form id="f"></form><script>setTimeout(()=>location.href=' + json.dumps(config.environment_url) + ',2500)</script>'
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        instance.context.route('https://lcs.dynamics.com/**', lcs_route)
        instance.context.route('https://login.microsoftonline.com/**', lambda r: r.fulfill(content_type='text/html', body=hop))
        try:
            instance.navigate()
        finally:
            instance.close()
    assert config.environment_id == 'contoso-sandbox'


def test_unanswered_lcs_is_reported_as_network_not_sign_in(tmp_path, monkeypatch):
    fast_lcs_timings(monkeypatch)
    monkeypatch.setattr(lcs.LCSAutomation, 'NAVIGATION_TIMEOUT_MS', 800)
    monkeypatch.setattr(lcs.time, 'sleep', lambda _: None)
    config = make_config(tmp_path, monkeypatch)
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        instance.context.route('https://lcs.dynamics.com/**', lambda route: None)  # never answered
        try:
            with pytest.raises(AutomationError) as raised:
                instance.navigate()
        finally:
            instance.close()
    assert raised.value.step == 'network'  # not 'authentication': signing in again cannot help
    assert 'LCS could not be reached (net::ERR_' in raised.value.message


def test_cleanup_refuses_when_another_row_ends_up_selected(tmp_path, monkeypatch):
    # Simulates the grid rebinding between selection and Delete.
    fast_lcs_timings(monkeypatch)
    config = make_config(tmp_path, monkeypatch)
    state = {'adds': 0, 'deletes': 0, 'rule': True}
    other = rule_row('someone-else', ip='9.9.9.9').replace('onclick="this.setAttribute', 'id="other" onclick="this.setAttribute')
    ours = rule_row('validation').replace(
        'onclick="this.setAttribute(\'aria-checked\', this.getAttribute(\'aria-checked\')===\'true\'?\'false\':\'true\')"',
        'onclick="document.querySelector(\'#other\').setAttribute(\'aria-checked\',\'true\')"')
    with sync_playwright() as playwright:
        instance = lcs.LCSAutomation(config, playwright, tmp_path / 'logs')
        serve(instance, state, lambda: grid_page(other + ours))
        try:
            instance.navigate()
            instance.public_ip, instance.rule_name, instance.ip_rule_attempted = '8.8.8.8', 'validation', True
            with pytest.raises(AutomationError, match='Could not exclusively select firewall rule validation'):
                instance.disable_ip()
        finally:
            instance.close()
    assert state['deletes'] == 0
