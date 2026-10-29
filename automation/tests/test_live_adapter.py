from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
import os

import pytest
from cryptography.fernet import Fernet

from automation_support import AutomationError, Config
from lcs_jit_automation import LCSAutomation, protected_local_key
from sql_executor import connection_string


def adapter():
    config = MagicMock()
    config.selectors = {'expiry_format': 'lcs_utc'}
    result = object.__new__(LCSAutomation)
    result.config = config
    return result


def test_lcs_utc_expiry_formats():
    instance = adapter()
    assert instance.expiry_value('10/7/2026 4:12 PM') == datetime(2026, 10, 7, 16, 12, tzinfo=timezone.utc)
    assert instance.expiry_value('10/7/2026 4:26:05 PM') == datetime(2026, 10, 7, 16, 26, 5, tzinfo=timezone.utc)
    with pytest.raises(AutomationError):
        instance.expiry_value('tomorrow')


def test_dpapi_protected_local_key_roundtrip(tmp_path):
    if os.name != 'nt':
        with pytest.raises(AutomationError, match='requires Windows'):
            protected_local_key(tmp_path / 'key.dpapi', create=True)
        return
    path = tmp_path / 'key.dpapi'
    key = protected_local_key(path, create=True)
    assert len(key) == 44
    assert path.read_bytes() != key
    assert protected_local_key(path) == key
    message = b'test auth state'
    assert Fernet(key).decrypt(Fernet(key).encrypt(message)) == message


def test_advanced_reference_profile_is_a_template_until_edited(tmp_path, monkeypatch):
    reference = Path(__file__).resolve().parents[1] / 'config.advanced.yaml'
    with pytest.raises(AutomationError, match='ACCESS_DETAILS still contains the REPLACE_ placeholder'):
        Config.load(reference)
    import yaml
    data = yaml.safe_load(reference.read_text(encoding='utf-8'))
    assert data['LCS_PROJECT_ID'] == '123456' and data['ACCESS_LEVEL'] == 'read_only'
    assert 'SQL_ODBC_DRIVER' not in data  # Driver choice is automatic unless a profile forces one.
    data['ACCESS_DETAILS'] = 'Approved validation'
    edited = tmp_path / 'my-profile.local.yaml'
    edited.write_text(yaml.safe_dump(data), encoding='utf-8')
    config = Config.load(edited)
    assert config.reason == 'AX troubleshooting (read-only to AX)'
    assert config.selectors['rule_name'].startswith('lcsjit-')
    assert config.state_path == (tmp_path / '.auth' / 'advanced_profile_auth.enc').resolve()
    assert config.minimal_profile is False
    from automation_support import Credentials, utcnow
    from datetime import timedelta
    now = utcnow()
    credentials = Credentials('server.database.windows.net', 'AxDB', 'user', 'secret', now, now + timedelta(hours=8))
    assert 'DRIVER={ODBC Driver 18 for SQL Server}' in connection_string(credentials, config.odbc_driver)
    data['SQL_ODBC_DRIVER'] = 'ODBC Driver 17 for SQL Server'
    edited.write_text(yaml.safe_dump(data), encoding='utf-8')
    value = connection_string(credentials, Config.load(edited).odbc_driver)
    assert 'DRIVER={ODBC Driver 17 for SQL Server}' in value
    assert 'Encrypt=yes;TrustServerCertificate=no' in value


def test_owned_rule_identity_must_match():
    instance = adapter()
    instance.rule_name = 'test'
    instance.public_ip = '8.8.8.8'
    row = MagicMock()
    values = {
        "input[name='NetworkSecurityRuleName']": 'test',
        "input[name='NetworkSecurityRuleIpOrCidr']": '1.1.1.1',
        "input[name='NetworkSecurityGroupService']": 'AzureSQL',
    }
    row.locator.side_effect = lambda key: MagicMock(input_value=lambda: values[key])
    instance.rule_rows = MagicMock(return_value=MagicMock(all=lambda: [row]))
    with pytest.raises(AutomationError, match='refusing'):
        instance.matching_owned_rows(MagicMock())


def test_reusing_existing_rule_never_claims_ownership():
    instance = adapter()
    instance.public_ip = '8.8.8.8'
    instance.ip_rule_attempted = False
    instance.rule_name = ''
    instance.rule_created = False
    from automation_support import utcnow
    from datetime import timedelta
    instance.firewall_expires_at = utcnow() + timedelta(hours=8)
    instance.expiry_value = MagicMock(return_value=utcnow() + timedelta(hours=1))
    row = MagicMock()
    values = {
        "input[name='NetworkSecurityRuleIpOrCidr']": '8.8.8.8',
        "input[name='NetworkSecurityGroupService']": 'AzureSQL',
        "input[name='NetworkSecurityGroupRuleExpiration']": 'future',
    }
    row.locator.side_effect = lambda key: MagicMock(input_value=lambda: values[key])
    instance.open_rule_grid = MagicMock()
    instance.rule_rows = MagicMock(return_value=MagicMock(all=lambda: [row]))
    instance.locator = MagicMock()
    instance.screenshot = MagicMock()
    instance.wait_idle = MagicMock()
    instance.enable_rule_grid('8.8.8.8')
    assert instance.ip_rule_attempted is False
    assert instance.rule_name == ''
    assert instance.rule_created is False
    assert instance.firewall_expires_at < utcnow() + timedelta(hours=2)
    # Only close the dialog, never add or delete a rule.
    assert instance.locator.call_args.args[0] == 'rule_close'


def test_expired_matching_rule_is_not_reused():
    from automation_support import utcnow
    from datetime import timedelta
    instance = adapter()
    instance.config.selectors['rule_name'] = 'test'
    instance.firewall_expires_at = utcnow() + timedelta(hours=8)
    instance.expiry_value = MagicMock(return_value=utcnow() - timedelta(minutes=1))
    values = {
        "input[name='NetworkSecurityRuleName']": 'test',
        "input[name='NetworkSecurityRuleIpOrCidr']": '8.8.8.8',
        "input[name='NetworkSecurityGroupService']": 'AzureSQL',
        "input[name='NetworkSecurityGroupRuleExpiration']": 'expired',
    }
    row = MagicMock()
    row.locator.side_effect = lambda key: MagicMock(input_value=lambda: values[key])
    instance.open_rule_grid = MagicMock()
    instance.rule_rows = MagicMock(return_value=MagicMock(all=lambda: [row]))
    instance.close_dialog = MagicMock()
    with pytest.raises(AutomationError, match='Firewall rule test already exists in LCS'):
        instance.enable_rule_grid('8.8.8.8')
    instance.close_dialog.assert_not_called()


def test_safe_click_never_bypasses_browser_actionability():
    from playwright.sync_api import Error as BrowserError
    instance = adapter()
    instance.wait_idle = MagicMock()
    button = MagicMock()
    button.click.side_effect = BrowserError('overlay intercepted')
    with pytest.raises(BrowserError):
        instance.safe_click(button)
    instance.wait_idle.assert_called_once()
    button.evaluate.assert_not_called()


@pytest.mark.chromium
def test_browser_grid_add_cleanup_with_stale_modal_layer(tmp_path, monkeypatch):
    import json
    from datetime import timedelta
    from playwright.sync_api import sync_playwright
    from automation_support import utcnow
    import lcs_jit_automation as lcs

    import yaml
    profile = tmp_path / 'config.yaml'
    profile.write_text(yaml.safe_dump({
        'ENVIRONMENT_URL': 'https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/123456?EnvironmentId=11111111-2222-4333-8444-555555555555',
        'ACCESS_REASON': 'AX troubleshooting (read-only to AX)',
        'ACCESS_DETAILS': 'Fixture validation', 'FIREWALL_RULE_NAME': 'test',
    }))
    config = Config.load(profile)
    config.state_path = tmp_path / 'auth.enc'
    config.auth_key_path = None
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    from helpers import fast_lcs_timings
    fast_lcs_timings(monkeypatch)
    config.state_path.write_bytes(lcs.cipher().encrypt(json.dumps({'cookies': [], 'origins': []}).encode()))
    state = {'rule': False, 'adds': 0, 'deletes': 0, 'reloads': 0}
    expiry = (utcnow() + timedelta(hours=7)).strftime('%m/%d/%Y %I:%M:%S %p')

    def html():
        row = f'''<div class="rowTemplate">
          <input name="NetworkSecurityRuleName" value="test">
          <input name="NetworkSecurityRuleIpOrCidr" value="8.8.8.8">
          <input name="NetworkSecurityGroupService" value="AzureSQL">
          <input name="NetworkSecurityGroupRuleExpiration" value="{expiry}">
          <button role="checkbox" aria-checked="false"
            onclick="this.setAttribute('aria-checked', this.getAttribute('aria-checked')==='true'?'false':'true')">Select</button>
        </div>''' if state['rule'] else ''
        return f'''<h1>contoso-sandbox</h1><section id="x_ManageEnvironmentSection">Database Accounts</section>
          <button id="x_MaintainEnvironment_button">Maintain</button>
          <button id="NetworkSecurityGroupModify" onclick="document.querySelector('#grid-dialog').hidden=false">Enable access</button>
          <div role="dialog" id="grid-dialog" hidden>
            <div id="x_NetworkSecurityRuleList" style="min-height:20px">{row}</div>
            <button id="x_AddRule" onclick="document.querySelector('#add-dialog').hidden=false">Add</button>
            <button id="x_DeleteRules" onclick="fetch('/delete',{{method:'POST'}})">Delete</button>
            <button id="x_CloseButton" onclick="this.parentNode.hidden=true">Close</button>
          </div>
          <div role="dialog" id="add-dialog" hidden>
            <input name="Services" value="AzureSQL"><input name="NameField"><input name="IpOrCidrField">
            <button id="x_CreateTopBtn" onclick="fetch('/add',{{method:'POST'}}).then(()=>{{
              this.parentNode.hidden=true;
              const layer=document.createElement('div');layer.className='popupShadow';
              layer.style='position:fixed;inset:0;z-index:999;background:transparent';document.body.appendChild(layer);
            }})">Create</button>
          </div>'''

    with sync_playwright() as p:
        instance = LCSAutomation(config, p, tmp_path / 'logs')
        def route(r):
            if r.request.url.endswith('/add'):
                state['rule'] = True
                state['adds'] += 1
                r.fulfill(body='ok')
            elif r.request.url.endswith('/delete'):
                state['rule'] = False
                state['deletes'] += 1
                r.fulfill(body='ok')
            else:
                state['reloads'] += 1
                r.fulfill(content_type='text/html', body=html())
        instance.context.route('https://lcs.dynamics.com/**', route)
        try:
            assert config.environment_id == ''
            instance.navigate()
            assert config.environment_id == 'contoso-sandbox'
            instance.enable_ip('8.8.8.8')
            assert instance.rule_created is True
            assert instance.rule_name == 'test'
            instance.disable_ip()
            assert instance.rule_created is False
            assert state['rule'] is False
            assert state['adds'] == state['deletes'] == 1
            assert state['reloads'] >= 4
        finally:
            instance.close()
