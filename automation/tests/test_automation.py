from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pyodbc
import pytest
import yaml
from cryptography.fernet import Fernet
from playwright.sync_api import sync_playwright

import lcs_jit_automation as lcs
import main
import sql_executor as sql
from automation_support import AutomationError, Config, Credentials, parse_expiry, parse_server_database, utcnow
from helpers import fast_lcs_timings



@pytest.fixture
def config(tmp_path):
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / '01.sql').write_text('SELECT 1;\nGO\nSELECT 2;', encoding='utf-8')
    return Config('123', 'UAT', 'read_only', 'Read only', 'Validation', scripts,
                  tmp_path / 'auth.enc', tmp_path / 'logs', False, True,
                  '8.8.8.8', 'database.windows.net', 30, 2,
                  {'accounts': '#accounts', 'rows': '.credential',
                   'server_database': '.server-db', 'username': '.username',
                   'password': '.password', 'expires_at': '.expiry',
                   'disable_ip_address': '#disable-ip'})


@pytest.fixture
def credentials():
    now = utcnow()
    return Credentials('test.database.windows.net', 'AxDB', 'reader', 'TOP_SECRET};PWD=injected;', now, now + timedelta(hours=8))


def test_credentials_and_expiry(credentials):
    assert credentials.password not in repr(credentials)
    credentials.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(AutomationError, match='expired'):
        credentials.ensure_valid()
    assert parse_server_database('test\\AxDB', 'database.windows.net') == ('test.database.windows.net', 'AxDB')
    with pytest.raises(AutomationError):
        parse_server_database('other.example.com\\AxDB', 'database.windows.net')
    with pytest.raises(AutomationError):
        parse_expiry('2026-10-07T10:00:00')


def test_odbc_escape_and_redaction(credentials):
    assert 'PWD={TOP_SECRET}};PWD=injected;};' in sql.connection_string(credentials)
    assert 'Encrypt=yes;TrustServerCertificate=no' in sql.connection_string(credentials)
    result = sql.scrub({credentials.password: [[credentials.password], b'raw']}, (credentials.password,))
    assert credentials.password not in json.dumps(result)
    assert 'BINARY OMITTED' in json.dumps(result)
    assert sql.scrub(float('nan'), ()) == 'nan'
    error = pyodbc.Error('42000', 'password=' + credentials.password)
    assert credentials.password not in sql.safe_sql_error(error)
    assert '42000' in sql.safe_sql_error(error)


def test_batch_parser():
    text = "SELECT 'first\nGO\nlast';\n/* outer\n/* nested */\nGO\n*/\nGO -- batch\nSELECT [GO], \"GO\";\n"
    batches = sql.split_batches(text)
    assert len(batches) == 2
    assert 'first\nGO\nlast' in batches[0]
    assert len(sql.split_batches("SELECT 'a''b';\nGO\nSELECT [x]]y];")) == 2
    for invalid in ['SELECT 1;\nGO 3', ':r script.sql', "SELECT 'unfinished", '/* unclosed']:
        with pytest.raises(AutomationError):
            sql.split_batches(invalid)


def test_sql_results_transactions_and_failure(config, credentials, monkeypatch):
    (config.scripts_path / '02.sql').write_text('BROKEN;', encoding='utf-8')
    (config.scripts_path / '03.sql').write_text('SELECT 3;', encoding='utf-8')
    config.continue_on_error = True
    preflight = MagicMock()
    preflight.fetchone.return_value = (1,)
    good = MagicMock()
    good.rowcount = 3
    good.description = [('value',)]
    good.fetchmany.side_effect = [[(credentials.password,), ('b',), ('c',)], [], [('d',)], []]
    good.nextset.return_value = False
    bad = MagicMock()
    bad.execute.side_effect = pyodbc.Error('42000', credentials.password)
    last = MagicMock()
    last.rowcount = -1
    last.description = None
    last.nextset.return_value = False
    connection = MagicMock()
    connection.cursor.side_effect = [preflight, good, bad, last]
    monkeypatch.setattr(sql.pyodbc, 'connect', lambda *a, **k: connection)
    report = sql.execute_sql_scripts(credentials, config)
    assert report['scripts_executed'] == 2
    assert report['scripts_failed'] == 1
    assert report['details'][0]['rows_affected'] == 6
    assert report['details'][0]['result_sets'][0]['truncated'] is True
    assert report['details'][0]['result_sets'][0]['rows_returned'] == 3
    assert credentials.password not in json.dumps(report)
    assert connection.commit.call_count == 2
    assert connection.rollback.call_count == 2 # preflight + failed script
    connection.close.assert_called_once()


def test_expiry_rolls_back_and_stops_even_with_continue(config, credentials, monkeypatch):
    config.continue_on_error = True
    (config.scripts_path / '02.sql').write_text('SELECT 2;', encoding='utf-8')
    preflight = MagicMock()
    preflight.fetchone.return_value = (1,)
    cursor = MagicMock()
    def expire(_):
        credentials.expires_at = utcnow() - timedelta(seconds=1)
    cursor.execute.side_effect = expire
    connection = MagicMock()
    connection.cursor.side_effect = [preflight, cursor]
    monkeypatch.setattr(sql.pyodbc, 'connect', lambda *a, **k: connection)
    report = sql.execute_sql_scripts(credentials, config)
    assert report['scripts_failed'] == 1
    assert len(report['details']) == 1
    assert 'expired' in report['details'][0]['error']
    connection.commit.assert_not_called()
    assert connection.rollback.call_count == 2
    connection.close.assert_called_once()


def test_connection_retry(config, credentials, monkeypatch):
    connect = MagicMock(side_effect=pyodbc.Error('08001', credentials.password))
    monkeypatch.setattr(sql.pyodbc, 'connect', connect)
    monkeypatch.setattr(sql.time, 'sleep', lambda _: None)
    with pytest.raises(AutomationError, match='failed twice') as error:
        sql.execute_sql_scripts(credentials, config)
    assert credentials.password not in str(error.value)
    assert connect.call_count == 2


def test_stop_and_rollback_failure(config, credentials, monkeypatch):
    preflight = MagicMock()
    preflight.fetchone.return_value = (1,)
    broken = MagicMock()
    broken.execute.side_effect = pyodbc.Error('42000', credentials.password)
    connection = MagicMock()
    connection.cursor.side_effect = [preflight, broken]
    connection.rollback.side_effect = [None, pyodbc.Error('08001', credentials.password)]
    monkeypatch.setattr(sql.pyodbc, 'connect', lambda *a, **k: connection)
    with pytest.raises(AutomationError, match='Rollback failed'):
        sql.execute_sql_scripts(credentials, config)
    connection.close.assert_called_once()


PROJECT = '<a href="/V2/EnvironmentDetailsV3New/123?EnvironmentId=fixture">UAT</a>'


def environment_html(expiry, password, granted):
    row = f'''<div class="credential"><span class="server-db">test\\AxDB</span>
    <span class="username">reader</span><input class="password" value="{password}">
    <span class="expiry">{expiry}</span></div>''' if granted else ''
    return f'''<html><body><h1>UAT</h1>
    <button onclick="document.querySelector('#menu').hidden=false">Maintain</button>
    <div id="menu" hidden><button role="menuitem" onclick="document.querySelector('#enable').hidden=false">Enable access</button>
    <button role="menuitem" onclick="document.querySelector('#disable').hidden=false">Disable access</button></div>
    <div id="enable" role="dialog" aria-label="Enable access" hidden>
      <label>IP address<input id="ip"></label>
      <button onclick="window.ip=document.querySelector('#ip').value;this.parentNode.hidden=true">OK</button></div>
    <div id="disable" role="dialog" aria-label="Disable access" hidden>
      <input id="disable-ip"><button onclick="window.removed=document.querySelector('#disable-ip').value;this.parentNode.hidden=true">OK</button></div>
    <section id="accounts"><h2>Database Accounts</h2>
      <label for="reason">Reason for access</label><select id="reason"><option>Read only</option></select>
      <label for="details">Details</label><textarea id="details"></textarea>
      <button onclick="fetch('/grant', {{method:'POST'}})">Request access</button>{row}</section>
    </body></html>'''


@pytest.fixture
def browser_fixture(config, monkeypatch):
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    # This fixture mocks ODBC connections, so mock installed drivers too.
    monkeypatch.setattr(sql.pyodbc, 'drivers', lambda: ['ODBC Driver 18 for SQL Server'])
    config.state_path.write_bytes(lcs.cipher().encrypt(json.dumps({'cookies': [], 'origins': []}).encode()))
    monkeypatch.setattr(lcs.time, 'sleep', lambda _: None)
    fast_lcs_timings(monkeypatch)
    granted = {'value': False}
    expiry = (utcnow() + timedelta(hours=7)).isoformat()
    password = 'FIXTURE_PASSWORD_DO_NOT_LOG'
    original = lcs.LCSAutomation.__init__
    def init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        def route_handler(route):
            url = route.request.url
            if url.endswith('/grant'):
                granted['value'] = True
                route.fulfill(status=200, body='ok')
            elif '/V2/Project/' in url:
                route.fulfill(content_type='text/html', body=PROJECT)
            else:
                route.fulfill(content_type='text/html', body=environment_html(expiry, password, granted['value']))
        self.context.route('https://lcs.dynamics.com/**', route_handler)
    monkeypatch.setattr(lcs.LCSAutomation, '__init__', init)
    return password


@pytest.mark.chromium
def test_real_browser_flow_and_prewrite_masks(config, browser_fixture, monkeypatch, tmp_path):
    with sync_playwright() as playwright:
        adapter = lcs.LCSAutomation(config, playwright, tmp_path / 'shots')
        try:
            adapter.navigate()
            adapter.enable_ip('8.8.8.8')
            credentials = adapter.request_access()
            assert credentials.password == browser_fixture
            assert credentials.server == 'test.database.windows.net'
            assert credentials.expires_at < credentials.requested_at + timedelta(hours=8)
            # Select by parsed expiry, not DOM order, and reject unchanged rows.
            old_expiry = (utcnow() + timedelta(hours=1)).isoformat()
            adapter.locator('accounts').evaluate('''(el, expiry) => {
                const row = el.querySelector('.credential').cloneNode(true);
                row.querySelector('.expiry').textContent = expiry;
                row.querySelector('.username').textContent = 'older';
                el.appendChild(row);
            }''', old_expiry)
            assert adapter.extract(set(), credentials.requested_at).username == 'reader'
            latest_expiry = adapter.page.locator('.expiry').first.inner_text()
            server_db = adapter.page.locator('.server-db').first.inner_text()
            excluded = {(server_db, 'reader', latest_expiry)}
            assert adapter.extract(excluded, credentials.requested_at).username == 'older'
            # Browser screenshot bytes were actually written. Probe accounts pixels in
            # the browser canvas from the saved PNG; no extra image library required.
            screenshot = Path(adapter.screenshot('verify_mask'))
            import base64
            data = base64.b64encode(screenshot.read_bytes()).decode()
            box = adapter.locator('accounts').bounding_box()
            rgb = adapter.page.evaluate('''async ({data, x, y}) => {
              const img = new Image(); img.src = 'data:image/png;base64,' + data; await img.decode();
              const canvas = document.createElement('canvas'); canvas.width=img.width; canvas.height=img.height;
              const ctx=canvas.getContext('2d'); ctx.drawImage(img,0,0); return Array.from(ctx.getImageData(x,y,1,1).data);
            }''', {'data': data, 'x': int(box['x'] + 5), 'y': int(box['y'] + 5)})
            assert rgb == [0, 0, 0, 255]
            adapter.disable_ip()
            assert adapter.page.evaluate('window.removed') == '8.8.8.8'
            lcs.save_auth(adapter.context, config.state_path)
            assert json.loads(lcs.cipher().decrypt(config.state_path.read_bytes()))['cookies'] == []
            assert b'cookies' not in config.state_path.read_bytes()
            # Stored state is valid, but credentials in the DOM were never persisted.
            assert browser_fixture.encode() not in config.state_path.read_bytes()
        finally:
            adapter.close()


def config_file(config, tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump({
        'LCS_PROJECT_ID': config.project_id, 'ENVIRONMENT_ID': config.environment_id,
        'ACCESS_LEVEL': config.access_level, 'ACCESS_REASON': config.reason,
        'ACCESS_DETAILS': config.details, 'SQL_SCRIPTS_PATH': str(config.scripts_path),
        'STORAGE_STATE_PATH': str(config.state_path), 'LOGS_PATH': str(config.logs_path),
        'PUBLIC_IP': config.public_ip, 'selectors': config.selectors,
    }), encoding='utf-8')
    return path


@pytest.mark.chromium
def test_cli_run_fixture_json_and_reports(config, browser_fixture, monkeypatch, capsys, tmp_path):
    connection = MagicMock()
    preflight = MagicMock()
    preflight.fetchone.return_value = (1,)
    cursor = MagicMock()
    cursor.description = None
    cursor.rowcount = 0
    cursor.nextset.return_value = False
    connection.cursor.side_effect = [preflight, cursor]
    monkeypatch.setattr(sql.pyodbc, 'connect', lambda *a, **k: connection)
    path = config_file(config, tmp_path)
    assert main.main(['run', '--config', str(path)]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report['status'] == 'success'
    assert report['sql_execution']['total_scripts'] == 1
    assert report['cleanup']['sql_credentials_revoked'] is False
    assert browser_fixture not in captured.out
    report_path = next(config.logs_path.glob('*/report.json'))
    assert json.loads(report_path.read_text()) == report
    assert browser_fixture not in report_path.read_text()


@pytest.mark.chromium
def test_cli_failure_cleanup(config, browser_fixture, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sql.pyodbc, 'connect', MagicMock(side_effect=pyodbc.Error('08001', browser_fixture)))
    assert main.main(['run', '--config', str(config_file(config, tmp_path))]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report['failed_at_step'] == 'sql_connection'
    assert report['cleanup']['status'] == 'success'
    assert Path(report['screenshot_path']).exists()
    assert browser_fixture not in json.dumps(report)


def clean_child_environment(**extra):
    """A child process environment without machine-wide configuration overrides."""
    from conftest import ISOLATED_VARIABLES
    env = {key: value for key, value in os.environ.items() if key.upper() not in ISOLATED_VARIABLES}
    env.update(extra)
    return env


def test_cli_subprocess_validation_and_invalid_input(config, tmp_path):
    # Also proves validate works where pyodbc cannot load (it is only needed for SQL).
    path = config_file(config, tmp_path)
    result = subprocess.run([sys.executable, str(Path(main.__file__)), 'validate', '--config', str(path)],
                            capture_output=True, text=True, env=clean_child_environment())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['live_lcs_validated'] is False
    env = clean_child_environment(CONTINUE_ON_ERROR='not-a-bool')
    result = subprocess.run([sys.executable, str(Path(main.__file__)), 'validate', '--config', str(path)], capture_output=True, text=True, env=env)
    assert result.returncode == 1
    assert json.loads(result.stdout)['failed_at_step'] == 'configuration'
    assert 'Traceback' not in result.stderr


def test_auth_wrong_key_never_leaks(config, monkeypatch):
    secret = 'SUPER_SECRET_TOKEN'
    key = Fernet.generate_key()
    config.state_path.write_bytes(Fernet(key).encrypt(secret.encode()))
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    with pytest.raises(AutomationError) as error:
        lcs.load_auth(config.state_path)
    assert secret not in str(error.value)


@pytest.mark.parametrize('override', [
    {'PUBLIC_IP': '127.0.0.1'}, {'PUBLIC_IP': '10.0.0.1'}, {'ACCESS_LEVL': 'read_only'},
    {'ACCESS_REASON': 'Performance tuning for AX (write to AX)', 'ACCESS_LEVEL': 'read_only'},
    {'STORAGE_STATE_PATH': 'same.enc', 'AUTH_KEY_PATH': 'same.enc'},
])
def test_config_rejects_inconsistent_or_unsafe_settings(config, tmp_path, override):
    path = config_file(config, tmp_path)
    data = yaml.safe_load(path.read_text())
    data.update(override)
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(AutomationError, match='Invalid configuration'):
        Config.load(path)


def test_preflight_rejects_bad_sql_before_access(config, tmp_path, capsys, monkeypatch):
    (config.scripts_path / '01.sql').write_text('SELECT 1;\nGO 2;')
    adapter = MagicMock()
    monkeypatch.setattr(main, 'LCSAutomation', adapter)
    assert main.main(['run', '--config', str(config_file(config, tmp_path))]) == 1
    adapter.assert_not_called()
    assert 'unsupported' in json.loads(capsys.readouterr().out)['error_message']


def test_runtime_rejects_missing_driver(config, monkeypatch):
    monkeypatch.setattr(sql.pyodbc, 'drivers', lambda: [])
    with pytest.raises(AutomationError, match='not installed'):
        main.check_runtime(config)


def test_environment_lock_prevents_overlap_and_releases(config):
    from automation_support import environment_lock
    with environment_lock(config):
        with pytest.raises(AutomationError, match='Another run'):
            with environment_lock(config):
                pytest.fail('overlap was allowed')
    with environment_lock(config):
        pass


@pytest.mark.chromium
def test_environment_identity_guard_is_exact(config, browser_fixture, tmp_path):
    with sync_playwright() as playwright:
        adapter = lcs.LCSAutomation(config, playwright, tmp_path / 'shots')
        try:
            adapter.navigate()
            adapter.page.locator('h1').evaluate("el => el.textContent = 'UAT-other'")
            with pytest.raises(AutomationError, match='heading does not match'):
                adapter.verify_environment()
            adapter.page.locator('h1').evaluate("el => el.textContent = 'UAT'")
            adapter.config.environment_url = 'https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/123?EnvironmentId=other'
            with pytest.raises(AutomationError, match='URL does not match'):
                adapter.verify_environment()
        finally:
            adapter.close()
