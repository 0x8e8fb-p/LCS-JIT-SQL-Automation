import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet
import yaml

import main
import sql_executor as sql
import lcs_jit_automation as lcs
from automation_support import AutomationError, Config, utcnow
from helpers import ROOT, URL, make_adapter, make_config, profile, ps_quote, real_pyodbc, run_powershell
from helpers import run_setup_snippet as invoke_setup


def invoke(script, *args):
    return run_powershell(script, *args, cwd=ROOT)


@pytest.mark.powershell
def test_download_without_local_config_creates_safe_template_and_stops(tmp_path):
    shutil.copy2(ROOT / 'run.ps1', tmp_path / 'run.ps1')
    app = tmp_path / 'automation'
    app.mkdir()
    shutil.copy2(ROOT / 'automation/config.template.yaml', app / 'config.template.yaml')
    result = invoke(tmp_path / 'run.ps1')
    assert result.returncode == 1
    assert 'Created ' in result.stdout and 'No prerequisites or access changes' in result.stdout
    data = yaml.safe_load((tmp_path / 'config.yaml').read_text())
    assert data == {'ENVIRONMENT_URL': '', 'ACCESS_REASON': 'AX troubleshooting (read-only to AX)',
                    'ACCESS_DETAILS': '', 'FIREWALL_RULE_NAME': 'lcsjit'}
    config = tmp_path / 'config.yaml'
    before = config.read_bytes()
    result = invoke(tmp_path / 'run.ps1')
    assert result.returncode == 1
    assert config.read_bytes() == before
    assert 'Created ' not in result.stdout
    assert not (app / '.venv').exists()


@pytest.mark.parametrize('extra', ['ENVIRONMENT_URL: "https://example.com"', 'ACCESS_REASON: "different"',
                                  'ACCESS_DETAILS: "different"'])
def test_duplicate_yaml_keys_fail_closed(tmp_path, extra):
    path = profile(tmp_path)
    with path.open('a') as f:
        f.write('\n' + extra + '\n')
    with pytest.raises(AutomationError):
        Config.load(path)


def test_bom_and_whitespace_are_normalized(tmp_path):
    path = profile(tmp_path, ENVIRONMENT_URL='  ' + URL + '  ', ACCESS_REASON='  AX troubleshooting (read-only to AX)  ')
    path.write_bytes(b'\xef\xbb\xbf' + path.read_bytes())
    c = Config.load(path)
    assert c.environment_url == URL and c.access_level == 'read_only'


@pytest.mark.parametrize('key', ['DISABLE_ACCESS_AFTER', 'SQL_SCRIPTS_PATH', 'STORAGE_STATE_PATH', 'ACCESS_LEVEL'])
def test_stale_advanced_environment_override_cannot_change_minimal_profile(tmp_path, monkeypatch, key):
    monkeypatch.setenv(key, 'false' if key == 'DISABLE_ACCESS_AFTER' else 'unexpected')
    with pytest.raises(AutomationError):
        Config.load(profile(tmp_path))


@pytest.mark.parametrize('url', [URL + '&EnvironmentId=', URL + '#fragment',
                                 URL.replace('11111111-2222-4333-8444-555555555555', 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE')])
def test_noncanonical_environment_identity_refused(tmp_path, url):
    with pytest.raises(AutomationError):
        Config.load(profile(tmp_path, ENVIRONMENT_URL=url))


def test_prepared_scripts_execute_validated_snapshot(tmp_path, monkeypatch):
    path = profile(tmp_path)
    c = Config.load(path)
    c.scripts_path.mkdir()
    script = c.scripts_path / '01.sql'
    script.write_text('SELECT 123;')
    prepared = sql.prepare_scripts(c.scripts_path)
    script.write_text('DELETE FROM important_table;')
    (c.scripts_path / '02.sql').write_text('DELETE FROM another_table;')
    from datetime import timedelta
    credentials = lcs.Credentials('test.database.windows.net', 'AxDB', 'reader', 'secret', utcnow(), utcnow() + timedelta(hours=1))
    preflight = MagicMock()
    preflight.fetchone.return_value = (1,)
    cursor = MagicMock(description=None, rowcount=0)
    cursor.nextset.return_value = False
    connection = MagicMock()
    connection.cursor.side_effect = [preflight, cursor]
    monkeypatch.setattr(sql.pyodbc, 'connect', lambda *a, **k: connection)
    report = sql.execute_sql_scripts(credentials, c, prepared)
    cursor.execute.assert_called_once_with('SELECT 123;')
    assert report['total_scripts'] == report['scripts_executed'] == 1
    connection.commit.assert_called_once()


@pytest.mark.parametrize('sql_failed', [False, True])
def test_diagnostic_disk_failure_preserves_cleanup_outcome(tmp_path, monkeypatch, sql_failed):
    adapter = make_adapter(AutomationError('cleanup', 'Owned rule still present.'))
    monkeypatch.setattr(main, 'LCSAutomation', lambda *a, **k: adapter)
    monkeypatch.setattr(main, 'get_public_ip', lambda _: '8.8.8.8')
    def execute(*args):
        if sql_failed:
            raise AutomationError('sql_connection', 'Connection unavailable.')
        return {'scripts_failed': 0, 'scripts_executed': 1}
    monkeypatch.setattr(main, 'execute_sql_scripts', execute)
    monkeypatch.setattr(Path, 'write_text', MagicMock(side_effect=OSError('disk full')))
    result = main.run(make_config(), tmp_path)
    assert result['status'] == 'failure'
    assert result['failed_at_step'] == ('sql_connection' if sql_failed else 'cleanup')
    assert result['cleanup']['status'] == 'failure'
    assert result['diagnostic_write_failed'] is True
    adapter.disable_ip.assert_called_once()
    adapter.close.assert_called_once()
    assert 'SQL_SECRET' not in json.dumps(result)


def test_environment_url_override_cannot_bypass_stale_override_guard(tmp_path, monkeypatch):
    path = profile(tmp_path, ENVIRONMENT_URL='')
    monkeypatch.setenv('ENVIRONMENT_URL', URL)
    monkeypatch.setenv('DISABLE_ACCESS_AFTER', 'false')
    with pytest.raises(AutomationError):
        Config.load(path)


def test_reason_environment_override_is_trimmed(tmp_path, monkeypatch):
    monkeypatch.setenv('ACCESS_REASON', '  Performance tuning for AX (write to AX)  ')
    assert Config.load(profile(tmp_path)).access_level == 'read_write'


@pytest.mark.powershell
@pytest.mark.skipif(not real_pyodbc(), reason='the probe imports pyodbc in a child process (needs unixODBC on macOS/Linux)')
def test_runtime_version_drift_is_detected(tmp_path):
    requirements = tmp_path / 'requirements.txt'
    from importlib.metadata import version
    requirements.write_text('playwright==' + version('playwright') + '\n')
    result = invoke_setup(tmp_path, f"if (-not (Test-PythonPackages {ps_quote(sys.executable)} {ps_quote(requirements)})) {{ throw 'Correct version refused' }}")
    assert result.returncode == 0, result.stdout + result.stderr
    requirements.write_text('playwright==0.0.0\n')
    result = invoke_setup(tmp_path, f"if (Test-PythonPackages {ps_quote(sys.executable)} {ps_quote(requirements)}) {{ throw 'Drift accepted' }}")
    assert result.returncode == 0, result.stdout + result.stderr


def test_stale_encrypted_auth_temp_does_not_block_refresh(tmp_path, monkeypatch):
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    path = tmp_path / 'auth.enc'
    stale = path.with_suffix('.tmp')
    stale.write_bytes(b'old encrypted state')
    context = MagicMock()
    context.storage_state.return_value = {'cookies': [], 'origins': []}
    lcs.save_auth(context, path)
    assert lcs.load_auth(path) == {'cookies': [], 'origins': []}
    assert stale.read_bytes() == b'old encrypted state'
    assert list(tmp_path.glob('auth.enc.*.tmp')) == []


@pytest.mark.parametrize('host', ['eu.lcs.dynamics.com', 'fr.lcs.dynamics.com', 'sa.lcs.dynamics.com'])
def test_regional_lcs_hosts_are_supported(tmp_path, host):
    regional_url = URL.replace('lcs.dynamics.com', host)
    c = Config.load(profile(tmp_path, ENVIRONMENT_URL=regional_url))
    assert c.lcs_origin == f'https://{host}'
    assert c.project_id == '123456'


@pytest.mark.chromium
def test_bootstrap_recovers_from_logon_index_and_saves_session(tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    monkeypatch.setattr('builtins.input', lambda: '')
    c = Config.load(profile(tmp_path))
    c.state_path = tmp_path / 'auth.enc'
    c.auth_key_path = None
    with sync_playwright() as p:
        adapter = lcs.LCSAutomation(c, p, tmp_path / 'logs', bootstrap=True)
        def route(r):
            if '/Logon/Index' in r.request.url:
                r.fulfill(content_type='text/html', body='<a class="loginLink" href="/V2/Project/123456">Sign in</a>')
            else:
                r.fulfill(content_type='text/html', body='<h1>contoso-sandbox</h1><section id="x_ManageEnvironmentSection">Database Accounts</section>')
        adapter.context.route('https://lcs.dynamics.com/**', route)
        try:
            adapter.page.goto('https://lcs.dynamics.com/Logon/Index')
            adapter.bootstrap(navigate_first=False)
            assert c.state_path.exists()
            assert c.environment_id == 'contoso-sandbox'
        finally:
            adapter.close()


@pytest.mark.chromium
def test_persistent_profile_and_navigate_refresh_saved_auth(tmp_path, monkeypatch):
    from playwright.sync_api import sync_playwright
    monkeypatch.setenv('LCS_AUTH_KEY', Fernet.generate_key().decode())
    c = Config.load(profile(tmp_path))
    c.state_path = tmp_path / 'auth.enc'
    c.auth_key_path = tmp_path / 'auth.dpapi'
    c.state_path.write_bytes(lcs.cipher(c.auth_key_path, create=True).encrypt(json.dumps({
        'cookies': [{'name': 'lcscs', 'value': 'session123', 'domain': '.lcs.dynamics.com', 'path': '/', 'expires': -1, 'httpOnly': True, 'secure': True, 'sameSite': 'Lax'}],
        'origins': [],
    }).encode()))
    with sync_playwright() as p:
        adapter = lcs.LCSAutomation(c, p, tmp_path / 'logs')
        adapter.context.route('https://lcs.dynamics.com/**', lambda r: r.fulfill(
            content_type='text/html',
            headers={'Set-Cookie': 'lcsada=updated456; Path=/; Secure; HttpOnly'},
            body='<h1>contoso-sandbox</h1><section id="x_ManageEnvironmentSection">Database Accounts</section>',
        ))
        try:
            assert (tmp_path / 'auth.profile').is_dir()
            adapter.navigate()
            saved = lcs.load_auth(c.state_path, c.auth_key_path)
            names = {cookie['name']: cookie['value'] for cookie in saved['cookies']}
            assert names.get('lcscs') == 'session123'
            assert names.get('lcsada') == 'updated456'
        finally:
            adapter.close()
