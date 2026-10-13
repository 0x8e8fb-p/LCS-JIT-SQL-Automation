import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet
import yaml

import main
import sql_executor as sql
import lcs_jit_automation as lcs
from automation_support import AutomationError, Config, utcnow
from test_config import profile, URL
from test_launcher import ROOT, invoke
from test_cleanup import make_config, make_adapter
from test_setup import invoke as invoke_setup, ps_quote
import sys


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
                                 URL.replace('73caba6b', '73CABA6B')])
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
