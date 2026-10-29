"""Safe diagnostics: specific causes without raw messages or secrets."""
from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pyodbc
import pytest
from playwright.sync_api import Error as BrowserError
from playwright.sync_api import TimeoutError as BrowserTimeout

import lcs_jit_automation as lcs
import main
from automation_support import AutomationError, Config, describe_error, explain_error
from helpers import profile

SECRET = 'TOP_SECRET_VALUE_42'


def raised_from_none(inner: BaseException) -> AutomationError:
    try:
        try:
            raise inner
        except Exception:
            raise AutomationError('authentication', 'Wrapped.') from None
    except AutomationError as wrapped:
        return wrapped


@pytest.mark.parametrize(('error', 'key', 'expected'), [
    (BrowserError(f'net::ERR_PROXY_CONNECTION_FAILED at https://lcs.dynamics.com/?code={SECRET}'), 'browser', 'net::ERR_PROXY_CONNECTION_FAILED'),
    (BrowserTimeout(f'Timeout 30000ms exceeded waiting for {SECRET}'), 'browser', 'timeout'),
    (BrowserError(f"Executable doesn't exist at C:\\Users\\{SECRET}\\chrome.exe"), 'browser', 'executable_missing'),
    (BrowserError(f'Failed to create a ProcessSingleton for your profile directory {SECRET}'), 'browser', 'profile_in_use'),
    (BrowserError(f'Target page, context or browser has been closed {SECRET}'), 'browser', 'browser_closed'),
    (BrowserError(f'something unusual {SECRET}'), 'browser', 'other'),
    (PermissionError(13, f'Permission denied {SECRET}', f'C:\\Users\\{SECRET}\\automation\\.auth\\state.enc'), 'file', 'state.enc'),
    (ImportError(f'DLL load failed while importing pyodbc {SECRET}', name='pyodbc'), 'module', 'pyodbc'),
])
def test_describe_error_reports_category_without_secrets(error, key, expected):
    for candidate in (error, raised_from_none(error)):
        info = describe_error(candidate)
        assert info[key] == expected
        assert SECRET not in json.dumps(info)
    wrapped = describe_error(raised_from_none(error))
    assert wrapped['type'] == 'AutomationError'
    assert wrapped['causes'] == [type(error).__name__]


def test_odbc_codes_are_digits_only():
    error = pyodbc.Error('28000', f"[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user '{SECRET}'. (18456) (SQLDriverConnect)")
    info = describe_error(error)
    assert info['odbc'] == {'sqlstate': '28000', 'native': [18456]}
    assert SECRET not in json.dumps(info)
    message = explain_error(error, 'sql_connection')
    assert 'SQLSTATE 28000' in message and '18456' in message and SECRET not in message


@pytest.mark.parametrize(('error', 'phrase'), [
    (ImportError('broken', name='pyodbc'), 'Python package pyodbc is missing or damaged'),
    (BrowserError('net::ERR_NAME_NOT_RESOLVED'), 'Network error net::ERR_NAME_NOT_RESOLVED'),
    (BrowserError("Executable doesn't exist"), 'Rerun run.cmd to reinstall it'),
    (BrowserTimeout('Timeout 1ms exceeded'), 'did not respond in time during ip_rule'),
    (EOFError(), 'interactive console'),
    (PermissionError(13, 'denied', 'report.json'), 'File system error 13 on report.json'),
    (RuntimeError(SECRET), 'Unexpected RuntimeError during ip_rule'),
])
def test_explain_error_is_actionable_and_secret_free(error, phrase):
    message = explain_error(error, 'ip_rule')
    assert phrase in message
    assert SECRET not in message


def test_failed_pyodbc_load_gives_specific_message_and_diagnostic_file(tmp_path, monkeypatch, capsys):
    path = profile(tmp_path)
    logs = tmp_path / 'logs'
    real_load = Config.load

    def load(*args, **kwargs):
        config = real_load(*args, **kwargs)
        config.logs_path = logs
        return config

    monkeypatch.setattr(main.Config, 'load', load)
    scripts = tmp_path / 'sql_scripts'
    scripts.mkdir()
    (scripts / '01.sql').write_text('SELECT 1;', encoding='utf-8')
    monkeypatch.setitem(sys.modules, 'pyodbc', None)  # 'import pyodbc' now fails like a broken DLL
    assert main.main(['validate', '--check-runtime', '--config', str(path)]) == 1
    output = json.loads(capsys.readouterr().out)
    assert 'pyodbc' in output['error_message'] and 'run.cmd' in output['error_message']
    assert output['failed_at_step'] == 'configuration'
    files = list((logs / 'diagnostics').glob('validate-*.json'))
    assert len(files) == 1
    record = json.loads(files[0].read_text(encoding='utf-8'))
    assert record['error_message'] == output['error_message']
    assert record['runtime']['python']
    assert output['diagnostic_file'] == str(files[0])


def test_browser_launch_failure_reports_browser_start(tmp_path):
    config = MagicMock()
    config.auth_key_path = None
    config.browser_timezone = 'UTC'
    playwright = MagicMock()
    playwright.chromium.launch.side_effect = BrowserError(f'Failed to create a ProcessSingleton {SECRET}')
    with pytest.raises(AutomationError) as raised:
        lcs.LCSAutomation(config, playwright, tmp_path, bootstrap=True)
    assert raised.value.step == 'browser_start'
    assert 'in use by another Chromium window' in raised.value.message
    assert SECRET not in raised.value.message
    playwright.chromium.launch.side_effect = BrowserError("Executable doesn't exist at /x/chrome")
    with pytest.raises(AutomationError, match='reinstall') as raised:
        lcs.LCSAutomation(config, playwright, tmp_path, bootstrap=True)
    assert raised.value.step == 'browser_start'


def test_minimal_profile_driver_message_points_to_setup(tmp_path, monkeypatch):
    config = Config.load(profile(tmp_path))
    assert config.minimal_profile is True
    monkeypatch.setattr(pyodbc, 'drivers', lambda: ['SQL Server'])
    with pytest.raises(AutomationError, match='Rerun run.cmd') as raised:
        main.check_runtime(config)
    assert 'Driver 18 or 17' in raised.value.message
