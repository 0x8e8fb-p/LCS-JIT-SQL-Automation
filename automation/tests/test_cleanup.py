import json
from unittest.mock import MagicMock

import main
from automation_support import AutomationError, utcnow


def make_config():
    config = MagicMock()
    config.disable_access_after = True
    config.environment_id = 'UAT'
    config.access_level = 'read_only'
    return config


def make_adapter(error):
    adapter = MagicMock()
    adapter.ip_rule_attempted = True
    adapter.screenshot.return_value = None
    adapter.disable_ip.side_effect = error
    credentials = MagicMock()
    credentials.requested_at = utcnow()
    credentials.expires_at = utcnow()
    credentials.username = 'reader'
    credentials.server = 'test.database.windows.net'
    credentials.database = 'AxDB'
    credentials.password = 'SQL_SECRET'
    adapter.request_access.return_value = credentials
    return adapter


def run_with(monkeypatch, tmp_path, error):
    adapter = make_adapter(error)
    monkeypatch.setattr(main, 'LCSAutomation', lambda *a, **k: adapter)
    monkeypatch.setattr(main, 'get_public_ip', lambda _: '8.8.8.8')
    monkeypatch.setattr(main, 'execute_sql_scripts', lambda *a: {'scripts_failed': 0, 'scripts_executed': 1})
    return main.run(make_config(), tmp_path)


def test_cleanup_raw_exception_never_leaks(monkeypatch, tmp_path):
    result = run_with(monkeypatch, tmp_path, RuntimeError('PRIVATE RAW ERROR'))
    assert result['status'] == 'failure'
    assert result['failed_at_step'] == 'cleanup'
    assert result['sql_execution']['scripts_executed'] == 1
    encoded = json.dumps(result)
    assert 'PRIVATE RAW ERROR' not in encoded
    assert 'SQL_SECRET' not in encoded
    assert 'source IP removal' in result['cleanup']['error_message']


def test_cleanup_static_error_is_actionable(monkeypatch, tmp_path):
    # AutomationError messages are reviewed static strings (verified in source);
    # surfacing them keeps failures actionable, matching every other failure step.
    result = run_with(monkeypatch, tmp_path, AutomationError('cleanup', 'Owned rule still present in freshly opened grid; deletion not confirmed.'))
    assert result['status'] == 'failure'
    assert 'Owned rule still present' in result['cleanup']['error_message']
    assert 'SQL_SECRET' not in json.dumps(result)
