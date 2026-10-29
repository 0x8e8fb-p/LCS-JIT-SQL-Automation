import json

import main
from automation_support import AutomationError
from helpers import make_adapter, make_config


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
