from pathlib import Path
from dataclasses import replace

import pytest
import yaml

from automation_support import AutomationError, Config, environment_lock

ROOT = Path(__file__).resolve().parents[2]
URL = 'https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/123456?EnvironmentId=11111111-2222-4333-8444-555555555555'


def profile(tmp_path, **overrides):
    values = {'ENVIRONMENT_URL': URL, 'ACCESS_REASON': 'AX troubleshooting (read-only to AX)',
              'ACCESS_DETAILS': 'Approved validation', 'FIREWALL_RULE_NAME': 'validation'}
    values.update(overrides)
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump(values))
    return path


def test_minimal_config_derives_internal_values(tmp_path, monkeypatch):
    import pyodbc
    monkeypatch.setattr(pyodbc, 'drivers', lambda: ['ODBC Driver 17 for SQL Server'])
    c = Config.load(profile(tmp_path))
    assert c.project_id == '123456'
    assert c.environment_key == '11111111-2222-4333-8444-555555555555'
    assert c.environment_id == '' # Heading discovered after URL verification.
    assert c.access_level == 'read_only'
    assert c.scripts_path == tmp_path / 'sql_scripts'
    assert c.logs_path == ROOT / 'automation' / 'logs'
    assert c.state_path.parent == ROOT / 'automation' / '.auth'
    assert c.selectors['rule_name'] == 'validation'
    assert c.selectors['accounts']
    assert c.disable_access_after is True and c.continue_on_error is False
    assert c.odbc_driver == 'ODBC Driver 17 for SQL Server'
    write = Config.load(profile(tmp_path, ACCESS_REASON='Performance tuning for AX (write to AX)'))
    assert write.access_level == 'read_write'
    assert write.state_path == c.state_path


@pytest.mark.parametrize('overrides', [
    {'ENVIRONMENT_URL': 'https://example.com/V2/EnvironmentDetailsV3New/123456?EnvironmentId=11111111-2222-4333-8444-555555555555'},
    {'ENVIRONMENT_URL': URL + '&EnvironmentId=11111111-2222-4333-8444-555555555555'},
    {'ENVIRONMENT_URL': URL.replace('11111111-2222-4333-8444-555555555555', 'not-a-guid')},
    {'ACCESS_REASON': 'Unknown permission'}, {'ACCESS_DETAILS': ''},
    {'FIREWALL_RULE_NAME': ''}, {'FIREWALL_RULE_NAME': 'not a safe name'},
    {'LCS_PROJECT_ID': 'another'},
])
def test_minimal_config_refuses_unsafe_or_ambiguous_values(tmp_path, overrides):
    with pytest.raises(AutomationError, match='Invalid configuration'):
        Config.load(profile(tmp_path, **overrides))


def test_minimal_config_requires_rule_name(tmp_path):
    path = profile(tmp_path)
    data = yaml.safe_load(path.read_text())
    del data['FIREWALL_RULE_NAME']
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(AutomationError, match='Invalid configuration'):
        Config.load(path)


def test_driver_prefers_18_when_both_installed(tmp_path, monkeypatch):
    import pyodbc
    monkeypatch.setattr(pyodbc, 'drivers', lambda: ['ODBC Driver 17 for SQL Server', 'ODBC Driver 18 for SQL Server'])
    assert Config.load(profile(tmp_path)).odbc_driver == 'ODBC Driver 18 for SQL Server'


def test_environment_lock_identity_does_not_change_with_heading(tmp_path):
    c = Config.load(profile(tmp_path))
    c.logs_path = tmp_path / 'logs'
    after_navigation = replace(c, environment_id='discovered-name')
    with environment_lock(c):
        with pytest.raises(AutomationError, match='Another run'):
            with environment_lock(after_navigation):
                pytest.fail('Heading discovery changed the environment lock')
