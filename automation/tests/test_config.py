import json
import os
import re
from dataclasses import replace

import pytest
import yaml

from automation_support import AutomationError, Config, environment_lock
from helpers import ROOT, URL, profile


def test_machine_configuration_variables_do_not_leak_into_tests():
    # conftest removes machine-wide overrides such as a LOGS_PATH set by other software.
    for key in ('LOGS_PATH', 'PUBLIC_IP', 'ENVIRONMENT_URL', 'LCS_AUTH_KEY'):
        assert key not in os.environ


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
    {'ENVIRONMENT_URL': URL.replace('lcs.dynamics.com', 'example.com')},
    {'ENVIRONMENT_URL': URL + '&EnvironmentId=11111111-2222-4333-8444-555555555555'},
    {'ENVIRONMENT_URL': URL.replace('11111111-2222-4333-8444-555555555555', 'not-a-guid')},
    {'ACCESS_REASON': 'Unknown permission'}, {'ACCESS_DETAILS': ''},
    {'FIREWALL_RULE_NAME': 'not a safe name'}, {'FIREWALL_RULE_NAME': '-starts-with-hyphen'},
    {'LCS_PROJECT_ID': 'another'},
])
def test_minimal_config_refuses_unsafe_or_ambiguous_values(tmp_path, overrides):
    with pytest.raises(AutomationError, match='Invalid configuration'):
        Config.load(profile(tmp_path, **overrides))


@pytest.mark.parametrize('value', [None, ''])
def test_missing_or_blank_rule_name_uses_per_machine_default(tmp_path, monkeypatch, value):
    import getpass
    path = profile(tmp_path, FIREWALL_RULE_NAME=value or '')
    if value is None:
        data = yaml.safe_load(path.read_text())
        del data['FIREWALL_RULE_NAME']
        path.write_text(yaml.safe_dump(data))
    monkeypatch.setenv('COMPUTERNAME', 'PC-ONE')
    monkeypatch.setattr(getpass, 'getuser', lambda: 'alice')
    first = Config.load(path).selectors['rule_name']
    assert re.fullmatch(r'lcsjit-[0-9a-f]{8}', first)
    assert Config.load(path).selectors['rule_name'] == first  # stable on this computer and user
    monkeypatch.setattr(getpass, 'getuser', lambda: 'bob')
    assert Config.load(path).selectors['rule_name'] != first  # another Windows user
    monkeypatch.setattr(getpass, 'getuser', lambda: 'alice')
    monkeypatch.setenv('COMPUTERNAME', 'PC-TWO')
    assert Config.load(path).selectors['rule_name'] != first  # another computer


def test_explicit_rule_name_is_kept(tmp_path):
    assert Config.load(profile(tmp_path, FIREWALL_RULE_NAME='lcsjit')).selectors['rule_name'] == 'lcsjit'


def test_public_ip_in_config_yaml(tmp_path, capsys):
    import main
    config = Config.load(profile(tmp_path, PUBLIC_IP='8.8.8.8'))
    assert config.public_ip == '8.8.8.8' and config.public_ip_source == 'config'
    assert Config.load(profile(tmp_path)).public_ip_source == 'auto'
    for bad in ('10.0.0.5', '127.0.0.1', '203.0.113.10', '2001:db8::1', 'not-an-ip'):
        with pytest.raises(AutomationError, match='PUBLIC_IP must be the public IPv4 address') as raised:
            Config.load(profile(tmp_path, PUBLIC_IP=bad))
        assert bad not in raised.value.message
    scripts = tmp_path / 'sql_scripts'
    scripts.mkdir()
    (scripts / '01.sql').write_text('SELECT 1;', encoding='utf-8')
    assert main.main(['validate', '--config', str(profile(tmp_path, PUBLIC_IP='8.8.8.8', FIREWALL_RULE_NAME=''))]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['public_ip_source'] == 'config'
    assert re.fullmatch(r'lcsjit-[0-9a-f]{8}', output['firewall_rule_name'])


def test_public_ip_environment_variable_is_refused_by_name(tmp_path, monkeypatch):
    monkeypatch.setenv('PUBLIC_IP', '8.8.8.8')
    with pytest.raises(AutomationError, match='environment variable PUBLIC_IP is not used with config.yaml') as raised:
        Config.load(profile(tmp_path))
    assert 'Remove-Item Env:PUBLIC_IP' in raised.value.message
    assert '8.8.8.8' not in raised.value.message


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


SECRET = 'PLANTED_SECRET_9f3a'


def test_all_independent_problems_are_reported_together(tmp_path, monkeypatch):
    monkeypatch.setenv('LOGS_PATH', SECRET)
    path = profile(tmp_path, ENVIRONMENT_URL=f'https://lcs.dynamics.com/V2/Project/123?token={SECRET}',
                   ACCESS_DETAILS='', ACCESS_REASON='Something else')
    with pytest.raises(AutomationError) as raised:
        Config.load(path)
    message = raised.value.message
    assert message.startswith('Invalid configuration: ')
    assert 'environment-details page' in message
    assert 'EnvironmentId' in message
    assert 'ACCESS_DETAILS is empty' in message
    assert 'ACCESS_REASON must be exactly one of' in message and 'AX troubleshooting (read-only to AX)' in message
    assert 'environment variable(s) LOGS_PATH' in message and 'Remove-Item Env:LOGS_PATH' in message
    assert SECRET not in message
    assert message.endswith('See README.md#configuration.')


def test_unknown_and_duplicate_keys_are_named_without_values(tmp_path):
    path = profile(tmp_path, SQL_PASSWORD=SECRET)
    with pytest.raises(AutomationError, match='unknown setting.*SQL_PASSWORD') as raised:
        Config.load(path)
    assert SECRET not in raised.value.message
    path.write_text(path.read_text(encoding='utf-8') + f'ACCESS_DETAILS: "{SECRET}"\n', encoding='utf-8')
    with pytest.raises(AutomationError, match='duplicate key ACCESS_DETAILS on line') as raised:
        Config.load(path)
    assert SECRET not in raised.value.message


def test_yaml_errors_report_position_only(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text(f'ENVIRONMENT_URL: "https://lcs.dynamics.com\nACCESS_DETAILS: "{SECRET}\n', encoding='utf-8')
    with pytest.raises(AutomationError, match=r'not valid YAML near line \d+, column \d+') as raised:
        Config.load(path)
    assert SECRET not in raised.value.message


@pytest.mark.parametrize(('encoding', 'phrase'), [('utf-16', 'saved as UTF-16'), ('cp1252', 'is not UTF-8 text')])
def test_non_utf8_config_is_named(tmp_path, encoding, phrase):
    path = tmp_path / 'config.yaml'
    text = (f'ENVIRONMENT_URL: "{URL}"\nACCESS_REASON: "AX troubleshooting (read-only to AX)"\n'
            'ACCESS_DETAILS: "Approved caf\u00e9 validation"\nFIREWALL_RULE_NAME: "validation"\n')
    path.write_bytes(text.encode(encoding))
    with pytest.raises(AutomationError, match=phrase):
        Config.load(path)
    path.write_bytes(text.encode('utf-8'))
    assert Config.load(path).details == 'Approved caf\u00e9 validation'


@pytest.mark.parametrize(('content', 'phrase'), [
    ('SELECT 1;'.encode('utf-16'), 'SQL script 02_unicode.sql is saved as UTF-16'),
    ('SELECT \'caf\u00e9\';'.encode('cp1252'), 'SQL script 02_unicode.sql is not UTF-8 text'),
    (b'SELECT 1;\nGO 5\n', 'SQL script 02_unicode.sql: GO repetition'),
    (b'  \n', 'SQL script 02_unicode.sql is empty'),
])
def test_sql_script_problems_name_the_file(tmp_path, content, phrase):
    import sql_executor
    folder = tmp_path / 'sql'
    folder.mkdir()
    (folder / '01_ok.sql').write_text('SELECT 1;', encoding='utf-8')
    (folder / '02_unicode.sql').write_bytes(content)
    with pytest.raises(AutomationError, match=phrase) as raised:
        sql_executor.validate_scripts(folder)
    assert raised.value.step == 'configuration'
    with pytest.raises(AutomationError, match=phrase):
        sql_executor.prepare_scripts(folder)


def test_missing_or_empty_scripts_folder_is_named(tmp_path):
    import sql_executor
    with pytest.raises(AutomationError, match='folder missing_folder does not exist'):
        sql_executor.validate_scripts(tmp_path / 'missing_folder')
    (tmp_path / 'empty').mkdir()
    with pytest.raises(AutomationError, match='folder empty contains no .sql files'):
        sql_executor.validate_scripts(tmp_path / 'empty')


def test_fresh_template_lists_what_to_fill_in(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_bytes((ROOT / 'automation/config.template.yaml').read_bytes())
    with pytest.raises(AutomationError) as raised:
        Config.load(path)
    assert 'ENVIRONMENT_URL is empty' in raised.value.message
    assert 'ACCESS_DETAILS is empty' in raised.value.message
