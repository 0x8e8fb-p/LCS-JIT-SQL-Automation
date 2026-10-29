"""SQL connection retries follow Azure guidance and name the address Azure SQL saw."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock

import pyodbc
import pytest

import lcs_jit_automation as lcs
import sql_executor as sql
from automation_support import AutomationError, Credentials, utcnow

PASSWORD = 'SQL_PASSWORD_never_printed'
REFUSED = ("[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Cannot open server 'contoso' requested by the login. "
           "Client with IP address '{ip}' is not allowed to access the server. (40615) (SQLDriverConnect) " + PASSWORD)
LOGIN = "[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user 'reader'. (18456) (SQLDriverConnect) " + PASSWORD


@pytest.fixture
def credentials():
    now = utcnow()
    return Credentials('contoso.database.windows.net', 'AxDB', 'reader', PASSWORD, now, now + timedelta(hours=8))


@pytest.fixture
def config(tmp_path):
    settings = MagicMock()
    settings.odbc_driver = 'ODBC Driver 18 for SQL Server'
    settings.sql_timeout = 60
    settings.continue_on_error = False
    settings.max_result_rows = 10
    return settings


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(sql.time, 'sleep', calls.append)
    return calls


def connection():
    preflight = MagicMock()
    preflight.fetchone.return_value = (1,)
    script = MagicMock(description=None, rowcount=0)
    script.nextset.return_value = False
    handle = MagicMock()
    handle.cursor.side_effect = [preflight, script]
    return handle


def run(credentials, config, monkeypatch, outcomes, **kwargs):
    connect = MagicMock(side_effect=outcomes)
    monkeypatch.setattr(sql.pyodbc, 'connect', connect)
    report = sql.execute_sql_scripts(credentials, config, [sql.PreparedScript('01.sql', ('SELECT 1;',))], **kwargs)
    return report, connect


def test_azure_saw_another_address_stops_at_once_with_the_fix(credentials, config, monkeypatch, sleeps):
    with pytest.raises(AutomationError) as raised:
        run(credentials, config, monkeypatch, [pyodbc.Error('42000', REFUSED.format(ip='20.30.40.50'))],
            firewall_ip='8.8.8.8', ip_source='auto_proxy')
    message = raised.value.message
    assert 'Azure SQL saw this computer as 20.30.40.50' in message and 'created for 8.8.8.8' in message
    assert 'PUBLIC_IP: "20.30.40.50"' in message and 'web proxy' in message
    assert PASSWORD not in message and sleeps == []


def test_same_address_refusal_waits_for_the_rule_to_apply(credentials, config, monkeypatch, sleeps):
    report, connect = run(credentials, config, monkeypatch, [pyodbc.Error('42000', REFUSED.format(ip='8.8.8.8')), connection()],
                          firewall_ip='8.8.8.8', ip_source='auto_direct')
    assert report['scripts_executed'] == 1
    assert report['sql_connection'] == {'attempts': 2, 'waited_seconds': 5}
    assert sleeps == [5]


def test_new_login_not_active_yet_is_retried_with_backoff(credentials, config, monkeypatch, sleeps):
    report, connect = run(credentials, config, monkeypatch, [pyodbc.Error('28000', LOGIN), pyodbc.Error('28000', LOGIN), connection()])
    assert report['sql_connection'] == {'attempts': 3, 'waited_seconds': 15}
    assert sleeps == [5, 10]
    assert connect.call_count == 3


def test_network_failures_stop_after_three_attempts_with_codes(credentials, config, monkeypatch, sleeps):
    failure = pyodbc.Error('08001', '[Microsoft][ODBC Driver 18 for SQL Server]TCP Provider: timeout (10060) ' + PASSWORD)
    with pytest.raises(AutomationError) as raised:
        run(credentials, config, monkeypatch, [failure, failure, failure])
    assert 'after 3 attempt(s)' in raised.value.message and 'SQLSTATE 08001, native 10060' in raised.value.message
    assert 'TCP 1433' in raised.value.message and PASSWORD not in raised.value.message
    assert sleeps == [5, 10]


def test_retry_budget_and_credential_expiry_end_the_wait(credentials, config, monkeypatch, sleeps):
    refusal = pyodbc.Error('42000', REFUSED.format(ip='8.8.8.8'))
    with pytest.raises(AutomationError, match='still refuses 8.8.8.8') as raised:
        run(credentials, config, monkeypatch, [refusal] * 20, firewall_ip='8.8.8.8')
    assert sum(sleeps) <= sql.RETRY_BUDGET_SECONDS and sleeps[:4] == [5, 10, 20, 40] and max(sleeps) == 60
    assert 'Gave up after' in raised.value.message
    sleeps.clear()
    start = utcnow()
    monkeypatch.setattr(sql, 'utcnow', lambda: start + timedelta(seconds=sum(sleeps)))  # time passes while waiting
    credentials.expires_at = start + timedelta(seconds=12)
    with pytest.raises(AutomationError, match='Gave up'):
        run(credentials, config, monkeypatch, [refusal] * 20, firewall_ip='8.8.8.8')
    assert sleeps == [5]  # the next 10 s wait would pass the credential expiry


def test_missing_odbc_driver_is_not_retried(credentials, config, monkeypatch, sleeps):
    with pytest.raises(AutomationError, match='was not found by the ODBC driver manager'):
        run(credentials, config, monkeypatch, [pyodbc.Error('IM002', 'Data source name not found')])
    assert sleeps == []


class Opener:
    def __init__(self, outcome):
        self.outcome = outcome

    def open(self, url, timeout):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        response = MagicMock()
        response.__enter__.return_value.read.return_value = self.outcome
        return response


@pytest.mark.parametrize(('direct', 'proxy', 'expected'), [
    (b'20.1.2.3', b'unused', ('20.1.2.3', 'auto_direct')),
    (OSError('blocked'), b'20.9.9.9', ('20.9.9.9', 'auto_proxy')),
    (b'10.0.0.5', b'<html>blocked</html>', None),
    (OSError('blocked'), OSError('407'), None),
])
def test_public_ip_detection_order_and_sources(monkeypatch, direct, proxy, expected):
    def build(*handlers):
        is_direct = any(isinstance(handler, lcs.ProxyHandler) and handler.proxies == {} for handler in handlers)
        return Opener(direct if is_direct else proxy)

    monkeypatch.setattr(lcs, 'build_opener', build)
    settings = MagicMock(public_ip='')
    if expected is None:
        with pytest.raises(AutomationError, match='Add PUBLIC_IP') as raised:
            lcs.get_public_ip(settings)
        assert raised.value.step == 'ip_rule'
    else:
        assert lcs.get_public_ip(settings) == expected
    assert lcs.get_public_ip(MagicMock(public_ip='8.8.8.8')) == ('8.8.8.8', 'config')
