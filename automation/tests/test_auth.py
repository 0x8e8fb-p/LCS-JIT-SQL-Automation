"""Saved sign-in across Windows users, copied folders and locked files (DPAPI is faked)."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

import lcs_jit_automation as lcs
import main
from automation_support import AutomationError

STATE = {'cookies': [{'name': 'session', 'value': 'abc'}], 'origins': []}


@pytest.fixture
def windows_user(monkeypatch):
    """DPAPI stand-in: data protected by one user can only be read by that user."""
    current = {'user': 'alice', 'protect_error': 0}

    def dpapi(data, protect):
        if protect:
            if current['protect_error']:
                raise lcs.DpapiError(current['protect_error'])
            return current['user'].encode() + b':' + data
        owner, _, payload = data.partition(b':')
        if owner != current['user'].encode():
            raise lcs.DpapiError(-2146893813)  # NTE_BAD_KEY_STATE: another user's or computer's key
        return payload

    monkeypatch.setattr(lcs, '_dpapi_available', lambda: True)
    monkeypatch.setattr(lcs, '_dpapi', dpapi)
    monkeypatch.setattr(lcs.time, 'sleep', lambda _: None)
    return current


def context():
    browser_context = MagicMock()
    browser_context.storage_state.return_value = STATE
    return browser_context


def test_new_computer_reports_no_saved_sign_in(tmp_path, windows_user):
    with pytest.raises(AutomationError, match='No saved sign-in on this computer yet') as raised:
        lcs.load_auth(tmp_path / 'state.enc', tmp_path / 'key.dpapi')
    assert raised.value.step == 'authentication'
    assert not (tmp_path / 'key.dpapi').exists()


def test_foreign_key_check_auth_reports_then_bootstrap_rotates(tmp_path, windows_user):
    state, key = tmp_path / 'state.enc', tmp_path / 'key.dpapi'
    assert lcs.save_auth(context(), state, key) is False
    assert lcs.load_auth(state, key) == STATE
    windows_user['user'] = 'bob'  # copied folder or another Windows account
    with pytest.raises(AutomationError, match='belongs to a different Windows user or computer') as raised:
        lcs.load_auth(state, key)
    assert raised.value.step == 'authentication'  # the launcher then offers sign-in
    assert lcs.save_auth(context(), state, key) is True  # what bootstrap does after sign-in
    stale = sorted(path.name for path in tmp_path.glob('*.stale-*'))
    assert len(stale) == 2 and stale[0].startswith('key.dpapi.stale-') and stale[1].startswith('state.enc.stale-')
    assert lcs.load_auth(state, key) == STATE
    assert list(tmp_path.glob('*.tmp')) == []


def test_empty_or_damaged_key_is_rotated_on_sign_in(tmp_path, windows_user):
    state, key = tmp_path / 'state.enc', tmp_path / 'key.dpapi'
    key.write_bytes(b'')
    state.write_bytes(b'old')
    with pytest.raises(AutomationError, match='damaged'):
        lcs.load_auth(state, key)
    assert lcs.save_auth(context(), state, key) is True
    assert lcs.load_auth(state, key) == STATE


def test_failed_protection_never_leaves_a_key_file(tmp_path, windows_user):
    windows_user['protect_error'] = 5
    with pytest.raises(AutomationError, match='DPAPI error 5') as raised:
        lcs.save_auth(context(), tmp_path / 'state.enc', tmp_path / 'key.dpapi')
    assert raised.value.step == 'auth_state_write'
    assert list(tmp_path.iterdir()) == []


def test_locked_file_is_retried(tmp_path, windows_user, monkeypatch):
    real_replace = os.replace
    attempts = {'count': 0}

    def flaky_replace(source, target):
        attempts['count'] += 1
        if attempts['count'] <= 2 and str(target).endswith('state.enc'):
            raise PermissionError(13, 'locked by antivirus')
        return real_replace(source, target)

    monkeypatch.setattr(lcs.os, 'replace', flaky_replace)
    lcs.save_auth(context(), tmp_path / 'state.enc', tmp_path / 'key.dpapi')
    assert lcs.load_auth(tmp_path / 'state.enc', tmp_path / 'key.dpapi') == STATE
    assert list(tmp_path.glob('*.tmp')) == []


def test_permanently_locked_file_is_a_warning_for_check_auth(tmp_path, windows_user, monkeypatch):
    def locked(source, target):
        raise PermissionError(32, 'in use')

    monkeypatch.setattr(lcs.os, 'replace', locked)
    with pytest.raises(AutomationError, match='OneDrive') as raised:
        lcs.save_auth(context(), tmp_path / 'state.enc', tmp_path / 'key.dpapi')
    assert raised.value.step == 'auth_state_write'
    adapter = object.__new__(lcs.LCSAutomation)
    adapter.context, adapter.config = context(), MagicMock()
    adapter.config.state_path, adapter.config.auth_key_path = tmp_path / 'state.enc', tmp_path / 'other.dpapi'
    adapter.warnings, adapter.auth_reset = [], False
    adapter.refresh_saved_auth()  # check-auth and run keep going
    assert adapter.warnings and 'continues' in adapter.warnings[0]


def test_check_auth_output_carries_warnings(tmp_path, monkeypatch, capsys):
    from helpers import profile

    class Adapter:
        def __init__(self, *args, **kwargs):
            self.warnings = ['Cannot save the encrypted sign-in state (error 32).']

        def navigate(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(main, 'LCSAutomation', Adapter)
    assert main.main(['check-auth', '--config', str(profile(tmp_path))]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['status'] == 'success' and output['warnings'] == ['Cannot save the encrypted sign-in state (error 32).']


@pytest.mark.parametrize('error', [EOFError, RuntimeError])
def test_sign_in_without_an_interactive_console_is_explained(monkeypatch, error):
    def no_console():
        raise error()

    monkeypatch.setattr('builtins.input', no_console)
    with pytest.raises(AutomationError, match='interactive console') as raised:
        lcs.wait_for_enter('Press Enter')
    assert raised.value.step == 'authentication'
