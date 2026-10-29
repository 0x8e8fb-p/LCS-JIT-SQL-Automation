"""Make test results independent of the machine running them.

* Every configuration environment variable (and a few debug switches) is removed
  for each test, so a machine-wide LOGS_PATH or PUBLIC_IP cannot change results.
* pyodbc.drivers() reports Driver 18 unless a test says otherwise. When pyodbc
  cannot load at all (no unixODBC on macOS/Linux), a small stub replaces it.
* Markers explain every skip: windows, powershell, chromium, integration.
"""
from __future__ import annotations

import os
import sys
import types
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

APP = Path(__file__).resolve().parents[1]
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))


def _install_pyodbc_stub() -> None:
    try:
        import pyodbc  # noqa: F401
    except ImportError:
        stub = types.ModuleType('pyodbc')

        class Error(Exception):
            pass

        Error.__module__ = 'pyodbc'

        def connect(*args: Any, **kwargs: Any) -> Any:
            raise Error('08001', 'pyodbc stub: no ODBC driver manager on this machine')

        stub.Error = Error  # type: ignore[attr-defined]
        stub.drivers = lambda: []  # type: ignore[attr-defined]
        stub.connect = connect  # type: ignore[attr-defined]
        stub.__lcsjit_stub__ = True  # type: ignore[attr-defined]
        sys.modules['pyodbc'] = stub


_install_pyodbc_stub()

if (APP / 'browsers').is_dir():
    os.environ.setdefault('PLAYWRIGHT_BROWSERS_PATH', str(APP / 'browsers'))

from automation_support import ENV_KEYS  # noqa: E402
from helpers import POWERSHELL  # noqa: E402

ISOLATED_VARIABLES = set(ENV_KEYS) | {'LCS_AUTH_KEY', 'PWDEBUG', 'DEBUG', 'NODE_OPTIONS'}


@pytest.fixture(autouse=True)
def _isolated_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ISOLATED_VARIABLES:
        monkeypatch.delenv(key, raising=False)
    import pyodbc
    monkeypatch.setattr(pyodbc, 'drivers', lambda: ['ODBC Driver 18 for SQL Server'])


@lru_cache(maxsize=None)
def _chromium_missing() -> str | None:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            executable = Path(playwright.chromium.executable_path)
    except Exception as error:  # driver missing or broken
        return f'Playwright driver unavailable ({type(error).__name__})'
    if not executable.is_file():
        return 'Playwright Chromium is not installed; run "python -m playwright install chromium" first'
    return None


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker('integration') and os.environ.get('LCSJIT_INTEGRATION') != '1':
        pytest.skip('integration test (real launcher and installers); set LCSJIT_INTEGRATION=1 on Windows to run it')
    windows = item.get_closest_marker('windows')
    if windows is not None and os.name != 'nt':
        pytest.skip('Windows only' + (f': {windows.args[0]}' if windows.args else ''))
    if item.get_closest_marker('powershell') and not POWERSHELL:
        pytest.skip('PowerShell is not installed (Windows PowerShell on Windows, pwsh elsewhere)')
    if item.get_closest_marker('chromium'):
        reason = _chromium_missing()
        if reason:
            pytest.skip(reason)
