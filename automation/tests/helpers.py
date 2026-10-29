"""Shared test helpers. Nothing here reads or writes the real automation/ state."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml

from automation_support import utcnow

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'automation'
URL = 'https://lcs.dynamics.com/V2/EnvironmentDetailsV3New/123456?EnvironmentId=11111111-2222-4333-8444-555555555555'


def find_powershell() -> str | None:
    """Windows PowerShell 5.1 on Windows (what users run), pwsh elsewhere."""
    override = os.environ.get('LCSJIT_TEST_POWERSHELL')
    if override:
        return shutil.which(override) or override
    if os.name == 'nt':
        return shutil.which('powershell') or shutil.which('pwsh')
    return shutil.which('pwsh')


POWERSHELL = find_powershell()


def real_pyodbc() -> bool:
    """False when conftest installed the stub because the ODBC driver manager is missing."""
    module = sys.modules.get('pyodbc')
    return module is not None and not getattr(module, '__lcsjit_stub__', False)


def profile(tmp_path: Path, **overrides: Any) -> Path:
    values = {'ENVIRONMENT_URL': URL, 'ACCESS_REASON': 'AX troubleshooting (read-only to AX)',
              'ACCESS_DETAILS': 'Approved validation', 'FIREWALL_RULE_NAME': 'validation'}
    values.update(overrides)
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump(values), encoding='utf-8')
    return path


def ps_quote(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == 'nt':
        subprocess.run(['taskkill', '/T', '/F', '/PID', str(process.pid)], capture_output=True, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()


def run_powershell(script: Path, *args: Any, cwd: Path | None = None, env: dict[str, str] | None = None,
                   timeout: float = 120, utf8_output: bool = False) -> subprocess.CompletedProcess[str]:
    """Run a .ps1 like run.cmd does. On timeout the whole process tree is killed."""
    if not POWERSHELL:
        pytest.skip('PowerShell is not installed (Windows PowerShell on Windows, pwsh elsewhere)')
    command = [POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
               '-File', str(script), *[str(arg) for arg in args]]
    options: dict[str, Any] = {}
    if os.name == 'nt':
        # Own hidden console: encoding changes never leak into the developer's terminal.
        options['creationflags'] = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    else:
        options['start_new_session'] = True
    # Windows PowerShell writes redirected output in the console (OEM) code page.
    encoding = 'utf-8' if utf8_output or os.name != 'nt' else 'oem'
    with subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **options) as process:
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(process)
            out, err = process.communicate()
            raise subprocess.TimeoutExpired(command, timeout, output=out.decode(encoding, 'replace'),
                                            stderr=err.decode(encoding, 'replace')) from None
    return subprocess.CompletedProcess(command, process.returncode, out.decode(encoding, 'replace'),
                                       err.decode(encoding, 'replace'))


def run_setup_snippet(tmp_path: Path, body: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    """Dot-source automation/setup.ps1 and run a PowerShell snippet against it."""
    script = tmp_path / 'verify.ps1'
    prelude = ('[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n'
               "$ErrorActionPreference = 'Stop'\n"
               '. ' + ps_quote(APP / 'setup.ps1') + '\n')
    # BOM: Windows PowerShell 5.1 reads BOM-less scripts in the ANSI code page.
    script.write_text(prelude + body, encoding='utf-8-sig')
    return run_powershell(script, timeout=timeout, utf8_output=True)


def make_config() -> MagicMock:
    config = MagicMock()
    config.disable_access_after = True
    config.environment_id = 'UAT'
    config.access_level = 'read_only'
    return config


def make_adapter(error: BaseException | None) -> MagicMock:
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
