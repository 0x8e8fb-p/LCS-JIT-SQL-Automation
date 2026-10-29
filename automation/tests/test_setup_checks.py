"""setup_checks.py: the probes setup.ps1 runs inside automation/.venv."""
from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

import setup_checks

CHECKS = Path(setup_checks.__file__)


def run(*args, env=None):
    return subprocess.run([sys.executable, '-I', str(CHECKS), *args], capture_output=True, text=True, env=env, timeout=180)


def test_packages_match_exact_pins_and_name_the_first_mismatch(tmp_path):
    requirements = tmp_path / 'requirements.txt'
    requirements.write_text(f'# comment\nPyYAML=={version("PyYAML")}\ncryptography=={version("cryptography")}  # inline\n', encoding='utf-8')
    assert setup_checks.check_packages(requirements) in (None, 'cannot import pyodbc (ImportError)')  # pyodbc needs unixODBC off Windows
    requirements.write_text('PyYAML==0.0.1\n', encoding='utf-8')
    assert setup_checks.check_packages(requirements) == f'PyYAML {version("PyYAML")} is installed, 0.0.1 is required'
    requirements.write_text('not-installed-package==1.0\n', encoding='utf-8')
    assert setup_checks.check_packages(requirements) == 'missing package: not-installed-package'
    requirements.write_text('PyYAML>=6\n', encoding='utf-8')
    assert setup_checks.check_packages(requirements).startswith('unsupported requirements line')


def test_command_line_reports_problems_with_exit_code(tmp_path):
    requirements = tmp_path / 'requirements.txt'
    requirements.write_text('PyYAML==0.0.1\n', encoding='utf-8')
    result = run('packages', str(requirements))
    assert result.returncode == 1 and 'is required' in result.stdout
    assert run('unknown').returncode == 1


def test_chromium_probe_uses_the_full_browser(tmp_path, monkeypatch):
    source = CHECKS.read_text(encoding='utf-8')
    assert "channel='chromium'" in source  # never the headless shell, which runs do not use
    empty = tmp_path / 'no-browsers'
    empty.mkdir()
    import os
    result = run('chromium', env={**os.environ, 'PLAYWRIGHT_BROWSERS_PATH': str(empty)})
    assert result.returncode == 1 and 'Chromium is not installed' in result.stdout


@pytest.mark.chromium
def test_chromium_probe_starts_an_installed_browser():
    import os
    assert run('chromium', env=dict(os.environ)).returncode == 0
