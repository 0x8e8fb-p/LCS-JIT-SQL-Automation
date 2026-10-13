from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which('powershell') or shutil.which('pwsh')


def invoke(script, *args, cwd=ROOT, env=None):
    if not POWERSHELL:
        pytest.skip('PowerShell is not installed on this platform')
    return subprocess.run([POWERSHELL, '-NoLogo', '-NoProfile', '-File', str(script), *args],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=45)


def test_real_launcher_config_from_another_directory(tmp_path):
    # Independent of the user's personal config; no access changes.
    if os.name != 'nt':
        pytest.skip('The supplied Windows DPAPI profile targets Windows')
    from test_config import profile
    import yaml
    config = profile(tmp_path)
    data = yaml.safe_load(config.read_text())
    data['SQL_SCRIPTS_PATH'] = str(ROOT / 'sql_scripts')
    data['selectors'] = yaml.safe_load((ROOT / 'automation/defaults.yaml').read_text())['selectors']
    config.write_text(yaml.safe_dump(data))
    result = invoke(ROOT / 'run.ps1', '-ValidateOnly', '-Config', str(config), cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert str(config) in result.stdout
    assert '"runtime_checked": true' in result.stdout
    assert '"total_scripts": 2' in result.stdout


@pytest.mark.parametrize('args', [('-Headless', '-LaunchOnly'), ('-Headless', '-ForceInteractive'),
                                  ('-ValidateOnly', '-LaunchOnly'), ('-Config', 'missing.yaml')])
def test_launcher_rejects_invalid_modes_or_missing_config(args):
    result = invoke(ROOT / 'run.ps1', *args)
    assert result.returncode == 1
    assert 'Launcher failed:' in result.stdout


@pytest.mark.parametrize(('mode', 'auth_step', 'expected', 'exit_code'), [
    ([], '', ['validate', 'check-auth', 'run'], 0),
    ([], 'authentication', ['validate', 'check-auth', 'bootstrap', 'run'], 0),
    ([], 'environment', ['validate', 'check-auth'], 1),
    (['-Headless'], '', ['validate', 'run'], 0),
    (['-LaunchOnly'], '', ['validate', 'bootstrap'], 0),
    (['-ForceInteractive'], '', ['validate', 'bootstrap', 'run'], 0),
])
def test_launcher_workflow_and_exit_codes(tmp_path, mode, auth_step, expected, exit_code, monkeypatch):
    # Keep launcher control flow intact; provide a fake setup helper/CLI.
    monkeypatch.delenv('TEST_FAIL_COMMAND', raising=False)
    script = tmp_path / 'run.ps1'
    script.write_text((ROOT / 'run.ps1').read_text())
    app = tmp_path / 'automation'
    app.mkdir()
    (app / 'setup.ps1').write_text("function Initialize-Prerequisites { param($AppDir) return '" + sys.executable.replace("'", "''") + "' }")
    (tmp_path / 'config.yaml').write_text('test: true')
    (app / 'main.py').write_text('''import json, os, sys
from pathlib import Path
command = sys.argv[1]
with Path(__file__).with_name('calls.txt').open('a') as f:
    f.write(command + '\\n')
step = os.environ.get('TEST_AUTH_STEP', '')
failed = (command == 'check-auth' and bool(step)) or command == os.environ.get('TEST_FAIL_COMMAND')
print(json.dumps({'status': 'failure' if failed else 'success', 'failed_at_step': step}))
sys.exit(1 if failed else 0)
''')
    result = invoke(script, *mode, env=dict(os.environ, TEST_AUTH_STEP=auth_step))
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert (app / 'calls.txt').read_text().splitlines() == expected


@pytest.mark.parametrize(('command', 'expected'), [('validate', ['validate']),
                                                       ('bootstrap', ['validate', 'check-auth', 'bootstrap']),
                                                       ('run', ['validate', 'check-auth', 'run'])])
def test_launcher_preserves_failure_exit_and_stops(tmp_path, command, expected, monkeypatch):
    monkeypatch.setenv('TEST_FAIL_COMMAND', command)
    # Reuse the same fake CLI, but keep its failure variable set for this test.
    script = tmp_path / 'run.ps1'
    script.write_text((ROOT / 'run.ps1').read_text())
    app = tmp_path / 'automation'
    app.mkdir()
    (app / 'setup.ps1').write_text("function Initialize-Prerequisites { param($AppDir) return '" + sys.executable.replace("'", "''") + "' }")
    (tmp_path / 'config.yaml').write_text('test: true')
    (app / 'main.py').write_text('''import json, os, sys
from pathlib import Path
command = sys.argv[1]
with Path(__file__).with_name('calls.txt').open('a') as f:
    f.write(command + '\\n')
failed = command == os.environ['TEST_FAIL_COMMAND']
needs_login = command == 'check-auth' and os.environ['TEST_FAIL_COMMAND'] == 'bootstrap'
print(json.dumps({'status': 'failure' if failed or needs_login else 'success', 'failed_at_step': 'authentication' if needs_login else ''}))
sys.exit(7 if failed else (1 if needs_login else 0))
''')
    result = invoke(script)
    assert result.returncode == 7, result.stdout + result.stderr
    assert (app / 'calls.txt').read_text().splitlines() == expected


@pytest.mark.skipif(os.name != 'nt', reason='Windows batch compatibility wrapper')
def test_batch_wrapper_from_another_directory(tmp_path):
    # Regression: SHIFT empties %0 after parsing, so resolve run.ps1 before SHIFT.
    from test_config import profile
    import yaml
    config = profile(tmp_path)
    data = yaml.safe_load(config.read_text())
    data['SQL_SCRIPTS_PATH'] = str(ROOT / 'sql_scripts')
    data['selectors'] = yaml.safe_load((ROOT / 'automation/defaults.yaml').read_text())['selectors']
    config.write_text(yaml.safe_dump(data))
    result = subprocess.run(['cmd.exe', '/d', '/c', str(ROOT / 'automation' / 'run.cmd'), '--validate-only', '--config', str(config)],
                            cwd=tmp_path, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert str(config) in result.stdout
    result = subprocess.run(['cmd.exe', '/d', '/c', str(ROOT / 'automation' / 'run.cmd'), '--unknown'],
                            cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert 'Unknown argument' in result.stdout
