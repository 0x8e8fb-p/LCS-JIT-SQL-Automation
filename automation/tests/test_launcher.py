from __future__ import annotations

import os
import subprocess
import sys

import pytest
import yaml

from helpers import ROOT, profile, run_powershell

pytestmark = pytest.mark.powershell


def invoke(script, *args, cwd=ROOT, env=None):
    return run_powershell(script, *args, cwd=cwd, env=env)


def sample_scripts(tmp_path):
    scripts = tmp_path / 'sql'
    scripts.mkdir()
    (scripts / '01_first.sql').write_text('SELECT 1 AS first_value;\n', encoding='utf-8')
    (scripts / '02_second.sql').write_text('SELECT 2 AS second_value;\n', encoding='utf-8')
    return scripts


def advanced_profile(tmp_path):
    config = profile(tmp_path)
    data = yaml.safe_load(config.read_text(encoding='utf-8'))
    data['SQL_SCRIPTS_PATH'] = str(sample_scripts(tmp_path))
    data['selectors'] = yaml.safe_load((ROOT / 'automation/defaults.yaml').read_text(encoding='utf-8'))['selectors']
    config.write_text(yaml.safe_dump(data), encoding='utf-8')
    return config


@pytest.mark.integration
@pytest.mark.windows('runs the real prerequisite setup')
def test_real_launcher_config_from_another_directory(tmp_path):
    # Independent of the user's personal config and scripts; no access changes.
    config = advanced_profile(tmp_path)
    result = run_powershell(ROOT / 'run.ps1', '-ValidateOnly', '-Config', str(config), cwd=tmp_path, timeout=1800)
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


def fake_launcher(tmp_path, main_source):
    """Copy run.ps1 next to a fake setup helper and a fake main.py."""
    script = tmp_path / 'run.ps1'
    script.write_text((ROOT / 'run.ps1').read_text(encoding='utf-8'), encoding='utf-8')
    app = tmp_path / 'automation'
    app.mkdir()
    (app / 'setup.ps1').write_text("function Initialize-Prerequisites { param($AppDir) return '" + sys.executable.replace("'", "''") + "' }",
                                   encoding='utf-8')
    (tmp_path / 'config.yaml').write_text('test: true', encoding='utf-8')
    (app / 'main.py').write_text(main_source, encoding='utf-8')
    return script, app


WORKFLOW_MAIN = '''import json, os, sys
from pathlib import Path
command = sys.argv[1]
with Path(__file__).with_name('calls.txt').open('a') as f:
    f.write(command + '\\n')
step = os.environ.get('TEST_AUTH_STEP', '')
failed = (command == 'check-auth' and bool(step)) or command == os.environ.get('TEST_FAIL_COMMAND')
print(json.dumps({'status': 'failure' if failed else 'success', 'failed_at_step': step}))
sys.exit(1 if failed else 0)
'''


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
    script, app = fake_launcher(tmp_path, WORKFLOW_MAIN)
    result = invoke(script, *mode, env=dict(os.environ, TEST_AUTH_STEP=auth_step))
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert (app / 'calls.txt').read_text().splitlines() == expected


@pytest.mark.parametrize(('command', 'expected'), [('validate', ['validate']),
                                                       ('bootstrap', ['validate', 'check-auth', 'bootstrap']),
                                                       ('run', ['validate', 'check-auth', 'run'])])
def test_launcher_preserves_failure_exit_and_stops(tmp_path, command, expected, monkeypatch):
    monkeypatch.setenv('TEST_FAIL_COMMAND', command)
    script, app = fake_launcher(tmp_path, '''import json, os, sys
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


@pytest.mark.integration
@pytest.mark.windows('cmd.exe batch wrapper')
def test_batch_wrapper_from_another_directory(tmp_path):
    # Regression: SHIFT empties %0 after parsing, so resolve run.ps1 before SHIFT.
    config = advanced_profile(tmp_path)
    result = subprocess.run(['cmd.exe', '/d', '/c', str(ROOT / 'automation' / 'run.cmd'), '--validate-only', '--config', str(config)],
                            cwd=tmp_path, capture_output=True, text=True, encoding='oem', errors='replace', timeout=1800)
    assert result.returncode == 0, result.stdout + result.stderr
    assert str(config) in result.stdout
    result = subprocess.run(['cmd.exe', '/d', '/c', str(ROOT / 'automation' / 'run.cmd'), '--unknown'],
                            cwd=tmp_path, capture_output=True, text=True, encoding='oem', errors='replace', timeout=60)
    assert result.returncode == 1
    assert 'Unknown argument' in result.stdout


def test_check_auth_without_a_result_is_explained(tmp_path):
    script, app = fake_launcher(tmp_path, '''import sys
command = sys.argv[1]
if command == 'check-auth':
    print('not json: crashed early')
    sys.exit(1)
print('{"status": "success"}')
''')
    result = invoke(script)
    assert result.returncode == 1
    assert 'not json: crashed early' in result.stdout
    assert 'check-auth returned no result (exit 1)' in result.stdout


def test_check_auth_with_empty_output_is_explained(tmp_path):
    script, app = fake_launcher(tmp_path, '''import sys
if sys.argv[1] == 'check-auth':
    sys.exit(3)
print('{"status": "success"}')
''')
    result = invoke(script)
    assert result.returncode == 1
    assert 'check-auth returned no result (exit 3)' in result.stdout


def test_sign_in_reason_is_shown_before_bootstrap(tmp_path, monkeypatch):
    monkeypatch.delenv('TEST_FAIL_COMMAND', raising=False)
    script, app = fake_launcher(tmp_path, '''import json, sys
from pathlib import Path
command = sys.argv[1]
with Path(__file__).with_name('calls.txt').open('a') as f:
    f.write(command + '\\n')
if command == 'check-auth':
    print(json.dumps({'status': 'failure', 'failed_at_step': 'authentication', 'error_message': 'No saved sign-in on this computer yet.'}))
    sys.exit(1)
print(json.dumps({'status': 'success'}))
''')
    result = invoke(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Sign-in needed: No saved sign-in on this computer yet.' in result.stdout
    assert (app / 'calls.txt').read_text().splitlines() == ['validate', 'check-auth', 'bootstrap', 'run']


def test_held_lock_names_the_reason(tmp_path):
    script, app = fake_launcher(tmp_path, 'print("{}")\n')
    lock = app / '.launcher.lock'
    with lock.open('a+b') as handle:
        if os.name == 'nt':
            import msvcrt
            handle.write(b'0')
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = invoke(script)
    assert result.returncode == 1
    assert 'Cannot take the launcher lock: ' in result.stdout
    assert 'Close other runs of .\\run.cmd' in result.stdout


def test_gitattributes_keep_windows_scripts_crlf():
    rules = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
    for pattern in ('*.cmd', '*.bat', '*.ps1'):
        assert f'{pattern} text eol=crlf' in rules
    for launcher in (ROOT / 'run.cmd', ROOT / 'automation' / 'run.cmd'):
        data = launcher.read_bytes()
        assert data.count(b'\n') == data.count(b'\r\n'), f'{launcher.name} must use CRLF line endings'
        assert b'-ExecutionPolicy Bypass' in data


@pytest.mark.windows('runs cmd.exe')
def test_root_run_cmd_forwards_arguments_and_exit_code(tmp_path):
    folder = tmp_path / 'project & co'
    folder.mkdir()
    (folder / 'run.cmd').write_bytes((ROOT / 'run.cmd').read_bytes())
    (folder / 'run.ps1').write_text('param([string]$Config, [switch]$ValidateOnly)\n'
                                    '"config=$Config validate=$ValidateOnly policy=$(Get-ExecutionPolicy -Scope Process)" | Set-Content -LiteralPath (Join-Path $PSScriptRoot "args.txt")\n'
                                    'exit 7\n', encoding='utf-8')
    # cmd /s /c strips only the outer quotes; inner quotes protect the spaces and '&'.
    line = f'cmd.exe /d /s /c ""{folder / "run.cmd"}" -ValidateOnly -Config "my profile & more.yaml""'
    result = subprocess.run(line, cwd=tmp_path, capture_output=True, text=True, encoding='oem', errors='replace', timeout=120)
    assert result.returncode == 7, result.stdout + result.stderr
    assert (folder / 'args.txt').read_text(encoding='utf-8-sig').strip() == 'config=my profile & more.yaml validate=True policy=Bypass'


def test_constrained_language_mode_is_explained_before_anything_runs(tmp_path):
    wrapper = tmp_path / 'constrained.ps1'
    wrapper.write_text("$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n& " + "'" + str(ROOT / 'run.ps1').replace("'", "''") + "' -ValidateOnly\nexit $LASTEXITCODE\n",
                       encoding='utf-8-sig')
    result = run_powershell(wrapper)
    assert result.returncode == 1
    assert 'ConstrainedLanguage mode (application control)' in result.stdout
