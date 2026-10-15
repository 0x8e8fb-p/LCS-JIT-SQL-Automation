from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which('powershell') or shutil.which('pwsh')


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def invoke(tmp_path, body):
    if not POWERSHELL:
        pytest.skip('PowerShell is not installed on this platform')
    script = tmp_path / 'verify.ps1'
    script.write_text("$ErrorActionPreference = 'Stop'\n. " + ps_quote(ROOT / 'automation/setup.ps1') + '\n' + body)
    return subprocess.run([POWERSHELL, '-NoLogo', '-NoProfile', '-File', str(script)],
                          capture_output=True, text=True, timeout=45)


def test_expected_probe_failure_does_not_abort_setup(tmp_path):
    # Regression for Windows PowerShell 5 native stderr + ErrorActionPreference Stop.
    missing_browser = tmp_path / 'missing-browsers'
    result = invoke(tmp_path, f'''
$Python = {ps_quote(sys.executable)}
$env:PLAYWRIGHT_BROWSERS_PATH = {ps_quote(missing_browser)}
if (Test-Chromium $Python) {{ throw 'Unexpected browser found' }}
if ($ErrorActionPreference -ne 'Stop') {{ throw 'Probe changed caller error policy' }}
Write-Output 'probe-returned-false'
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'probe-returned-false' in result.stdout
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('fresh', [True, False])
@pytest.mark.skipif(os.name != 'nt', reason='Windows-only automatic prerequisite setup')
def test_setup_first_run_and_repeat_are_idempotent(tmp_path, fresh):
    app = tmp_path / 'app with spaces'
    app.mkdir()
    (app / 'requirements.txt').write_text('requirements')
    for name in ('main.py', 'automation_support.py', 'lcs_jit_automation.py', 'sql_executor.py', 'defaults.yaml'):
        (app / name).write_text('fixture')
    body = f'''
$script:Ready = ${str(not fresh).lower()}
$script:Packages = ${str(not fresh).lower()}
$script:Driver = ${str(not fresh).lower()}
$script:Browser = ${str(not fresh).lower()}
$script:Calls = New-Object 'System.Collections.Generic.List[string]'
$App = {ps_quote(app)}
function Test-SupportedPython {{ param($Executable, $Prefix) return $script:Ready }}
function Find-SupportedPython {{ param($AppDir) $script:Calls.Add('find'); return $null }}
function Install-LocalPython {{ param($AppDir) $script:Calls.Add('python'); return 'fake-python' }}
function Test-PythonPackages {{ param($Python) return $script:Packages }}
function Test-SqlDriver {{ param($Python) return $script:Driver }}
function Install-SqlDriver {{ param($AppDir) $script:Calls.Add('odbc'); $script:Driver=$true }}
function Test-Chromium {{ param($Python) return $script:Browser }}
function Invoke-PythonStep {{
    param($Python, $Arguments, $Failure)
    if ($Arguments[1] -eq 'venv') {{
        $script:Calls.Add('venv'); $script:Ready=$true
        New-Item -ItemType Directory -Force -Path $Arguments[2] | Out-Null
    }} elseif ($Arguments[1] -eq 'pip' -and $Arguments[2] -eq 'install') {{
        $script:Calls.Add('pip-install'); $script:Packages=$true
    }} elseif ($Arguments[1] -eq 'pip') {{ $script:Calls.Add('pip-check') }}
    elseif ($Arguments[1] -eq 'playwright') {{ $script:Calls.Add('chromium'); $script:Browser=$true }}
}}
New-Item -ItemType Directory -Path (Join-Path $App '.venv') | Out-Null
if ($script:Ready) {{
    Set-Content -LiteralPath (Join-Path $App '.venv/requirements.sha256') -Value (Get-FileHash (Join-Path $App 'requirements.txt')).Hash
}}
$first = Initialize-Prerequisites -AppDir $App
$second = Initialize-Prerequisites -AppDir $App
if ($first -ne $second -or $first -notlike '*python.exe') {{ throw 'Incorrect Python return value' }}
Write-Output ('calls=' + ($script:Calls -join ','))
Write-Output ('backups=' + @(Get-ChildItem -LiteralPath $App -Directory -Filter '.venv.backup-*').Count)
'''
    result = invoke(tmp_path, body)
    assert result.returncode == 0, result.stdout + result.stderr
    if fresh:
        assert 'calls=find,python,venv,pip-install,pip-check,odbc,chromium,pip-check' in result.stdout
        assert 'backups=1' in result.stdout
    else:
        assert 'calls=pip-check,pip-check\n' in result.stdout
        assert 'backups=0' in result.stdout


@pytest.mark.parametrize(('code', 'expected'), [(0, 'ok'), (3010, 'requires a restart'),
                                               (1641, 'requires a restart'), (1603, 'Installer failed')])
def test_installer_exit_codes(tmp_path, code, expected):
    result = invoke(tmp_path, f'''
function Start-Process {{ param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $Verb) return [pscustomobject]@{{ExitCode={code}}} }}
try {{ Invoke-SetupProcess -Executable 'fake-installer' -Arguments @('/quiet') -LogPath 'setup.log'; Write-Output 'ok' }}
catch {{ Write-Output $_.Exception.Message; exit 1 }}
''')
    assert result.returncode == (0 if code == 0 else 1), result.stdout + result.stderr
    assert expected in result.stdout


@pytest.mark.parametrize('failure', ['checksum', 'unsigned', 'publisher'])
def test_installer_verification_refuses_unsafe_downloads(tmp_path, failure):
    destination = tmp_path / 'download' / 'installer.exe'
    status = 'NotSigned' if failure == 'unsigned' else 'Valid'
    publisher = 'O=Untrusted Company' if failure == 'publisher' else 'O=Python Software Foundation, C=US'
    hash_arg = "-Sha256 'incorrect'" if failure == 'checksum' else ''
    result = invoke(tmp_path, f'''
$script:CheckedSignature = $false
function Invoke-WebRequest {{ param([switch]$UseBasicParsing, $Uri, $OutFile, $TimeoutSec) Set-Content -LiteralPath $OutFile -Value 'fake-download' }}
function Get-AuthenticodeSignature {{
    param($LiteralPath)
    $script:CheckedSignature=$true
    return [pscustomobject]@{{Status='{status}'; SignerCertificate=[pscustomobject]@{{Subject='{publisher}'}}}}
}}
try {{ Get-VerifiedInstaller -Url 'https://example.com/installer' -Destination {ps_quote(destination)} -Publisher 'O=Python Software Foundation(?:,|$)' {hash_arg}; throw 'Unsafe installer accepted' }}
catch {{
    if ($_.Exception.Message -eq 'Unsafe installer accepted') {{ throw }}
    if (Test-Path -LiteralPath {ps_quote(destination)}) {{ throw 'Unsafe installer remained cached' }}
    Write-Output $_.Exception.Message
}}
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert ('checksum mismatch' if failure == 'checksum' else 'signature/publisher verification failed') in result.stdout


def test_dependency_failure_stops_before_returning_success(tmp_path):
    result = invoke(tmp_path, f'''
try {{ Invoke-PythonStep -Python {ps_quote(sys.executable)} -Arguments @('-c', 'import sys; sys.exit(7)') -Failure 'Dependency step failed'; throw 'Failure ignored' }}
catch {{ Write-Output $_.Exception.Message; exit 1 }}
''')
    assert result.returncode == 1
    assert 'Dependency step failed' in result.stdout


def test_find_supported_python_discovers_registry_install_when_not_on_path(tmp_path):
    reg_python = tmp_path / 'previous_folder' / 'runtime' / 'python' / 'python.exe'
    reg_python.parent.mkdir(parents=True)
    reg_python.write_text('fake-python')
    result = invoke(tmp_path, f'''
function Get-Command {{ param($Name, $ErrorAction) return $null }}
function Get-RegistryPythonCandidates {{ return @({ps_quote(reg_python)}) }}
function Test-SupportedPython {{ param($Executable, $Prefix) return ($Executable -eq {ps_quote(reg_python)}) }}
$found = Find-SupportedPython -AppDir {ps_quote(tmp_path / 'new_app')}
if ($found -ne {ps_quote(reg_python)}) {{ throw "Unexpected found: $found" }}
Write-Output "found=$found"
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'found={reg_python}' in result.stdout


def test_install_local_python_repairs_stale_wix_burn_registration(tmp_path):
    app = tmp_path / 'new_app'
    target_py = app / 'runtime' / 'python' / 'python.exe'
    result = invoke(tmp_path, f'''
$script:Steps = New-Object 'System.Collections.Generic.List[string]'
$script:Uninstalled = $false
function Get-VerifiedInstaller {{
    param($Url, $Destination, $Publisher, $Sha256)
    New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
    Set-Content -LiteralPath $Destination -Value 'fake-installer'
    return $Destination
}}
function Find-SupportedPython {{ param($AppDir) return $null }}
function Test-SupportedPython {{
    param($Executable, $Prefix)
    return ($Executable -eq {ps_quote(target_py)} -and (Test-Path -LiteralPath $Executable))
}}
function Invoke-SetupProcess {{
    param($Executable, $Arguments, [switch]$Elevate, $LogPath)
    if ($Arguments -contains '/uninstall') {{
        $script:Steps.Add('uninstall')
        $script:Uninstalled = $true
    }} elseif ($script:Uninstalled) {{
        $script:Steps.Add('clean-install')
        New-Item -ItemType Directory -Force -Path {ps_quote(target_py.parent)} | Out-Null
        Set-Content -LiteralPath {ps_quote(target_py)} -Value 'usable-python'
    }} else {{
        $script:Steps.Add('noop-modify')
    }}
}}
$py = Install-LocalPython -AppDir {ps_quote(app)}
if ($py -ne {ps_quote(target_py)}) {{ throw "Unexpected python: $py" }}
Write-Output ('steps=' + ($script:Steps -join ','))
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'steps=noop-modify,uninstall,clean-install' in result.stdout
