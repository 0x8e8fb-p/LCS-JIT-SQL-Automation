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


def test_install_local_python_extracts_without_windows_installer_registration(tmp_path):
    # A per-user Python registration that outlives the project folder breaks the next
    # install (no-op Modify, then 1603 from pip.msi on uninstall), so the preferred
    # path only extracts files and must never run the official installer.
    app = tmp_path / 'new_app'
    target_py = app / 'runtime' / 'python' / 'python.exe'
    result = invoke(tmp_path, f'''
$script:Steps = New-Object 'System.Collections.Generic.List[string]'
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
    $script:Steps.Add('official-installer')
}}
function Unpack-PythonInstaller {{
    param($Installer, $Target, $Cache)
    $script:Steps.Add('unpack')
    New-Item -ItemType Directory -Force -Path (Split-Path {ps_quote(target_py)}) | Out-Null
    Set-Content -LiteralPath {ps_quote(target_py)} -Value 'usable-python'
}}
$py = Install-LocalPython -AppDir {ps_quote(app)}
if ($py -ne {ps_quote(target_py)}) {{ throw "Unexpected python: $py" }}
Write-Output ('steps=' + ($script:Steps -join ','))
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'steps=unpack' in result.stdout


def test_install_local_python_falls_back_to_official_installer_when_extraction_fails(tmp_path):
    # Blocked MSI administrative installation falls back to the registered per-user
    # installer instead of failing the run.
    app = tmp_path / 'new_app'
    target_py = app / 'runtime' / 'python' / 'python.exe'
    result = invoke(tmp_path, f'''
$script:Steps = New-Object 'System.Collections.Generic.List[string]'
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
    $script:Steps.Add('official-installer')
    New-Item -ItemType Directory -Force -Path (Split-Path {ps_quote(target_py)}) | Out-Null
    Set-Content -LiteralPath {ps_quote(target_py)} -Value 'registered-python'
}}
function Unpack-PythonInstaller {{
    param($Installer, $Target, $Cache)
    $script:Steps.Add('unpack')
    throw 'MSI administrative installation is blocked by policy.'
}}
$py = Install-LocalPython -AppDir {ps_quote(app)}
if ($py -ne {ps_quote(target_py)}) {{ throw "Unexpected python: $py" }}
Write-Output ('steps=' + ($script:Steps -join ','))
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'steps=unpack,official-installer' in result.stdout
    assert 'Local extraction failed: MSI administrative installation is blocked by policy.' in result.stdout


def test_install_local_python_restart_requirement_stops_instead_of_extracting(tmp_path):
    app = tmp_path / 'new_app'
    result = invoke(tmp_path, f'''
$script:Steps = New-Object 'System.Collections.Generic.List[string]'
function Get-VerifiedInstaller {{
    param($Url, $Destination, $Publisher, $Sha256)
    New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
    Set-Content -LiteralPath $Destination -Value 'fake-installer'
    return $Destination
}}
function Find-SupportedPython {{ param($AppDir) return $null }}
function Test-SupportedPython {{ param($Executable, $Prefix) return $false }}
function Invoke-SetupProcess {{
    param($Executable, $Arguments, [switch]$Elevate, $LogPath)
    throw "Installation requires a restart. Restart Windows and rerun ./run.ps1. Log: python-install.log"
}}
function Unpack-PythonInstaller {{
    param($Installer, $Target, $Cache)
    $script:Steps.Add('unpack')
}}
try {{ Install-LocalPython -AppDir {ps_quote(app)}; throw 'Restart requirement ignored' }}
catch {{
    if ($_.Exception.Message -eq 'Restart requirement ignored') {{ throw }}
    Write-Output $_.Exception.Message
}}
Write-Output ('steps=' + ($script:Steps -join ','))
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'requires a restart' in result.stdout
    # Extraction produced no interpreter, so the run still stops instead of
    # continuing with the unrelated discovery fallback.
    assert 'steps=unpack' in result.stdout
    assert 'find' not in result.stdout


def test_unpack_python_installer_extracts_attached_msi_container(tmp_path):
    import struct
    installer = tmp_path / 'fake-python.exe'
    cab_bytes = bytearray(10_000_064)
    cab_bytes[0:8] = b'MSCF\x00\x00\x00\x00'
    struct.pack_into('<I', cab_bytes, 8, 10_000_032)
    cab_bytes[24] = 3
    cab_bytes[25] = 1
    installer.write_bytes(b'MZ' + b'\x00' * 126 + bytes(cab_bytes))
    target_dir = tmp_path / 'target'
    cache_dir = tmp_path / 'cache'
    cache_dir.mkdir()
    result = invoke(tmp_path, f'''
$script:Msis = New-Object 'System.Collections.Generic.List[string]'
$FakeBin = Join-Path {ps_quote(tmp_path)} 'fake-sys/System32'
New-Item -ItemType Directory -Force -Path $FakeBin | Out-Null
Set-Content -LiteralPath (Join-Path $FakeBin 'expand.exe') -Value ''
$env:SystemRoot = Join-Path {ps_quote(tmp_path)} 'fake-sys'
Set-Alias -Name (Join-Path $FakeBin 'expand.exe') -Value Invoke-FakeExpand
function Invoke-FakeExpand {{
    param($Cab, $Flag, $WorkDir)
    if ((Get-Item -LiteralPath $Cab).Length -ne 10000032) {{ throw 'Unexpected CAB length' }}
    $Id = $Flag -replace '^-F:', ''
    [IO.File]::WriteAllBytes((Join-Path $WorkDir $Id), [byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1,0x00,0x00))
    $global:LASTEXITCODE = 0
}}
function Invoke-SetupProcess {{
    param($Executable, $Arguments, [switch]$Elevate, $LogPath)
    $MsiPath = $Arguments[1] -replace '"', ''
    if (-not (Test-Path -LiteralPath $MsiPath)) {{ throw "Missing extracted MSI: $MsiPath" }}
    $script:Msis.Add([IO.Path]::GetFileName($MsiPath))
}}
Unpack-PythonInstaller -Installer {ps_quote(installer)} -Target {ps_quote(target_dir)} -Cache {ps_quote(cache_dir)}
if (Test-Path -LiteralPath (Join-Path {ps_quote(cache_dir)} 'python-unpack')) {{ throw 'WorkDir not cleaned up' }}
Write-Output ('msis=' + ($script:Msis -join ','))
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'msis=core.msi,exe.msi,dev.msi,lib.msi' in result.stdout


def test_unpack_python_installer_rejects_unexpected_container_payload(tmp_path):
    # Payload ids come from the verified 3.13.16 amd64 layout; a layout change must
    # fail loudly instead of feeding a wrong file to msiexec.
    import struct
    installer = tmp_path / 'fake-python.exe'
    cab_bytes = bytearray(10_000_064)
    cab_bytes[0:8] = b'MSCF\x00\x00\x00\x00'
    struct.pack_into('<I', cab_bytes, 8, 10_000_032)
    cab_bytes[24] = 3
    cab_bytes[25] = 1
    installer.write_bytes(b'MZ' + b'\x00' * 126 + bytes(cab_bytes))
    target_dir = tmp_path / 'target'
    cache_dir = tmp_path / 'cache'
    cache_dir.mkdir()
    result = invoke(tmp_path, f'''
$script:MsiExecCalled = $false
$FakeBin = Join-Path {ps_quote(tmp_path)} 'fake-sys/System32'
New-Item -ItemType Directory -Force -Path $FakeBin | Out-Null
Set-Content -LiteralPath (Join-Path $FakeBin 'expand.exe') -Value ''
$env:SystemRoot = Join-Path {ps_quote(tmp_path)} 'fake-sys'
Set-Alias -Name (Join-Path $FakeBin 'expand.exe') -Value Invoke-FakeExpand
function Invoke-FakeExpand {{
    param($Cab, $Flag, $WorkDir)
    Set-Content -LiteralPath (Join-Path $WorkDir ($Flag -replace '^-F:', '')) -Value 'not-an-msi'
    $global:LASTEXITCODE = 0
}}
function Invoke-SetupProcess {{
    param($Executable, $Arguments, [switch]$Elevate, $LogPath)
    $script:MsiExecCalled = $true
}}
try {{ Unpack-PythonInstaller -Installer {ps_quote(installer)} -Target {ps_quote(target_dir)} -Cache {ps_quote(cache_dir)}; throw 'Unexpected payload accepted' }}
catch {{
    if ($_.Exception.Message -eq 'Unexpected payload accepted') {{ throw }}
    Write-Output $_.Exception.Message
}}
if ($script:MsiExecCalled) {{ throw 'msiexec ran for an unexpected payload' }}
if (Test-Path -LiteralPath (Join-Path {ps_quote(cache_dir)} 'python-unpack')) {{ throw 'WorkDir not cleaned up' }}
Write-Output 'rejected'
''')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'no longer matches the verified payload layout' in result.stdout
    assert 'rejected' in result.stdout

