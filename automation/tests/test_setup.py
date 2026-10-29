from __future__ import annotations

import json
import sys

import pytest

from helpers import ps_quote, run_setup_snippet

pytestmark = pytest.mark.powershell


def invoke(tmp_path, body):
    return run_setup_snippet(tmp_path, body)


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
function Assert-SetupReady {{ param($AppDir) $script:Calls.Add('preflight') }}
function Test-DownloadAccess {{ param($AppDir) }}
function Initialize-RuntimePython {{ param($AppDir) if (-not $script:Ready) {{ $script:Calls.Add('python') }}; return 'runtime-python.exe' }}
function Initialize-Venv {{
    param($AppDir, $RuntimePython)
    if (-not $script:Ready) {{ $script:Calls.Add('venv'); $script:Ready = $true }}
    New-Item -ItemType Directory -Force -Path (Join-Path $AppDir '.venv') | Out-Null
    return (Join-Path $AppDir '.venv/Scripts/python.exe')
}}
function Test-PythonPackages {{ param($Python) return $script:Packages }}
function Test-SqlDriver {{ param($Python) return $script:Driver }}
function Install-SqlDriver {{ param($AppDir) $script:Calls.Add('odbc'); $script:Driver=$true }}
function Test-Chromium {{ param($Python) return $script:Browser }}
function Invoke-PythonStep {{
    param($Python, $Arguments, $Failure)
    if ($Arguments -contains 'install' -and $Arguments -contains 'pip') {{ $script:Calls.Add('pip-install'); $script:Packages=$true }}
    elseif ($Arguments -contains 'check') {{ $script:Calls.Add('pip-check') }}
    elseif ($Arguments -contains 'playwright') {{ $script:Calls.Add('chromium'); $script:Browser=$true }}
}}
if ($script:Ready) {{
    New-Item -ItemType Directory -Force -Path (Join-Path $App '.venv') | Out-Null
    Set-Content -LiteralPath (Join-Path $App '.venv/requirements.sha256') -Value (Get-FileHash (Join-Path $App 'requirements.txt')).Hash
}}
$first = Initialize-Prerequisites -AppDir $App
$second = Initialize-Prerequisites -AppDir $App
if ($first -ne $second -or $first -notlike '*python.exe') {{ throw 'Incorrect Python return value' }}
Write-Output ('calls=' + ($script:Calls -join ','))
'''
    result = invoke(tmp_path, body)
    assert result.returncode == 0, result.stdout + result.stderr
    if fresh:
        assert 'calls=preflight,python,venv,pip-install,pip-check,odbc,chromium,preflight,pip-check' in result.stdout
    else:
        assert 'calls=preflight,pip-check,preflight,pip-check\n' in result.stdout


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


WINDOWS_FACTS = ("@{ IsWindows = $true; Is64BitOs = $true; Is64BitProcess = $true; Arm64 = $false; Build = 19045; Major = 10; "
                 "LanguageMode = 'FullLanguage'; HostName = 'ConsoleHost'; LongPathsEnabled = $false; DriveType = 'Fixed'; "
                 "FreeBytes = [long]50GB; Writable = $true; OneDriveRoots = @(); ControlledFolderAccess = $false }")


def test_preflight_lists_every_blocker_at_once(tmp_path):
    result = invoke(tmp_path, f"""
$Facts = {WINDOWS_FACTS}
$Facts.Is64BitProcess = $false; $Facts.LanguageMode = 'ConstrainedLanguage'; $Facts.DriveType = 'Network'
$Facts.Writable = $false; $Facts.FreeBytes = [long]200MB
function Get-SetupPlatform {{ param($AppDir) return $Facts }}
$App = 'Z:\\Projects\\copy [1]\\' + ('x' * 150) + '\\automation'
try {{ Assert-SetupReady -AppDir $App; throw 'not stopped' }} catch {{ Write-Output $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert out.startswith('Setup cannot continue on this computer:')
    for phrase in ('32-bit PowerShell', 'ConstrainedLanguage mode', 'network drive', 'contains [ ] or a backtick',
                   'not writable', 'GB is free', 'path is too long'):
        assert phrase in out, phrase
    assert out.count('\n  - ') == 7


def test_preflight_warnings_do_not_stop_setup(tmp_path):
    result = invoke(tmp_path, f"""
$Facts = {WINDOWS_FACTS}
$Facts.OneDriveRoots = @('C:\\Users\\pat\\OneDrive - Contoso'); $Facts.ControlledFolderAccess = $true
function Get-SetupPlatform {{ param($AppDir) return $Facts }}
Assert-SetupReady -AppDir 'C:\\Users\\pat\\OneDrive - Contoso\\LCS\\automation'
Write-Output 'continued'
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'inside OneDrive' in result.stdout and 'Controlled Folder Access' in result.stdout
    assert 'continued' in result.stdout


def test_child_environment_removes_breaking_settings_and_keeps_user_choices(tmp_path):
    result = invoke(tmp_path, f"""
$env:PYTHONHOME = 'C:\\ArcGIS\\Python'; $env:PYTHONPATH = 'x'; $env:PIP_TARGET = 'y'; $env:NODE_OPTIONS = '--inspect'
$env:PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = '1'; $env:PIP_INDEX_URL = 'https://mirror.example/simple'; $env:HTTPS_PROXY = 'http://proxy.example:8080'
$env:NODE_EXTRA_CA_CERTS = 'C:\\certs\\corp.pem'
Set-ChildEnvironment -AppDir {ps_quote(tmp_path)}
foreach ($Name in 'PYTHONHOME','PYTHONPATH','PIP_TARGET','NODE_OPTIONS','PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD') {{ if (Test-Path "Env:$Name") {{ throw "$Name kept" }} }}
Write-Output ("user=" + $env:PIP_INDEX_URL + "|" + $env:HTTPS_PROXY + "|" + $env:NODE_EXTRA_CA_CERTS)
Write-Output ("set=" + $env:PYTHONNOUSERSITE + $env:PIP_USER + "|" + $env:PLAYWRIGHT_BROWSERS_PATH)
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'user=https://mirror.example/simple|http://proxy.example:8080|C:\\certs\\corp.pem' in result.stdout
    assert f'set=10|{tmp_path / "browsers"}' in result.stdout


def test_invoke_native_reports_missing_programs_and_exit_codes(tmp_path):
    result = invoke(tmp_path, f"""
Start-SetupLog -AppDir {ps_quote(tmp_path)}
$global:LASTEXITCODE = 0
$Missing = Invoke-Native -FilePath {ps_quote(tmp_path / 'missing.exe')} -Quiet
Write-Output ("missing=" + $Missing.ExitCode + "/" + $Missing.Started)
$Failed = Invoke-Native -FilePath {ps_quote(sys.executable)} -Arguments @('-c', 'import sys; print(''probe-line''); sys.exit(3)') -Quiet
Write-Output ("failed=" + $Failed.ExitCode + "/" + ($Failed.Tail -join ','))
Write-Output ("log=" + (Get-Content -LiteralPath $script:SetupLog -Raw).Contains('probe-line'))
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'missing=-1/False' in result.stdout
    assert 'failed=3/probe-line' in result.stdout
    assert 'log=True' in result.stdout


@pytest.mark.parametrize('failures', [2, 3])
def test_downloads_retry_then_explain(tmp_path, failures):
    destination = tmp_path / 'downloads' / 'file.bin'
    result = invoke(tmp_path, f"""
$script:Attempts = 0
function Start-Sleep {{ param($Seconds) }}
function Invoke-WebRequest {{
    param([switch]$UseBasicParsing, $Uri, $OutFile, $TimeoutSec, $Proxy, [switch]$ProxyUseDefaultCredentials)
    $script:Attempts++
    if ($script:Attempts -le {failures}) {{ throw [System.Net.WebException]::new('The operation has timed out') }}
    Set-Content -LiteralPath $OutFile -Value 'payload'
}}
try {{ $Path = Get-Download -Url 'https://example.com/file.bin' -Destination {ps_quote(destination)}; Write-Output "ok=$($script:Attempts)" }}
catch {{ Write-Output $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stdout + result.stderr
    if failures == 2:
        assert 'ok=3' in result.stdout and destination.exists()
        assert not destination.with_name('file.bin.partial').exists()
    else:
        assert 'Download failed after 3 attempts: https://example.com/file.bin (the connection timed out)' in result.stdout
        assert not destination.exists()


def fake_package(path, entries):
    """A stand-in nupkg (ZIP) plus the size and base64 SHA-512 the setup script should expect."""
    import base64
    import hashlib
    import zipfile
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, 'w') as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    data = path.read_bytes()
    return len(data), base64.b64encode(hashlib.sha512(data).digest()).decode()


def package_overrides(size, digest):
    return f"$script:PythonPackageSize = {size}; $script:PythonPackageSha512 = '{digest}'\n"


def test_prestaged_package_is_used_without_download(tmp_path):
    app = tmp_path / 'app'
    size, digest = fake_package(app / 'runtime/installers/python.3.13.16.nupkg', {'tools/python.exe': 'x'})
    result = invoke(tmp_path, package_overrides(size, digest) + f"""
function Get-Download {{ throw 'no network' }}
Write-Output ("package=" + (Split-Path -Leaf (Get-PythonPackage -AppDir {ps_quote(app)})))
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'package=python.3.13.16.nupkg' in result.stdout


def test_package_with_the_wrong_hash_is_refused_and_deleted(tmp_path):
    app = tmp_path / 'app'
    staged = app / 'runtime/installers/python.3.13.16.nupkg'
    fake_package(staged, {'tools/python.exe': 'tampered'})
    result = invoke(tmp_path, f"""
function Get-Download {{ param($Url, $Destination) Set-Content -LiteralPath $Destination -Value 'tampered download' }}
try {{ Get-PythonPackage -AppDir {ps_quote(app)}; throw 'accepted' }} catch {{ Write-Output $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'does not match the published SHA-512' in result.stdout  # the pre-staged file
    assert 'does not match the published size and SHA-512; nothing was installed' in result.stdout
    assert not staged.exists()


def test_package_paths_outside_the_folder_are_refused(tmp_path):
    package = tmp_path / 'evil.nupkg'
    fake_package(package, {'tools/python.exe': 'x', 'tools/../../escaped.txt': 'boom'})
    result = invoke(tmp_path, f"""
try {{ Expand-PythonPackage -Package {ps_quote(package)} -Destination {ps_quote(tmp_path / 'target')}; throw 'extracted' }}
catch {{ Write-Output $_.Exception.Message }}
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'contains an unsafe path' in result.stdout
    assert not (tmp_path / 'escaped.txt').exists()


def test_runtime_is_staged_marked_and_swapped_then_reused_offline(tmp_path):
    app = tmp_path / 'app'
    old = app / 'runtime/python'
    old.mkdir(parents=True)
    (old / 'python.exe').write_text('old msi extraction')  # unmarked runtime from an earlier version
    size, digest = fake_package(app / 'runtime/installers/python.3.13.16.nupkg',
                                {'tools/python.exe': 'new', 'tools/Lib/os.py': '#', '[Content_Types].xml': '<x/>'})
    result = invoke(tmp_path, package_overrides(size, digest) + f"""
function Test-RuntimePython {{ param($Python) return ((Test-Path -LiteralPath $Python) -and ((Get-Content -LiteralPath $Python -Raw) -match 'new')) }}
$First = Initialize-RuntimePython -AppDir {ps_quote(app)}
function Get-PythonPackage {{ throw 'network used on the second run' }}
$Second = Initialize-RuntimePython -AppDir {ps_quote(app)}
Write-Output ("same=" + ($First -eq $Second))
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'same=True' in result.stdout
    assert (app / 'runtime/python/python.exe').read_text() == 'new'
    assert (app / 'runtime/python/Lib/os.py').exists() and not (app / 'runtime/python/[Content_Types].xml').exists()
    assert json.loads((app / 'runtime/python/.lcsjit-runtime.json').read_text())['version'] == '3.13.16'
    kept = list((app / 'runtime').glob('python.old-*'))
    assert len(kept) == 1 and (kept[0] / 'python.exe').read_text() == 'old msi extraction'
    assert not list((app / 'runtime').glob('python.new-*'))


@pytest.mark.parametrize(('home', 'version', 'rebuilt'), [
    ('RUNTIME', '3.13.16', False),
    ('C:/Users/old/AppData/Local/Programs/Python/Python311', '3.11.9', True),  # system Python on the first machine
    ('MOVED', '3.13.16', True),  # the project folder was moved or copied
])
def test_venv_is_rebuilt_only_for_another_runtime_or_folder(tmp_path, home, version, rebuilt):
    app = tmp_path / 'app'
    runtime = app / 'runtime/python'
    runtime.mkdir(parents=True)
    venv_python = app / '.venv/Scripts/python.exe'
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text('venv python')
    home_path = {'RUNTIME': str(runtime), 'MOVED': str(tmp_path / 'old-location/automation/runtime/python')}.get(home, home)
    (app / '.venv/pyvenv.cfg').write_text(f'home = {home_path}\ninclude-system-site-packages = false\nversion = {version}\n')
    result = invoke(tmp_path, f"""
function Invoke-Native {{ param($FilePath, $Arguments, [switch]$Quiet) return [pscustomobject]@{{ ExitCode = 0; Started = $true; Tail = @(); Output = '' }} }}
function Invoke-PythonStep {{
    param($Python, $Arguments, $Failure)
    $Venv = $Arguments[-1]
    New-Item -ItemType Directory -Force -Path (Join-Path $Venv 'Scripts') | Out-Null
    Set-Content -LiteralPath (Join-Path $Venv 'Scripts/python.exe') -Value 'rebuilt'
    Set-Content -LiteralPath (Join-Path $Venv 'pyvenv.cfg') -Value ("home = {runtime}`nversion = 3.13.16")
}}
$Py = Initialize-Venv -AppDir {ps_quote(app)} -RuntimePython {ps_quote(runtime / 'python.exe')}
Write-Output ("python=" + (Get-Content -LiteralPath $Py -Raw).Trim())
""")
    assert result.returncode == 0, result.stdout + result.stderr
    backups = list(app.glob('.venv.backup-*'))
    if rebuilt:
        assert 'python=rebuilt' in result.stdout and len(backups) == 1
        assert (backups[0] / 'Scripts/python.exe').read_text() == 'venv python'
    else:
        assert 'python=venv python' in result.stdout and backups == []
