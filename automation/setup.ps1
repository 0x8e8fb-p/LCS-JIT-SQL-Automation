# Internal bootstrap helpers; dot-sourced by ../run.ps1. No execution on import.
Set-StrictMode -Version 2.0

function Test-SupportedPython {
    param([string]$Executable, [string[]]$Prefix = @())
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { return $false }
    # PowerShell 5 turns redirected native stderr into ErrorRecords. An expected
    # failed probe must return false, not abort automatic installation.
    $ErrorActionPreference = 'Continue'
    & $Executable @Prefix -c 'import sys, struct; sys.exit(0 if (3,10) <= sys.version_info[:2] < (3,14) and struct.calcsize(''P'') == 8 else 1)' *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-RegistryPythonCandidates {
    $Candidates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Root in @('HKCU:\Software\Python\PythonCore', 'HKLM:\Software\Python\PythonCore')) {
        foreach ($Version in @('3.13', '3.12', '3.11', '3.10')) {
            $Key = Join-Path $Root "$Version\InstallPath"
            if (-not (Test-Path -LiteralPath $Key)) { continue }
            $Props = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
            if ($null -eq $Props) { continue }
            if ($Props.PSObject.Properties['ExecutablePath'] -and $Props.ExecutablePath) {
                $Candidates.Add([string]$Props.ExecutablePath)
            }
            if ($Props.PSObject.Properties['(default)'] -and $Props.'(default)') {
                $Candidates.Add((Join-Path ([string]$Props.'(default)') 'python.exe'))
            }
        }
    }
    return $Candidates
}

function Find-SupportedPython {
    param([string]$AppDir)
    $Local = Join-Path $AppDir 'runtime/python/python.exe'
    if (Test-SupportedPython $Local) { return $Local }
    # Avoid Windows Store aliases, which can open a Store window rather than run.
    $Python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($Python -and $Python.Source -notmatch '[\\/]WindowsApps[\\/]' -and (Test-SupportedPython $Python.Source)) {
        return $Python.Source
    }
    $Launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($Launcher) {
        foreach ($Version in @('-3.13', '-3.12', '-3.11', '-3.10')) {
            if (Test-SupportedPython $Launcher.Source @($Version)) {
                $Result = & $Launcher.Source $Version -c 'import sys; print(sys.executable)'
                if ($LASTEXITCODE -eq 0) { return ($Result | Select-Object -Last 1) }
            }
        }
    }
    foreach ($Candidate in (Get-RegistryPythonCandidates)) {
        if ($Candidate -notmatch '[\\/]WindowsApps[\\/]' -and (Test-SupportedPython $Candidate)) {
            return $Candidate
        }
    }
    return $null
}

function Get-VerifiedInstaller {
    param([string]$Url, [string]$Destination, [string]$Publisher, [string]$Sha256 = '')
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installer URL must use HTTPS.' }
    New-Item -ItemType Directory -Force -Path (Split-Path $Destination) | Out-Null
    # Re-download on each installation attempt; never trust a cached executable.
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination -TimeoutSec 180
    if ($Sha256 -and (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne $Sha256) {
        Remove-Item -LiteralPath $Destination -Force
        throw 'Installer checksum mismatch. Nothing was installed; retry on a trusted network.'
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Destination
    if ($Signature.Status -ne 'Valid' -or $null -eq $Signature.SignerCertificate -or
        $Signature.SignerCertificate.Subject -notmatch $Publisher) {
        Remove-Item -LiteralPath $Destination -Force
        throw 'Installer signature/publisher verification failed. Nothing was installed.'
    }
    return $Destination
}

function Invoke-SetupProcess {
    param([string]$Executable, [string[]]$Arguments, [switch]$Elevate, [string]$LogPath)
    $Options = @{ FilePath = $Executable; ArgumentList = $Arguments; Wait = $true; PassThru = $true }
    if ($Elevate) { $Options.Verb = 'RunAs' }
    $Process = Start-Process @Options
    if ($Process.ExitCode -eq 3010 -or $Process.ExitCode -eq 1641) {
        throw "Installation requires a restart. Restart Windows and rerun ./run.ps1. Log: $LogPath"
    }
    if ($Process.ExitCode -ne 0) { throw "Installer failed (exit $($Process.ExitCode)). Log: $LogPath" }
}

function Install-LocalPython {
    param([string]$AppDir)
    $Cache = Join-Path $AppDir 'runtime/installers'
    $Target = Join-Path $AppDir 'runtime/python'
    Write-Host 'Installing Python 3.13.16 locally (no PATH changes)...'
    $Installer = Get-VerifiedInstaller `
        -Url 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-amd64.exe' `
        -Destination (Join-Path $Cache 'python-3.13.16-amd64.exe') `
        -Publisher 'O=Python Software Foundation(?:,|$)' `
        -Sha256 'fb4f9f5d438b2396da0086dc70b935c530cb578e37adc6d354f7ad2037fee83b'
    $Log = Join-Path $Cache 'python-install.log'
    $InstallArgs = @(
        '/quiet', '/norestart', 'InstallAllUsers=0', 'PrependPath=0', 'Include_launcher=0',
        'Include_test=0', 'Include_doc=0', 'Include_tcltk=0', 'AssociateFiles=0', 'Shortcuts=0',
        ('TargetDir="{0}"' -f $Target), '/log', ('"{0}"' -f $Log)
    )
    Invoke-SetupProcess -Executable $Installer -LogPath $Log -Arguments $InstallArgs
    $Python = Join-Path $Target 'python.exe'
    if (Test-SupportedPython $Python) { return $Python }
    $Found = Find-SupportedPython $AppDir
    if ($Found) { return $Found }
    # If Python 3.13 was previously installed to a deleted/moved folder, WiX Burn
    # treats a normal run as a no-op Modify. Uninstall the stale registration and
    # perform a clean install into TargetDir.
    Write-Host 'Repairing stale Python 3.13 installer registration...'
    $UninstallLog = Join-Path $Cache 'python-uninstall.log'
    Invoke-SetupProcess -Executable $Installer -LogPath $UninstallLog -Arguments @(
        '/uninstall', '/quiet', '/norestart', '/log', ('"{0}"' -f $UninstallLog)
    )
    Invoke-SetupProcess -Executable $Installer -LogPath $Log -Arguments $InstallArgs
    if (Test-SupportedPython $Python) { return $Python }
    $Found = Find-SupportedPython $AppDir
    if ($Found) { return $Found }
    throw "Python installation did not produce a usable x64 interpreter. Log: $Log"
}

function Test-SqlDriver {
    param([string]$Python)
    $ErrorActionPreference = 'Continue'
    & $Python -c 'import pyodbc, sys; sys.exit(0 if any(d in pyodbc.drivers() for d in (''ODBC Driver 18 for SQL Server'', ''ODBC Driver 17 for SQL Server'')) else 1)' *> $null
    return ($LASTEXITCODE -eq 0)
}

function Install-SqlDriver {
    param([string]$AppDir)
    $Cache = Join-Path $AppDir 'runtime/installers'
    Write-Host 'Installing Microsoft ODBC Driver 18. Windows may ask for administrator approval.'
    # 18.7 includes the C++ runtime; no separate redistributable is required.
    $Installer = Get-VerifiedInstaller -Url 'https://go.microsoft.com/fwlink/?linkid=2378279' `
        -Destination (Join-Path $Cache 'msodbcsql18.msi') -Publisher 'O=Microsoft Corporation(?:,|$)'
    $Log = Join-Path $Cache 'odbc-install.log'
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    $Admin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Invoke-SetupProcess -Executable (Join-Path $env:SystemRoot 'System32/msiexec.exe') -Elevate:(-not $Admin) -LogPath $Log -Arguments @(
        '/i', ('"{0}"' -f $Installer), '/quiet', '/norestart', 'IACCEPTMSODBCSQLLICENSETERMS=YES',
        '/L*v', ('"{0}"' -f $Log)
    )
}

function Invoke-PythonStep {
    param([string]$Python, [string[]]$Arguments, [string]$Failure)
    $ErrorActionPreference = 'Continue'
    & $Python @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw $Failure }
}

function Test-PythonPackages {
    param([string]$Python, [string]$Requirements)
    $ErrorActionPreference = 'Continue'
    & $Python -c 'import playwright.sync_api, pyodbc, yaml, cryptography.fernet; import sys; from importlib.metadata import version; from pathlib import Path; lines=Path(sys.argv[1]).read_text().splitlines(); pins=[line.strip().split(''=='') for line in lines if line.strip() and not line.lstrip().startswith(''#'')]; sys.exit(0 if all(len(p)==2 and version(p[0])==p[1] for p in pins) else 1)' $Requirements *> $null
    return ($LASTEXITCODE -eq 0)
}

function Test-Chromium {
    param([string]$Python)
    $ErrorActionPreference = 'Continue'
    & $Python -c 'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(headless=True); b.close(); p.stop()' *> $null
    return ($LASTEXITCODE -eq 0)
}

function Initialize-Prerequisites {
    param([string]$AppDir)
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem -or
        $env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
        throw 'Automatic setup supports Windows 10/11 or Server (x64) only; ARM64, 32-bit Windows, macOS and Linux need a separate installer.'
    }
    foreach ($Name in @('main.py', 'automation_support.py', 'lcs_jit_automation.py', 'sql_executor.py', 'requirements.txt', 'defaults.yaml')) {
        if (-not (Test-Path -LiteralPath (Join-Path $AppDir $Name) -PathType Leaf)) {
            throw "Incomplete download: automation/$Name is missing. Extract the whole repository before running."
        }
    }
    $Version = [Environment]::OSVersion.Version
    if ($Version.Major -lt 10 -or $Version.Build -lt 17763) { throw 'Windows 10 1809 / Server 2019 or newer is required.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $env:PYTHONPYCACHEPREFIX = Join-Path $AppDir 'runtime/pycache'
    $env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $AppDir 'browsers'
    $Py = Join-Path $AppDir '.venv/Scripts/python.exe'
    if (-not (Test-SupportedPython $Py)) {
        $BasePython = Find-SupportedPython $AppDir
        if (-not $BasePython) { $BasePython = Install-LocalPython $AppDir }
        $Venv = Join-Path $AppDir '.venv'
        if (Test-Path -LiteralPath $Venv) {
            # Preserve an unusable/copied environment instead of deleting it.
            Move-Item -LiteralPath $Venv -Destination ($Venv + '.backup-' + [Guid]::NewGuid().ToString('N'))
        }
        Write-Host 'Creating isolated Python environment...'
        Invoke-PythonStep $BasePython @('-m', 'venv', $Venv) 'Could not create the local Python environment.'
        if (-not (Test-SupportedPython $Py)) { throw 'The new Python environment is not usable.' }
    }
    $Requirements = Join-Path $AppDir 'requirements.txt'
    $Stamp = Join-Path $AppDir '.venv/requirements.sha256'
    $Hash = (Get-FileHash -LiteralPath $Requirements -Algorithm SHA256).Hash
    if (-not (Test-Path -LiteralPath $Stamp) -or (Get-Content -LiteralPath $Stamp -Raw).Trim() -ne $Hash -or
        -not (Test-PythonPackages $Py $Requirements)) {
        Write-Host 'Installing/verifying Python dependencies...'
        Invoke-PythonStep $Py @('-m', 'pip', 'install', '--disable-pip-version-check', '--only-binary=:all:', '-r', $Requirements) 'Python dependencies failed to install. Check Internet/proxy access and automation/requirements.txt.'
        if (-not (Test-PythonPackages $Py $Requirements)) { throw 'Installed Python dependencies could not be imported.' }
        Set-Content -LiteralPath $Stamp -Value $Hash -Encoding ASCII
    }
    # Check repeat runs too; imports alone do not establish compatibility.
    Invoke-PythonStep $Py @('-m', 'pip', 'check') 'Python dependency compatibility check failed. Repair the project-local environment before running.'
    if (-not (Test-SqlDriver $Py)) {
        Install-SqlDriver $AppDir
        if (-not (Test-SqlDriver $Py)) { throw 'ODBC driver still unavailable. Review automation/runtime/installers/odbc-install.log and rerun after any required restart.' }
    }
    if (-not (Test-Chromium $Py)) {
        Write-Host 'Installing project-local Playwright Chromium...'
        Invoke-PythonStep $Py @('-m', 'playwright', 'install', 'chromium') 'Chromium installation failed. Check Internet/proxy access and disk space.'
        if (-not (Test-Chromium $Py)) { throw 'Chromium could not launch after installation. Check endpoint security and OS compatibility.' }
    }
    return $Py
}
