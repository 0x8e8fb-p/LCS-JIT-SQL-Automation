# Internal bootstrap helpers; dot-sourced by ../run.ps1. No execution on import.
# Windows PowerShell 5.1 compatible: no ternaries, ??, && or ||, three-argument
# Join-Path or ConvertFrom-Json -AsHashtable. ASCII only.
Set-StrictMode -Version 2.0

# Deepest path setup creates below automation\ (measured for the pinned versions):
#   .venv\Lib\site-packages\playwright\driver\package\lib\tools\skills\
#     playwright-component-testing\references\gallery-spec.md   122 characters
#   runtime\python.new-xxxxxxxx\Lib\site-packages\pip-26.2.1.dist-info\...  116
#   browsers\chromium-1243\chrome-win64\PrivacySandboxAttestationsPreloaded\... 104
# plus the separator after automation. Windows paths are limited to 259
# characters unless Win32 long paths are enabled.
$script:DeepestSetupPath = 123
# Chromium's saved profile (automation\.auth\<id>.profile\Default\Service Worker\
# CacheStorage\<40 hex>\<36>\index-dir\...) reaches about 180 characters.
$script:DeepestProfilePath = 180
$script:MaxPath = 259
$script:MinimumFreeBytes = 1.5GB
$script:SetupLog = $null
$script:SetupChecks = Join-Path $PSScriptRoot 'setup_checks.py'
# Microsoft's stable link to the current ODBC Driver 18 for SQL Server x64 MSI (18.7.1.1 when verified).
$script:OdbcDriverUrl = 'https://go.microsoft.com/fwlink/?linkid=2378279'

function Write-SetupLog {
    param([string[]]$Lines)
    if (-not $script:SetupLog -or -not $Lines) { return }
    try { Add-Content -LiteralPath $script:SetupLog -Value $Lines -Encoding UTF8 } catch { $script:SetupLog = $null }
}

function Start-SetupLog {
    param([string]$AppDir)
    try {
        $Folder = Join-Path $AppDir 'runtime/logs'
        [IO.Directory]::CreateDirectory($Folder) | Out-Null
        $script:SetupLog = Join-Path $Folder ('setup-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '.log')
        Write-SetupLog @("Setup started $([DateTime]::UtcNow.ToString('o')) PowerShell $($PSVersionTable.PSVersion)")
    } catch { $script:SetupLog = $null }
}

function Invoke-Native {
    <#
        Runs a program and never throws for its exit code. Resets LASTEXITCODE first,
        so a program that could not start (application control, missing file) is never
        mistaken for the previous command's success. Returns ExitCode and the last 20
        output lines (stdout and stderr); everything is also appended to the setup log.
    #>
    param([string]$FilePath, [string[]]$Arguments = @(), [switch]$Quiet)
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = -1
    $Lines = New-Object 'System.Collections.Generic.List[string]'
    $Started = $true
    try {
        & $FilePath @Arguments 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $Line = [string]$_.Exception.Message } else { $Line = [string]$_ }
            $Lines.Add($Line)
            if (-not $Quiet) { Write-Host $Line }
        }
    } catch {
        $Started = $false
        $Lines.Add("Could not start $([IO.Path]::GetFileName($FilePath)): $($_.Exception.Message)")
    }
    $Code = $LASTEXITCODE
    if (-not $Started) {
        $Code = -1
        if ($Lines.Count -eq 0) { $Lines.Add("Could not start $([IO.Path]::GetFileName($FilePath)).") }
    }
    Write-SetupLog (@("> $([IO.Path]::GetFileName($FilePath)) $($Arguments -join ' ')") + @($Lines) + @("exit $Code"))
    $Tail = @($Lines | Select-Object -Last 20)
    return [pscustomobject]@{ ExitCode = $Code; Started = $Started; Tail = $Tail; Output = ($Lines -join "`n") }
}

function Get-SetupPlatform {
    # Machine facts in one mockable place (tests replace this function).
    param([string]$AppDir)
    $Facts = @{
        IsWindows = ($env:OS -eq 'Windows_NT'); Is64BitOs = [Environment]::Is64BitOperatingSystem
        Is64BitProcess = [Environment]::Is64BitProcess; Arm64 = ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64')
        Build = [Environment]::OSVersion.Version.Build; Major = [Environment]::OSVersion.Version.Major
        LanguageMode = [string]$ExecutionContext.SessionState.LanguageMode; HostName = [string]$Host.Name
        LongPathsEnabled = $false; DriveType = 'Fixed'; FreeBytes = [long]::MaxValue; Writable = $true
        OneDriveRoots = @(); ControlledFolderAccess = $false
    }
    if ($Facts.IsWindows) {
        try {
            $Value = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction Stop
            $Facts.LongPathsEnabled = ($Value.LongPathsEnabled -eq 1)
        } catch { $Facts.LongPathsEnabled = $false }
        try { $Facts.ControlledFolderAccess = ((Get-MpPreference -ErrorAction Stop).EnableControlledFolderAccess -eq 1) } catch { $Facts.ControlledFolderAccess = $false }
    }
    if ($AppDir -match '^[A-Za-z]:') {
        try {
            $Drive = New-Object IO.DriveInfo($AppDir.Substring(0, 2))
            $Facts.DriveType = [string]$Drive.DriveType
            $Facts.FreeBytes = [long]$Drive.AvailableFreeSpace
        } catch { $Facts.DriveType = 'Unknown' }
    } elseif ($AppDir.StartsWith('\\')) { $Facts.DriveType = 'Network' }
    $Probe = Join-Path $AppDir ('.write-test-' + [Guid]::NewGuid().ToString('N'))
    try { [IO.File]::WriteAllText($Probe, 'ok'); [IO.File]::Delete($Probe) } catch { $Facts.Writable = $false }
    $Facts.OneDriveRoots = @(@($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) | Where-Object { $_ })
    return $Facts
}

function Get-SetupProblems {
    <# Every local blocker at once: Errors stop setup, Warnings are shown and setup continues. #>
    param([string]$AppDir, [hashtable]$Facts)
    $Errors = New-Object 'System.Collections.Generic.List[string]'
    $Warnings = New-Object 'System.Collections.Generic.List[string]'
    if (-not $Facts.IsWindows -or -not $Facts.Is64BitOs -or $Facts.Arm64) {
        $Errors.Add('Windows 10/11 or Windows Server (x64) is required; ARM64, 32-bit Windows, macOS and Linux are not supported.')
    } else {
        if (-not $Facts.Is64BitProcess) { $Errors.Add('This is 32-bit PowerShell. Start .\run.cmd instead, which uses 64-bit Windows PowerShell.') }
        if ($Facts.Major -lt 10 -or $Facts.Build -lt 17763) { $Errors.Add('Windows 10 version 1809, Windows Server 2019 or newer is required.') }
    }
    if ($Facts.LanguageMode -ne 'FullLanguage') {
        $Errors.Add("PowerShell runs in $($Facts.LanguageMode) mode (application control). Ask IT to allow this project's scripts (run.ps1, automation\setup.ps1).")
    }
    if ($Facts.HostName -match 'ISE') { $Errors.Add('The PowerShell ISE cannot run the sign-in prompt. Run .\run.cmd from PowerShell or Windows Terminal.') }
    if ($Facts.DriveType -eq 'Network' -or $AppDir.StartsWith('\\')) {
        $Errors.Add("The project is on a network drive ($AppDir). Copy it to a local folder such as C:\LCSJIT; Python and Chromium do not run reliably from network paths.")
    }
    if ($AppDir.IndexOfAny([char[]]'[]`') -ge 0) {
        $Errors.Add("The folder path contains [ ] or a backtick ($AppDir), which PowerShell treats as wildcards. Rename the folder or move the project, for example to C:\LCSJIT.")
    }
    if (-not $Facts.Writable) { $Errors.Add("The automation folder is not writable ($AppDir). Check permissions, or move the project to a folder you own.") }
    if ($Facts.FreeBytes -lt $script:MinimumFreeBytes) {
        $Errors.Add(('Only {0:N1} GB is free on this drive; setup needs about 1.5 GB for Python, packages and Chromium.' -f ($Facts.FreeBytes / 1GB)))
    }
    if (-not $Facts.LongPathsEnabled) {
        if ($AppDir.Length + $script:DeepestSetupPath -gt $script:MaxPath) {
            $Errors.Add("The folder path is too long ($($AppDir.Length) characters) for Windows without long-path support. Move the project to a shorter folder such as C:\LCSJIT, or ask IT to enable Win32 long paths.")
        } elseif ($AppDir.Length + $script:DeepestProfilePath -gt $script:MaxPath) {
            $Warnings.Add("The folder path is long ($($AppDir.Length) characters); the saved browser profile may exceed the Windows path limit. A shorter folder such as C:\LCSJIT is safer.")
        }
    }
    foreach ($Root in $Facts.OneDriveRoots) {
        if ($AppDir.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) {
            $Warnings.Add('The project is inside OneDrive. Syncing can lock files during setup and runs; a local folder such as C:\LCSJIT is more reliable.')
            break
        }
    }
    if ($Facts.ControlledFolderAccess) {
        $Warnings.Add('Windows Controlled Folder Access is on. If setup or the browser cannot write files, allow automation\runtime\python\python.exe and automation\browsers, or move the project to C:\LCSJIT.')
    }
    return [pscustomobject]@{ Errors = @($Errors); Warnings = @($Warnings) }
}

function Assert-SetupReady {
    param([string]$AppDir)
    $Problems = Get-SetupProblems -AppDir $AppDir -Facts (Get-SetupPlatform -AppDir $AppDir)
    foreach ($Warning in $Problems.Warnings) { Write-Host "Warning: $Warning" -ForegroundColor Yellow }
    Write-SetupLog (@($Problems.Warnings | ForEach-Object { "warning: $_" }) + @($Problems.Errors | ForEach-Object { "error: $_" }))
    if ($Problems.Errors.Count -gt 0) {
        throw ("Setup cannot continue on this computer:`n  - " + ($Problems.Errors -join "`n  - "))
    }
}

function Export-WindowsCertificates {
    <# PEM bundle of the Windows root and intermediate stores for Playwright's Node downloader. #>
    param([string]$Path)
    $Seen = @{}
    $Builder = New-Object System.Text.StringBuilder
    foreach ($Store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\CA', 'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\CA')) {
        foreach ($Certificate in @(Get-ChildItem -Path $Store -ErrorAction SilentlyContinue)) {
            if (-not ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2])) { continue }
            if ($Seen.ContainsKey($Certificate.Thumbprint)) { continue }
            $Seen[$Certificate.Thumbprint] = $true
            $Base64 = [Convert]::ToBase64String($Certificate.RawData)
            [void]$Builder.Append("-----BEGIN CERTIFICATE-----`n")
            for ($Index = 0; $Index -lt $Base64.Length; $Index += 64) {
                [void]$Builder.Append($Base64.Substring($Index, [Math]::Min(64, $Base64.Length - $Index))).Append("`n")
            }
            [void]$Builder.Append("-----END CERTIFICATE-----`n")
        }
    }
    if ($Seen.Count -eq 0) { return $false }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    [IO.File]::WriteAllText($Path, $Builder.ToString(), (New-Object System.Text.ASCIIEncoding))
    return $true
}

function Set-ChildEnvironment {
    <#
        Process-scope environment for Python, pip and Playwright. Removes inherited
        settings that redirect or break them; keeps the user's index, certificate and
        proxy settings; adds the system proxy and Windows certificates when unset.
        Nothing is changed outside this PowerShell process.
    #>
    param([string]$AppDir)
    foreach ($Name in @('PYTHONHOME', 'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONSAFEPATH', 'PYTHONUSERBASE', 'PYTHONPYCACHEPREFIX',
                        'PIP_TARGET', 'PIP_PREFIX', 'PIP_ROOT', 'PIP_CONSTRAINT', 'PIP_NO_BINARY', 'PIP_ONLY_BINARY',
                        'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD', 'PLAYWRIGHT_NODEJS_PATH', 'PWDEBUG', 'DEBUG', 'NODE_OPTIONS')) {
        if (Test-Path -LiteralPath "Env:$Name") {
            Write-SetupLog @("removed inherited $Name for this run")
            Remove-Item -LiteralPath "Env:$Name"
        }
    }
    $env:PYTHONNOUSERSITE = '1'
    $env:PIP_USER = '0'
    $env:PIP_NO_INPUT = '1'
    $env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
    $env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $AppDir 'browsers'
    $env:PLAYWRIGHT_DOWNLOAD_NO_PROGRESS = '1'
    if (-not $env:PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT) { $env:PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT = '120000' }
    if (-not $env:HTTPS_PROXY) {
        try {
            $Target = New-Object Uri('https://pypi.org/')
            $Proxy = [Net.WebRequest]::GetSystemWebProxy().GetProxy($Target)
            if ($null -ne $Proxy -and $Proxy.Authority -ne $Target.Authority) {
                $Value = $Proxy.GetLeftPart([UriPartial]::Authority)
                $env:HTTPS_PROXY = $Value
                $env:HTTP_PROXY = $Value
                if (-not $env:NO_PROXY) { $env:NO_PROXY = 'localhost,127.0.0.1,::1' }
                Write-Host "Using the system proxy $Value for downloads."
                Write-SetupLog @("system proxy: $Value")
            }
        } catch { Write-SetupLog @('system proxy detection failed') }
    }
    if (-not $env:NODE_EXTRA_CA_CERTS) {
        $Bundle = Join-Path $AppDir 'runtime/certs/windows-ca.pem'
        try {
            if (Export-WindowsCertificates -Path $Bundle) { $env:NODE_EXTRA_CA_CERTS = $Bundle }
        } catch { Write-SetupLog @('Windows certificate export failed') }
    }
}

function Get-DownloadFailure {
    param([System.Management.Automation.ErrorRecord]$Record)
    $Exception = $Record.Exception
    while ($null -ne $Exception.InnerException -and -not $Exception.PSObject.Properties['Response']) { $Exception = $Exception.InnerException }
    $Status = $null
    if ($Exception.PSObject.Properties['Response'] -and $null -ne $Exception.Response) {
        try { $Status = [int]$Exception.Response.StatusCode } catch { $Status = $null }
    }
    if ($Status -eq 407) { return 'the proxy requires authentication (HTTP 407)' }
    if ($null -ne $Status) { return "HTTP $Status" }
    $Text = [string]$Record.Exception.Message
    if ($Text -match 'trust|certificate|SSL|TLS') { return 'the certificate was not trusted (TLS inspection?)' }
    if ($Text -match 'resolve|No such host|name') { return 'the host name could not be resolved (DNS or proxy)' }
    if ($Text -match 'timed out|timeout') { return 'the connection timed out' }
    return $Record.Exception.GetType().Name
}

function Get-Download {
    <# HTTPS download with retries, no progress bar (slow in PowerShell 5.1) and proxy credentials. #>
    param([string]$Url, [string]$Destination, [int]$TimeoutSec = 600)
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw 'Downloads must use HTTPS.' }
    $ProgressPreference = 'SilentlyContinue'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Destination)) | Out-Null
    $Partial = $Destination + '.partial'
    $Delay = 5
    for ($Attempt = 1; $true; $Attempt++) {
        try {
            $Options = @{ UseBasicParsing = $true; Uri = $Url; OutFile = $Partial; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
            if ($env:HTTPS_PROXY) { $Options.Proxy = $env:HTTPS_PROXY; $Options.ProxyUseDefaultCredentials = $true }
            Invoke-WebRequest @Options
            Move-Item -LiteralPath $Partial -Destination $Destination -Force
            return $Destination
        } catch {
            $Reason = Get-DownloadFailure $_
            Remove-Item -LiteralPath $Partial -Force -ErrorAction SilentlyContinue
            Write-SetupLog @("download attempt $Attempt failed: $Url ($Reason)")
            if ($Attempt -ge 3) { throw "Download failed after 3 attempts: $Url ($Reason). Check Internet and proxy access; see README.md#troubleshooting." }
            Start-Sleep -Seconds $Delay
            $Delay *= 2
        }
    }
}

# ---- Project Python: CPython from the official nuget.org package -------------
# The package is a plain ZIP: no installer, no Installed apps entry, no registry
# or PATH change. Size and SHA-512 come from the nuget.org catalog entry
# https://api.nuget.org/v3/catalog0/data/2026.09.30.20.50.40/python.3.13.16.json
$script:PythonVersion = '3.13.16'
$script:PythonPackageName = 'python.3.13.16.nupkg'
$script:PythonPackageUrl = 'https://api.nuget.org/v3-flatcontainer/python/3.13.16/python.3.13.16.nupkg'
$script:PythonPackageSize = 14817881
$script:PythonPackageSha512 = 'TGEhuRTpWtRifDR4r/GEhmg/cGMqtwB4kOCkt1QhXnCmdDE3Dict3iLJI1xrsNSRbXGyCwLEhe6qa5Rd2s376w=='

function New-ShortId { return [Guid]::NewGuid().ToString('N').Substring(0, 8) }

function Convert-Base64ToHex {
    param([string]$Base64)
    return ([BitConverter]::ToString([Convert]::FromBase64String($Base64))).Replace('-', '')
}

function Test-PythonPackageFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ((Get-Item -LiteralPath $Path).Length -ne $script:PythonPackageSize) { return $false }
    return ((Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash -eq (Convert-Base64ToHex $script:PythonPackageSha512))
}

function Get-PythonPackage {
    <# A pre-staged package in runtime\installers is used when its hash matches (offline/blocked networks). #>
    param([string]$AppDir)
    $Package = Join-Path $AppDir ('runtime/installers/' + $script:PythonPackageName)
    if (Test-PythonPackageFile $Package) { return $Package }
    if (Test-Path -LiteralPath $Package) {
        Write-Host "Ignoring automation\runtime\installers\$($script:PythonPackageName): it does not match the published SHA-512."
        Remove-Item -LiteralPath $Package -Force
    }
    Write-Host "Downloading Python $($script:PythonVersion) (14.8 MB) from nuget.org..."
    Get-Download -Url $script:PythonPackageUrl -Destination $Package | Out-Null
    if (-not (Test-PythonPackageFile $Package)) {
        Remove-Item -LiteralPath $Package -Force -ErrorAction SilentlyContinue
        throw ("The downloaded Python package does not match the published size and SHA-512; nothing was installed. Retry on a trusted network, " +
               "or download $($script:PythonPackageUrl) yourself and place it in automation\runtime\installers.")
    }
    return $Package
}

function Expand-PythonPackage {
    <# Extracts only tools\ from the package; refuses entries that would land outside the folder. #>
    param([string]$Package, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $Root = [IO.Path]::GetFullPath($Destination).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $Zip = [IO.Compression.ZipFile]::OpenRead($Package)
    try {
        foreach ($Entry in $Zip.Entries) {
            $Name = [Uri]::UnescapeDataString($Entry.FullName.Replace('\', '/'))
            if (-not $Name.StartsWith('tools/') -or $Name.EndsWith('/')) { continue }
            $Relative = $Name.Substring(6)
            $Target = [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $Relative))
            if (-not $Target.StartsWith($Root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw "The Python package contains an unsafe path ($Name); nothing was installed."
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Target)) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($Entry, $Target, $true)
        }
    } finally { $Zip.Dispose() }
}

function Test-RuntimePython {
    param([string]$Python)
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { return $false }
    $Probe = "import sys, struct, ssl, ctypes, venv, ensurepip, sqlite3; sys.exit(0 if sys.version.split()[0] == '$($script:PythonVersion)' and struct.calcsize('P') == 8 else 1)"
    return ((Invoke-Native -FilePath $Python -Arguments @('-I', '-c', $Probe) -Quiet).ExitCode -eq 0)
}

function Test-RuntimeMarker {
    param([string]$Runtime)
    $Marker = Join-Path $Runtime '.lcsjit-runtime.json'
    if (-not (Test-Path -LiteralPath $Marker -PathType Leaf)) { return $false }
    try { $Data = [IO.File]::ReadAllText($Marker) | ConvertFrom-Json } catch { return $false }
    return ($null -ne $Data.PSObject.Properties['version'] -and $Data.version -eq $script:PythonVersion -and
            $null -ne $Data.PSObject.Properties['sha512'] -and $Data.sha512 -eq $script:PythonPackageSha512)
}

function Initialize-RuntimePython {
    <# Marked, working runtime: reused without network access. Otherwise extracted, probed, then swapped in. #>
    param([string]$AppDir)
    $Runtime = Join-Path $AppDir 'runtime/python'
    $Python = Join-Path $Runtime 'python.exe'
    if ((Test-RuntimeMarker $Runtime) -and (Test-RuntimePython $Python)) { return $Python }
    $Package = Get-PythonPackage -AppDir $AppDir
    $Staging = Join-Path $AppDir ('runtime/python.new-' + (New-ShortId))
    try {
        Write-Host "Installing Python $($script:PythonVersion) into automation\runtime\python (no installer, registry or PATH changes)..."
        Expand-PythonPackage -Package $Package -Destination $Staging
        if (-not (Test-RuntimePython (Join-Path $Staging 'python.exe'))) {
            throw ("The extracted Python $($script:PythonVersion) does not start. Security software may block programs in automation\runtime; " +
                   'ask IT to allow it. Nothing was replaced.')
        }
        $Marker = @{ version = $script:PythonVersion; sha512 = $script:PythonPackageSha512; source = $script:PythonPackageUrl } | ConvertTo-Json
        [IO.File]::WriteAllText((Join-Path $Staging '.lcsjit-runtime.json'), $Marker)
        if (Test-Path -LiteralPath $Runtime) {
            $Old = Join-Path $AppDir ('runtime/python.old-' + (New-ShortId))
            Write-Host "Keeping the previous automation\runtime\python as $(Split-Path -Leaf $Old)."
            Move-Item -LiteralPath $Runtime -Destination $Old
        }
        Move-Item -LiteralPath $Staging -Destination $Runtime
    } finally {
        if (Test-Path -LiteralPath $Staging) { Remove-Item -LiteralPath $Staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
    return $Python
}

function Test-VenvMatches {
    <# The environment must belong to this runtime, in this folder, with this Python version. #>
    param([string]$Venv, [string]$RuntimeHome)
    $Config = Join-Path $Venv 'pyvenv.cfg'
    $Python = Join-Path $Venv 'Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf) -or -not (Test-Path -LiteralPath $Python -PathType Leaf)) { return $false }
    $Values = @{}
    foreach ($Line in [IO.File]::ReadAllLines($Config)) {
        $Index = $Line.IndexOf('=')
        if ($Index -gt 0) { $Values[$Line.Substring(0, $Index).Trim().ToLowerInvariant()] = $Line.Substring($Index + 1).Trim() }
    }
    if (-not $Values.ContainsKey('home') -or -not $Values.ContainsKey('version')) { return $false }
    try {
        $VenvHome = [IO.Path]::GetFullPath($Values['home']).TrimEnd('\', '/')
        $Expected = [IO.Path]::GetFullPath($RuntimeHome).TrimEnd('\', '/')
    } catch { return $false }
    if (-not $VenvHome.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    if ($Values['version'] -ne $script:PythonVersion) { return $false }
    $Probe = "import sys; sys.exit(0 if sys.version.split()[0] == '$($script:PythonVersion)' else 1)"
    return ((Invoke-Native -FilePath $Python -Arguments @('-I', '-c', $Probe) -Quiet).ExitCode -eq 0)
}

function Initialize-Venv {
    <# Rebuilt when the Python version or the project folder changed; the old one is kept as a backup. #>
    param([string]$AppDir, [string]$RuntimePython)
    $Venv = Join-Path $AppDir '.venv'
    $Python = Join-Path $Venv 'Scripts/python.exe'
    $RuntimeHome = Split-Path -Parent $RuntimePython
    if (Test-VenvMatches -Venv $Venv -RuntimeHome $RuntimeHome) { return $Python }
    if (Test-Path -LiteralPath $Venv) {
        $Backup = $Venv + '.backup-' + (New-ShortId)
        Write-Host "Rebuilding automation\.venv for Python $($script:PythonVersion) in this folder; the previous one is kept as $(Split-Path -Leaf $Backup)."
        Move-Item -LiteralPath $Venv -Destination $Backup
    }
    Write-Host 'Creating isolated Python environment...'
    Invoke-PythonStep $RuntimePython @('-I', '-m', 'venv', $Venv) 'Could not create the local Python environment (automation\.venv).'
    if (-not (Test-VenvMatches -Venv $Venv -RuntimeHome $RuntimeHome)) {
        throw 'The new Python environment (automation\.venv) does not start. Security software may block it; ask IT to allow automation\.venv.'
    }
    return $Python
}

function Get-VerifiedInstaller {
    param([string]$Url, [string]$Destination, [string]$Publisher, [string]$Sha256 = '')
    if (-not $Url.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw 'Installer URL must use HTTPS.' }
    # Re-download on each installation attempt; never trust a cached executable.
    Get-Download -Url $Url -Destination $Destination | Out-Null
    if ($Sha256 -and (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne $Sha256) {
        Remove-Item -LiteralPath $Destination -Force
        throw 'Installer checksum mismatch. Nothing was installed; retry on a trusted network.'
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Destination
    if ($Signature.Status -ne 'Valid' -or $null -eq $Signature.SignerCertificate -or
        $Signature.SignerCertificate.Subject -notmatch $Publisher) {
        $Status = [string]$Signature.Status
        $Detail = ''
        if ($Signature.PSObject.Properties['StatusMessage'] -and $Signature.StatusMessage) { $Detail = " ($($Signature.StatusMessage))" }
        Remove-Item -LiteralPath $Destination -Force
        throw "Installer signature/publisher verification failed: status $Status$Detail. Nothing was installed. If Windows cannot check certificates (offline or blocked revocation checks), ask IT to install the driver."
    }
    return $Destination
}

function Test-Administrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-Installer {
    <# Returns the installer's exit code; 1223 when the administrator prompt was declined. #>
    param([string]$FilePath, [string[]]$Arguments, [switch]$Elevate)
    $Options = @{ FilePath = $FilePath; ArgumentList = $Arguments; Wait = $true; PassThru = $true; ErrorAction = 'Stop' }
    if ($Elevate) { $Options.Verb = 'RunAs' }
    try { $Process = Start-Process @Options }
    catch {
        $Inner = $_.Exception
        while ($null -ne $Inner.InnerException) { $Inner = $Inner.InnerException }
        if ($Inner -is [ComponentModel.Win32Exception] -and $Inner.NativeErrorCode -eq 1223) { return 1223 }
        if ($Inner -is [ComponentModel.Win32Exception]) { throw "Could not start $([IO.Path]::GetFileName($FilePath)) (Windows error $($Inner.NativeErrorCode))." }
        throw "Could not start $([IO.Path]::GetFileName($FilePath)) ($($Inner.GetType().Name))."
    }
    return [int]$Process.ExitCode
}

function Test-SqlDriver {
    param([string]$Python)
    $Checks = $script:SetupChecks
    return ((Invoke-Native -FilePath $Python -Arguments @('-I', $Checks, 'odbc') -Quiet).ExitCode -eq 0)
}

function Install-SqlDriver {
    param([string]$AppDir)
    $Cache = Join-Path $AppDir 'runtime/installers'
    Write-Host 'Installing Microsoft ODBC Driver 18 for SQL Server (x64). Windows asks for administrator approval.'
    # 18.7 and later include the C++ runtime; no separate redistributable is required.
    $Installer = Get-VerifiedInstaller -Url $script:OdbcDriverUrl -Destination (Join-Path $Cache 'msodbcsql18.msi') -Publisher 'O=Microsoft Corporation(?:,|$)'
    # An elevated msiexec can run as another account (over-the-shoulder approval) that cannot
    # read this folder, OneDrive or a mapped drive: stage the package and log in the user's temp.
    $Stage = Join-Path ([IO.Path]::GetTempPath()) ('lcsjit-odbc-' + (New-ShortId))
    [IO.Directory]::CreateDirectory($Stage) | Out-Null
    $Msi = Join-Path $Stage 'msodbcsql18.msi'
    $StageLog = Join-Path $Stage 'odbc-install.log'
    $Log = Join-Path $Cache 'odbc-install.log'
    Copy-Item -LiteralPath $Installer -Destination $Msi
    $Elevate = -not (Test-Administrator)
    $MsiExec = Join-Path $env:SystemRoot 'System32/msiexec.exe'
    try {
        for ($Attempt = 1; $true; $Attempt++) {
            $Code = Start-Installer -FilePath $MsiExec -Elevate:$Elevate -Arguments @(
                '/i', ('"{0}"' -f $Msi), '/quiet', '/norestart', 'IACCEPTMSODBCSQLLICENSETERMS=YES', '/L*v', ('"{0}"' -f $StageLog))
            if (Test-Path -LiteralPath $StageLog) { Copy-Item -LiteralPath $StageLog -Destination $Log -Force -ErrorAction SilentlyContinue }
            Write-SetupLog @("ODBC installer attempt $Attempt exit $Code")
            if ($Code -eq 0) { return }
            if ($Code -eq 3010) { Write-Host 'ODBC Driver 18 is installed. Windows recommends a restart later; this run can continue.'; return }
            if ($Code -eq 1641) { throw 'The ODBC driver installer restarted Windows or requires a restart now. Restart, then rerun .\run.cmd.' }
            if ($Code -eq 1223) { throw 'Installing the ODBC driver needs administrator approval and the Windows prompt was declined. Ask IT to install Microsoft ODBC Driver 18 for SQL Server (x64), then rerun .\run.cmd.' }
            if ($Code -eq 1618) {
                if ($Attempt -le 4) { Write-Host 'Another installation is running (Windows Update, Intune or Software Center). Waiting 30 s...'; Start-Sleep -Seconds 30; continue }
                throw 'Another installation kept running for about 2 minutes, so the ODBC driver could not be installed. Let it finish, then rerun .\run.cmd.'
            }
            throw "The ODBC driver installer failed (exit $Code). Log: $Log"
        }
    } finally {
        Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PythonStep {
    param([string]$Python, [string[]]$Arguments, [string]$Failure, [string]$Hint = '')
    $Result = Invoke-Native -FilePath $Python -Arguments $Arguments
    if ($Result.ExitCode -ne 0) {
        $Last = @($Result.Tail | Select-Object -Last 8) -join "`n    "
        $Advice = ''
        if ($Hint) { $Advice = "`n  $Hint" }
        throw "$Failure$Advice`n  Last output:`n    $Last"
    }
    return $Result
}

function Get-InstallHint {
    <# A likely cause for a failed pip or Playwright download, from its output. #>
    param([string]$Output)
    if ($Output -match 'CERTIFICATE_VERIFY_FAILED|certificate verify failed|self[- ]signed certificate|unable to get local issuer|SSLError') {
        return 'The network replaces certificates (TLS inspection). Windows root certificates are used; ask IT to install the inspection root certificate, or set PIP_CERT / NODE_EXTRA_CA_CERTS to its PEM file.'
    }
    if ($Output -match '407|Proxy Authentication Required') {
        return 'The proxy requires authentication, which pip and Playwright cannot do. Ask IT for a proxy exception for the hosts listed in README.md#requirements.'
    }
    if ($Output -match 'No matching distribution|from versions: none') {
        return 'pip could not find the pinned packages. PIP_INDEX_URL or pip.ini may point to a mirror without them; see automation\runtime\logs for the pip configuration.'
    }
    if ($Output -match 'Long Path|long path|path too long|\[Errno 2\] No such file or directory') {
        return 'A path became too long. Move the project to a shorter folder such as C:\LCSJIT, or ask IT to enable Win32 long paths.'
    }
    if ($Output -match 'getaddrinfo|Name or service not known|ENOTFOUND|NewConnectionError|ECONNREFUSED|timed out') {
        return 'The download host could not be reached. Check Internet, VPN and proxy access (README.md#requirements).'
    }
    if ($Output -match 'EPERM|EBUSY|Access is denied|being used by another process') {
        return 'A file was locked, often by antivirus or OneDrive. Retry, or exclude the project folder from scanning and syncing.'
    }
    return ''
}

function Get-RequirementsStamp {
    <# Line endings never matter (CRLF checkouts); the Python version does. #>
    param([string]$Requirements)
    $Text = [IO.File]::ReadAllText($Requirements) -replace "`r`n", "`n"
    $Bytes = [Text.Encoding]::UTF8.GetBytes($Text + "`npython=" + $script:PythonVersion)
    $Sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($Sha.ComputeHash($Bytes))).Replace('-', '') } finally { $Sha.Dispose() }
}

function Test-PythonPackages {
    param([string]$Python, [string]$Requirements)
    $Checks = $script:SetupChecks
    $Result = Invoke-Native -FilePath $Python -Arguments @('-I', $Checks, 'packages', $Requirements) -Quiet
    if ($Result.ExitCode -ne 0) { Write-SetupLog @("package check: $($Result.Output)") }
    return ($Result.ExitCode -eq 0)
}

function Test-Chromium {
    param([string]$Python)
    $Checks = $script:SetupChecks
    return ((Invoke-Native -FilePath $Python -Arguments @('-I', $Checks, 'chromium') -Quiet).ExitCode -eq 0)
}

function Test-OdbcRegistered {
    try {
        $Drivers = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers' -ErrorAction Stop
        foreach ($Name in @('ODBC Driver 18 for SQL Server', 'ODBC Driver 17 for SQL Server')) {
            if ($Drivers.PSObject.Properties[$Name]) { return $true }
        }
    } catch { return $false }
    return $false
}

function Test-HostReachable {
    <# HTTPS reachability through the same proxy as the downloads; any HTTP answer except 407 counts. #>
    param([string]$Url)
    try {
        $Request = [Net.HttpWebRequest]::Create($Url)
        $Request.Method = 'HEAD'
        $Request.Timeout = 15000
        $Request.AllowAutoRedirect = $false
        if ($env:HTTPS_PROXY) {
            $Proxy = New-Object Net.WebProxy($env:HTTPS_PROXY)
            $Proxy.UseDefaultCredentials = $true
            $Request.Proxy = $Proxy
        }
        $Response = $Request.GetResponse()
        $Response.Close()
        return ''
    } catch {
        $Exception = $_.Exception
        while ($null -ne $Exception.InnerException -and -not ($Exception -is [Net.WebException])) { $Exception = $Exception.InnerException }
        if ($Exception -is [Net.WebException] -and $null -ne $Exception.Response) {
            $Status = [int]$Exception.Response.StatusCode
            $Exception.Response.Close()
            if ($Status -eq 407) { return 'proxy authentication required (407)' }
            return ''
        }
        if ($Exception -is [Net.WebException]) {
            switch ([string]$Exception.Status) {
                'NameResolutionFailure' { return 'name not resolved' }
                'ProxyNameResolutionFailure' { return 'proxy name not resolved' }
                'TrustFailure' { return 'certificate not trusted (TLS inspection?)' }
                'SecureChannelFailure' { return 'TLS connection failed' }
                'Timeout' { return 'timed out' }
                'ConnectFailure' { return 'connection refused or blocked' }
            }
            return [string]$Exception.Status
        }
        return $Exception.GetType().Name
    }
}

function Get-RequiredDownloads {
    <# Hosts this run will download from, decided cheaply before anything is installed. #>
    param([string]$AppDir)
    $Hosts = New-Object 'System.Collections.Generic.List[string]'
    $Runtime = Join-Path $AppDir 'runtime/python'
    if (-not (Test-RuntimeMarker $Runtime) -and -not (Test-PythonPackageFile (Join-Path $AppDir ('runtime/installers/' + $script:PythonPackageName)))) {
        $Hosts.Add('https://api.nuget.org/')
    }
    $Stamp = Join-Path $AppDir '.venv/requirements.sha256'
    $Recorded = ''
    if (Test-Path -LiteralPath $Stamp -PathType Leaf) { $Recorded = ([string](Get-Content -LiteralPath $Stamp -Raw)).Trim() }
    if ($Recorded -ne (Get-RequirementsStamp (Join-Path $AppDir 'requirements.txt'))) {
        if ($env:PIP_INDEX_URL) { $Hosts.Add(([Uri]$env:PIP_INDEX_URL).GetLeftPart([UriPartial]::Authority) + '/') }
        else { $Hosts.Add('https://pypi.org/'); $Hosts.Add('https://files.pythonhosted.org/') }
    }
    if (-not (Test-OdbcRegistered)) { $Hosts.Add('https://go.microsoft.com/'); $Hosts.Add('https://download.microsoft.com/') }
    $Chrome = @(Get-ChildItem -Path (Join-Path $AppDir 'browsers') -Filter 'chromium-*' -Directory -ErrorAction SilentlyContinue |
                Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'chrome-win64/chrome.exe') })
    if ($Chrome.Count -eq 0) {
        $Download = $env:PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST
        if (-not $Download) { $Download = $env:PLAYWRIGHT_DOWNLOAD_HOST }
        if ($Download) { $Hosts.Add(([Uri]$Download).GetLeftPart([UriPartial]::Authority) + '/') } else { $Hosts.Add('https://cdn.playwright.dev/') }
    }
    return @($Hosts | Select-Object -Unique)
}

function Test-DownloadAccess {
    <# Lists every unreachable download host in one message before any installation starts. #>
    param([string]$AppDir)
    $Needed = @(Get-RequiredDownloads -AppDir $AppDir)
    if ($Needed.Count -eq 0) { return }
    $Blocked = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Url in $Needed) {
        $Reason = Test-HostReachable -Url $Url
        if ($Reason) { $Blocked.Add("$(([Uri]$Url).Host): $Reason") }
    }
    Write-SetupLog (@('download hosts: ' + ($Needed -join ', ')) + @($Blocked | ForEach-Object { "blocked: $_" }))
    if ($Blocked.Count -gt 0) {
        $Via = 'directly'
        if ($env:HTTPS_PROXY) { $Via = "through the proxy $($env:HTTPS_PROXY)" }
        throw ("Setup needs to download from hosts that cannot be reached $Via; nothing was installed:`n  - " + ($Blocked -join "`n  - ") +
               "`nAsk IT to allow them (README.md#requirements). Offline: place $($script:PythonPackageName) in automation\runtime\installers.")
    }
}

function Initialize-Prerequisites {
    param([string]$AppDir)
    foreach ($Name in @('main.py', 'automation_support.py', 'lcs_jit_automation.py', 'sql_executor.py', 'setup_checks.py', 'requirements.txt', 'defaults.yaml')) {
        if (-not (Test-Path -LiteralPath (Join-Path $AppDir $Name) -PathType Leaf)) {
            throw "Incomplete download: automation/$Name is missing. Extract the whole repository before running."
        }
    }
    Assert-SetupReady -AppDir $AppDir
    Start-SetupLog -AppDir $AppDir
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Set-ChildEnvironment -AppDir $AppDir
    Test-DownloadAccess -AppDir $AppDir
    $RuntimePython = Initialize-RuntimePython -AppDir $AppDir
    $Py = Initialize-Venv -AppDir $AppDir -RuntimePython $RuntimePython
    $Requirements = Join-Path $AppDir 'requirements.txt'
    $Stamp = Join-Path $AppDir '.venv/requirements.sha256'
    $Expected = Get-RequirementsStamp $Requirements
    $Recorded = ''
    if (Test-Path -LiteralPath $Stamp -PathType Leaf) { $Recorded = ([string](Get-Content -LiteralPath $Stamp -Raw)).Trim() }
    if ($Recorded -ne $Expected -or -not (Test-PythonPackages $Py $Requirements)) {
        Write-Host 'Installing/verifying Python dependencies...'
        $Install = Invoke-Native -FilePath $Py -Arguments @('-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--only-binary=:all:', '--progress-bar', 'off', '-r', $Requirements)
        if ($Install.ExitCode -ne 0) {
            $Config = Invoke-Native -FilePath $Py -Arguments @('-I', '-m', 'pip', 'config', 'debug') -Quiet  # recorded in the setup log
            $Hint = Get-InstallHint $Install.Output
            $Last = @($Install.Tail | Select-Object -Last 8) -join "`n    "
            throw "Python dependencies failed to install.`n  $Hint`n  Last output:`n    $Last"
        }
        if (-not (Test-PythonPackages $Py $Requirements)) { throw 'Installed Python dependencies do not match automation\requirements.txt; see automation\runtime\logs for the first mismatch.' }
        Set-Content -LiteralPath $Stamp -Value $Expected -Encoding ASCII
    }
    # Check repeat runs too; imports alone do not establish compatibility.
    Invoke-PythonStep $Py @('-I', '-m', 'pip', 'check') 'Python dependency compatibility check failed. Repair the project-local environment before running.' | Out-Null
    if (-not (Test-SqlDriver $Py)) {
        Install-SqlDriver $AppDir
        if (-not (Test-SqlDriver $Py)) { throw 'ODBC driver still unavailable. Review automation\runtime\installers\odbc-install.log and rerun after any required restart.' }
    }
    if (-not (Test-Chromium $Py)) {
        Write-Host 'Installing project-local Playwright Chromium...'
        $Browser = Invoke-Native -FilePath $Py -Arguments @('-I', '-m', 'playwright', 'install', 'chromium', '--no-shell')
        if ($Browser.ExitCode -ne 0) {
            $Last = @($Browser.Tail | Select-Object -Last 8) -join "`n    "
            throw "Chromium installation failed.`n  $(Get-InstallHint $Browser.Output)`n  Last output:`n    $Last"
        }
        if (-not (Test-Chromium $Py)) { throw 'Chromium could not start after installation. Security software or application control may block automation\browsers; ask IT to allow it.' }
    }
    return $Py
}
