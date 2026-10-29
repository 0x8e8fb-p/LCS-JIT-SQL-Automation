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

function Test-SupportedPython {
    param([string]$Executable, [string[]]$Prefix = @())
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { return $false }
    # PowerShell 5 turns redirected native stderr into ErrorRecords. An expected
    # failed probe must return false, not abort automatic installation.
    $Result = Invoke-Native -FilePath $Executable -Arguments (@($Prefix) + @('-c', 'import sys, struct; sys.exit(0 if (3,10) <= sys.version_info[:2] < (3,14) and struct.calcsize(''P'') == 8 else 1)')) -Quiet
    return ($Result.ExitCode -eq 0)
}

function Get-RegistryPythonCandidates {
    $Candidates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Root in @('HKCU:\Software\Python\PythonCore', 'HKLM:\Software\Python\PythonCore')) {
        foreach ($Version in @('3.13', '3.12', '3.11', '3.10')) {
            $Key = Join-Path $Root "$Version\InstallPath"
            if (-not (Test-Path -LiteralPath $Key)) { continue }
            $Props = Get-ItemProperty -LiteralPath $Key -ErrorAction SilentlyContinue
            if ($null -eq $Props) { continue }
            # A normal registration records the same interpreter twice (ExecutablePath
            # and the InstallPath default); probe each path only once.
            if ($Props.PSObject.Properties['ExecutablePath'] -and $Props.ExecutablePath) {
                $Executable = [string]$Props.ExecutablePath
                if (-not $Candidates.Contains($Executable)) { $Candidates.Add($Executable) }
            }
            if ($Props.PSObject.Properties['(default)'] -and $Props.'(default)') {
                $FromDefault = Join-Path ([string]$Props.'(default)') 'python.exe'
                if (-not $Candidates.Contains($FromDefault)) { $Candidates.Add($FromDefault) }
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
                $Result = Invoke-Native -FilePath $Launcher.Source -Arguments @($Version, '-c', 'import sys; print(sys.executable)') -Quiet
                if ($Result.ExitCode -eq 0) { return ($Result.Tail | Select-Object -Last 1) }
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
    # Re-download on each installation attempt; never trust a cached executable.
    Get-Download -Url $Url -Destination $Destination | Out-Null
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
        throw "Installation requires a restart. Restart Windows and rerun .\run.cmd. Log: $LogPath"
    }
    if ($Process.ExitCode -ne 0) { throw "Installer failed (exit $($Process.ExitCode)). Log: $LogPath" }
}

function Unpack-PythonInstaller {
    param([string]$Installer, [string]$Target, [string]$Cache)
    $Bytes = [IO.File]::ReadAllBytes($Installer)
    $CabOffset = -1
    $CabSize = 0
    $Pos = 0
    while ($Pos -le $Bytes.Length - 28) {
        $Idx = [Array]::IndexOf($Bytes, [byte]0x4D, $Pos)
        if ($Idx -lt 0 -or $Idx -gt $Bytes.Length - 28) { break }
        if ($Bytes[$Idx + 1] -eq 0x53 -and $Bytes[$Idx + 2] -eq 0x43 -and $Bytes[$Idx + 3] -eq 0x46 -and
            $Bytes[$Idx + 4] -eq 0x00 -and $Bytes[$Idx + 5] -eq 0x00 -and $Bytes[$Idx + 6] -eq 0x00 -and $Bytes[$Idx + 7] -eq 0x00 -and
            $Bytes[$Idx + 24] -eq 3 -and $Bytes[$Idx + 25] -eq 1) {
            $Size = [BitConverter]::ToInt32($Bytes, $Idx + 8)
            if ($Size -gt 10000000 -and ($Idx + $Size) -le $Bytes.Length) {
                $CabOffset = $Idx
                $CabSize = $Size
                break
            }
        }
        $Pos = $Idx + 1
    }
    if ($CabOffset -lt 0) { throw "Could not locate attached MSI container in $Installer" }
    $WorkDir = Join-Path $Cache 'python-unpack'
    if (Test-Path -LiteralPath $WorkDir) { Remove-Item -LiteralPath $WorkDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    try {
        $CabPath = Join-Path $WorkDir 'attached.cab'
        $Stream = [IO.File]::Open($CabPath, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $Stream.Write($Bytes, $CabOffset, $CabSize) } finally { $Stream.Dispose() }
        $Expand = Join-Path $env:SystemRoot 'System32/expand.exe'
        $MsiExec = Join-Path $env:SystemRoot 'System32/msiexec.exe'
        $Payloads = @(
            @{ Id = 'a0'; Name = 'core.msi' },
            @{ Id = 'a2'; Name = 'exe.msi' },
            @{ Id = 'a4'; Name = 'dev.msi' },
            @{ Id = 'a6'; Name = 'lib.msi' }
        )
        foreach ($Payload in $Payloads) {
            $Expanded = Invoke-Native -FilePath $Expand -Arguments @($CabPath, ("-F:{0}" -f $Payload.Id), $WorkDir) -Quiet
            if ($Expanded.ExitCode -ne 0) { throw "Failed to extract $($Payload.Name) from Python installer." }
            # Payload ids are taken from the verified 3.13.16 amd64 container layout.
            # Refuse anything that is not an installable MSI (OLE2/compound file) rather
            # than handing an unexpected file to msiexec after a layout change.
            $Extracted = Join-Path $WorkDir $Payload.Id
            $Header = New-Object byte[] 8
            $Stream = [IO.File]::OpenRead($Extracted)
            try { $Read = $Stream.Read($Header, 0, $Header.Length) } finally { $Stream.Dispose() }
            if ($Read -ne 8 -or [BitConverter]::ToString($Header) -ne 'D0-CF-11-E0-A1-B1-1A-E1') {
                throw "The Python installer's attached container no longer matches the verified payload layout: $($Payload.Id) is not the expected $($Payload.Name) package."
            }
            $MsiPath = Join-Path $WorkDir $Payload.Name
            Move-Item -LiteralPath $Extracted -Destination $MsiPath -Force
            $MsiLog = Join-Path $Cache ("python-admin-$($Payload.Name).log")
            Invoke-SetupProcess -Executable $MsiExec -LogPath $MsiLog -Arguments @(
                '/a', ('"{0}"' -f $MsiPath), '/qn', '/norestart',
                ('TARGETDIR="{0}"' -f $Target), '/L*v', ('"{0}"' -f $MsiLog)
            )
        }
    }
    finally {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-LocalPython {
    param([string]$AppDir)
    $Cache = Join-Path $AppDir 'runtime/installers'
    $Target = Join-Path $AppDir 'runtime/python'
    $Python = Join-Path $Target 'python.exe'
    Write-Host 'Installing Python 3.13.16 into automation/runtime/python (no PATH changes)...'
    $Installer = Get-VerifiedInstaller `
        -Url 'https://www.python.org/ftp/python/3.13.16/python-3.13.16-amd64.exe' `
        -Destination (Join-Path $Cache 'python-3.13.16-amd64.exe') `
        -Publisher 'O=Python Software Foundation(?:,|$)' `
        -Sha256 'fb4f9f5d438b2396da0086dc70b935c530cb578e37adc6d354f7ad2037fee83b'
    # Preferred path: extract the attached MSI container from the verified download.
    # An administrative install writes only files under TargetDir. It creates no
    # Windows Installer product, no ARP (Apps > Installed apps) entry and no PATH or
    # PEP 514 registry entry, so deleting or moving the project folder cannot leave a
    # stale Python 3.13 registration behind. Such a registration makes every later run
    # a no-op Modify whose /uninstall fails (for example 1603 from pip.msi) because
    # python.exe is missing at the recorded InstallDirectory.
    $ExtractError = $null
    try {
        Unpack-PythonInstaller -Installer $Installer -Target $Target -Cache $Cache
    }
    catch { $ExtractError = $_.Exception.Message }
    if (Test-SupportedPython $Python) { return $Python }
    # Fallback for hosts where MSI administrative installation is blocked: the official
    # per-user bundle installer. It registers a per-user 'Python 3.13.16 (64-bit)'
    # entry, so remove it through Settings > Installed apps (or its recorded uninstall
    # command) before deleting or moving the project folder.
    Write-Host 'Local extraction did not produce an interpreter; using the official installer (registers a per-user Python entry)...'
    if ($ExtractError) { Write-Host "Local extraction failed: $ExtractError" }
    $Log = Join-Path $Cache 'python-install.log'
    $InstallArgs = @(
        '/quiet', '/norestart', 'InstallAllUsers=0', 'PrependPath=0', 'Include_launcher=0',
        'Include_test=0', 'Include_doc=0', 'Include_tcltk=0', 'Include_pip=1', 'AssociateFiles=0', 'Shortcuts=0',
        ('TargetDir="{0}"' -f $Target), '/log', ('"{0}"' -f $Log)
    )
    $InstallError = $null
    try {
        Invoke-SetupProcess -Executable $Installer -LogPath $Log -Arguments $InstallArgs
    }
    catch {
        # A required restart still stops the run.
        if ($_.Exception.Message -match 'requires a restart') { throw }
        $InstallError = $_.Exception.Message
    }
    if (Test-SupportedPython $Python) { return $Python }
    $Found = Find-SupportedPython $AppDir
    if ($Found) { return $Found }
    $Details = @($ExtractError, $InstallError) | Where-Object { $_ }
    if ($Details) { throw "Python installation did not produce a usable x64 interpreter. $($Details -join ' ') Log: $Log" }
    throw "Python installation did not produce a usable x64 interpreter. Log: $Log"
}

function Test-SqlDriver {
    param([string]$Python)
    $Result = Invoke-Native -FilePath $Python -Arguments @('-I', '-c', 'import pyodbc, sys; sys.exit(0 if any(d in pyodbc.drivers() for d in (''ODBC Driver 18 for SQL Server'', ''ODBC Driver 17 for SQL Server'')) else 1)') -Quiet
    return ($Result.ExitCode -eq 0)
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
    $Result = Invoke-Native -FilePath $Python -Arguments $Arguments
    if ($Result.ExitCode -ne 0) {
        $Last = @($Result.Tail | Select-Object -Last 8) -join "`n    "
        throw "$Failure`n  Last output:`n    $Last"
    }
}

function Test-PythonPackages {
    param([string]$Python, [string]$Requirements)
    $Result = Invoke-Native -FilePath $Python -Arguments @('-c', 'import playwright.sync_api, pyodbc, yaml, cryptography.fernet; import sys; from importlib.metadata import version; from pathlib import Path; lines=Path(sys.argv[1]).read_text().splitlines(); pins=[line.strip().split(''=='') for line in lines if line.strip() and not line.lstrip().startswith(''#'')]; sys.exit(0 if all(len(p)==2 and version(p[0])==p[1] for p in pins) else 1)', $Requirements) -Quiet
    return ($Result.ExitCode -eq 0)
}

function Test-Chromium {
    param([string]$Python)
    $Result = Invoke-Native -FilePath $Python -Arguments @('-c', 'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(headless=True); b.close(); p.stop()') -Quiet
    return ($Result.ExitCode -eq 0)
}

function Initialize-Prerequisites {
    param([string]$AppDir)
    foreach ($Name in @('main.py', 'automation_support.py', 'lcs_jit_automation.py', 'sql_executor.py', 'requirements.txt', 'defaults.yaml')) {
        if (-not (Test-Path -LiteralPath (Join-Path $AppDir $Name) -PathType Leaf)) {
            throw "Incomplete download: automation/$Name is missing. Extract the whole repository before running."
        }
    }
    Assert-SetupReady -AppDir $AppDir
    Start-SetupLog -AppDir $AppDir
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Set-ChildEnvironment -AppDir $AppDir
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
    $Recorded = ''
    if (Test-Path -LiteralPath $Stamp -PathType Leaf) { $Recorded = [string](Get-Content -LiteralPath $Stamp -Raw) }
    if ($Recorded.Trim() -ne $Hash -or
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
