<#
.SYNOPSIS
    Configure config.yaml, then run .\run.cmd (or ./run.ps1).
.DESCRIPTION
    Prepares the local Python/browser dependencies and validates configuration,
    scripts, and ODBC. Reuses saved authentication when valid; otherwise opens
    a browser for sign-in/MFA. Then runs the complete workflow visibly.
    Installs Python locally and the Microsoft ODBC driver with Windows
    administrator approval when required. Never changes execution/network policy.
    run.cmd starts this script with -ExecutionPolicy Bypass for its own process,
    so it also works on machines whose policy blocks downloaded scripts.
.PARAMETER Config
    YAML path, relative to this script's directory unless absolute.
.PARAMETER Headless
    Use existing authentication without interactive login or visible automation.
.PARAMETER LaunchOnly
    Sign in and save authentication only; do not grant access or run SQL.
.PARAMETER ForceInteractive
    Refresh authentication even when a saved session is valid.
.PARAMETER ValidateOnly
    Check local prerequisites/configuration without accessing LCS or SQL.
#>
[CmdletBinding()]
param(
    [string]$Config = 'config.yaml',
    [switch]$Headless,
    [switch]$LaunchOnly,
    [switch]$ForceInteractive,
    [switch]$ValidateOnly
)

if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    # First statement: Constrained Language mode blocks the .NET calls used below.
    Write-Host "Launcher failed: PowerShell runs in $($ExecutionContext.SessionState.LanguageMode) mode (application control). Ask IT to allow this project's scripts (run.ps1 and automation\setup.ps1)." -ForegroundColor Red
    exit 1
}
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Native failures are checked explicitly, including on PowerShell 7.3+.
$PSNativeCommandUseErrorActionPreference = $false

function Remove-DownloadMark {
    # Files extracted from a downloaded ZIP carry the Internet zone mark, which a
    # RemoteSigned policy blocks. Only this project's own launcher scripts are unblocked.
    param([string]$Root)
    if (-not (Get-Command Unblock-File -ErrorAction SilentlyContinue)) { return }
    foreach ($Name in @('run.ps1', 'run.cmd', 'automation/setup.ps1', 'automation/run.cmd')) {
        $Path = Join-Path $Root $Name
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try { Unblock-File -LiteralPath $Path -ErrorAction Stop } catch { Write-Verbose "Could not unblock $Name" }
        }
    }
}

function Get-LockFailureReason {
    param([System.Exception]$Exception)
    $Inner = $Exception
    while ($null -ne $Inner.InnerException) { $Inner = $Inner.InnerException }
    $Name = $Inner.GetType().Name
    if ($Name -eq 'UnauthorizedAccessException') { return 'no permission to write in the automation folder' }
    if ($Name -eq 'PathTooLongException') { return 'the folder path is too long' }
    if ($Name -eq 'DirectoryNotFoundException') { return 'the automation folder is missing' }
    if (($Inner.HResult -band 0xFFFF) -eq 32 -or $Inner.Message -match 'being used by another process') {
        return 'another launcher is already running from this folder'
    }
    return ('{0} (0x{1:X8})' -f $Name, $Inner.HResult)
}

try {
    Remove-DownloadMark -Root $PSScriptRoot
    if (($Headless -and ($LaunchOnly -or $ForceInteractive)) -or
        ($ValidateOnly -and ($Headless -or $LaunchOnly -or $ForceInteractive))) {
        throw 'Conflicting modes: use -Headless, -LaunchOnly, -ForceInteractive, or -ValidateOnly separately.'
    }
    if ([string]::IsNullOrWhiteSpace($Config)) { throw 'Config path cannot be empty.' }
    if (-not [IO.Path]::IsPathRooted($Config)) { $Config = Join-Path $PSScriptRoot $Config }
    $Config = [IO.Path]::GetFullPath($Config)
    $AppDir = Join-Path $PSScriptRoot 'automation'
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
        $DefaultConfig = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'config.yaml'))
        $Template = Join-Path $AppDir 'config.template.yaml'
        if ($Config -eq $DefaultConfig -and -not (Test-Path -LiteralPath $Config)) {
            if (-not (Test-Path -LiteralPath $Template -PathType Leaf)) {
                throw 'Incomplete download: automation/config.template.yaml is missing. Extract the whole project before running.'
            }
            # Exclusive creation: never overwrite another user's configuration.
            $Content = [IO.File]::ReadAllBytes($Template)
            $NewConfig = [IO.File]::Open($Config, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $NewConfig.Write($Content, 0, $Content.Length) } finally { $NewConfig.Dispose() }
            throw "Created $Config from the safe template. Set ENVIRONMENT_URL and ACCESS_DETAILS, review the reason and rule name, then rerun .\run.cmd. No prerequisites or access changes were made. Instructions: README.md#quick-start"
        }
        throw "Config file not found: $Config"
    }
    $Main = Join-Path $AppDir 'main.py'
    $Setup = Join-Path $AppDir 'setup.ps1'
    if (-not (Test-Path -LiteralPath $Setup) -or -not (Test-Path -LiteralPath $Main)) {
        throw 'The automation folder is missing/incomplete. Extract the entire project before running.'
    }
    Write-Host "LCS JIT automation | config: $Config"
    . $Setup
    # OS lock serializes setup and the complete run, including auth refresh.
    $LockPath = Join-Path $AppDir '.launcher.lock'
    try {
        $LauncherLock = [IO.File]::Open($LockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        throw "Cannot take the launcher lock: $(Get-LockFailureReason $_.Exception). Close other runs of .\run.cmd, or check permissions and antivirus/OneDrive locks on the automation folder."
    }
    $Py = Initialize-Prerequisites -AppDir $AppDir

    Write-Host 'Validating configuration, SQL scripts, browser, and ODBC...'
    & $Py $Main validate --check-runtime --config $Config
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($ValidateOnly) { exit 0 }

    if (-not $Headless) {
        $NeedsLogin = $LaunchOnly -or $ForceInteractive
        if (-not $NeedsLogin) {
            Write-Host 'Checking saved authentication (no access changes)...'
            $AuthLines = @(& $Py $Main check-auth --config $Config)
            $AuthExit = $LASTEXITCODE
            $AuthText = ($AuthLines -join "`n").Trim()
            $AuthResult = $null
            if ($AuthText) {
                try { $AuthResult = $AuthText | ConvertFrom-Json } catch { $AuthResult = $null }
            }
            if ($null -eq $AuthResult) {
                if ($AuthText) { Write-Output $AuthText }
                throw "check-auth returned no result (exit $AuthExit). Rerun .\run.cmd; if it repeats, see automation/logs/diagnostics and README.md#troubleshooting."
            }
            if ($AuthExit -ne 0) {
                $Step = ''
                if ($AuthResult.PSObject.Properties['failed_at_step']) { $Step = [string]$AuthResult.failed_at_step }
                if ($Step -ne 'authentication') {
                    Write-Output $AuthText
                    exit $AuthExit
                }
                if ($AuthResult.PSObject.Properties['error_message']) { Write-Host "Sign-in needed: $($AuthResult.error_message)" }
                $NeedsLogin = $true
            }
        }
        if ($NeedsLogin) {
            Write-Host 'Complete sign-in/MFA in the browser, then press Enter in this terminal.'
            & $Py $Main bootstrap --config $Config
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        if ($LaunchOnly) { exit 0 }
    }

    Write-Host 'Running JIT access, SQL scripts, and configured cleanup...'
    if ($Headless) { & $Py $Main run --config $Config }
    else { & $Py $Main run --headed --config $Config }
    exit $LASTEXITCODE
}
catch {
    Write-Host "Launcher failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if (Get-Variable LauncherLock -ErrorAction SilentlyContinue) {
        if ($null -ne $LauncherLock) { $LauncherLock.Dispose() }
    }
}
