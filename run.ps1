<#
.SYNOPSIS
    Configure config.yaml, then run ./run.ps1.
.DESCRIPTION
    Prepares the local Python/browser dependencies and validates configuration,
    scripts, and ODBC. Reuses saved authentication when valid; otherwise opens
    a browser for sign-in/MFA. Then runs the complete workflow visibly.
    Installs missing Python locally and the Microsoft ODBC driver with Windows
    administrator approval when required. Never changes execution/network policy.
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

$ErrorActionPreference = 'Stop'
# Native failures are checked explicitly, including on PowerShell 7.3+.
$PSNativeCommandUseErrorActionPreference = $false

try {
    if (($Headless -and ($LaunchOnly -or $ForceInteractive)) -or
        ($ValidateOnly -and ($Headless -or $LaunchOnly -or $ForceInteractive))) {
        throw 'Conflicting modes: use -Headless, -LaunchOnly, -ForceInteractive, or -ValidateOnly separately.'
    }
    if ([string]::IsNullOrWhiteSpace($Config)) { throw 'Config path cannot be empty.' }
    if (-not [IO.Path]::IsPathRooted($Config)) { $Config = Join-Path $PSScriptRoot $Config }
    $Config = [IO.Path]::GetFullPath($Config)
    if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { throw "Config file not found: $Config" }

    $AppDir = Join-Path $PSScriptRoot 'automation'
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
    } catch { throw 'Another launcher is active, or the automation folder is not writable. Close the other run or check permissions.' }
    $Py = Initialize-Prerequisites -AppDir $AppDir

    Write-Host 'Validating configuration, SQL scripts, browser, and ODBC...'
    & $Py $Main validate --check-runtime --config $Config
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($ValidateOnly) { exit 0 }

    if (-not $Headless) {
        $NeedsLogin = $LaunchOnly -or $ForceInteractive
        if (-not $NeedsLogin) {
            Write-Host 'Checking saved authentication (no access changes)...'
            $AuthLines = & $Py $Main check-auth --config $Config
            $AuthExit = $LASTEXITCODE
            $AuthResult = ($AuthLines -join "`n") | ConvertFrom-Json
            if ($AuthExit -ne 0) {
                if ($AuthResult.failed_at_step -ne 'authentication') {
                    Write-Output ($AuthLines -join "`n")
                    exit $AuthExit
                }
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
