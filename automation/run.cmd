@echo off
setlocal
rem Compatibility wrapper. All setup and workflow logic lives in run.ps1.
set "LAUNCHER=%~dp0..\run.ps1"
set "CONFIG=%~dp0..\config.yaml"
set "FLAGS="
:parse
if "%~1"=="" goto :run
if /i "%~1"=="--config" goto :config
if /i "%~1"=="--headless" (
    set "FLAGS=%FLAGS% -Headless"
    goto :next
)
if /i "%~1"=="--launch-only" (
    set "FLAGS=%FLAGS% -LaunchOnly"
    goto :next
)
if /i "%~1"=="--force-interactive" (
    set "FLAGS=%FLAGS% -ForceInteractive"
    goto :next
)
if /i "%~1"=="--validate-only" (
    set "FLAGS=%FLAGS% -ValidateOnly"
    goto :next
)
echo ERROR: Unknown argument: %~1
exit /b 1
:config
if "%~2"=="" (
    echo ERROR: --config requires a YAML path.
    exit /b 1
)
set "CONFIG=%~2"
shift
:next
shift
goto :parse
:run
powershell.exe -NoLogo -NoProfile -File "%LAUNCHER%" -Config "%CONFIG%" %FLAGS%
exit /b %ERRORLEVEL%
