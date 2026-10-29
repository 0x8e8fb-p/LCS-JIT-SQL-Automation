@echo off
rem Starts run.ps1 with Windows PowerShell and -ExecutionPolicy Bypass for this
rem process only. The machine policy is not changed; Group Policy still applies.
rem Usage: run.cmd [-ValidateOnly or -Headless or -LaunchOnly or -ForceInteractive] [-Config path]
setlocal EnableExtensions DisableDelayedExpansion
set "LCSJIT_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "LCSJIT_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%LCSJIT_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
exit /b %ERRORLEVEL%
