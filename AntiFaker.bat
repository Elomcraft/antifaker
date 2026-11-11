@echo off
rem Runs AntiFaker.ps1 without changing the machine's script policy.
rem Usage: AntiFaker.bat                     (detects the server automatically)
rem        AntiFaker.bat play.example.com
cd /d "%~dp0"
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AntiFaker.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AntiFaker.ps1" -Server "%~1"
)
echo.
pause
