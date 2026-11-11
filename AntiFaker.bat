@echo off
rem Lanza AntiFaker.ps1 sin cambiar la politica de scripts del equipo.
rem Uso: AntiFaker.bat            (detecta el server solo)
rem      AntiFaker.bat play.ejemplo.com
cd /d "%~dp0"
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AntiFaker.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AntiFaker.ps1" -Servidor "%~1"
)
echo.
pause
