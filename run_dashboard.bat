@echo off
setlocal
cd /d "%~dp0"
set "AGENT_PYTHONW=%USERPROFILE%\.network_security_agent\venv\Scripts\pythonw.exe"
if not exist "%AGENT_PYTHONW%" (
    echo Run setup_windows.bat first.
    pause
    exit /b 1
)
start "" "%AGENT_PYTHONW%" -B network_agent_gui.py
