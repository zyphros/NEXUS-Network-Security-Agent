@echo off
setlocal
cd /d "%~dp0"
set "AGENT_PYTHON=%USERPROFILE%\.network_security_agent\venv\Scripts\python.exe"
if not exist "%AGENT_PYTHON%" (
    echo Run setup_windows.bat first.
    pause
    exit /b 1
)
"%AGENT_PYTHON%" -B network_threat_detection.py %*
pause
