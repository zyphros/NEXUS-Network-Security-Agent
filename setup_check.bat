@echo off
setlocal
cd /d "%~dp0"
set "AGENT_PYTHON=%USERPROFILE%\.network_security_agent\venv\Scripts\python.exe"
if not exist "%AGENT_PYTHON%" (
    echo Run setup_windows.bat first.
    pause
    exit /b 1
)
"%AGENT_PYTHON%" -B network_threat_detection.py --once --no-ai
if errorlevel 1 (
    echo The one-time connection check failed.
    pause
    exit /b 1
)
echo.
echo Checking whether the local Ollama service is reachable...
curl --silent --show-error --max-time 3 http://127.0.0.1:11434/api/tags
if errorlevel 1 (
    echo Ollama is not reachable. Monitoring works, but local AI analysis needs Ollama running.
)
echo.
pause
