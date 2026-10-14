@echo off
setlocal
set "PYTHONUTF8=1"
cd /d "%~dp0"
set "AGENT_ENV=%USERPROFILE%\.network_security_agent\venv"
if not exist "%USERPROFILE%\.network_security_agent" mkdir "%USERPROFILE%\.network_security_agent"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m venv "%AGENT_ENV%"
) else (
    python -m venv "%AGENT_ENV%"
)
if errorlevel 1 (
    echo Could not create the Python environment. Install Python 3.10 or newer.
    pause
    exit /b 1
)

"%AGENT_ENV%\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
    echo Could not upgrade pip.
    pause
    exit /b 1
)
"%AGENT_ENV%\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo Python setup completed.
echo Install Ollama separately, then run: ollama pull qwen2.5:3b
echo Run setup_check.bat to check monitoring permissions and Ollama.
echo Python runtime: %USERPROFILE%\.network_security_agent
echo Local logs and reports: %USERPROFILE%\.network_security_agent\data
pause
