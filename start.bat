@echo off
REM start.bat — launch PhishLab AI (dev server) on Windows
cd /d "%~dp0"

if not exist ".venv" (
    echo Virtual environment missing. Run deploy_windows.ps1 first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
echo Starting PhishLab AI on http://127.0.0.1:5000
python app.py
pause
