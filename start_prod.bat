@echo off
REM start_prod.bat — launch PhishLab AI behind waitress (production WSGI)
cd /d "%~dp0"

if not exist ".venv" (
    echo Virtual environment missing. Run deploy_windows.ps1 first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
echo Starting PhishLab AI (waitress) on http://127.0.0.1:5000
waitress-serve --host=127.0.0.1 --port=5000 app:app
pause
