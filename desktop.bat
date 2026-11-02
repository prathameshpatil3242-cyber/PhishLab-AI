@echo off
REM desktop.bat — launch PhishLab AI as a native Windows app
cd /d "%~dp0"

if exist "dist\PhishLabAI.exe" (
    start "" "dist\PhishLabAI.exe"
    exit /b 0
)

if not exist ".venv" (
    echo Virtual environment missing. Run deploy_windows.ps1 first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat
python desktop.py
