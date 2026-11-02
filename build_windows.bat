@echo off
REM build_windows.bat — build PhishLabAI.exe (single windowed binary)
cd /d "%~dp0"

if not exist ".venv" (
    echo Virtual environment missing. Run deploy_windows.ps1 first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat

echo Installing build dependencies...
pip install --quiet pyinstaller pywebview waitress

echo Building PhishLabAI.exe ...
pyinstaller --clean --noconfirm PhishLabAI.spec

if exist "dist\PhishLabAI.exe" (
    echo.
    echo Build successful: dist\PhishLabAI.exe
    echo Copy that single file to any Windows machine and double-click it.
) else (
    echo Build failed — check the output above.
)
pause
