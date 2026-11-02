# deploy_windows.ps1
# One-shot setup for PhishLab AI on Windows 10/11.
# Run from the project root:  powershell -ExecutionPolicy Bypass -File deploy_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "=== PhishLab AI — Windows deploy ===" -ForegroundColor Cyan

# 1. Python check
try {
    $pyVer = python --version 2>&1
    Write-Host "Found $pyVer"
} catch {
    Write-Host "Python not found. Install Python 3.10+ from https://python.org and tick 'Add to PATH'." -ForegroundColor Red
    exit 1
}

# 2. Virtual environment
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
} else {
    Write-Host "Virtual environment already exists."
}

# 3. Activate + install dependencies
& .\.venv\Scripts\Activate.ps1
Write-Host "Installing dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
pip install waitress pyinstaller --quiet

# 4. Train ML model
if (-not (Test-Path "models\model.joblib")) {
    Write-Host "Training ML model..."
    python train_model.py
} else {
    Write-Host "Model already trained — skipping."
}

# 5. Initialise database
Write-Host "Initialising database..."
python database.py init

Write-Host ""
Write-Host "Deploy complete." -ForegroundColor Green
Write-Host "Start the app:  .\start.bat   (or:  python app.py)"
