$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (!(Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
}

Write-Host "Installing core requirements..."
.\.venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host "Installing optional requirements (best effort)..."
try {
    .\.venv\Scripts\python.exe -m pip install -r requirements-optional.txt
    Write-Host "Optional requirements installed."
} catch {
    Write-Warning "Optional requirements failed. Core server still works."
    Write-Warning "Details: $($_.Exception.Message)"
}

Write-Host "Running preflight check..."
.\.venv\Scripts\python.exe src\self_test.py

Write-Host "Setup complete."
Write-Host "Start server with: .\.venv\Scripts\python.exe src\osint_tools_mcp_server.py"
