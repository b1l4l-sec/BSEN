# BSEN installer (Windows)
# Created by b1l4l-sec.
# Usage (from Windows Terminal / PowerShell):
#   .\scripts\install.ps1
#   .\scripts\install.ps1 -WithRemote      # also installs pywinrm/paramiko for `bsen remote`
#
# If script execution is blocked, run once as your user:
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

param(
    [switch]$WithRemote
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "==> BSEN installer (by b1l4l-sec)" -ForegroundColor Cyan

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "!! Python not found on PATH. Install Python 3.9+ from python.org and re-run." -ForegroundColor Red
    exit 1
}

$pyVersion = & python -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"
Write-Host "==> Using Python $pyVersion"

$venvDir = ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "==> Creating virtual environment at $venvDir"
    python -m venv $venvDir
}

& "$venvDir\Scripts\Activate.ps1"

Write-Host "==> Installing BSEN"
python -m pip install --upgrade pip -q
python -m pip install -e . -q

if ($WithRemote) {
    Write-Host "==> Installing remote-audit extras (paramiko, pywinrm)"
    python -m pip install -e ".[remote]" -q
}

Write-Host ""
Write-Host "==> Done. Activate with:  $venvDir\Scripts\Activate.ps1" -ForegroundColor Green
Write-Host "==> Then run:             bsen scan" -ForegroundColor Green
Write-Host ""
Write-Host "Verifying installation..."
bsen --version
