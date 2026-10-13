# Starts a synthetic-data demo of the Oracle Proxy dashboard.
# NO CHANGES to WireGuard, WireSock, the Oracle server, or Windows routes.
$ErrorActionPreference = 'Stop'
$backend = Join-Path (Split-Path -Parent $PSScriptRoot) 'backend'
Set-Location $backend
$venvPython = Join-Path $backend '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv .venv
    } else {
        & python -m venv .venv
    }
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create a Python virtual environment.' }
}
& $venvPython -m pip install -r requirements.txt -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw 'Failed to install Python dependencies.' }

[byte[]]$bytes = New-Object byte[] 48
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$token = [Convert]::ToBase64String($bytes)
$env:ORACLE_PROXY_API_TOKEN = $token
$env:ORACLE_PROXY_SNAPSHOT_PATH = Join-Path $backend 'tests\fixture_snapshot.json'

Write-Host ''
Write-Host 'Oracle Proxy DEMO (synthetic data only)' -ForegroundColor Green
Write-Host 'Open: http://127.0.0.1:8765/dashboard'
Write-Host 'User: admin'
Write-Host "Password: $token"
Write-Host 'Keep this password private. Press Ctrl+C to stop.'
Write-Host ''
& $venvPython -m uvicorn app.main:app --host 127.0.0.1 --port 8765
