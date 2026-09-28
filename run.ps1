# Starts the ThreatLens API (port 8000) and web app (port 3000) for local use.
# First run installs dependencies. Usage:  powershell -ExecutionPolicy Bypass -File .\run.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# --- API ---
$api = Join-Path $root "api"
$py = Join-Path $api ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Creating Python environment..."
    python -m venv (Join-Path $api ".venv")
    & $py -m pip install -q --upgrade pip
    & $py -m pip install -q -r (Join-Path $api "requirements.txt")
    & $py -m playwright install chromium
}
if (-not (Test-Path (Join-Path $api ".env"))) { Copy-Item (Join-Path $api ".env.example") (Join-Path $api ".env") }

# --- Web ---
$web = Join-Path $root "web"
if (-not (Test-Path (Join-Path $web "node_modules"))) {
    Write-Host "Installing web dependencies..."
    Push-Location $web; npm.cmd install; Pop-Location
}

Write-Host "Starting API on http://localhost:8000 ..."
$apiProc = Start-Process -FilePath $py -ArgumentList "-m", "uvicorn", "app.main:app", "--port", "8000" -WorkingDirectory $api -PassThru -NoNewWindow
Write-Host "Starting web app on http://localhost:3000 ..."
$webProc = Start-Process -FilePath "npm.cmd" -ArgumentList "run", "dev" -WorkingDirectory $web -PassThru -NoNewWindow
Write-Host "ThreatLens is starting. Open http://localhost:3000  (Ctrl+C to stop)"
try { Wait-Process -Id $apiProc.Id, $webProc.Id }
finally {
    foreach ($p in @($apiProc, $webProc)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}
