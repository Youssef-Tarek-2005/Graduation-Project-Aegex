# Start the whole AEGEX demo with one command (from the backend folder):
#
#     powershell -ExecutionPolicy Bypass -File .\start_demo.ps1
#
# 1. Docker Desktop and the database (aegex-db, port 5433)
# 2. the PoC database's tables and devices (python -m ingest.poc_db)
# 3. three windows: the API (port 8001, aegex_poc), the dashboard (port 8095), the live demo (demo.live_demo)
# 4. the dashboard in the browser
# Anything already running is left alone, so running it twice is safe. Close a window to stop that part.

$ErrorActionPreference = "Stop"
$backend = $PSScriptRoot
$py = Join-Path $backend ".venv\Scripts\python.exe"
$dbUrl = "postgresql://aegex:aegex@127.0.0.1:5433/aegex_poc"

function Test-Port([int]$port) {
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1", $port); $c.Close(); return $true } catch { return $false }
}

function Start-Window([string]$title, [string]$command) {
    $full = "`$host.UI.RawUI.WindowTitle = '$title'; Set-Location '$backend'; $command"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $full | Out-Null
}

Write-Host "1/4 Docker and the database" -ForegroundColor Cyan
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    Write-Host "    starting Docker Desktop ..."
    for ($i = 0; $i -lt 60; $i++) { Start-Sleep 3; docker info *> $null; if ($LASTEXITCODE -eq 0) { break } }
}
if (-not (Test-Port 5433)) {
    docker start aegex-db *> $null
    if ($LASTEXITCODE -ne 0) { docker compose -f (Join-Path $backend "docker-compose.yml") up -d | Out-Null }
    for ($i = 0; $i -lt 30; $i++) { Start-Sleep 2; if (Test-Port 5433) { break } }
}
if (-not (Test-Port 5433)) { Write-Host "The database did not start (port 5433). Is Docker Desktop running?" -ForegroundColor Red; exit 1 }
Start-Sleep 3

Write-Host "2/4 PoC database (tables + devices)" -ForegroundColor Cyan
& $py -m ingest.poc_db | Select-Object -First 1

Write-Host "3/4 API, dashboard, live demo" -ForegroundColor Cyan
if (-not (Test-Port 8001)) {
    Start-Window "AEGEX API 8001" "`$env:AEGEX_DB_URL = '$dbUrl'; .venv\Scripts\python -m api --host 0.0.0.0"
    for ($i = 0; $i -lt 30; $i++) { Start-Sleep 1; if (Test-Port 8001) { break } }
} else { Write-Host "    API already running on 8001" }
if (-not (Test-Port 8095)) {
    Start-Window "AEGEX dashboard 8095" ".venv\Scripts\python -m http.server 8095 --bind 127.0.0.1 --directory ..\frontend"
} else { Write-Host "    dashboard already running on 8095" }
$running = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Where-Object { $_.CommandLine -like "*demo.live_demo*" }
if (-not $running) {
    Start-Sleep 2
    Start-Window "AEGEX live demo" ".venv\Scripts\python -m demo.live_demo"
} else { Write-Host "    live demo already running" }

Write-Host "4/4 opening the dashboard" -ForegroundColor Cyan
Start-Sleep 3
Start-Process "http://localhost:8095/dashboard_new.html"
Write-Host "`nReady. 15 min / 1 h fill within a minute; 6 h / 24 h fill in the background (newest first)." -ForegroundColor Green
Write-Host "Stop: close the three windows. Remove all demo data: .venv\Scripts\python -m demo.live_demo --clean"
