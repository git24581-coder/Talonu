param()

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "School Meal Vouchers System" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

try {
    $nodeVersion = & node --version 2>$null
    Write-Host "[OK] Node.js: $nodeVersion" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Node.js not found" -ForegroundColor Red
    exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "Checking dependencies..." -ForegroundColor Yellow

if (!(Test-Path "$scriptDir\backend\node_modules")) {
    Write-Host "[INSTALL] Backend dependencies..." -ForegroundColor Yellow
    Push-Location "$scriptDir\backend"
    & npm install 2>&1 | Out-Null
    Pop-Location
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] npm install failed" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[OK] Dependencies ready" -ForegroundColor Green

Write-Host ""
Write-Host "Stopping old processes..." -ForegroundColor Yellow
Get-Process node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host ""
Write-Host "Starting Backend Window 1..." -ForegroundColor Cyan
$backendPath = "$scriptDir\backend"
# Use a small helper script to avoid complex quoting issues when launching a new PowerShell process
$backendScript = Join-Path $backendPath 'run-server.ps1'
if (!(Test-Path $backendScript)) {
    Write-Host "[WARN] Backend runner script not found, falling back to inline command" -ForegroundColor Yellow
    $backendCmd = "Set-Location -LiteralPath '$backendPath'; `$env:PORT=3000; node server.js"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd -WindowStyle Normal
} else {
    Start-Process powershell -ArgumentList "-NoExit", "-File", $backendScript, "3000" -WindowStyle Normal
}

Write-Host "Starting Frontend Window 2..." -ForegroundColor Cyan
$frontendCmd = @'
Write-Host 'FRONTEND SERVER'
Write-Host ''
Write-Host 'Status: RUNNING'
Write-Host 'URL: http://localhost:3000'
Write-Host ''
Write-Host 'Demo credentials are disabled by default - no auto-created users/classes.' -ForegroundColor Yellow
Write-Host 'To enable demo seed set AUTO_SEED_DEMO_DATA=true before start.' -ForegroundColor Yellow
Write-Host ''
Write-Host 'Frontend served by Node.js backend on port 3000'
Write-Host 'Keep this window open'
Write-Host ''
Read-Host 'Press Enter to exit'
'@
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd -WindowStyle Normal

Write-Host ""
Write-Host "[WAIT] 3 seconds for startup..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "[SUCCESS] System started" -ForegroundColor Green
Write-Host ""
Write-Host "Windows opened:" -ForegroundColor Cyan
Write-Host "  1. Backend (PowerShell) - Live logs" -ForegroundColor Gray
Write-Host "  2. Frontend (PowerShell) - Status" -ForegroundColor Gray
Write-Host ""
Write-Host "Access:" -ForegroundColor Cyan
Write-Host "  http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan

Start-Sleep -Seconds 5


