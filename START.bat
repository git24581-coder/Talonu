@echo off
setlocal enabledelayedexpansion

cls
echo.
echo ==================================
echo School Vouchers Management System
echo ==================================
echo.

REM Check if Node.js is installed
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js found
echo.
echo Checking dependencies...
cd /d c:\Mafis\backend
if not exist node_modules (
    echo [Installing] npm packages...
    call npm install
    if !ERRORLEVEL! NEQ 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)
echo [OK] Dependencies ready
echo.

echo Starting services...
echo.

REM Stop any existing Node processes
echo [Stopping] Existing services...
echo [Stopping] PM2 daemon if running...
call npx pm2 delete all >nul 2>&1
call npx pm2 kill >nul 2>&1
taskkill /F /IM node.exe /T >nul 2>&1
timeout /t 1 >nul

REM Open PowerShell window #1 - Backend Server with logs
echo [Opening] PowerShell window #1 - Backend Server (with logs)...
powershell -NoExit -Command "cd 'c:\Mafis\backend'; Write-Host '`n==== BACKEND SERVER - LOGS ====`n' -ForegroundColor Cyan; Write-Host 'Starting Node.js server...`n' -ForegroundColor Yellow; `$env:PORT='3000'; node server.js"

REM Wait for backend to start
timeout /t 3 >nul

REM Open PowerShell window #2 - Status Monitor and Info
echo [Opening] PowerShell window #2 - System Status Monitor...
powershell -Command "
`$host.UI.RawUI.WindowTitle = 'School Vouchers - Status Monitor'
Write-Host @'

╔════════════════════════════════════════════════════╗
║   School Vouchers Management System - READY       ║
║                                                    ║
║   BACKEND SERVER STARTED                          ║
║   • Port: 3000                                     ║
║   • Status: Running                                ║
║   • Database: SQLite                               ║
╚════════════════════════════════════════════════════╝

WEBSITE ACCESS:
  ► http://localhost:3000

DEMO CREDENTIALS:
  ► Disabled by default (no auto-created users/classes)
  ► To enable demo seed: set AUTO_SEED_DEMO_DATA=true before backend start

API ENDPOINTS:
  ► Health:  http://localhost:3000/api/health
  ► Users:   http://localhost:3000/api/users
  ► Classes: http://localhost:3000/api/classes

LOGS WINDOW:
  ► Check the other PowerShell window for detailed logs

TO STOP:
  ► Close the Backend Server window (PowerShell #1)

'@ -ForegroundColor Green

Write-Host 'System is running and ready to use!' -ForegroundColor Yellow
Write-Host "`nPress CTRL+C to close this window" -ForegroundColor Gray

Start-Sleep -Seconds 999999
"
