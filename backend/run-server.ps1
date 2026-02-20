param(
    [string]$Port = '3000'
)

# Ensure working directory is the backend folder where this script lives
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

$env:PORT = $Port
Write-Host "Starting Node.js server (PORT=$env:PORT)..." -ForegroundColor Yellow
try {
    node server.js
} catch {
    Write-Host "Failed to start Node.js: $_" -ForegroundColor Red
}
