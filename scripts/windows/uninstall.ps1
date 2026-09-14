# ===========================================================================
# AEGIS EDR Agent - Windows PowerShell Uninstaller Script
# Run with: powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
# ===========================================================================

param (
    [string]$InstallDir = "C:\Program Files\AEGIS Agent",
    [string]$DataDir = "C:\ProgramData\AEGIS"
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "             AEGIS EDR AGENT - WINDOWS UNINSTALLER               " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This uninstaller must be executed as Administrator." -ForegroundColor Red
    exit 1
}

$taskName = "AEGIS-EDR-Agent"

Write-Host "[*] Stopping and unregistering scheduled task '$taskName'..." -ForegroundColor Yellow
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[*] Removing installation files from $InstallDir..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[*] Removing configuration and cache files from $DataDir..." -ForegroundColor Yellow
if (Test-Path $DataDir) {
    Remove-Item -Path (Join-Path $DataDir "agent.conf") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $DataDir "agent.pid") -Force -ErrorAction SilentlyContinue
}

Write-Host "`n✓ AEGIS EDR Agent has been successfully uninstalled." -ForegroundColor Green
