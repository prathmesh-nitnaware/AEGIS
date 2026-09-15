# ===========================================================================
# AEGIS EDR Agent - Windows PowerShell Installer & Service Setup Script
# Run with: powershell -ExecutionPolicy Bypass -File .\scripts\windows\install.ps1
# ===========================================================================

param (
    [string]$CommandNodeUrl = "http://127.0.0.1:8000",
    [string]$AgentId = $env:COMPUTERNAME,
    [string]$InstallDir = "C:\Program Files\AEGIS Agent",
    [string]$DataDir = "C:\ProgramData\AEGIS"
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "       AEGIS EDR AGENT - WINDOWS INSTALLER & SERVICE SETUP       " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This installer must be executed as Administrator." -ForegroundColor Red
    Write-Host "Please right-click PowerShell and choose 'Run as Administrator'." -ForegroundColor Yellow
    exit 1
}

# 2. Verify Python 3.10+
Write-Host ""
Write-Host "[1/6] Checking Python runtime..." -ForegroundColor Green
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[ERROR] Python 3.10+ was not found in PATH." -ForegroundColor Red
    Write-Host "Please install Python from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked." -ForegroundColor Yellow
    exit 1
}

$pyVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "  Found Python $pyVersion ($($pythonCmd.Source))"

# 3. Create Directory Structure
Write-Host "[2/6] Provisioning AEGIS system directories..." -ForegroundColor Green
$quarantineDir = Join-Path $DataDir "Quarantine"
$logDir = Join-Path $DataDir "Logs"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

# 4. Copy Agent Files & Models
Write-Host "[3/6] Deploying agent engine and trained ML models..." -ForegroundColor Green
$scriptRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")

Copy-Item -Path (Join-Path $scriptRoot "agent") -Destination $InstallDir -Recurse -Force
Copy-Item -Path (Join-Path $scriptRoot "trained_models") -Destination $InstallDir -Recurse -Force
Copy-Item -Path (Join-Path $scriptRoot "requirements.txt") -Destination $InstallDir -Force

# 5. Initialize Python Virtual Environment
Write-Host "[4/6] Setting up dedicated Python virtual environment..." -ForegroundColor Green
$venvDir = Join-Path $InstallDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$venvPip = Join-Path $venvDir "Scripts\pip.exe"

if (-not (Test-Path $venvPython)) {
    python -m venv $venvDir
}

& $venvPip install --upgrade pip --quiet
& $venvPip install -r (Join-Path $InstallDir "requirements.txt") --quiet

# 6. Generate Configuration File
Write-Host "[5/6] Writing configuration to $DataDir\agent.conf..." -ForegroundColor Green
$configFile = Join-Path $DataDir "agent.conf"
$configJson = @{
    agent_id = $AgentId
    command_node_url = $CommandNodeUrl
    heartbeat_interval = 5.0
    silence_threshold = 15.0
    p2p_enabled = $true
    p2p_bind_port = 9001
    p2p_peers = @()
    enable_active_response = $true
    quarantine_dir = $quarantineDir
    log_dir = $logDir
} | ConvertTo-Json -Depth 4

Set-Content -Path $configFile -Value $configJson -Encoding UTF8

# 7. Register Background Service / Scheduled Task
Write-Host "[6/6] Registering AEGIS Background Task / Windows Service..." -ForegroundColor Green
$taskName = "AEGIS-EDR-Agent"

# Remove existing task if present
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$taskArgs = "-m agent.daemon_service start --config `"$configFile`""
$action = New-ScheduledTaskAction -Execute $venvPython -Argument $taskArgs -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "AEGIS Autonomous EDR Agent Daemon" | Out-Null
Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  [OK] AEGIS EDR AGENT INSTALLED AND REGISTERED SUCCESSFULLY!    " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Service Task:     $taskName (SYSTEM level, Auto-Start)"
Write-Host "  Node Identifier:  $AgentId"
Write-Host "  Command Node:     $CommandNodeUrl"
Write-Host "  Config Path:      $configFile"
Write-Host "  Installation:     $InstallDir"
Write-Host ""

# Run doctor diagnostic
Write-Host "[*] Executing health verification probe..." -ForegroundColor Cyan
& $venvPython -m agent.daemon_service doctor --config $configFile
