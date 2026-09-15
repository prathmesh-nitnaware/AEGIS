<#
.SYNOPSIS
    AEGIS Turnkey Production Stack Deployment & Health Probing Harness (Windows PowerShell).

.DESCRIPTION
    Automates pre-flight diagnostics, directory provisioning, multi-container orchestration
    (PostgreSQL, FastAPI Backend, SOC Defender UI, Red Team Console, EDR Agent Swarm),
    and active readiness probe polling.

.PARAMETER Down
    Stops and removes all running AEGIS containers and volumes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/deploy_stack.ps1
    powershell -ExecutionPolicy Bypass -File scripts/deploy_stack.ps1 -Down
#>

[CmdletBinding()]
param (
    [switch]$Down
)

$ErrorActionPreference = "Stop"

function Write-Color([string]$text, [string]$color = "White") {
    Write-Host $text -ForegroundColor $color
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $ProjectRoot

# Handle -Down switch
if ($Down) {
    Write-Color "`n[*] Tearing down AEGIS containerized stack..." "Yellow"
    docker compose down -v
    Write-Color "[OK] Stack stopped and volumes cleared.`n" "Green"
    exit 0
}

Write-Color "================================================================================" "Cyan"
Write-Color "         AEGIS — TURNKEY PRODUCTION STACK DEPLOYMENT & READINESS HARNESS" "Cyan"
Write-Color "================================================================================" "Cyan"
Write-Color "  Target Stack: PostgreSQL + FastAPI Backend + Blue SOC + Red C2 + Swarm Agents`n" "White"

# ------------------------------------------------------------------------------
# 1. Pre-flight Checks
# ------------------------------------------------------------------------------
Write-Color "[1/5] Running pre-flight system diagnostics..." "Yellow"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Color "[ERROR] 'docker' command not found. Please install Docker Desktop for Windows." "Red"
    exit 1
}

try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Color "[ERROR] Docker daemon is not running. Please start Docker Desktop." "Red"
        exit 1
    }
    Write-Color "  [OK] Docker daemon is active." "Green"
} catch {
    Write-Color "[ERROR] Could not communicate with Docker daemon." "Red"
    exit 1
}

# Check port availability
$ports = @(8000, 5173, 5174, 5432)
foreach ($port in $ports) {
    $activeConn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($activeConn) {
        Write-Color "  [WARN] Port $port appears to be in use. Existing process or container may conflict." "Yellow"
    } else {
        Write-Color "  [OK] Port $port is available." "Green"
    }
}

# ------------------------------------------------------------------------------
# 2. Directory Provisioning
# ------------------------------------------------------------------------------
Write-Color "`n[2/5] Provisioning required persistent directories..." "Yellow"
@("quarantine", "logs", "db") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ | Out-Null
    }
}
Write-Color "  [OK] Created/verified ./quarantine, ./logs, ./db." "Green"

# ------------------------------------------------------------------------------
# 3. Environment Configuration
# ------------------------------------------------------------------------------
Write-Color "`n[3/5] Validating environment templates..." "Yellow"
if (-not (Test-Path ".env.docker")) {
    Write-Color "[ERROR] .env.docker not found in project root!" "Red"
    exit 1
}
Write-Color "  [OK] .env.docker loaded successfully." "Green"

# ------------------------------------------------------------------------------
# 4. Container Build & Orchestration
# ------------------------------------------------------------------------------
Write-Color "`n[4/5] Building and launching containerized cluster..." "Yellow"
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    Write-Color "[ERROR] Docker compose build or startup failed." "Red"
    exit 1
}

# ------------------------------------------------------------------------------
# 5. Readiness Probes & Health Polling
# ------------------------------------------------------------------------------
Write-Color "`n[5/5] Polling readiness probes..." "Yellow"

function Poll-Endpoint([string]$name, [string]$url, [int]$maxRetries = 30) {
    Write-Host -NoNewline "  Waiting for $name ($url) "
    $count = 0
    while ($count -lt $maxRetries) {
        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 400) {
                Write-Color " [READY]" "Green"
                return
            }
        } catch {}
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 2
        $count++
    }
    Write-Color " [FAILED]" "Red"
    Write-Color "[ERROR] Timeout waiting for $name to become healthy." "Red"
    docker compose logs --tail=20
    exit 1
}

Poll-Endpoint "aegis-command-node" "http://localhost:8000/api/health" 30
Poll-Endpoint "aegis-dashboard (SOC)" "http://localhost:5173" 20
Poll-Endpoint "aegis-attacker-dashboard (C2)" "http://localhost:5174" 20

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
Write-Color "`n================================================================================" "Cyan"
Write-Color "             AEGIS PRODUCTION STACK DEPLOYED SUCCESSFULLY!                     " "Green"
Write-Color "================================================================================" "Cyan"
Write-Color "  FastAPI Backend / REST / WS:  http://localhost:8000 (API Docs: /docs)" "White"
Write-Color "  SOC Defender Dashboard:        http://localhost:5173" "White"
Write-Color "  Red Team Adversary Console:    http://localhost:5174" "White"
Write-Color "  PostgreSQL / TimescaleDB:      localhost:5432 (User: aegis, DB: aegis)" "White"
Write-Color "  EDR Agent Swarm Mesh:          3 Containerized Agents (vm1, vm2, vm3)`n" "White"

Write-Color "Management Commands:" "Yellow"
Write-Color "  View live logs:          docker compose logs -f" "White"
Write-Color "  Run Red Team Simulation: docker compose exec agent-vm1 python -m experiments.simulations.run_multi_node_demo --all" "White"
Write-Color "  Run Swarm Byzantine Sim: python scripts/simulate_swarm_cluster.py --scenario all" "White"
Write-Color "  Stop stack:              powershell -ExecutionPolicy Bypass -File scripts/deploy_stack.ps1 -Down`n" "White"
