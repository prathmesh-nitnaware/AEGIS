#!/usr/bin/env bash
# ==============================================================================
# scripts/deploy_stack.sh
# ==============================================================================
# AEGIS — Turnkey Production Stack Deployment Script (Linux / macOS)
#
# Automates:
# 1. Pre-flight checks: Docker daemon, Docker Compose plugin, port availability (8000, 5173, 5174, 5432).
# 2. Directory provisioning: quarantine/, logs/, db/.
# 3. Environment configuration validation (.env.docker).
# 4. Multi-container build and orchestration:
#      - aegis-db: PostgreSQL 15 / TimescaleDB with persistent storage.
#      - aegis-command-node: FastAPI backend + WebSocket event hub (:8000).
#      - aegis-dashboard: SOC Defender React/Vite UI (:5173).
#      - aegis-attacker-dashboard: Red Team Adversary Console (:5174).
#      - aegis-agent-vm1/2/3: Distributed EDR Agent Swarm with P2P mesh voting.
# 5. Active readiness probe polling with timeout and error diagnostics.
#
# Usage:
#   chmod +x scripts/deploy_stack.sh
#   ./scripts/deploy_stack.sh
#   ./scripts/deploy_stack.sh --down
# ==============================================================================

set -eo pipefail

# Formatting
BOLD="\033[1m"
GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
CYAN="\033[96m"
WHITE="\033[97m"
RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

print_banner() {
    echo -e "${CYAN}${BOLD}================================================================================"
    echo -e "         AEGIS — TURNKEY PRODUCTION STACK DEPLOYMENT & READINESS HARNESS"
    echo -e "================================================================================${RESET}"
    echo -e "  ${WHITE}Target Stack:${RESET} PostgreSQL + FastAPI Backend + Blue SOC + Red C2 + Swarm Agents"
    echo ""
}

# Handle --down flag
if [[ "$1" == "--down" || "$1" == "down" ]]; then
    echo -e "${YELLOW}[*] Tearing down AEGIS containerized stack...${RESET}"
    docker compose down -v
    echo -e "${GREEN}[OK] Stack stopped and volumes cleared.${RESET}"
    exit 0
fi

print_banner

# ------------------------------------------------------------------------------
# 1. Pre-flight Checks
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[1/5] Running pre-flight system diagnostics...${RESET}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERROR] 'docker' command not found. Please install Docker Engine.${RESET}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}[ERROR] Docker daemon is not running. Please start Docker.${RESET}"
    exit 1
fi
echo -e "  ${GREEN}[OK]${RESET} Docker daemon is active."

# Check ports
PORTS=(8000 5173 5174 5432)
for port in "${PORTS[@]}"; do
    if lsof -Pi :"$port" -sTCP:LISTEN -t >/dev/null 2>&1 || nc -z 127.0.0.1 "$port" 2>/dev/null; then
        echo -e "  ${YELLOW}[WARN]${RESET} Port $port appears to be in use. Existing process or container may conflict."
    else
        echo -e "  ${GREEN}[OK]${RESET} Port $port is available."
    fi
done

# ------------------------------------------------------------------------------
# 2. Directory Provisioning
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/5] Provisioning required persistent directories...${RESET}"
mkdir -p quarantine logs db
echo -e "  ${GREEN}[OK]${RESET} Created/verified ./quarantine, ./logs, ./db."

# ------------------------------------------------------------------------------
# 3. Environment Configuration
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/5] Validating environment templates...${RESET}"
if [ ! -f .env.docker ]; then
    echo -e "${RED}[ERROR] .env.docker not found in project root!${RESET}"
    exit 1
fi
echo -e "  ${GREEN}[OK]${RESET} .env.docker loaded successfully."

# ------------------------------------------------------------------------------
# 4. Container Build & Orchestration
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/5] Building and launching containerized cluster...${RESET}"
docker compose up -d --build

# ------------------------------------------------------------------------------
# 5. Readiness Probes & Health Polling
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/5] Polling readiness probes...${RESET}"

poll_endpoint() {
    local name="$1"
    local url="$2"
    local max_retries="${3:-30}"
    local count=0

    echo -n "  Waiting for $name ($url) "
    until curl -s -f -m 2 "$url" > /dev/null 2>&1; do
        count=$((count+1))
        if [ "$count" -ge "$max_retries" ]; then
            echo -e " ${RED}[FAILED]${RESET}"
            echo -e "${RED}[ERROR] Timeout waiting for $name to become healthy.${RESET}"
            docker compose logs --tail=20
            exit 1
        fi
        echo -n "."
        sleep 2
    done
    echo -e " ${GREEN}[READY]${RESET}"
}

poll_endpoint "aegis-command-node" "http://localhost:8000/api/health" 30
poll_endpoint "aegis-dashboard (SOC)" "http://localhost:5173" 20
poll_endpoint "aegis-attacker-dashboard (C2)" "http://localhost:5174" 20

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo -e "${CYAN}${BOLD}================================================================================${RESET}"
echo -e "${GREEN}${BOLD}             AEGIS PRODUCTION STACK DEPLOYED SUCCESSFULLY!                     ${RESET}"
echo -e "${CYAN}${BOLD}================================================================================${RESET}"
echo -e "  ${WHITE}FastAPI Backend / REST / WS:${RESET}  ${CYAN}http://localhost:8000${RESET} (API Docs: /docs)"
echo -e "  ${WHITE}SOC Defender Dashboard:${RESET}        ${CYAN}http://localhost:5173${RESET}"
echo -e "  ${WHITE}Red Team Adversary Console:${RESET}    ${CYAN}http://localhost:5174${RESET}"
echo -e "  ${WHITE}PostgreSQL / TimescaleDB:${RESET}      ${CYAN}localhost:5432${RESET} (User: aegis, DB: aegis)"
echo -e "  ${WHITE}EDR Agent Swarm Mesh:${RESET}          3 Containerized Agents (node-1, node-2, node-3)"
echo ""
echo -e "${BOLD}Management Commands:${RESET}"
echo -e "  View live logs:         ${YELLOW}docker compose logs -f${RESET}"
echo -e "  Run Red Team Simulation: ${YELLOW}docker compose exec agent-node-1 python -m experiments.simulations.run_multi_node_demo --all${RESET}"
echo -e "  Run Swarm Byzantine Sim: ${YELLOW}python scripts/simulate_swarm_cluster.py --scenario all${RESET}"
echo -e "  Stop stack:             ${YELLOW}./scripts/deploy_stack.sh --down${RESET}"
echo ""
