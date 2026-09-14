#!/usr/bin/env bash
# ===========================================================================
# AEGIS EDR Agent - Linux Installation & Service Setup Script
# Supported Distros: Ubuntu, Debian, RHEL, CentOS, Rocky Linux, Fedora, Arch
# ===========================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/aegis-agent"
CONFIG_DIR="/etc/aegis"
LOG_DIR="/var/log/aegis"
QUARANTINE_DIR="/var/lib/aegis/quarantine"
SERVICE_FILE="/etc/systemd/system/aegis-agent.service"

COMMAND_NODE_URL="http://127.0.0.1:8000"
AGENT_ID=$(hostname)
NON_INTERACTIVE=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --server) COMMAND_NODE_URL="$2"; shift ;;
        --agent-id) AGENT_ID="$2"; shift ;;
        --non-interactive|-y) NON_INTERACTIVE=true ;;
        --help|-h)
            echo "Usage: sudo ./install.sh [OPTIONS]"
            echo "Options:"
            echo "  --server URL       Command Node URL (default: http://127.0.0.1:8000)"
            echo "  --agent-id ID      Unique Node Identifier (default: hostname)"
            echo "  --non-interactive  Run without prompting"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

echo -e "${CYAN}"
echo "================================================================="
echo "        AEGIS EDR AGENT - LINUX INSTALLER & DAEMON SETUP         "
echo "================================================================="
echo -e "${NC}"

# 1. Verify Root Privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This installer must be run as root (use sudo).${NC}"
   exit 1
fi

echo -e "${GREEN}[1/6] Checking system prerequisites...${NC}"

# 2. Check Python 3.10+
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] python3 is not installed. Please install Python 3.10+.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 10 ]]; then
    echo -e "${RED}[ERROR] Python 3.10+ is required (detected Python $PYTHON_VERSION).${NC}"
    exit 1
fi
echo -e "  Found Python $PYTHON_VERSION ($(/usr/bin/which python3))"

# 3. Create Directories
echo -e "${GREEN}[2/6] Provisioning directory structure...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$QUARANTINE_DIR"

# 4. Copy Agent Files & Models
echo -e "${GREEN}[3/6] Deploying agent binary payload and ML models...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cp -r "$SCRIPT_DIR/agent" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/trained_models" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# 5. Setup Python Virtual Environment
echo -e "${GREEN}[4/6] Initializing isolated Python virtual environment...${NC}"
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet

# 6. Generate Configuration File
echo -e "${GREEN}[5/6] Generating configuration in $CONFIG_DIR/agent.env...${NC}"
cat <<EOF > "$CONFIG_DIR/agent.env"
# AEGIS EDR Agent Configuration
AGENT_ID=$AGENT_ID
COMMAND_NODE_URL=$COMMAND_NODE_URL
HEARTBEAT_INTERVAL=5.0
SILENCE_THRESHOLD=15.0
P2P_ENABLED=true
P2P_BIND_PORT=9001
ENABLE_ACTIVE_RESPONSE=true
QUARANTINE_DIR=$QUARANTINE_DIR
LOG_DIR=$LOG_DIR
EOF
chmod 600 "$CONFIG_DIR/agent.env"

# 7. Install and Start Systemd Service
echo -e "${GREEN}[6/6] Registering and starting systemd background daemon...${NC}"
cp "$SCRIPT_DIR/scripts/linux/aegis-agent.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable aegis-agent
systemctl restart aegis-agent

echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  ✓ AEGIS EDR AGENT INSTALLED AND RUNNING SUCCESSFULLY!          ${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo -e "  Service Name:     ${YELLOW}aegis-agent.service${NC}"
echo -e "  Agent ID:         ${YELLOW}$AGENT_ID${NC}"
echo -e "  Command Node:     ${YELLOW}$COMMAND_NODE_URL${NC}"
echo -e "  Config File:      ${YELLOW}$CONFIG_DIR/agent.env${NC}"
echo -e "  Status Command:   ${YELLOW}sudo systemctl status aegis-agent${NC}"
echo -e "  Log Stream:       ${YELLOW}sudo journalctl -u aegis-agent -f${NC}"
echo ""

# Run doctor diagnostic
echo -e "${CYAN}[*] Running post-install health verification probe...${NC}"
"$INSTALL_DIR/.venv/bin/python" -m agent.daemon_service doctor || true
