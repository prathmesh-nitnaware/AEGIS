#!/usr/bin/env bash
# ===========================================================================
# AEGIS EDR Agent - Linux Uninstaller Script
# ===========================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/aegis-agent"
CONFIG_DIR="/etc/aegis"
LOG_DIR="/var/log/aegis"
SERVICE_FILE="/etc/systemd/system/aegis-agent.service"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This uninstaller must be run as root (use sudo).${NC}"
   exit 1
fi

echo -e "${CYAN}Stopping and disabling aegis-agent service...${NC}"
systemctl stop aegis-agent 2>/dev/null || true
systemctl disable aegis-agent 2>/dev/null || true

if [[ -f "$SERVICE_FILE" ]]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
fi

echo -e "${CYAN}Removing agent installation files...${NC}"
rm -rf "$INSTALL_DIR"
rm -rf "$CONFIG_DIR"

echo -e "${GREEN}✓ AEGIS EDR Agent has been completely uninstalled from this host.${NC}"
