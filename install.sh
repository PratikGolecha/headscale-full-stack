#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Headscale + Headplane + Caddy Production Installer
# Version: 1.0.0
# =============================================================================

INSTALL_DIR="/opt/containers"
LOG_FILE="/var/log/headscale-install.log"

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m"

MIN_DISK_SPACE=1000

log() { echo -e "$1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}ERROR: $1${NC}" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}WARNING: $1${NC}" | tee -a "$LOG_FILE"; }

validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

validate_email() {
    [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

check_port_available() {
    ss -tlnp 2>/dev/null | grep -q ":$1 " && return 1
    netstat -tlnp 2>/dev/null | grep -q ":$1 " && return 1
    return 0
}

check_dns_resolution() {
    host "$1" >/dev/null 2>&1 || nslookup "$1" >/dev/null 2>&1
}

preflight_checks() {
    log "${YELLOW}Running pre-flight checks...${NC}"
    [[ $EUID -ne 0 ]] && { log_error "Must run as root"; exit 1; }
    
    local available_space
    available_space=$(df /opt --output=avail 2>/dev/null | tail -n1)
    [[ $available_space -lt $((MIN_DISK_SPACE * 1024)) ]] && {
        log_error "Need ${MIN_DISK_SPACE}MB free"
        exit 1
    }
    
    for port in 80 443; do
        check_port_available "$port" || { log_error "Port $port in use"; exit 1; }
    done
    
    log "${GREEN}Pre-flight checks passed${NC}"
}

INSTALL_STARTED=false

cleanup() {
    [[ "$INSTALL_STARTED" == false ]] && return
    log_error "Installation failed. Rolling back..."
    docker rm -f headscale headplane headplane-agent caddy 2>/dev/null || true
    docker network rm headscale_net 2>/dev/null || true
}

trap cleanup ERR

log "${GREEN}======================================================"
log "     Headscale + Headplane + Caddy Installer"
log "======================================================${NC}"

preflight_checks

# TODO: Add your full production installer here
# This is a minimal version for demonstration

echo "✅ Installation complete (demo mode)"
echo "Replace this with your full production script"
