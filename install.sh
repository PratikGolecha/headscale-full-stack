#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Headscale + Headplane + Caddy Production Installer
# Version: 1.0.0
# Automated installer for self-hosted Tailscale control server
# =============================================================================

INSTALL_DIR="/opt/containers"
LOG_FILE="/var/log/headscale-install.log"

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
NC="\033[0m"

MIN_DISK_SPACE=1000  # MB

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

# =============================================================================
# VALIDATION HELPERS
# =============================================================================

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

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

preflight_checks() {
    log "${YELLOW}Running pre-flight checks...${NC}"

    [[ $EUID -ne 0 ]] && { log_error "Must run as root"; exit 1; }

    local available_space
    available_space=$(df /opt --output=avail 2>/dev/null | tail -n1)
    [[ $available_space -lt $((MIN_DISK_SPACE * 1024)) ]] &&
        { log_error "Need ${MIN_DISK_SPACE}MB free under /opt"; exit 1; }

    local existing_containers
    existing_containers=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^(headscale|headplane|headplane-agent|caddy)$' || true)
    if [[ -n "$existing_containers" ]]; then
        log_error "Existing conflicting containers found:"
        echo "$existing_containers"
        exit 1
    fi

    for port in 80 443; do
        check_port_available "$port" || { log_error "Port $port in use"; exit 1; }
    done

    if command -v timedatectl >/dev/null 2>&1; then
        ! timedatectl status | grep -q "synchronized: yes" &&
            log_warn "Time unsynchronized; TLS issues possible"
    fi

    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
        log_warn "SELinux enabled, applying contexts"
        if command -v semanage >/dev/null 2>&1; then
            semanage fcontext -a -t container_file_t "$INSTALL_DIR(/.*)?" 2>/dev/null || true
            restorecon -Rv "$INSTALL_DIR" 2>/dev/null || true
        else
            log_warn "Install semanage for SELinux fixes"
        fi
    fi

    log "${GREEN}Pre-flight checks passed${NC}"
}

# =============================================================================
# FAILURE CLEANUP
# =============================================================================

INSTALL_STARTED=false

cleanup() {
    [[ "$INSTALL_STARTED" == false ]] && return

    log_error "Installation failed. Rolling back..."

    [[ -f "$INSTALL_DIR/manage.sh" ]] &&
        (cd "$INSTALL_DIR" && ./manage.sh stop all 2>/dev/null || true)

    docker rm -f headscale headplane headplane-agent caddy >/dev/null 2>&1 || true

    local network_containers
    network_containers=$(docker network inspect headscale_net -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null || true)

    [[ -z "$network_containers" ]] &&
        docker network rm headscale_net >/dev/null 2>&1 || true

    log_error "Rollback complete. You may delete: rm -rf $INSTALL_DIR"
}

trap cleanup ERR

# =============================================================================
# START INSTALLER
# =============================================================================

log "${GREEN}======================================================"
log "     Headscale + Headplane + Caddy Installer"
log "======================================================${NC}"

preflight_checks

log "${YELLOW}Starting interactive setup...${NC}"

# ------------------------
# HEADSCALE DOMAIN
# ------------------------
while true; do
    read -r -p "Enter Headscale domain (e.g. headscale.example.com): " HEADSCALE_DOMAIN
    HEADSCALE_DOMAIN=$(echo "$HEADSCALE_DOMAIN" | tr '[:upper:]' '[:lower:]' | xargs)

    [[ -z "$HEADSCALE_DOMAIN" ]] && { log_error "Cannot be empty"; continue; }
    ! validate_domain "$HEADSCALE_DOMAIN" && { log_error "Invalid domain"; continue; }

    check_dns_resolution "$HEADSCALE_DOMAIN" || {
        log_warn "DNS not resolving for $HEADSCALE_DOMAIN"
        read -r -p "Continue? (yes/no): " c
        c=$(echo "$c" | tr '[:upper:]' '[:lower:]')
        [[ "$c" =~ ^y(es)?$ ]] || continue
    }
    break
done

# ------------------------
# HEADPLANE URL / PATH
# ------------------------
while true; do
    read -r -p "Enter Headplane domain or domain/path (e.g. ui.example.com OR headscale.example.com/admin): " HP_INPUT
    HP_INPUT=$(echo "$HP_INPUT" | tr '[:upper:]' '[:lower:]' | xargs)
    HP_INPUT=$(echo "$HP_INPUT" | sed 's:/*$::')

    [[ -z "$HP_INPUT" ]] && { log_error "Cannot be empty"; continue; }

    if [[ "$HP_INPUT" == */* ]]; then
        HEADPLANE_DOMAIN="${HP_INPUT%%/*}"
        HEADPLANE_PATH="/${HP_INPUT#*/}"
        HEADPLANE_PATH=$(echo "$HEADPLANE_PATH" | sed 's:/*$::')
        [[ "$HEADPLANE_PATH" != /* ]] && HEADPLANE_PATH="/$HEADPLANE_PATH"
    else
        HEADPLANE_DOMAIN="$HP_INPUT"
        HEADPLANE_PATH=""
    fi

    ! validate_domain "$HEADPLANE_DOMAIN" && { log_error "Invalid domain"; continue; }

    if [[ "$HEADPLANE_DOMAIN" != "$HEADSCALE_DOMAIN" ]]; then
        check_dns_resolution "$HEADPLANE_DOMAIN" || {
            log_warn "DNS does not resolve"
            read -r -p "Continue? (yes/no): " d
            d=$(echo "$d" | tr '[:upper:]' '[:lower:]')
            [[ "$d" =~ ^y(es)?$ ]] || continue
        }
    fi

    break
done

if [[ -n "$HEADPLANE_PATH" ]]; then
    HEADPLANE_FULL="$HEADPLANE_DOMAIN$HEADPLANE_PATH"
else
    HEADPLANE_FULL="$HEADPLANE_DOMAIN"
fi

# ------------------------
# MAGIC DNS
# ------------------------
while true; do
    read -r -p "Enter MagicDNS domain (e.g. tail.example.com): " MAGICDNS_DOMAIN
    MAGICDNS_DOMAIN=$(echo "$MAGICDNS_DOMAIN" | tr '[:upper:]' '[:lower:]' | xargs)
    validate_domain "$MAGICDNS_DOMAIN" && break
    log_error "Invalid domain"
done

log_warn "Configure wildcard DNS: *.${MAGICDNS_DOMAIN} → ${HEADSCALE_DOMAIN}"

# ------------------------
# EMAIL
# ------------------------
while true; do
    read -r -p "Enter Let's Encrypt email: " LE_EMAIL
    LE_EMAIL=$(echo "$LE_EMAIL" | xargs)
    validate_email "$LE_EMAIL" && break
    log_error "Invalid email"
done

# ------------------------
# ACME MODE
# ------------------------
read -r -p "Use Let's Encrypt staging? (yes/no): " USE_STAGING
USE_STAGING=$(echo "$USE_STAGING" | tr '[:upper:]' '[:lower:]')
if [[ "$USE_STAGING" =~ ^y(es)?$ ]]; then
    LE_CA="https://acme-staging-v02.api.letsencrypt.org/directory"
    log "${YELLOW}STAGING MODE: Certs will not be browser-trusted${NC}"
else
    LE_CA="https://acme-v02.api.letsencrypt.org/directory"
fi

# =============================================================================
# CONFIRMATION
# =============================================================================

log ""
log "${GREEN}----- Confirm Settings -----${NC}"
log "Headscale Domain:    $HEADSCALE_DOMAIN"
log "Headplane URL:       $HEADPLANE_FULL"
log "MagicDNS Domain:     $MAGICDNS_DOMAIN"
log "Let's Encrypt Email: $LE_EMAIL"
log "ACME Mode:           $([[ "$USE_STAGING" =~ ^y ]] && echo "Staging" || echo "Production")"
log ""

read -r -p "Proceed? (yes/no): " CONFIRM
CONFIRM=$(echo "$CONFIRM" | tr '[:upper:]' '[:lower:]')
[[ "$CONFIRM" =~ ^y(es)?$ ]] || { log "Installation cancelled"; exit 0; }

INSTALL_STARTED=true

# =============================================================================
# INSTALL PREREQUISITES
# =============================================================================

log "${GREEN}[1/10] Installing prerequisites...${NC}"

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq curl wget python3 bind9-host
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl wget python3 bind-utils policycoreutils-python-utils
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl wget python3 bind-utils policycoreutils-python-utils
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl wget python3 bind-tools
else
    log_error "Unsupported package manager"
    exit 1
fi

log "✓ Prerequisites installed"

# =============================================================================
# INSTALL DOCKER
# =============================================================================

log "${GREEN}[2/10] Installing Docker...${NC}"

if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com | bash
    systemctl enable --now docker
    sleep 3
    log "✓ Docker installed"
else
    log "✓ Docker already installed"
fi

docker ps >/dev/null || { log_error "Docker daemon not running"; exit 1; }

# =============================================================================
# DIRECTORIES
# =============================================================================

log "${GREEN}[3/10] Creating directories...${NC}"

mkdir -p "$INSTALL_DIR"/{headscale/{config,lib,run},headplane/{agent,data},caddy/{data,config}}

# =============================================================================
# NETWORK
# =============================================================================

log "${GREEN}[4/10] Creating network...${NC}"

docker network inspect headscale_net >/dev/null 2>&1 || {
    docker network create headscale_net
    log "✓ Network created"
}

# =============================================================================
# GENERATE CONFIG FILES
# =============================================================================

log "${GREEN}[5/10] Writing config files...${NC}"

COOKIE_SECRET=$(openssl rand -base64 32)

#
# HEADSCALE ENV
#
cat <<EOF > "$INSTALL_DIR/headscale/.env"
HEADSCALE_IMAGE=docker.io/headscale/headscale:v0.27.1
HEADSCALE_CONFIG_DIR=$INSTALL_DIR/headscale/config
HEADSCALE_DATA_DIR=$INSTALL_DIR/headscale/lib
HEADSCALE_RUN_DIR=$INSTALL_DIR/headscale/run
HEADSCALE_LOG_LEVEL=info
EOF

#
# HEADSCALE CONFIG
#
cat <<EOF > "$INSTALL_DIR/headscale/config/config.yaml"
server_url: https://$HEADSCALE_DOMAIN
listen_addr: :8080
metrics_listen_addr: :9090
grpc_listen_addr: :50443

log:
  level: info

database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite

ip_prefixes:
  - 100.64.0.0/10

dns:
  magic_dns: true
  base_domain: $MAGICDNS_DOMAIN

derp:
  urls: []
  auto_update_enabled: false

acme:
  enabled: false
EOF

#
# HEADSCALE DOCKER COMPOSE
#
cat <<EOF > "$INSTALL_DIR/headscale/compose.yaml"
services:
  headscale:
    image: \${HEADSCALE_IMAGE}
    container_name: headscale
    restart: unless-stopped
    env_file:
      - .env
    command: serve
    volumes:
      - \${HEADSCALE_CONFIG_DIR}:/etc/headscale
      - \${HEADSCALE_DATA_DIR}:/var/lib/headscale
      - \${HEADSCALE_RUN_DIR}:/var/run/headscale
    healthcheck:
      test: ["CMD", "curl", "-fs", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    networks:
      - headscale_net

networks:
  headscale_net:
    external: true
EOF

#
# HEADPLANE ENV
#
cat <<EOF > "$INSTALL_DIR/headplane/.env"
HEADPLANE_IMAGE=ghcr.io/tale/headplane:0.6.1
HEADPLANE_AGENT_IMAGE=ghcr.io/tale/headplane-agent:0.6.1

HEADPLANE_SERVER__PUBLIC_URL=https://$HEADPLANE_FULL
HEADPLANE_HEADSCALE__URL=https://$HEADSCALE_DOMAIN
HEADPLANE_SERVER__COOKIE_SECRET=$COOKIE_SECRET
HEADPLANE_LOAD_ENV_OVERRIDES=true
HEADPLANE_DEBUG_LOG=false
HEADPLANE_SERVER__PORT=3000
EOF

#
# HEADPLANE CONFIG
#
cat <<EOF > "$INSTALL_DIR/headplane/config.yaml"
server:
  port: 3000
  public_url: https://$HEADPLANE_FULL
  cookie_secret: "$COOKIE_SECRET"

headscale:
  url: https://$HEADSCALE_DOMAIN
  api_key: ""

storage:
  path: /var/lib/headplane/headplane.db

integration:
  mode: integration
  agent:
    enabled: true
    grpc_url: 0.0.0.0:5010

ssh:
  enabled: true
  session_log_dir: /var/lib/headplane/sessions

agent:
  config_path: /etc/headplane-agent/config.yaml
EOF

#
# HEADPLANE AGENT CONFIG
#
cat <<EOF > "$INSTALL_DIR/headplane/agent/config.yaml"
grpc:
  listen_addr: 0.0.0.0:5010

logs:
  enabled: true
  directory: /var/lib/headplane/agent-logs

docker:
  socket: /var/run/docker.sock
EOF

#
# HEADPLANE DOCKER COMPOSE
#
cat <<EOF > "$INSTALL_DIR/headplane/compose.yaml"
services:
  headplane:
    image: \${HEADPLANE_IMAGE}
    container_name: headplane
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - $INSTALL_DIR/headplane/config.yaml:/etc/headplane/config.yaml
      - $INSTALL_DIR/headplane/data:/var/lib/headplane
      - $INSTALL_DIR/headscale/config/config.yaml:/etc/headscale/config.yaml:ro
    networks:
      - headscale_net

  headplane-agent:
    image: \${HEADPLANE_AGENT_IMAGE}
    container_name: headplane-agent
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - $INSTALL_DIR/headplane/agent/config.yaml:/etc/headplane-agent/config.yaml
      - $INSTALL_DIR/headplane/data:/var/lib/headplane
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - headscale_net

networks:
  headscale_net:
    external: true
EOF

#
# CADDYFILE LOGIC (SAME-DOMAIN PATH OR SEPARATE DOMAIN)
#
if [[ -n "${HEADPLANE_PATH:-}" ]]; then
cat <<EOF > "$INSTALL_DIR/caddy/Caddyfile"
{
  email $LE_EMAIL
  acme_ca $LE_CA
}

http://$HEADSCALE_DOMAIN {
  redir https://{host}{uri} permanent
}

$HEADSCALE_DOMAIN {
  @headplane path $HEADPLANE_PATH $HEADPLANE_PATH/*
  handle @headplane {
    uri strip_prefix $HEADPLANE_PATH
    reverse_proxy headplane:3000
  }

  handle {
    reverse_proxy headscale:8080
  }
}
EOF
else
cat <<EOF > "$INSTALL_DIR/caddy/Caddyfile"
{
  email $LE_EMAIL
  acme_ca $LE_CA
}

http://$HEADSCALE_DOMAIN {
  redir https://{host}{uri} permanent
}

http://$HEADPLANE_DOMAIN {
  redir https://{host}{uri} permanent
}

$HEADSCALE_DOMAIN {
  reverse_proxy headscale:8080
}

$HEADPLANE_DOMAIN {
  reverse_proxy headplane:3000
}
EOF
fi

#
# CADDY DOCKER COMPOSE
#
cat <<EOF > "$INSTALL_DIR/caddy/compose.yaml"
services:
  caddy:
    image: caddy:2.8.4
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - $INSTALL_DIR/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - $INSTALL_DIR/caddy/data:/data
      - $INSTALL_DIR/caddy/config:/config
    networks:
      - headscale_net

networks:
  headscale_net:
    external: true
EOF

# =============================================================================
# MANAGEMENT SCRIPT
# =============================================================================

cat <<'EOF' > "$INSTALL_DIR/manage.sh"
#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
cmd="${1:-}"
service="${2:-}"

if [[ -z "$cmd" || -z "$service" ]]; then
  echo "Usage: ./manage.sh {start|stop|restart|logs|status} {headscale|headplane|caddy|all}"
  exit 1
fi

case "$cmd" in
  start)
    if [[ "$service" == "all" ]]; then
      (cd "$ROOT/headscale" && docker compose up -d)
      (cd "$ROOT/headplane" && docker compose up -d)
      (cd "$ROOT/caddy" && docker compose up -d)
    else
      (cd "$ROOT/$service" && docker compose up -d)
    fi
    ;;
  stop)
    if [[ "$service" == "all" ]]; then
      (cd "$ROOT/caddy" && docker compose stop)
      (cd "$ROOT/headplane" && docker compose stop)
      (cd "$ROOT/headscale" && docker compose stop)
    else
      (cd "$ROOT/$service" && docker compose stop)
    fi
    ;;
  restart)
    "$0" stop "$service"
    sleep 2
    "$0" start "$service"
    ;;
  logs)
    (cd "$ROOT/$service" && docker compose logs -f)
    ;;
  status)
    docker ps --filter "name=headscale|headplane|caddy" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|logs|status} {headscale|headplane|caddy|all}"
    exit 1
    ;;
esac
EOF

chmod +x "$INSTALL_DIR/manage.sh"

# =============================================================================
# PERMISSIONS
# =============================================================================

log "${GREEN}[6/10] Setting permissions...${NC}"

chmod 600 "$INSTALL_DIR/headplane/config.yaml"
chmod 600 "$INSTALL_DIR/headplane/.env"
chmod 600 "$INSTALL_DIR/headscale/.env"

chmod 755 "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR/headscale/config"
chmod -R 755 "$INSTALL_DIR/caddy"
chmod 755 "$INSTALL_DIR/manage.sh"

chown -R root:root "$INSTALL_DIR"

# =============================================================================
# START SERVICES
# =============================================================================

log "${GREEN}[7/10] Starting Headscale...${NC}"

(cd "$INSTALL_DIR/headscale" && docker compose up -d)
sleep 5

log "Waiting for Headscale to become healthy..."
MAX_WAIT=120
ELAPSED=0
while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' headscale 2>/dev/null || echo "unknown")
    [[ "$HEALTH" == "healthy" ]] && break
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo -n "."
done
echo ""

[[ "$HEALTH" != "healthy" ]] && { log_error "Headscale failed to start"; exit 1; }

log "${GREEN}✓ Headscale healthy!${NC}"

log "${GREEN}[8/10] Starting Headplane & Caddy...${NC}"

(cd "$INSTALL_DIR/headplane" && docker compose up -d)
(cd "$INSTALL_DIR/caddy" && docker compose up -d)

sleep 3

# =============================================================================
# API KEY GENERATION
# =============================================================================

log "${GREEN}[9/10] Generating API key...${NC}"

sleep 4

MAX_RETRIES=5
API_KEY=""

for attempt in $(seq 1 $MAX_RETRIES); do
    log "Attempt $attempt/$MAX_RETRIES..."
    output=$(docker exec headscale headscale apikeys create --expiration 90d 2>&1 || true)
    API_KEY=$(echo "$output" | grep -oE '[A-Za-z0-9+/=]{32,}' | head -n1 || true)

    if [[ -n "$API_KEY" && ${#API_KEY} -ge 32 ]]; then
        log "${GREEN}✓ API key generated${NC}"
        break
    fi

    [[ $attempt -eq $MAX_RETRIES ]] && {
        log_error "Failed to extract API key"
        log "Manual steps:"
        log "  1. docker exec headscale headscale apikeys create --expiration 90d"
        log "  2. Edit $INSTALL_DIR/headplane/config.yaml"
        log "  3. Replace api_key: \"\" with your key"
        log "  4. docker compose -f $INSTALL_DIR/headplane/compose.yaml restart"
        exit 1
    }

    sleep 2
done

#
# PYTHON API KEY INJECTION (SAFE ESCAPING)
#
if ! python3 <<PYEOF
import re

config_file = "$INSTALL_DIR/headplane/config.yaml"
api_key = r"""$API_KEY"""

with open(config_file, "r") as f:
    content = f.read()

content = re.sub(r'api_key:\s*".*?"', f'api_key: "{api_key}"', content)

with open(config_file, "w") as f:
    f.write(content)
PYEOF
then
    log_error "Python injection failed"
    exit 1
fi

# VERIFY
if [[ -f "$INSTALL_DIR/headplane/config.yaml" ]] &&
   grep -q "api_key: \"$API_KEY\"" "$INSTALL_DIR/headplane/config.yaml"; then
    log "${GREEN}✓ API key applied${NC}"
else
    log_error "API key verification failed"
    exit 1
fi

(cd "$INSTALL_DIR/headplane" && docker compose restart)
sleep 3

# =============================================================================
# SSL WAIT
# =============================================================================

log "${GREEN}[10/10] Waiting for SSL certificates...${NC}"

sleep 10

SSL_OK=false
for _ in {1..12}; do
    if docker logs caddy 2>&1 | grep -qi "certificate obtained successfully\|serving"; then
        SSL_OK=true
        log "${GREEN}✓ SSL certificates obtained${NC}"
        break
    fi
    sleep 5
done

[[ "$SSL_OK" == false ]] && log_warn "SSL cert not confirmed, may need more time"

# =============================================================================
# FINAL VERIFICATION
# =============================================================================

log "Verifying all containers..."
ALL_OK=true
for c in headscale headplane headplane-agent caddy; do
    if ! docker ps --format '{{.Names}}' | grep -q "^$c$"; then
        log_error "$c is not running"
        ALL_OK=false
    fi
done

[[ "$ALL_OK" == false ]] && { log_error "Some containers failed to start"; exit 1; }

# Disable error trap - we succeeded
trap - ERR

# =============================================================================
# SUCCESS
# =============================================================================

log ""
log "${GREEN}======================================================"
log " Installation Complete!"
log "======================================================${NC}"
log " Headscale URL:   https://$HEADSCALE_DOMAIN"
log " Headplane UI:    https://$HEADPLANE_FULL"
log " MagicDNS Domain: $MAGICDNS_DOMAIN"
log ""
log " Next Steps:"
log "   1. Wait 1-2 minutes for SSL to fully provision"
log "   2. Access Headplane: https://$HEADPLANE_FULL"
log "   3. Create your first user"
log "   4. Connect devices with Tailscale client"
log ""
log " Manage services:"
log "   cd $INSTALL_DIR"
log "   ./manage.sh status"
log "   ./manage.sh logs headscale"
log "   ./manage.sh restart all"
log ""
log " Installation log: $LOG_FILE"
log "${GREEN}======================================================${NC}"
