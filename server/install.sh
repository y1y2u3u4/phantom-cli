#!/usr/bin/env bash
# Phantom Server - One-click VPS installer
# Usage: curl -fsSL https://raw.githubusercontent.com/.../server/install.sh | bash
#
# Installs: Docker + SOCKS5 container + Phantom Server (proxy + API + UI) + Claude Code

set -euo pipefail

PHANTOM_DIR="/opt/phantom-cli"
REPO_RAW="https://raw.githubusercontent.com/nicegongqing/phantom-cli/main"
SERVER_PORT=8080

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${CYAN}[info]${NC} $*"; }
log_success() { echo -e "${GREEN}[ok]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
log_error()   { echo -e "${RED}[error]${NC} $*" >&2; }

# ── Pre-flight checks ──────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}Phantom Server Installer${NC}"
echo "════════════════════════════════════════════"
echo ""

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Try: sudo bash install.sh"
    exit 1
fi

# OS check (Ubuntu/Debian only)
if ! command -v apt-get &>/dev/null; then
    log_error "Only Ubuntu/Debian (apt-get) is supported."
    exit 1
fi

# Check if already installed
if [ -d "$PHANTOM_DIR" ]; then
    log_warn "Phantom Server already installed at $PHANTOM_DIR"
    log_info "Upgrading existing installation..."
    echo ""
fi

# ── Step 1: Install Docker ─────────────────────────────────────────

echo -e "${BOLD}Step 1: Docker${NC}"
echo "────────────────────────────────────────"

if command -v docker &>/dev/null; then
    log_success "Docker already installed: $(docker --version)"
else
    log_info "Installing Docker..."
    apt-get update -qq
    apt-get install -y -qq docker.io docker-compose >/dev/null 2>&1
    systemctl enable --now docker
    log_success "Docker installed"
fi

if command -v docker-compose &>/dev/null; then
    log_success "Docker Compose available"
else
    apt-get install -y -qq docker-compose >/dev/null 2>&1
    log_success "Docker Compose installed"
fi

echo ""

# ── Step 2: Download server files ──────────────────────────────────

echo -e "${BOLD}Step 2: Server files${NC}"
echo "────────────────────────────────────────"

mkdir -p "$PHANTOM_DIR/server"
mkdir -p "$PHANTOM_DIR/data"
chmod 700 "$PHANTOM_DIR/data"

# Docker / SOCKS5 files
DOCKER_FILES=(
    "Dockerfile"
    "docker-compose.yml"
    "danted.conf"
    "entrypoint.sh"
    "manage-users.sh"
    ".env.example"
)

for f in "${DOCKER_FILES[@]}"; do
    if curl -fsSL "$REPO_RAW/server/$f" -o "$PHANTOM_DIR/server/$f" 2>/dev/null; then
        log_success "Downloaded $f"
    else
        log_warn "Failed to download $f from repo, checking local..."
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
        if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$f" ]; then
            cp "$SCRIPT_DIR/$f" "$PHANTOM_DIR/server/$f"
            log_success "Copied $f from local"
        else
            log_error "Cannot find $f. Please run from the repo directory or check network."
            exit 1
        fi
    fi
done

# Phantom Server files (proxy + API + UI)
PHANTOM_FILES=(
    "phantom_server.py"
    "ui.html"
)

for f in "${PHANTOM_FILES[@]}"; do
    if curl -fsSL "$REPO_RAW/server/$f" -o "$PHANTOM_DIR/$f" 2>/dev/null; then
        log_success "Downloaded $f"
    else
        log_warn "Failed to download $f from repo, checking local..."
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
        if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$f" ]; then
            cp "$SCRIPT_DIR/$f" "$PHANTOM_DIR/$f"
            log_success "Copied $f from local"
        else
            log_error "Cannot find $f. Please run from the repo directory or check network."
            exit 1
        fi
    fi
done

# Ensure .env exists
if [ ! -f "$PHANTOM_DIR/server/.env" ]; then
    cp "$PHANTOM_DIR/server/.env.example" "$PHANTOM_DIR/server/.env"
fi

chmod +x "$PHANTOM_DIR/server/entrypoint.sh" "$PHANTOM_DIR/server/manage-users.sh"
chmod +x "$PHANTOM_DIR/phantom_server.py"

echo ""

# ── Step 3: Build & start Docker container ─────────────────────────

echo -e "${BOLD}Step 3: Docker container${NC}"
echo "────────────────────────────────────────"

cd "$PHANTOM_DIR/server"

log_info "Building and starting SOCKS5 container..."
docker-compose up -d --build 2>&1 | tail -3

# Verify container is running
sleep 2
if docker ps --format '{{.Names}}' | grep -q phantom-server; then
    log_success "Container 'phantom-server' is running"
else
    log_error "Container failed to start. Check: docker logs phantom-server"
    exit 1
fi

echo ""

# ── Step 4: Deploy Phantom Server ─────────────────────────────────

echo -e "${BOLD}Step 4: Phantom Server (proxy + API + management UI)${NC}"
echo "────────────────────────────────────────"

# Check Python3
if ! command -v python3 &>/dev/null; then
    log_info "Installing Python3..."
    apt-get install -y -qq python3 >/dev/null 2>&1
fi
log_success "Python3 available: $(python3 --version)"

# Set up master password (interactive)
if [ -f "$PHANTOM_DIR/data/server_config.json" ]; then
    log_info "Master password already configured (skipping)"
else
    echo ""
    echo -e "${BOLD}Set Master Password${NC}"
    echo -e "This password protects the management UI where you create API keys."
    echo ""

    while true; do
        read -rsp "  Enter master password (min 8 chars): " master_pw
        echo ""

        if [ ${#master_pw} -lt 8 ]; then
            log_error "Password must be at least 8 characters."
            continue
        fi

        read -rsp "  Confirm master password: " master_pw_confirm
        echo ""

        if [ "$master_pw" != "$master_pw_confirm" ]; then
            log_error "Passwords do not match. Try again."
            continue
        fi

        break
    done

    # Hash password with scrypt via Python and write config
    python3 -c "
import hashlib, os, json

password = '''$master_pw'''
salt = os.urandom(16)
key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
password_hash = salt.hex() + ':' + key.hex()

config = {'master_password_hash': password_hash}
config_path = '$PHANTOM_DIR/data/server_config.json'
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
os.chmod(config_path, 0o600)
print('  Master password configured')
"
    log_success "Master password set"
fi

# Create/update systemd service
cat > /etc/systemd/system/phantom-http-proxy.service <<SVCEOF
[Unit]
Description=Phantom Server (HTTP proxy + API + Management UI)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $PHANTOM_DIR/phantom_server.py $SERVER_PORT $PHANTOM_DIR/data
Restart=always
RestartSec=3
WorkingDirectory=$PHANTOM_DIR

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now phantom-http-proxy
sleep 1

if systemctl is-active --quiet phantom-http-proxy; then
    log_success "Phantom Server running on port $SERVER_PORT"
else
    log_error "Phantom Server failed to start. Check: journalctl -u phantom-http-proxy"
    exit 1
fi

echo ""

# ── Step 5: Firewall ───────────────────────────────────────────────

echo -e "${BOLD}Step 5: Firewall${NC}"
echo "────────────────────────────────────────"

if command -v ufw &>/dev/null; then
    ufw allow "$SERVER_PORT"/tcp 2>/dev/null && log_success "UFW: port $SERVER_PORT opened" || log_warn "UFW: could not open port $SERVER_PORT"
    ufw allow 1080/tcp 2>/dev/null && log_success "UFW: port 1080 opened" || log_warn "UFW: could not open port 1080"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="$SERVER_PORT"/tcp 2>/dev/null && log_success "firewalld: port $SERVER_PORT opened" || true
    firewall-cmd --permanent --add-port=1080/tcp 2>/dev/null && log_success "firewalld: port 1080 opened" || true
    firewall-cmd --reload 2>/dev/null || true
else
    log_info "No firewall detected (ufw/firewalld). Ensure ports $SERVER_PORT and 1080 are open."
fi

echo ""

# ── Step 6: Install Claude Code ────────────────────────────────────

echo -e "${BOLD}Step 6: Claude Code${NC}"
echo "────────────────────────────────────────"

# Install Node.js if needed
if ! command -v node &>/dev/null; then
    log_info "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
    apt-get install -y -qq nodejs >/dev/null 2>&1
    log_success "Node.js installed: $(node --version)"
else
    log_success "Node.js available: $(node --version)"
fi

# Install Claude Code
if command -v claude &>/dev/null; then
    log_success "Claude Code already installed"
else
    log_info "Installing Claude Code..."
    npm install -g @anthropic-ai/claude-code 2>/dev/null
    if command -v claude &>/dev/null; then
        log_success "Claude Code installed"
    else
        log_warn "Could not install Claude Code. Install manually: npm install -g @anthropic-ai/claude-code"
    fi
fi

echo ""

# ── Verify & Summary ──────────────────────────────────────────────

echo -e "${BOLD}${CYAN}════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}Phantom Server deployed!${NC}"
echo -e "${BOLD}${CYAN}════════════════════════════════════════════${NC}"
echo ""

# Check services
VPS_IP=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "  ${BOLD}Service Status:${NC}"

if docker ps --format '{{.Names}}' | grep -q phantom-server; then
    echo -e "    SOCKS5 proxy:      ${GREEN}:1080 running${NC}"
else
    echo -e "    SOCKS5 proxy:      ${RED}not running${NC}"
fi

if systemctl is-active --quiet phantom-http-proxy; then
    echo -e "    Phantom Server:    ${GREEN}:${SERVER_PORT} running${NC}"
else
    echo -e "    Phantom Server:    ${RED}not running${NC}"
fi

if command -v claude &>/dev/null; then
    echo -e "    Claude Code:       ${GREEN}installed${NC}"
else
    echo -e "    Claude Code:       ${YELLOW}not installed${NC}"
fi

echo ""
echo -e "  ${BOLD}VPS IP:${NC} ${CYAN}${VPS_IP}${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    ${YELLOW}1.${NC} Log in to Claude Code on this VPS:"
echo -e "       ${GREEN}claude${NC}"
echo -e "       Complete the OAuth authentication in your browser."
echo ""
echo -e "    ${YELLOW}2.${NC} Open the management UI to create an API key:"
echo -e "       ${GREEN}http://${VPS_IP}:${SERVER_PORT}/${NC}"
echo -e "       Log in with your master password, then create an API key."
echo ""
echo -e "    ${YELLOW}3.${NC} On your ${BOLD}local Mac${NC}, install the client and connect:"
echo -e "       ${GREEN}curl -fsSL $REPO_RAW/client/install.sh | bash${NC}"
echo -e "       ${GREEN}phantom setup ${VPS_IP} --key sk-phantom-xxxx${NC}"
echo ""
echo -e "  ${YELLOW}Tip:${NC} For secure access to the management UI, use SSH tunnel:"
echo -e "       ${GREEN}ssh -L 8080:localhost:${SERVER_PORT} root@${VPS_IP}${NC}"
echo -e "       Then visit: ${GREEN}http://localhost:8080/${NC}"
echo ""
