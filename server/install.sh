#!/usr/bin/env bash
# Phantom Server - One-click VPS installer
# Usage: curl -fsSL https://raw.githubusercontent.com/.../server/install.sh | bash
#
# Installs: Docker + SOCKS5 container + HTTP CONNECT proxy + Claude Code

set -euo pipefail

PHANTOM_DIR="/opt/phantom-cli"
REPO_RAW="https://raw.githubusercontent.com/nicegongqing/phantom-cli/main"
HTTP_PROXY_PORT=8080

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

SERVER_FILES=(
    "Dockerfile"
    "docker-compose.yml"
    "danted.conf"
    "entrypoint.sh"
    "manage-users.sh"
    ".env.example"
)

for f in "${SERVER_FILES[@]}"; do
    if curl -fsSL "$REPO_RAW/server/$f" -o "$PHANTOM_DIR/server/$f" 2>/dev/null; then
        log_success "Downloaded $f"
    else
        log_warn "Failed to download $f from repo, checking local..."
        # Fallback: if running from cloned repo
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

# Ensure .env exists
if [ ! -f "$PHANTOM_DIR/server/.env" ]; then
    cp "$PHANTOM_DIR/server/.env.example" "$PHANTOM_DIR/server/.env"
fi

chmod +x "$PHANTOM_DIR/server/entrypoint.sh" "$PHANTOM_DIR/server/manage-users.sh"

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

# ── Step 4: Deploy HTTP CONNECT proxy ──────────────────────────────

echo -e "${BOLD}Step 4: HTTP CONNECT proxy${NC}"
echo "────────────────────────────────────────"

# Check Python3
if ! command -v python3 &>/dev/null; then
    log_info "Installing Python3..."
    apt-get install -y -qq python3 >/dev/null 2>&1
fi
log_success "Python3 available: $(python3 --version)"

# Write HTTP CONNECT proxy script
cat > "$PHANTOM_DIR/http_proxy.py" <<'PYEOF'
#!/usr/bin/env python3
"""Minimal HTTP CONNECT proxy for Claude Code (Node.js compatible)."""

import socket
import threading
import sys

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
BUFFER_SIZE = 65536


def handle_client(client_socket):
    try:
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            client_socket.close()
            return

        first_line = request.split(b"\r\n")[0].decode("utf-8", errors="replace")
        method = first_line.split(" ")[0]

        if method == "CONNECT":
            target = first_line.split(" ")[1]
            host, port = target.split(":")
            port = int(port)

            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(30)
            remote_socket.connect((host, port))

            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            def forward(src, dst):
                try:
                    while True:
                        data = src.recv(BUFFER_SIZE)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        src.close()
                    except Exception:
                        pass
                    try:
                        dst.close()
                    except Exception:
                        pass

            t1 = threading.Thread(target=forward, args=(client_socket, remote_socket), daemon=True)
            t2 = threading.Thread(target=forward, args=(remote_socket, client_socket), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        else:
            client_socket.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\nOnly CONNECT supported\n")
            client_socket.close()
    except Exception:
        try:
            client_socket.close()
        except Exception:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(128)
    print(f"[phantom-http-proxy] Listening on 0.0.0.0:{LISTEN_PORT}")

    while True:
        client_socket, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client_socket,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
PYEOF

chmod +x "$PHANTOM_DIR/http_proxy.py"

# Create systemd service
cat > /etc/systemd/system/phantom-http-proxy.service <<SVCEOF
[Unit]
Description=Phantom HTTP CONNECT Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $PHANTOM_DIR/http_proxy.py $HTTP_PROXY_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now phantom-http-proxy
sleep 1

if systemctl is-active --quiet phantom-http-proxy; then
    log_success "HTTP CONNECT proxy running on port $HTTP_PROXY_PORT"
else
    log_error "HTTP proxy failed to start. Check: journalctl -u phantom-http-proxy"
    exit 1
fi

echo ""

# ── Step 5: Firewall ───────────────────────────────────────────────

echo -e "${BOLD}Step 5: Firewall${NC}"
echo "────────────────────────────────────────"

if command -v ufw &>/dev/null; then
    ufw allow "$HTTP_PROXY_PORT"/tcp 2>/dev/null && log_success "UFW: port $HTTP_PROXY_PORT opened" || log_warn "UFW: could not open port $HTTP_PROXY_PORT"
    ufw allow 1080/tcp 2>/dev/null && log_success "UFW: port 1080 opened" || log_warn "UFW: could not open port 1080"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port="$HTTP_PROXY_PORT"/tcp 2>/dev/null && log_success "firewalld: port $HTTP_PROXY_PORT opened" || true
    firewall-cmd --permanent --add-port=1080/tcp 2>/dev/null && log_success "firewalld: port 1080 opened" || true
    firewall-cmd --reload 2>/dev/null || true
else
    log_info "No firewall detected (ufw/firewalld). Ensure ports $HTTP_PROXY_PORT and 1080 are open."
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
    echo -e "    SOCKS5 proxy:    ${GREEN}:1080 running${NC}"
else
    echo -e "    SOCKS5 proxy:    ${RED}not running${NC}"
fi

if systemctl is-active --quiet phantom-http-proxy; then
    echo -e "    HTTP proxy:      ${GREEN}:${HTTP_PROXY_PORT} running${NC}"
else
    echo -e "    HTTP proxy:      ${RED}not running${NC}"
fi

if command -v claude &>/dev/null; then
    echo -e "    Claude Code:     ${GREEN}installed${NC}"
else
    echo -e "    Claude Code:     ${YELLOW}not installed${NC}"
fi

echo ""
echo -e "  ${BOLD}VPS IP:${NC} ${CYAN}${VPS_IP}${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    ${YELLOW}1.${NC} Log in to Claude Code on this VPS:"
echo -e "       ${GREEN}claude${NC}"
echo -e "       Complete the OAuth authentication in your browser."
echo ""
echo -e "    ${YELLOW}2.${NC} Then, on your ${BOLD}local Mac${NC}, install the client and connect:"
echo -e "       ${GREEN}curl -fsSL $REPO_RAW/client/install.sh | bash${NC}"
echo -e "       ${GREEN}phantom setup ${VPS_IP}${NC}"
echo ""
