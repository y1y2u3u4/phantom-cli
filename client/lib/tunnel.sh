#!/usr/bin/env bash
# Phantom CLI - SSH SOCKS5 tunnel management via autossh

TUNNEL_PID_FILE="$PHANTOM_DIR/tunnel.pid"

# Start autossh SOCKS5 tunnel to VPS
phantom_tunnel_connect() {
    # Check if already connected
    if _tunnel_is_alive; then
        log_warn "Tunnel is already running (PID: $(cat "$TUNNEL_PID_FILE"))"
        return 0
    fi

    # Load config
    local host port socks_port ssh_key
    host=$(phantom_config_get "SERVER_HOST") || { log_error "SERVER_HOST not configured. Run: phantom setup <VPS_IP>"; return 1; }
    port=$(phantom_config_get "SERVER_PORT") || port="22"
    socks_port=$(phantom_config_get "SOCKS_PORT") || socks_port="1080"
    ssh_key=$(phantom_config_get "SSH_KEY") || ssh_key="$HOME/.ssh/id_rsa"

    # Validate
    if ! command -v autossh &>/dev/null; then
        log_error "autossh not found. Install with: brew install autossh"
        return 1
    fi

    if [ ! -f "$ssh_key" ]; then
        log_error "SSH key not found: $ssh_key"
        return 1
    fi

    log_info "Connecting to ${host}:${port} (SOCKS5 on 127.0.0.1:${socks_port})..."

    # Start autossh in background
    # AUTOSSH_GATETIME=0: don't wait before first connection attempt
    # AUTOSSH_PORT=0: disable echo monitoring, rely on SSH ServerAlive
    AUTOSSH_GATETIME=0 \
    AUTOSSH_PORT=0 \
    autossh -f -N \
        -D "127.0.0.1:${socks_port}" \
        -p "$port" \
        -i "$ssh_key" \
        -o "ServerAliveInterval=30" \
        -o "ServerAliveCountMax=3" \
        -o "ExitOnForwardFailure=yes" \
        -o "StrictHostKeyChecking=accept-new" \
        "root@${host}"

    # Give autossh a moment to fork
    sleep 1

    # Find and save the autossh PID
    local pid
    pid=$(pgrep -f "autossh.*-D 127.0.0.1:${socks_port}" | head -1)

    if [ -n "$pid" ]; then
        echo "$pid" > "$TUNNEL_PID_FILE"
        log_success "Tunnel established (PID: ${pid})"

        # Verify SOCKS5 is reachable
        sleep 1
        if nc -z 127.0.0.1 "$socks_port" 2>/dev/null; then
            log_success "SOCKS5 proxy is reachable on 127.0.0.1:${socks_port}"
        else
            log_warn "Tunnel started but SOCKS5 port not yet reachable. It may take a moment."
        fi
    else
        log_error "Failed to start tunnel. Check your SSH config and try: ssh -p ${port} -i ${ssh_key} root@${host}"
        return 1
    fi
}

# Kill autossh tunnel
phantom_tunnel_disconnect() {
    if [ ! -f "$TUNNEL_PID_FILE" ]; then
        log_warn "No tunnel PID file found. Tunnel may not be running."
        # Try to clean up any orphaned autossh processes
        _tunnel_cleanup_orphans
        return 0
    fi

    local pid
    pid=$(cat "$TUNNEL_PID_FILE")

    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        # Also kill any child ssh processes
        pkill -P "$pid" 2>/dev/null || true
        sleep 0.5
        # Force kill if still alive
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        log_success "Tunnel disconnected (PID: ${pid})"
    else
        log_warn "Tunnel process (PID: ${pid}) was not running"
    fi

    rm -f "$TUNNEL_PID_FILE"
    _tunnel_cleanup_orphans
}

# Check if tunnel is alive
phantom_tunnel_status() {
    local socks_port
    socks_port=$(phantom_config_get "SOCKS_PORT" 2>/dev/null || echo "1080")

    if _tunnel_is_alive; then
        local pid
        pid=$(cat "$TUNNEL_PID_FILE")
        echo -e "  Tunnel:     ${GREEN}connected${NC} (PID: ${pid})"

        if nc -z 127.0.0.1 "$socks_port" 2>/dev/null; then
            echo -e "  SOCKS5:     ${GREEN}reachable${NC}"
        else
            echo -e "  SOCKS5:     ${RED}port not responding${NC}"
        fi
        return 0
    else
        echo -e "  Tunnel:     ${RED}disconnected${NC}"
        return 1
    fi
}

# Ensure tunnel is connected (connect if not)
phantom_tunnel_ensure() {
    if _tunnel_is_alive; then
        return 0
    fi

    local auto_connect
    auto_connect=$(phantom_config_get "AUTO_CONNECT" 2>/dev/null || echo "true")

    if [ "$auto_connect" = "true" ]; then
        log_info "Tunnel not connected. Auto-connecting..."
        phantom_tunnel_connect
    else
        log_error "Tunnel not connected. Run: phantom connect"
        return 1
    fi
}

# ── Internal helpers ────────────────────────────────────────────────

_tunnel_is_alive() {
    if [ ! -f "$TUNNEL_PID_FILE" ]; then
        return 1
    fi

    local pid
    pid=$(cat "$TUNNEL_PID_FILE")

    if [ -z "$pid" ]; then
        return 1
    fi

    kill -0 "$pid" 2>/dev/null
}

_tunnel_cleanup_orphans() {
    local socks_port
    socks_port=$(phantom_config_get "SOCKS_PORT" 2>/dev/null || echo "1080")

    # Kill any orphaned autossh processes for our port
    local orphans
    orphans=$(pgrep -f "autossh.*-D 127.0.0.1:${socks_port}" 2>/dev/null || true)
    if [ -n "$orphans" ]; then
        echo "$orphans" | while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done
        log_info "Cleaned up orphaned autossh processes"
    fi
}
