#!/usr/bin/env bash
# Phantom CLI - SSH tunnel management (port forwarding)
# Creates SSH -L tunnel to forward local port to VPS proxy port

TUNNEL_PID_FILE="$PHANTOM_DIR/tunnel.pid"

# Start SSH port-forward tunnel to VPS
phantom_tunnel_connect() {
    # Check if already connected
    if _tunnel_is_alive; then
        local pid
        pid=$(cat "$TUNNEL_PID_FILE")
        log_warn "Tunnel is already running (PID: $pid)"
        return 0
    fi

    # Load config
    local host ssh_port proxy_port
    host=$(phantom_config_get "SERVER_HOST") || { log_error "SERVER_HOST not configured. Run: phantom setup <VPS_IP>"; return 1; }
    ssh_port=$(phantom_config_get "SERVER_PORT" 2>/dev/null || echo "22")
    proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")

    # If host is already 127.0.0.1, read the real VPS host
    if [ "$host" = "127.0.0.1" ] || [ "$host" = "localhost" ]; then
        host=$(phantom_config_get "VPS_HOST" 2>/dev/null || echo "")
        if [ -z "$host" ]; then
            log_error "VPS_HOST not configured (SERVER_HOST is localhost). Run: phantom setup <VPS_IP>"
            return 1
        fi
    fi

    # Check if local port is already in use
    if nc -z 127.0.0.1 "$proxy_port" 2>/dev/null; then
        log_warn "Port $proxy_port is already in use. Checking if it's our tunnel..."
        local existing_pid
        existing_pid=$(_tunnel_find_pid "$proxy_port")
        if [ -n "$existing_pid" ]; then
            echo "$existing_pid" > "$TUNNEL_PID_FILE"
            log_success "Found existing tunnel (PID: $existing_pid)"
            return 0
        else
            log_error "Port $proxy_port is in use by another process"
            return 1
        fi
    fi

    log_info "Creating SSH tunnel: localhost:${proxy_port} → ${host}:${proxy_port}..."

    if ! _tunnel_start_port_forward "$host" "$ssh_port" "$proxy_port"; then
        log_error "Failed to create SSH tunnel"
        log_info "  Possible fixes:"
        log_info "    1. Install sshpass: brew install hudochenkov/sshpass/sshpass"
        log_info "    2. Set SSH password: phantom config SSH_PASSWORD <password>"
        log_info "    3. Set up SSH key: ssh-keygen && ssh-copy-id root@${host}"
        return 1
    fi

    # Give SSH a moment to fork and bind port
    sleep 2

    # Find and save PID
    local pid
    pid=$(_tunnel_find_pid "$proxy_port")

    if [ -n "$pid" ]; then
        echo "$pid" > "$TUNNEL_PID_FILE"

        # Verify port is reachable
        if nc -z 127.0.0.1 "$proxy_port" 2>/dev/null; then
            log_success "Tunnel established (PID: ${pid}, localhost:${proxy_port})"
        else
            log_warn "Tunnel started (PID: ${pid}) but port not yet reachable"
        fi
    else
        log_error "SSH tunnel process not found after start"
        return 1
    fi
}

# Kill SSH tunnel
phantom_tunnel_disconnect() {
    if [ ! -f "$TUNNEL_PID_FILE" ]; then
        log_warn "No tunnel PID file found"
        _tunnel_cleanup_orphans
        return 0
    fi

    local pid
    pid=$(cat "$TUNNEL_PID_FILE")

    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        sleep 0.5
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

# Check and display tunnel status
phantom_tunnel_status() {
    local proxy_port
    proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")

    if _tunnel_is_alive; then
        local pid
        pid=$(cat "$TUNNEL_PID_FILE")
        echo -e "  Tunnel:     ${GREEN}connected${NC} (PID: ${pid})"

        if nc -z 127.0.0.1 "$proxy_port" 2>/dev/null; then
            echo -e "  Port:       ${GREEN}localhost:${proxy_port} reachable${NC}"
        else
            echo -e "  Port:       ${RED}localhost:${proxy_port} not responding${NC}"
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
        local proxy_port
        proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")
        # Also verify port is actually reachable
        if nc -z 127.0.0.1 "$proxy_port" 2>/dev/null; then
            return 0
        fi
        log_warn "Tunnel process alive but port unreachable, reconnecting..."
        phantom_tunnel_disconnect
    fi

    phantom_tunnel_connect
}

# ── Internal helpers ────────────────────────────────────────────────

# Start SSH port-forward tunnel
_tunnel_start_port_forward() {
    local host="$1" ssh_port="$2" proxy_port="$3"
    local ssh_password ssh_key
    ssh_password=$(phantom_config_get "SSH_PASSWORD" 2>/dev/null || echo "")
    ssh_key=$(phantom_config_get "SSH_KEY" 2>/dev/null || echo "$HOME/.ssh/id_rsa")

    local ssh_opts="-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o ConnectTimeout=10"

    # Find sshpass (may not be in PATH for non-interactive SSH sessions)
    local sshpass_cmd=""
    if command -v sshpass &>/dev/null; then
        sshpass_cmd="sshpass"
    elif [ -x /opt/homebrew/bin/sshpass ]; then
        sshpass_cmd="/opt/homebrew/bin/sshpass"
    elif [ -x /usr/local/bin/sshpass ]; then
        sshpass_cmd="/usr/local/bin/sshpass"
    fi

    if [ -n "$ssh_password" ] && [ -n "$sshpass_cmd" ]; then
        "$sshpass_cmd" -p "$ssh_password" ssh $ssh_opts -f -N \
            -L "${proxy_port}:localhost:${proxy_port}" \
            -p "$ssh_port" "root@${host}" 2>/dev/null
    elif [ -f "$ssh_key" ]; then
        ssh $ssh_opts -f -N -i "$ssh_key" \
            -L "${proxy_port}:localhost:${proxy_port}" \
            -p "$ssh_port" "root@${host}" 2>/dev/null
    else
        return 1
    fi
}

# Check if tunnel process is alive
_tunnel_is_alive() {
    if [ ! -f "$TUNNEL_PID_FILE" ]; then
        return 1
    fi

    local pid
    pid=$(cat "$TUNNEL_PID_FILE")
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

# Find SSH tunnel PID by port
_tunnel_find_pid() {
    local port="$1"
    pgrep -f "ssh.*-L.*${port}:localhost" 2>/dev/null | head -1
}

# Clean up orphaned SSH tunnel processes
_tunnel_cleanup_orphans() {
    local proxy_port
    proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")

    local orphans
    orphans=$(pgrep -f "ssh.*-L.*${proxy_port}:localhost" 2>/dev/null || true)
    if [ -n "$orphans" ]; then
        echo "$orphans" | while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done
        log_info "Cleaned up orphaned SSH tunnel processes"
    fi
}
