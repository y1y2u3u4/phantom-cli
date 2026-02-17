#!/usr/bin/env bash
# Phantom CLI - Credential management (sync from VPS + status check)

# Sync Claude credentials from VPS to local sandbox
# Usage: phantom_auth_sync [--password PASSWORD]
phantom_auth_sync() {
    local server_host password=""

    server_host=$(phantom_config_get "SERVER_HOST") || {
        log_error "SERVER_HOST not configured. Run: phantom setup <VPS_IP>"
        return 1
    }

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --password)
                password="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    # Build SSH command
    local ssh_cmd="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
    if [ -n "$password" ]; then
        if ! command -v sshpass &>/dev/null; then
            log_error "sshpass is required for password auth. Install: brew install sshpass"
            return 1
        fi
        ssh_cmd="sshpass -p '$password' $ssh_cmd"
    fi

    # Ensure sandbox directory exists
    mkdir -p "$SHADOW_HOME/.claude"

    log_info "Syncing credentials from $server_host..."

    # Files to sync from VPS
    local files=(".claude/.credentials.json" ".claude.json" ".claude/settings.json")
    local synced=0

    for f in "${files[@]}"; do
        local target_dir
        target_dir=$(dirname "$SHADOW_HOME/$f")
        mkdir -p "$target_dir"

        if eval "$ssh_cmd root@$server_host 'cat /root/$f 2>/dev/null'" > "$SHADOW_HOME/$f.tmp" 2>/dev/null; then
            if [ -s "$SHADOW_HOME/$f.tmp" ]; then
                mv "$SHADOW_HOME/$f.tmp" "$SHADOW_HOME/$f"
                log_success "Synced $f"
                ((synced++)) || true
            else
                rm -f "$SHADOW_HOME/$f.tmp"
            fi
        else
            rm -f "$SHADOW_HOME/$f.tmp"
        fi
    done

    if [ "$synced" -eq 0 ]; then
        log_error "No credentials found on VPS."
        log_info "Please SSH into $server_host and run 'claude' to complete OAuth login first."
        return 1
    fi

    # Verify key credential file
    if [ -f "$SHADOW_HOME/.claude/.credentials.json" ]; then
        log_success "Credentials synced ($synced file(s))"
    else
        log_warn "Synced $synced file(s), but .credentials.json not found."
        log_info "You may need to run 'claude' on the VPS first."
    fi
}

# Check current credential and connection status
phantom_auth_status() {
    echo -e "${BOLD}Auth Status${NC}"
    echo "────────────────────────────────────────"

    # Check credentials
    local cred_file="$SHADOW_HOME/.claude/.credentials.json"
    if [ -f "$cred_file" ]; then
        # Try to extract email from credentials
        local email=""
        if command -v python3 &>/dev/null; then
            email=$(python3 -c "import json; d=json.load(open('$cred_file')); print(d.get('email', d.get('account', {}).get('email', '')))" 2>/dev/null || echo "")
        fi
        if [ -n "$email" ]; then
            echo -e "  Credentials: ${GREEN}valid${NC} ($email)"
        else
            echo -e "  Credentials: ${GREEN}found${NC} (email not parsed)"
        fi
    else
        echo -e "  Credentials: ${RED}not found${NC}"
        echo -e "               Run: ${GREEN}phantom auth sync${NC}"
    fi

    # Check proxy
    local server_host http_proxy_port
    server_host=$(phantom_config_get "SERVER_HOST" 2>/dev/null || echo "")
    http_proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")

    if [ -n "$server_host" ]; then
        if nc -z -w 3 "$server_host" "$http_proxy_port" 2>/dev/null; then
            echo -e "  Proxy:       ${GREEN}connected${NC} ($server_host:$http_proxy_port)"
        else
            echo -e "  Proxy:       ${RED}unreachable${NC} ($server_host:$http_proxy_port)"
        fi
    else
        echo -e "  Proxy:       ${YELLOW}not configured${NC}"
    fi

    # Check sandbox
    if [ -d "$SHADOW_HOME" ]; then
        echo -e "  Sandbox:     ${GREEN}ready${NC} ($SHADOW_HOME)"
    else
        echo -e "  Sandbox:     ${RED}not created${NC}"
    fi
}
