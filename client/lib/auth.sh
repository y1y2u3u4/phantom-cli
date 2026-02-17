#!/usr/bin/env bash
# Phantom CLI - Credential management (sync from VPS + status check)

# Sync Claude credentials from VPS to local sandbox
# Usage: phantom_auth_sync [--key API_KEY | --password PASSWORD]
#   --key KEY       Use API-based credential sync (recommended)
#   --password PASS Use SSH/sshpass-based credential sync (legacy)
#   (no args)       Fall back to API_KEY from config, or prompt
phantom_auth_sync() {
    local api_key="" password="" method=""

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --key)
                if [ -z "${2:-}" ]; then
                    log_error "--key requires a value"
                    return 1
                fi
                api_key="$2"
                method="api"
                shift 2
                ;;
            --password)
                if [ -z "${2:-}" ]; then
                    log_error "--password requires a value"
                    return 1
                fi
                password="$2"
                method="ssh"
                shift 2
                ;;
            *)
                log_warn "Unknown argument: $1"
                shift
                ;;
        esac
    done

    # If no explicit method, try API_KEY from config
    if [ -z "$method" ]; then
        local config_api_key
        config_api_key=$(phantom_config_get "API_KEY" 2>/dev/null || echo "")
        if [ -n "$config_api_key" ]; then
            api_key="$config_api_key"
            method="api"
        else
            log_error "No authentication method provided."
            log_info "Use: phantom auth sync --key YOUR_API_KEY"
            log_info "  or: phantom auth sync --password YOUR_SSH_PASSWORD"
            log_info "  or: set API_KEY in $PHANTOM_CONFIG"
            return 1
        fi
    fi

    case "$method" in
        api)
            _auth_sync_via_api "$api_key"
            ;;
        ssh)
            _auth_sync_via_ssh "$password"
            ;;
    esac
}

# Sync credentials via HTTP API using an API key
_auth_sync_via_api() {
    local api_key="$1"
    local server_host http_proxy_port

    server_host=$(phantom_config_get "SERVER_HOST") || {
        log_error "SERVER_HOST not configured. Run: phantom setup <VPS_IP>"
        return 1
    }
    http_proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")

    log_info "Syncing credentials via API from $server_host..."

    # Ensure sandbox exists
    mkdir -p "$SHADOW_HOME/.claude"

    # Pipe curl directly to python3 to avoid bash variable issues with large JSON
    curl -sf -H "Authorization: Bearer $api_key" \
        "http://${server_host}:${http_proxy_port}/api/credentials" 2>/dev/null \
    | SHADOW_HOME="$SHADOW_HOME" python3 -c "
import json, os, sys
raw = sys.stdin.read()
if not raw:
    print('ERROR: Empty response from server', file=sys.stderr)
    sys.exit(1)
try:
    data = json.loads(raw)
except json.JSONDecodeError as e:
    print(f'ERROR: Invalid JSON: {e}', file=sys.stderr)
    sys.exit(1)
files = data.get('files', {})
if not files:
    print('ERROR: No credential files in response', file=sys.stderr)
    sys.exit(1)
shadow = os.environ.get('SHADOW_HOME', os.path.expanduser('~/.phantom_env'))
for path, content in files.items():
    full = os.path.join(shadow, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, 'w') as f:
        f.write(content)
    print(f'  Synced {path}')
print(f'Total: {len(files)} file(s)')
" || {
        log_error "API credential sync failed. Check your API key and server status."
        return 1
    }

    log_success "Credentials synced via API"
}

# Sync credentials via SSH (legacy sshpass approach)
_auth_sync_via_ssh() {
    local password="$1"
    local server_host

    server_host=$(phantom_config_get "SERVER_HOST") || {
        log_error "SERVER_HOST not configured. Run: phantom setup <VPS_IP>"
        return 1
    }

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
