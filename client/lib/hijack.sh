#!/usr/bin/env bash
# Phantom CLI - Network hijack execution
# Sets proxy env vars and executes command in shadow sandbox
# Uses HTTP CONNECT proxy (Node.js/Claude Code does NOT support SOCKS5 via env vars)

# Execute a command through the HTTP proxy with shadow HOME
# Usage: phantom_hijack_exec CMD [ARGS...]
phantom_hijack_exec() {
    if [ $# -eq 0 ]; then
        log_error "No command specified"
        log_info "Usage: phantom <command> [args...]"
        return 1
    fi

    # Load config
    local server_host http_proxy_port connection_mode
    server_host=$(phantom_config_get "SERVER_HOST") || { log_error "SERVER_HOST not configured. Run: phantom setup <VPS_IP>"; return 1; }
    http_proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")
    connection_mode=$(phantom_config_get "CONNECTION_MODE" 2>/dev/null || echo "direct")

    local proxy_host
    if [ "$connection_mode" = "direct" ]; then
        proxy_host="$server_host"
    else
        # Tunnel mode: SSH tunnel forwards HTTP proxy port to localhost
        proxy_host="127.0.0.1"
        phantom_tunnel_ensure || return 1
    fi

    # Verify HTTP proxy is reachable
    if ! nc -z -w 3 "$proxy_host" "$http_proxy_port" 2>/dev/null; then
        log_error "Cannot reach HTTP proxy at ${proxy_host}:${http_proxy_port}"
        log_info "Possible fixes:"
        if [ "$connection_mode" = "direct" ]; then
            log_info "  1. Check VPS: ssh root@${server_host} systemctl status phantom-http-proxy"
            log_info "  2. Restart proxy: ssh root@${server_host} systemctl restart phantom-http-proxy"
        else
            log_info "  1. Ensure tunnel is connected: phantom connect"
        fi
        log_info "  3. Run diagnostics: phantom doctor"
        return 1
    fi

    # Ensure sandbox exists
    if [ ! -d "$SHADOW_HOME" ]; then
        phantom_sandbox_setup
    fi

    # Auto-sync credentials if token is expired or missing
    _hijack_ensure_credentials "$proxy_host" "$http_proxy_port"

    # Build HTTP proxy URL (embed API key for upstream account routing)
    local api_key proxy_url
    api_key=$(phantom_config_get "API_KEY" 2>/dev/null || echo "")
    if [ -n "$api_key" ]; then
        proxy_url="http://${api_key}:x@${proxy_host}:${http_proxy_port}"
    else
        proxy_url="http://${proxy_host}:${http_proxy_port}"
    fi

    log_info "Hijacking: $* (via HTTP proxy at ${proxy_host}:${http_proxy_port})"

    # Set proxy environment (HTTP CONNECT proxy - compatible with Node.js/curl/etc.)
    export HTTP_PROXY="$proxy_url"
    export HTTPS_PROXY="$proxy_url"
    export ALL_PROXY="$proxy_url"
    export http_proxy="$proxy_url"
    export https_proxy="$proxy_url"
    export all_proxy="$proxy_url"
    export NO_PROXY="localhost,127.0.0.1,::1"
    export no_proxy="localhost,127.0.0.1,::1"

    # Switch to shadow HOME
    export HOME="$SHADOW_HOME"

    # Clear Claude Code nesting detection vars — Phantom launches
    # an independent Claude Code session, not a nested one
    unset CLAUDECODE
    unset CLAUDE_CODE_ENTRYPOINT
    unset CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS

    # Source phantom profile if exists (custom env vars)
    if [ -f "$SHADOW_HOME/.phantom_profile" ]; then
        source "$SHADOW_HOME/.phantom_profile"
        log_info "Loaded custom environment from .phantom_profile"
    fi

    exec "$@"
}

# Check if local credentials are valid; auto-sync from VPS if expired
_hijack_ensure_credentials() {
    local proxy_host="$1" http_proxy_port="$2"
    local cred_file="$SHADOW_HOME/.claude/.credentials.json"

    # Skip if no credentials file exists yet (first run)
    if [ ! -f "$cred_file" ]; then
        log_info "No local credentials found. Syncing from VPS..."
        _hijack_sync_credentials "$proxy_host" "$http_proxy_port"
        return
    fi

    # Check if token is expired (python one-liner)
    local expired
    expired=$(python3 -c "
import json, datetime, sys
try:
    d = json.load(open('$cred_file'))
    exp = d.get('claudeAiOauth', {}).get('expiresAt', 0)
    now_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    print('yes' if now_ms > exp else 'no')
except: print('yes')
" 2>/dev/null || echo "yes")

    if [ "$expired" = "yes" ]; then
        log_warn "OAuth token expired. Syncing fresh credentials..."
        _hijack_sync_credentials "$proxy_host" "$http_proxy_port"
    fi
}

# Download credentials from VPS via /api/credentials
_hijack_sync_credentials() {
    local proxy_host="$1" http_proxy_port="$2"
    local api_key
    api_key=$(phantom_config_get "API_KEY" 2>/dev/null || echo "")

    if [ -z "$api_key" ]; then
        log_warn "No API_KEY configured — cannot auto-sync credentials"
        return 1
    fi

    local resp
    resp=$(curl -s --max-time 15 \
        -H "Authorization: Bearer $api_key" \
        "http://${proxy_host}:${http_proxy_port}/api/credentials" 2>/dev/null)

    if [ -z "$resp" ]; then
        log_warn "Could not reach VPS for credential sync"
        return 1
    fi

    echo "$resp" | python3 -c "
import json, sys, os
resp = json.load(sys.stdin)
if 'error' in resp:
    print(f'Sync failed: {resp[\"error\"]}', file=sys.stderr)
    sys.exit(1)
files = resp.get('files', {})
shadow = '$SHADOW_HOME'
for rel_path, content in files.items():
    full_path = os.path.join(shadow, rel_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, 'w') as f:
        f.write(content)
    os.chmod(full_path, 0o600)
" 2>/dev/null

    if [ $? -eq 0 ]; then
        log_success "Credentials synced from VPS"
    else
        log_warn "Credential sync failed — Claude Code may prompt for login"
    fi
}
