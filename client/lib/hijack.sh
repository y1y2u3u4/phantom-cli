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
    connection_mode=$(phantom_config_get "CONNECTION_MODE" 2>/dev/null || echo "auto")

    # Determine proxy_host based on connection mode
    local proxy_host
    case "$connection_mode" in
        direct)
            proxy_host="$server_host"
            ;;
        tunnel)
            proxy_host="127.0.0.1"
            phantom_tunnel_ensure || return 1
            ;;
        auto)
            # Auto-detect: try direct first, fall back to tunnel
            proxy_host=$(_hijack_auto_connect "$server_host" "$http_proxy_port")
            if [ "$proxy_host" = "FAIL" ]; then
                return 1
            fi
            ;;
        *)
            log_error "Unknown CONNECTION_MODE: $connection_mode"
            return 1
            ;;
    esac

    # Verify HTTP proxy is reachable
    if ! nc -z -w 3 "$proxy_host" "$http_proxy_port" 2>/dev/null; then
        log_error "Cannot reach HTTP proxy at ${proxy_host}:${http_proxy_port}"
        log_info "Possible fixes:"
        if [ "$proxy_host" = "127.0.0.1" ]; then
            log_info "  1. Reconnect tunnel: phantom connect"
        else
            log_info "  1. Check VPS: ssh root@${server_host} systemctl status phantom-http-proxy"
            log_info "  2. Restart proxy: ssh root@${server_host} systemctl restart phantom-http-proxy"
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

    # Clear Anthropic env vars that would override OAuth authentication
    # (user may have API keys or custom base URLs for their own use)
    unset ANTHROPIC_API_KEY
    unset ANTHROPIC_BASE_URL
    unset ANTHROPIC_AUTH_TOKEN
    unset CLAUDE_API_KEY
    unset CLAUDE_CODE_USE_BEDROCK
    unset CLAUDE_CODE_USE_VERTEX

    # Source phantom profile if exists (custom env vars)
    if [ -f "$SHADOW_HOME/.phantom_profile" ]; then
        source "$SHADOW_HOME/.phantom_profile"
        log_info "Loaded custom environment from .phantom_profile"
    fi

    exec "$@"
}

# ── Auto-connection logic ──────────────────────────────────────────

# Auto-detect whether to use direct or tunnel mode
# Returns the proxy_host to use (server_host or 127.0.0.1), or "FAIL"
_hijack_auto_connect() {
    local server_host="$1" http_proxy_port="$2"
    local cache_file="$PHANTOM_DIR/connect_mode_cache"

    # NOTE: This function is called inside $(), so all log output must go to
    # stderr (>&2) to avoid polluting the captured return value (proxy_host).

    # Check cache (valid for 24 hours)
    if [ -f "$cache_file" ]; then
        local cached_mode cached_time now
        cached_mode=$(head -1 "$cache_file" 2>/dev/null || echo "")
        cached_time=$(tail -1 "$cache_file" 2>/dev/null || echo "0")
        now=$(date +%s)
        if [ $((now - cached_time)) -lt 86400 ] && [ -n "$cached_mode" ]; then
            if [ "$cached_mode" = "tunnel" ]; then
                phantom_tunnel_ensure >&2 || { echo "FAIL"; return; }
                echo "127.0.0.1"
            else
                echo "$server_host"
            fi
            return
        fi
    fi

    # Quick CONNECT test (3s timeout) — use API key if available
    local api_key proxy_test_url
    api_key=$(phantom_config_get "API_KEY" 2>/dev/null || echo "")
    if [ -n "$api_key" ]; then
        proxy_test_url="http://${api_key}:x@${server_host}:${http_proxy_port}"
    else
        proxy_test_url="http://${server_host}:${http_proxy_port}"
    fi

    log_info "Detecting connection mode..." >&2
    local test_resp
    test_resp=$(curl -s --max-time 4 -o /dev/null -w "%{http_code}" \
        --proxy "$proxy_test_url" \
        "https://api.anthropic.com/api/oauth/usage" 2>/dev/null) || true
    [ -z "$test_resp" ] && test_resp="000"

    if [ "$test_resp" != "000" ] && [ "$test_resp" != "400" ]; then
        # Direct CONNECT works
        log_success "Direct connection OK" >&2
        _hijack_cache_mode "direct"
        echo "$server_host"
    else
        # CONNECT blocked — try SSH tunnel
        log_warn "Direct CONNECT blocked (HTTP $test_resp). Trying SSH tunnel..." >&2
        if phantom_tunnel_ensure >&2; then
            log_success "SSH tunnel established" >&2
            _hijack_cache_mode "tunnel"
            echo "127.0.0.1"
        else
            log_error "Cannot connect: direct CONNECT blocked and SSH tunnel failed"
            log_info "  Fix: phantom config SSH_PASSWORD <vps_password>" >&2
            log_info "  Or:  install sshpass: brew install hudochenkov/sshpass/sshpass" >&2
            echo "FAIL"
        fi
    fi
}

# Cache the detected connection mode
_hijack_cache_mode() {
    local mode="$1"
    local cache_file="$PHANTOM_DIR/connect_mode_cache"
    echo "$mode" > "$cache_file"
    date +%s >> "$cache_file"
}

# ── Credential sync ────────────────────────────────────────────────

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
