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
    server_host=$(phantom_config_get "SERVER_HOST") || { log_error "SERVER_HOST not configured. Run: phantom init"; return 1; }
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
        log_info "Ensure the HTTP CONNECT proxy is running on the VPS."
        return 1
    fi

    # Ensure sandbox exists
    if [ ! -d "$SHADOW_HOME" ]; then
        phantom_sandbox_setup
    fi

    # Build HTTP proxy URL
    local proxy_url="http://${proxy_host}:${http_proxy_port}"

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

    # Source phantom profile if exists (custom env vars)
    if [ -f "$SHADOW_HOME/.phantom_profile" ]; then
        source "$SHADOW_HOME/.phantom_profile"
        log_info "Loaded custom environment from .phantom_profile"
    fi

    exec "$@"
}
