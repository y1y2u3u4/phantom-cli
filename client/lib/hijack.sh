#!/usr/bin/env bash
# Phantom CLI - Network hijack execution
# Sets proxy env vars and executes command in shadow sandbox

# Execute a command through the SOCKS5 proxy with shadow HOME
# Usage: phantom_hijack_exec CMD [ARGS...]
phantom_hijack_exec() {
    if [ $# -eq 0 ]; then
        log_error "No command specified"
        log_info "Usage: phantom <command> [args...]"
        return 1
    fi

    # Load config
    local socks_port socks_user socks_pass
    socks_port=$(phantom_config_get "SOCKS_PORT" 2>/dev/null || echo "1080")
    socks_user=$(phantom_config_get "SOCKS_USER" 2>/dev/null || echo "")
    socks_pass=$(phantom_config_get "SOCKS_PASS" 2>/dev/null || echo "")

    # Ensure tunnel is up
    phantom_tunnel_ensure || return 1

    # Ensure sandbox exists
    if [ ! -d "$SHADOW_HOME" ]; then
        phantom_sandbox_setup
    fi

    # Build proxy URL with optional auth
    local proxy_url
    if [ -n "$socks_user" ] && [ -n "$socks_pass" ]; then
        proxy_url="socks5h://${socks_user}:${socks_pass}@127.0.0.1:${socks_port}"
    else
        proxy_url="socks5h://127.0.0.1:${socks_port}"
    fi

    log_info "Hijacking: $* (via SOCKS5 proxy)"

    # Set proxy environment and execute
    export HTTP_PROXY="$proxy_url"
    export HTTPS_PROXY="$proxy_url"
    export ALL_PROXY="$proxy_url"
    export http_proxy="$proxy_url"
    export https_proxy="$proxy_url"
    export all_proxy="$proxy_url"
    export NO_PROXY="localhost,127.0.0.1,::1"
    export no_proxy="localhost,127.0.0.1,::1"
    export HOME="$SHADOW_HOME"

    exec "$@"
}
