#!/usr/bin/env bash
# Phantom CLI - Diagnostic checks
# Verifies all components are working correctly

phantom_doctor_run() {
    echo -e "${BOLD}Phantom Doctor${NC}"
    echo "────────────────────────────────────────"
    echo ""

    local issues=0

    # Load config early for mode-aware checks
    local server_host http_proxy_port connection_mode proxy_host
    server_host=$(phantom_config_get "SERVER_HOST" 2>/dev/null || echo "")
    http_proxy_port=$(phantom_config_get "HTTP_PROXY_PORT" 2>/dev/null || echo "8080")
    connection_mode=$(phantom_config_get "CONNECTION_MODE" 2>/dev/null || echo "direct")
    if [ "$connection_mode" = "tunnel" ]; then
        proxy_host="127.0.0.1"
    elif [ "$connection_mode" = "auto" ] && _tunnel_is_alive; then
        proxy_host="127.0.0.1"
    else
        proxy_host="$server_host"
    fi

    # 1. Check dependencies
    echo -e "${BOLD}Dependencies${NC}"
    _doctor_check "nc (netcat) installed" \
        "command -v nc &>/dev/null" \
        "Netcat should be pre-installed on macOS"
    issues=$((issues + $?))

    _doctor_check "curl installed" \
        "command -v curl &>/dev/null" \
        "Install with: brew install curl"
    issues=$((issues + $?))

    if [ "$connection_mode" = "tunnel" ] || [ "$connection_mode" = "auto" ]; then
        _doctor_check "ssh installed" \
            "command -v ssh &>/dev/null" \
            "SSH should be pre-installed on macOS"
        issues=$((issues + $?))

        local ssh_password
        ssh_password=$(phantom_config_get "SSH_PASSWORD" 2>/dev/null || echo "")
        if [ -n "$ssh_password" ]; then
            _doctor_check "sshpass installed (needed for SSH password tunnel)" \
                "command -v sshpass &>/dev/null" \
                "Install with: brew install hudochenkov/sshpass/sshpass"
            issues=$((issues + $?))
        else
            local ssh_key
            ssh_key=$(phantom_config_get "SSH_KEY" 2>/dev/null || echo "$HOME/.ssh/id_rsa")
            if [ ! -f "$ssh_key" ] && [ ! -f "$HOME/.ssh/id_ed25519" ]; then
                echo -e "  ${YELLOW}[warn]${NC} No SSH_PASSWORD or SSH key found for tunnel mode"
                echo -e "         ${YELLOW}Fix: phantom config SSH_PASSWORD <vps_password>${NC}"
                issues=$((issues + 1))
            fi
        fi
    else
        echo -e "  ${CYAN}[skip]${NC} ssh/sshpass (not needed in direct mode)"
    fi

    # 2. Check config
    echo ""
    echo -e "${BOLD}Configuration${NC}"
    _doctor_check "Config file exists" \
        "[ -f '$PHANTOM_CONFIG' ]" \
        "Run: phantom setup <VPS_IP>"
    issues=$((issues + $?))

    if [ -n "$server_host" ]; then
        echo -e "  ${GREEN}[pass]${NC} SERVER_HOST = ${CYAN}${server_host}${NC}"
    else
        echo -e "  ${RED}[fail]${NC} SERVER_HOST not set"
        echo -e "         ${YELLOW}Fix: phantom setup <VPS_IP>${NC}"
        issues=$((issues + 1))
    fi

    echo -e "  ${CYAN}[info]${NC} Mode: ${BOLD}${connection_mode}${NC}, Port: ${http_proxy_port}"

    # 3. Tunnel checks (tunnel or auto mode)
    if [ "$connection_mode" = "tunnel" ] || [ "$connection_mode" = "auto" ]; then
        echo ""
        echo -e "${BOLD}SSH Tunnel${NC}"
        if _tunnel_is_alive; then
            local tunnel_pid
            tunnel_pid=$(cat "$TUNNEL_PID_FILE" 2>/dev/null || echo "?")
            echo -e "  ${GREEN}[pass]${NC} Tunnel is connected (PID: $tunnel_pid)"
        elif [ "$connection_mode" = "tunnel" ]; then
            echo -e "  ${RED}[fail]${NC} Tunnel is not connected"
            echo -e "         ${YELLOW}Fix: phantom connect${NC}"
            issues=$((issues + 1))
        else
            echo -e "  ${CYAN}[info]${NC} Tunnel not active (auto mode — will connect if needed)"
        fi
    fi

    # 4. Check proxy connectivity
    echo ""
    echo -e "${BOLD}Proxy Connection${NC}"
    _doctor_check "HTTP proxy reachable (${proxy_host}:${http_proxy_port})" \
        "nc -z -w 3 $proxy_host $http_proxy_port 2>/dev/null" \
        "Check VPS: ssh root@${server_host} systemctl status phantom-http-proxy"
    issues=$((issues + $?))

    # Health API check (HTTP GET — not affected by CONNECT interception)
    if nc -z -w 3 "$proxy_host" "$http_proxy_port" 2>/dev/null; then
        local health_resp
        health_resp=$(curl -s --max-time 5 "http://${proxy_host}:${http_proxy_port}/api/health" 2>/dev/null || echo "")
        if echo "$health_resp" | grep -q '"ok"' 2>/dev/null; then
            echo -e "  ${GREEN}[pass]${NC} Health API responds OK"
        else
            echo -e "  ${YELLOW}[warn]${NC} Health API unavailable (proxy may still work)"
        fi
    fi

    # CONNECT tunnel test (detects Cloudflare/enterprise interception)
    echo ""
    echo -e "${BOLD}CONNECT Tunnel${NC}"
    local connect_test_host="$server_host"
    if _tunnel_is_alive; then
        connect_test_host="127.0.0.1"
    fi
    if nc -z -w 3 "$connect_test_host" "$http_proxy_port" 2>/dev/null; then
        local api_key connect_proxy_url
        api_key=$(phantom_config_get "API_KEY" 2>/dev/null || echo "")
        if [ -n "$api_key" ]; then
            connect_proxy_url="http://${api_key}:x@${connect_test_host}:${http_proxy_port}"
        else
            connect_proxy_url="http://${connect_test_host}:${http_proxy_port}"
        fi

        local connect_resp
        connect_resp=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" \
            --proxy "$connect_proxy_url" \
            "https://api.anthropic.com/api/oauth/usage" 2>/dev/null) || true
        [ -z "$connect_resp" ] && connect_resp="000"

        if [ "$connect_resp" != "000" ] && [ "$connect_resp" != "400" ]; then
            echo -e "  ${GREEN}[pass]${NC} CONNECT tunnel works (HTTP $connect_resp via ${connect_test_host})"
        else
            echo -e "  ${RED}[fail]${NC} CONNECT blocked (HTTP $connect_resp) — Cloudflare/enterprise proxy detected"
            if [ "$connect_test_host" = "$server_host" ]; then
                echo -e "         ${YELLOW}Fix: phantom config SSH_PASSWORD <vps_password>${NC}"
                echo -e "         ${YELLOW}Then: phantom connect (creates SSH tunnel to bypass)${NC}"
            else
                echo -e "         ${YELLOW}CONNECT fails even through tunnel — check VPS proxy${NC}"
            fi
            issues=$((issues + 1))
        fi
    else
        echo -e "  ${YELLOW}[skip]${NC} Cannot test CONNECT (proxy not reachable)"
    fi

    # 5. Check sandbox
    _doctor_check "Shadow sandbox exists" \
        "[ -d '$SHADOW_HOME' ]" \
        "Run: phantom setup <VPS_IP>"
    issues=$((issues + $?))

    # 6. Network test (only if proxy is reachable)
    if nc -z -w 3 "$proxy_host" "$http_proxy_port" 2>/dev/null; then
        echo ""
        echo -e "${BOLD}Network Tests${NC}"

        local proxy_url="http://${proxy_host}:${http_proxy_port}"

        local proxy_ip
        proxy_ip=$(curl -s --max-time 10 --proxy "$proxy_url" https://ifconfig.me 2>/dev/null || echo "")
        local local_ip
        local_ip=$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null || echo "")

        if [ -n "$proxy_ip" ]; then
            echo -e "  ${GREEN}[pass]${NC} Proxy IP: ${CYAN}${proxy_ip}${NC}"
            if [ "$proxy_ip" != "$local_ip" ]; then
                echo -e "  ${GREEN}[pass]${NC} IP differs from local (${local_ip}) - no leak detected"
            else
                echo -e "  ${YELLOW}[warn]${NC} Proxy IP matches local IP - possible leak!"
                issues=$((issues + 1))
            fi
        else
            echo -e "  ${RED}[fail]${NC} Could not reach external service through proxy"
            issues=$((issues + 1))
        fi
    fi

    # 7. Proxy conflict detection
    echo ""
    echo -e "${BOLD}Conflict Detection${NC}"
    _doctor_check_conflict "Clash" "clash"
    _doctor_check_conflict "ClashX" "clashx"
    _doctor_check_conflict "Surge" "surge"
    _doctor_check_conflict "V2Ray" "v2ray"
    _doctor_check_conflict "Shadowsocks" "ss-local"
    _doctor_check_conflict "Trojan" "trojan"
    _doctor_check_conflict "Cloudflared" "cloudflared"

    # Summary
    echo ""
    echo "────────────────────────────────────────"
    if [ "$issues" -eq 0 ]; then
        log_success "All checks passed!"
    else
        log_warn "${issues} issue(s) found. Fix them and run phantom doctor again."
    fi

    return "$issues"
}

# ── Internal helpers ────────────────────────────────────────────────

# Run a diagnostic check
# Usage: _doctor_check "description" "test_command" "fix_hint"
_doctor_check() {
    local desc="$1"
    local test_cmd="$2"
    local hint="$3"

    if eval "$test_cmd"; then
        echo -e "  ${GREEN}[pass]${NC} $desc"
        return 0
    else
        echo -e "  ${RED}[fail]${NC} $desc"
        echo -e "         ${YELLOW}Fix: $hint${NC}"
        return 1
    fi
}

# Check for conflicting proxy processes
_doctor_check_conflict() {
    local name="$1"
    local process="$2"

    if pgrep -iq "$process" 2>/dev/null; then
        echo -e "  ${YELLOW}[warn]${NC} $name is running - may conflict with Phantom proxy"
        echo -e "         ${YELLOW}Consider disabling $name while using Phantom${NC}"
    else
        echo -e "  ${GREEN}[pass]${NC} No $name detected"
    fi
}
