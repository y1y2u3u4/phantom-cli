#!/usr/bin/env bash
# Phantom CLI - Diagnostic checks
# Verifies all components are working correctly

phantom_doctor_run() {
    echo -e "${BOLD}Phantom Doctor${NC}"
    echo "────────────────────────────────────────"
    echo ""

    local issues=0

    # 1. Check dependencies
    _doctor_check "autossh installed" \
        "command -v autossh &>/dev/null" \
        "Install with: brew install autossh"
    issues=$((issues + $?))

    _doctor_check "ssh installed" \
        "command -v ssh &>/dev/null" \
        "SSH should be pre-installed on macOS"
    issues=$((issues + $?))

    _doctor_check "nc (netcat) installed" \
        "command -v nc &>/dev/null" \
        "Netcat should be pre-installed on macOS"
    issues=$((issues + $?))

    _doctor_check "curl installed" \
        "command -v curl &>/dev/null" \
        "Install with: brew install curl"
    issues=$((issues + $?))

    # 2. Check config
    _doctor_check "Config file exists" \
        "[ -f '$PHANTOM_CONFIG' ]" \
        "Run: phantom init"
    issues=$((issues + $?))

    # 3. Check SSH key
    local ssh_key
    ssh_key=$(phantom_config_get "SSH_KEY" 2>/dev/null || echo "$HOME/.ssh/id_rsa")
    _doctor_check "SSH key exists ($ssh_key)" \
        "[ -f '$ssh_key' ]" \
        "Generate with: ssh-keygen -t ed25519 -f $ssh_key"
    issues=$((issues + $?))

    # 4. Check tunnel
    _doctor_check "Tunnel is connected" \
        "_tunnel_is_alive" \
        "Run: phantom connect"
    issues=$((issues + $?))

    # 5. Check SOCKS5 port
    local socks_port
    socks_port=$(phantom_config_get "SOCKS_PORT" 2>/dev/null || echo "1080")
    _doctor_check "SOCKS5 port reachable (127.0.0.1:${socks_port})" \
        "nc -z 127.0.0.1 $socks_port 2>/dev/null" \
        "Tunnel may not be running. Run: phantom connect"
    issues=$((issues + $?))

    # 6. Check sandbox
    _doctor_check "Shadow sandbox exists" \
        "[ -d '$SHADOW_HOME' ]" \
        "Run: phantom init"
    issues=$((issues + $?))

    # 7. DNS leak check (only if tunnel is up)
    if _tunnel_is_alive && nc -z 127.0.0.1 "$socks_port" 2>/dev/null; then
        echo ""
        echo -e "${BOLD}Network Tests${NC}"
        echo "────────────────────────────────────────"

        local socks_user socks_pass proxy_url
        socks_user=$(phantom_config_get "SOCKS_USER" 2>/dev/null || echo "")
        socks_pass=$(phantom_config_get "SOCKS_PASS" 2>/dev/null || echo "")

        if [ -n "$socks_user" ] && [ -n "$socks_pass" ]; then
            proxy_url="socks5h://${socks_user}:${socks_pass}@127.0.0.1:${socks_port}"
        else
            proxy_url="socks5h://127.0.0.1:${socks_port}"
        fi

        # Check external IP through proxy
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

    # 8. Proxy conflict detection
    echo ""
    echo -e "${BOLD}Conflict Detection${NC}"
    echo "────────────────────────────────────────"
    _doctor_check_conflict "Clash" "clash"
    _doctor_check_conflict "ClashX" "clashx"
    _doctor_check_conflict "Surge" "surge"
    _doctor_check_conflict "V2Ray" "v2ray"
    _doctor_check_conflict "Shadowsocks" "ss-local"
    _doctor_check_conflict "Trojan" "trojan"

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
