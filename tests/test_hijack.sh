#!/usr/bin/env bash
# Test: Phantom CLI - Network hijack (hijack.sh)
set -euo pipefail

# ── Test Framework ─────────────────────────────────────────────────
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

assert_equals() {
    local desc="$1" expected="$2" actual="$3"
    ((TESTS_TOTAL++)) || true
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         Expected: '${expected}'"
        echo -e "         Actual:   '${actual}'"
        ((TESTS_FAILED++)) || true
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    ((TESTS_TOTAL++)) || true
    if echo "$haystack" | grep -qF "$needle"; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         '${needle}' not found in output"
        ((TESTS_FAILED++)) || true
    fi
}

assert_return_code() {
    local desc="$1" expected="$2" actual="$3"
    ((TESTS_TOTAL++)) || true
    if [ "$expected" = "$actual" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         Expected return code: ${expected}, got: ${actual}"
        ((TESTS_FAILED++)) || true
    fi
}

# ── Setup ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Create temp directory for test isolation
TEST_TMP=$(mktemp -d)
trap 'rm -rf "$TEST_TMP"' EXIT

# Override HOME and PHANTOM vars for test isolation
export HOME="$TEST_TMP/home"
mkdir -p "$HOME"
export PHANTOM_DIR="$HOME/.phantom"
export PHANTOM_CONFIG="$PHANTOM_DIR/config"
export SHADOW_HOME="$HOME/.phantom_env"

# Stub log functions
log_info()    { :; }
log_success() { :; }
log_warn()    { :; }
log_error()   { :; }

# Source config module (needed by hijack)
source "$PROJECT_ROOT/client/lib/config.sh"

# Source sandbox module (needed by hijack)
source "$PROJECT_ROOT/client/lib/sandbox.sh"

# We need to mock phantom_tunnel_ensure since we can't establish real tunnels
# and we need to avoid sourcing tunnel.sh which sets TUNNEL_PID_FILE using PHANTOM_DIR
TUNNEL_PID_FILE="$PHANTOM_DIR/tunnel.pid"
phantom_tunnel_ensure() { return 0; }

# Source the module under test
source "$PROJECT_ROOT/client/lib/hijack.sh"

# ── Helper ─────────────────────────────────────────────────────────
# Since phantom_hijack_exec uses exec, we test it by replacing exec with
# a function that captures the environment instead of replacing the process.
# We'll create a wrapper that captures env vars and the command.

# Write a test helper script that prints env vars
cat > "$TEST_TMP/capture_env.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo "HTTP_PROXY=$HTTP_PROXY"
echo "HTTPS_PROXY=$HTTPS_PROXY"
echo "ALL_PROXY=$ALL_PROXY"
echo "http_proxy=$http_proxy"
echo "https_proxy=$https_proxy"
echo "all_proxy=$all_proxy"
echo "NO_PROXY=$NO_PROXY"
echo "no_proxy=$no_proxy"
echo "HOME=$HOME"
SCRIPT
chmod +x "$TEST_TMP/capture_env.sh"

# Override exec to capture instead of replace process
exec() {
    "$@"
}

# ── Tests ──────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}Test Suite: hijack.sh${NC}"
echo "════════════════════════════════════════════"

echo ""
echo -e "${BOLD}phantom_hijack_exec - No auth (default)${NC}"
echo "────────────────────────────────────────"

# Setup config with no auth
phantom_config_init
phantom_config_set "SOCKS_PORT" "1080"
phantom_config_set "SOCKS_USER" ""
phantom_config_set "SOCKS_PASS" ""

# Create shadow home so the check passes
mkdir -p "$SHADOW_HOME"

# Capture environment from hijack exec
output=$(phantom_hijack_exec "$TEST_TMP/capture_env.sh" 2>/dev/null || true)

# Test: socks5h:// scheme is used (remote DNS)
assert_contains "HTTP_PROXY uses socks5h:// scheme" "$output" "HTTP_PROXY=socks5h://"
assert_contains "HTTPS_PROXY uses socks5h:// scheme" "$output" "HTTPS_PROXY=socks5h://"
assert_contains "ALL_PROXY uses socks5h:// scheme" "$output" "ALL_PROXY=socks5h://"

# Test: lowercase variants also set
assert_contains "http_proxy (lowercase) is set" "$output" "http_proxy=socks5h://"
assert_contains "https_proxy (lowercase) is set" "$output" "https_proxy=socks5h://"
assert_contains "all_proxy (lowercase) is set" "$output" "all_proxy=socks5h://"

# Test: proxy URL without auth
assert_contains "Proxy URL is socks5h://127.0.0.1:1080 (no auth)" "$output" "socks5h://127.0.0.1:1080"

# Test: NO_PROXY includes localhost
assert_contains "NO_PROXY includes localhost" "$output" "NO_PROXY=localhost,127.0.0.1,::1"
assert_contains "no_proxy includes localhost" "$output" "no_proxy=localhost,127.0.0.1,::1"

# Test: HOME is switched to shadow home
assert_contains "HOME is set to SHADOW_HOME" "$output" "HOME=$SHADOW_HOME"

echo ""
echo -e "${BOLD}phantom_hijack_exec - With SOCKS5 auth${NC}"
echo "────────────────────────────────────────"

# Setup config with auth credentials
phantom_config_set "SOCKS_PORT" "1080"
phantom_config_set "SOCKS_USER" "dev01"
phantom_config_set "SOCKS_PASS" "s3cret"

output=$(phantom_hijack_exec "$TEST_TMP/capture_env.sh" 2>/dev/null || true)

# Test: SOCKS5 auth credentials are included in proxy URL
assert_contains "Proxy URL includes username" "$output" "dev01"
assert_contains "Proxy URL includes password" "$output" "s3cret"
assert_contains "Proxy URL format is socks5h://user:pass@host:port" "$output" "socks5h://dev01:s3cret@127.0.0.1:1080"

echo ""
echo -e "${BOLD}phantom_hijack_exec - Custom port${NC}"
echo "────────────────────────────────────────"

# Setup config with custom port
phantom_config_set "SOCKS_PORT" "9090"
phantom_config_set "SOCKS_USER" ""
phantom_config_set "SOCKS_PASS" ""

output=$(phantom_hijack_exec "$TEST_TMP/capture_env.sh" 2>/dev/null || true)

# Test: custom port is used
assert_contains "Custom SOCKS_PORT 9090 is used in proxy URL" "$output" "socks5h://127.0.0.1:9090"

echo ""
echo -e "${BOLD}phantom_hijack_exec - No command error${NC}"
echo "────────────────────────────────────────"

# Test: no command specified returns error
rc=0
phantom_hijack_exec 2>/dev/null || rc=$?
assert_return_code "No command returns exit code 1" "1" "$rc"

echo ""
echo -e "${BOLD}phantom_hijack_exec - Sandbox auto-creation${NC}"
echo "────────────────────────────────────────"

# Remove shadow home and verify it gets created
rm -rf "$SHADOW_HOME"
phantom_config_set "SOCKS_PORT" "1080"
phantom_config_set "SOCKS_USER" ""
phantom_config_set "SOCKS_PASS" ""

# Reset HOME dotfiles for sandbox
touch "$HOME/.gitconfig"

output=$(phantom_hijack_exec "$TEST_TMP/capture_env.sh" 2>/dev/null || true)

assert_contains "HOME points to SHADOW_HOME after auto-creation" "$output" "HOME=$SHADOW_HOME"

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo -e "  Total:  ${TESTS_TOTAL}"
echo -e "  Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "  Failed: ${RED}${TESTS_FAILED}${NC}"
echo "════════════════════════════════════════════"

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
