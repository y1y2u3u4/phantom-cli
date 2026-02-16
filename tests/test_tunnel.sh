#!/usr/bin/env bash
# Test: Phantom CLI - Tunnel management (tunnel.sh)
# Mock-based: does NOT require actual VPS connection
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

assert_file_exists() {
    local desc="$1" filepath="$2"
    ((TESTS_TOTAL++)) || true
    if [ -f "$filepath" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         File not found: ${filepath}"
        ((TESTS_FAILED++)) || true
    fi
}

assert_not_exists() {
    local desc="$1" filepath="$2"
    ((TESTS_TOTAL++)) || true
    if [ ! -e "$filepath" ] && [ ! -L "$filepath" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         Should not exist: ${filepath}"
        ((TESTS_FAILED++)) || true
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    ((TESTS_TOTAL++)) || true
    if echo "$haystack" | grep -qF -- "$needle"; then
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

# Source config module (needed by tunnel)
source "$PROJECT_ROOT/client/lib/config.sh"

# ── Mock autossh and nc ────────────────────────────────────────────
# Create mock bin directory
MOCK_BIN="$TEST_TMP/mock_bin"
mkdir -p "$MOCK_BIN"

# Track autossh call arguments
AUTOSSH_LOG="$TEST_TMP/autossh_calls.log"

# Mock autossh: launches a background sleep to simulate a daemon
cat > "$MOCK_BIN/autossh" <<'MOCK'
#!/usr/bin/env bash
# Log all arguments
echo "$@" >> "${AUTOSSH_LOG:-/dev/null}"
# Simulate autossh forking a background process
# Start a sleep process that will be our "tunnel"
nohup sleep 300 &>/dev/null &
MOCK
chmod +x "$MOCK_BIN/autossh"

# Mock nc: always report port as open
cat > "$MOCK_BIN/nc" <<'MOCK'
#!/usr/bin/env bash
# If -z flag, simulate port check (always success)
if [[ "$*" == *"-z"* ]]; then
    exit 0
fi
exit 1
MOCK
chmod +x "$MOCK_BIN/nc"

# Mock pgrep to return our sleep PID
cat > "$MOCK_BIN/pgrep" <<MOCK
#!/usr/bin/env bash
# Find sleep processes started by our mock autossh
/usr/bin/pgrep -f "sleep 300" 2>/dev/null | head -1
MOCK
chmod +x "$MOCK_BIN/pgrep"

# Mock pkill (no-op)
cat > "$MOCK_BIN/pkill" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$MOCK_BIN/pkill"

# Prepend mock bin to PATH
export PATH="$MOCK_BIN:$PATH"
export AUTOSSH_LOG

# Source the module under test
source "$PROJECT_ROOT/client/lib/tunnel.sh"

# Initialize config
phantom_config_init

# ── Tests ──────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}Test Suite: tunnel.sh${NC}"
echo "════════════════════════════════════════════"

echo ""
echo -e "${BOLD}_tunnel_is_alive - No PID file${NC}"
echo "────────────────────────────────────────"

# Test: no PID file means tunnel is not alive
rm -f "$TUNNEL_PID_FILE"
rc=0
_tunnel_is_alive || rc=$?
assert_return_code "No PID file: _tunnel_is_alive returns 1" "1" "$rc"

echo ""
echo -e "${BOLD}_tunnel_is_alive - Stale PID file${NC}"
echo "────────────────────────────────────────"

# Test: PID file with non-existent PID
echo "99999999" > "$TUNNEL_PID_FILE"
rc=0
_tunnel_is_alive || rc=$?
assert_return_code "Stale PID: _tunnel_is_alive returns 1" "1" "$rc"

echo ""
echo -e "${BOLD}_tunnel_is_alive - Empty PID file${NC}"
echo "────────────────────────────────────────"

# Test: empty PID file
echo "" > "$TUNNEL_PID_FILE"
rc=0
_tunnel_is_alive || rc=$?
assert_return_code "Empty PID file: _tunnel_is_alive returns 1" "1" "$rc"

echo ""
echo -e "${BOLD}_tunnel_is_alive - Valid PID${NC}"
echo "────────────────────────────────────────"

# Test: PID file with current shell PID (definitely alive)
echo "$$" > "$TUNNEL_PID_FILE"
rc=0
_tunnel_is_alive || rc=$?
assert_return_code "Valid PID ($$): _tunnel_is_alive returns 0" "0" "$rc"

echo ""
echo -e "${BOLD}phantom_tunnel_connect - Command construction${NC}"
echo "────────────────────────────────────────"

# Clean up for connect test
rm -f "$TUNNEL_PID_FILE" "$AUTOSSH_LOG"

# Setup config
phantom_config_set "SERVER_HOST" "10.0.0.1"
phantom_config_set "SERVER_PORT" "2222"
phantom_config_set "SOCKS_PORT" "1080"
phantom_config_set "SSH_KEY" "$HOME/.ssh/id_rsa"

# Create a fake SSH key so validation passes
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/id_rsa"

# Run connect
phantom_tunnel_connect 2>/dev/null || true

# Check autossh was called with correct arguments
if [ -f "$AUTOSSH_LOG" ]; then
    autossh_args=$(cat "$AUTOSSH_LOG")

    # Test: -D flag with correct bind address and port
    assert_contains "autossh uses -D 127.0.0.1:1080" "$autossh_args" "-D 127.0.0.1:1080"

    # Test: correct SSH port
    assert_contains "autossh uses -p 2222" "$autossh_args" "-p 2222"

    # Test: correct SSH key
    assert_contains "autossh uses -i with SSH key" "$autossh_args" "-i $HOME/.ssh/id_rsa"

    # Test: ServerAliveInterval is set
    assert_contains "autossh uses ServerAliveInterval=30" "$autossh_args" "ServerAliveInterval=30"

    # Test: ServerAliveCountMax is set
    assert_contains "autossh uses ServerAliveCountMax=3" "$autossh_args" "ServerAliveCountMax=3"

    # Test: ExitOnForwardFailure is set
    assert_contains "autossh uses ExitOnForwardFailure=yes" "$autossh_args" "ExitOnForwardFailure=yes"

    # Test: connects to root@host
    assert_contains "autossh connects to root@10.0.0.1" "$autossh_args" "root@10.0.0.1"

    # Test: -f flag (background)
    assert_contains "autossh runs in background (-f)" "$autossh_args" "-f"

    # Test: -N flag (no remote command)
    assert_contains "autossh uses -N (no remote command)" "$autossh_args" "-N"
else
    echo -e "  ${RED}[FAIL]${NC} autossh was not called (no log file)"
    ((TESTS_TOTAL += 9)) || true
    ((TESTS_FAILED += 9)) || true
fi

echo ""
echo -e "${BOLD}phantom_tunnel_connect - PID file creation${NC}"
echo "────────────────────────────────────────"

# Test: PID file should have been created
assert_file_exists "PID file created after connect" "$TUNNEL_PID_FILE"

# Test: PID file contains a numeric value
if [ -f "$TUNNEL_PID_FILE" ]; then
    pid_content=$(cat "$TUNNEL_PID_FILE")
    ((TESTS_TOTAL++)) || true
    if [[ "$pid_content" =~ ^[0-9]+$ ]]; then
        echo -e "  ${GREEN}[PASS]${NC} PID file contains numeric PID: ${pid_content}"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} PID file does not contain numeric value: '${pid_content}'"
        ((TESTS_FAILED++)) || true
    fi
fi

echo ""
echo -e "${BOLD}phantom_tunnel_disconnect - Cleanup${NC}"
echo "────────────────────────────────────────"

# Ensure we have a PID file for disconnect test
echo "$$" > "$TUNNEL_PID_FILE"

# Run disconnect (we mock kill/pkill so it won't actually kill our shell)
# Override kill for this test
_original_kill=$(which kill)
kill() {
    # Only pass through -0 (check) and ignore others
    if [ "$1" = "-0" ]; then
        command kill -0 "$2" 2>/dev/null
    fi
    return 0
}

phantom_tunnel_disconnect 2>/dev/null || true

# Restore kill
unset -f kill

# Test: PID file should be removed after disconnect
assert_not_exists "PID file removed after disconnect" "$TUNNEL_PID_FILE"

echo ""
echo -e "${BOLD}phantom_tunnel_disconnect - No PID file${NC}"
echo "────────────────────────────────────────"

# Test: disconnect when no PID file should not error
rm -f "$TUNNEL_PID_FILE"
rc=0
phantom_tunnel_disconnect 2>/dev/null || rc=$?
assert_return_code "Disconnect without PID file returns 0" "0" "$rc"

echo ""
echo -e "${BOLD}phantom_tunnel_connect - Missing config${NC}"
echo "────────────────────────────────────────"

# Test: connect without SERVER_HOST fails
rm -f "$TUNNEL_PID_FILE"
rm -rf "$PHANTOM_DIR"
phantom_config_init
# SERVER_HOST is empty by default
rc=0
phantom_tunnel_connect 2>/dev/null || rc=$?
assert_return_code "Connect without SERVER_HOST returns 1" "1" "$rc"

echo ""
echo -e "${BOLD}phantom_tunnel_connect - Missing SSH key${NC}"
echo "────────────────────────────────────────"

# Test: connect with non-existent SSH key fails
rm -f "$TUNNEL_PID_FILE"
phantom_config_set "SERVER_HOST" "10.0.0.1"
phantom_config_set "SSH_KEY" "/nonexistent/key"
rc=0
phantom_tunnel_connect 2>/dev/null || rc=$?
assert_return_code "Connect with missing SSH key returns 1" "1" "$rc"

echo ""
echo -e "${BOLD}phantom_tunnel_ensure - Auto connect${NC}"
echo "────────────────────────────────────────"

# Clean up
rm -f "$TUNNEL_PID_FILE" "$AUTOSSH_LOG"
phantom_config_set "SERVER_HOST" "10.0.0.1"
phantom_config_set "SSH_KEY" "$HOME/.ssh/id_rsa"
phantom_config_set "AUTO_CONNECT" "true"
touch "$HOME/.ssh/id_rsa"

# Ensure tunnel is not alive
rm -f "$TUNNEL_PID_FILE"
phantom_tunnel_ensure 2>/dev/null || true

# Test: with AUTO_CONNECT=true, ensure triggers connect
assert_file_exists "Auto-connect creates PID file" "$TUNNEL_PID_FILE"

echo ""
echo -e "${BOLD}phantom_tunnel_ensure - Auto connect disabled${NC}"
echo "────────────────────────────────────────"

# Clean up
rm -f "$TUNNEL_PID_FILE"
phantom_config_set "AUTO_CONNECT" "false"

rc=0
phantom_tunnel_ensure 2>/dev/null || rc=$?
assert_return_code "Ensure with AUTO_CONNECT=false returns 1 when disconnected" "1" "$rc"

# ── Cleanup mock processes ─────────────────────────────────────────
# Kill any sleep 300 processes we created
/usr/bin/pkill -f "sleep 300" 2>/dev/null || true

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
