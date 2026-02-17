#!/usr/bin/env bash
# Test: Phantom CLI - Config management (config.sh)
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

assert_dir_exists() {
    local desc="$1" dirpath="$2"
    ((TESTS_TOTAL++)) || true
    if [ -d "$dirpath" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         Directory not found: ${dirpath}"
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

# Stub log functions (suppress output during tests)
log_info()    { :; }
log_success() { :; }
log_warn()    { :; }
log_error()   { :; }

# Source the module under test
source "$PROJECT_ROOT/client/lib/config.sh"

# ── Tests ──────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}Test Suite: config.sh${NC}"
echo "════════════════════════════════════════════"

echo ""
echo -e "${BOLD}phantom_config_init${NC}"
echo "────────────────────────────────────────"

# Test: creates config directory
phantom_config_init
assert_dir_exists "Creates PHANTOM_DIR directory" "$PHANTOM_DIR"

# Test: creates config file
assert_file_exists "Creates config file" "$PHANTOM_CONFIG"

# Test: config file contains default SERVER_PORT
content=$(cat "$PHANTOM_CONFIG")
assert_contains "Config has default SERVER_PORT=22" "$content" "SERVER_PORT=22"

# Test: config file contains default SOCKS_PORT
assert_contains "Config has default HTTP_PROXY_PORT=8080" "$content" "HTTP_PROXY_PORT=8080"

# Test: config file contains default SSH_KEY
assert_contains "Config has default SSH_KEY=~/.ssh/id_rsa" "$content" "SSH_KEY=~/.ssh/id_rsa"

# Test: config file contains default AUTO_CONNECT
assert_contains "Config has default AUTO_CONNECT=true" "$content" "AUTO_CONNECT=true"

# Test: config file contains default AUTO_RECONNECT
assert_contains "Config has default AUTO_RECONNECT=true" "$content" "AUTO_RECONNECT=true"

# Test: config file has empty SERVER_HOST
assert_contains "Config has empty SERVER_HOST=" "$content" "SERVER_HOST="

# Test: idempotent - calling init again doesn't overwrite
phantom_config_set "SERVER_HOST" "1.2.3.4"
phantom_config_init
new_content=$(cat "$PHANTOM_CONFIG")
assert_contains "Init is idempotent (does not overwrite existing config)" "$new_content" "SERVER_HOST=1.2.3.4"

echo ""
echo -e "${BOLD}phantom_config_set${NC}"
echo "────────────────────────────────────────"

# Reset config for set tests
rm -rf "$PHANTOM_DIR"
phantom_config_init

# Test: set a new value
phantom_config_set "SERVER_HOST" "10.0.0.1"
result=$(grep "^SERVER_HOST=" "$PHANTOM_CONFIG" | cut -d'=' -f2-)
assert_equals "Set SERVER_HOST to 10.0.0.1" "10.0.0.1" "$result"

# Test: update an existing value
phantom_config_set "SERVER_HOST" "192.168.1.100"
result=$(grep "^SERVER_HOST=" "$PHANTOM_CONFIG" | cut -d'=' -f2-)
assert_equals "Update SERVER_HOST to 192.168.1.100" "192.168.1.100" "$result"

# Test: set SOCKS_PORT
phantom_config_set "SOCKS_PORT" "8080"
result=$(grep "^SOCKS_PORT=" "$PHANTOM_CONFIG" | cut -d'=' -f2-)
assert_equals "Set SOCKS_PORT to 8080" "8080" "$result"

# Test: set a custom/new key
phantom_config_set "CUSTOM_KEY" "custom_value"
result=$(grep "^CUSTOM_KEY=" "$PHANTOM_CONFIG" | cut -d'=' -f2-)
assert_equals "Set custom key CUSTOM_KEY" "custom_value" "$result"

# Test: set creates config if it doesn't exist
rm -rf "$PHANTOM_DIR"
phantom_config_set "SERVER_HOST" "new-host"
assert_file_exists "Set creates config file if not existing" "$PHANTOM_CONFIG"
result=$(grep "^SERVER_HOST=" "$PHANTOM_CONFIG" | cut -d'=' -f2-)
assert_equals "Set value persists after auto-creating config" "new-host" "$result"

echo ""
echo -e "${BOLD}phantom_config_get${NC}"
echo "────────────────────────────────────────"

# Reset config for get tests
rm -rf "$PHANTOM_DIR"
phantom_config_init

# Test: get default value
phantom_config_set "SERVER_PORT" "22"
result=$(phantom_config_get "SERVER_PORT")
assert_equals "Get SERVER_PORT returns 22" "22" "$result"

# Test: get set value
phantom_config_set "SERVER_HOST" "my-vps.example.com"
result=$(phantom_config_get "SERVER_HOST")
assert_equals "Get SERVER_HOST returns set value" "my-vps.example.com" "$result"

# Test: get non-existent key returns error
rc=0
phantom_config_get "NONEXISTENT_KEY" >/dev/null 2>&1 || rc=$?
assert_return_code "Get non-existent key returns exit code 1" "1" "$rc"

# Test: get with no config file returns error
rm -f "$PHANTOM_CONFIG"
rc=0
phantom_config_get "SERVER_HOST" >/dev/null 2>&1 || rc=$?
assert_return_code "Get with missing config returns exit code 1" "1" "$rc"

# Test: tilde expansion in paths
rm -rf "$PHANTOM_DIR"
phantom_config_init
phantom_config_set "SSH_KEY" "~/.ssh/id_rsa"
result=$(phantom_config_get "SSH_KEY")
expected="$HOME/.ssh/id_rsa"
assert_equals "Tilde is expanded in path values" "$expected" "$result"

# Test: get empty value returns error
rm -rf "$PHANTOM_DIR"
phantom_config_init
# SERVER_HOST= is empty by default
rc=0
phantom_config_get "SERVER_HOST" >/dev/null 2>&1 || rc=$?
assert_return_code "Get empty value returns exit code 1" "1" "$rc"

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
