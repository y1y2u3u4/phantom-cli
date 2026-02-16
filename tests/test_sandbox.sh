#!/usr/bin/env bash
# Test: Phantom CLI - Shadow sandbox (sandbox.sh)
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

assert_symlink() {
    local desc="$1" filepath="$2"
    ((TESTS_TOTAL++)) || true
    if [ -L "$filepath" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $desc"
        ((TESTS_PASSED++)) || true
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         Not a symlink: ${filepath}"
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

assert_symlink_target() {
    local desc="$1" filepath="$2" expected_target="$3"
    ((TESTS_TOTAL++)) || true
    if [ -L "$filepath" ]; then
        local actual_target
        actual_target=$(readlink "$filepath")
        if [ "$actual_target" = "$expected_target" ]; then
            echo -e "  ${GREEN}[PASS]${NC} $desc"
            ((TESTS_PASSED++)) || true
        else
            echo -e "  ${RED}[FAIL]${NC} $desc"
            echo -e "         Expected target: '${expected_target}'"
            echo -e "         Actual target:   '${actual_target}'"
            ((TESTS_FAILED++)) || true
        fi
    else
        echo -e "  ${RED}[FAIL]${NC} $desc"
        echo -e "         Not a symlink: ${filepath}"
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

# Source the module under test
source "$PROJECT_ROOT/client/lib/sandbox.sh"

# ── Tests ──────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}Test Suite: sandbox.sh${NC}"
echo "════════════════════════════════════════════"

echo ""
echo -e "${BOLD}phantom_sandbox_setup - Directory creation${NC}"
echo "────────────────────────────────────────"

# Test: creates shadow home directory
phantom_sandbox_setup
assert_dir_exists "Creates SHADOW_HOME directory" "$SHADOW_HOME"

echo ""
echo -e "${BOLD}phantom_sandbox_setup - Symlinks${NC}"
echo "────────────────────────────────────────"

# Create fixture files in fake HOME
touch "$HOME/.gitconfig"
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/id_rsa"
touch "$HOME/.npmrc"
touch "$HOME/.yarnrc"
touch "$HOME/.bashrc"
touch "$HOME/.zshrc"
mkdir -p "$HOME/.aws"
mkdir -p "$HOME/.kube"

# Re-run setup to create symlinks
rm -rf "$SHADOW_HOME"
phantom_sandbox_setup

# Test: .gitconfig is symlinked
assert_symlink ".gitconfig is symlinked" "$SHADOW_HOME/.gitconfig"
assert_symlink_target ".gitconfig points to real HOME" "$SHADOW_HOME/.gitconfig" "$HOME/.gitconfig"

# Test: .ssh is symlinked
assert_symlink ".ssh is symlinked" "$SHADOW_HOME/.ssh"
assert_symlink_target ".ssh points to real HOME" "$SHADOW_HOME/.ssh" "$HOME/.ssh"

# Test: .npmrc is symlinked
assert_symlink ".npmrc is symlinked" "$SHADOW_HOME/.npmrc"

# Test: .yarnrc is symlinked
assert_symlink ".yarnrc is symlinked" "$SHADOW_HOME/.yarnrc"

# Test: .bashrc is symlinked
assert_symlink ".bashrc is symlinked" "$SHADOW_HOME/.bashrc"

# Test: .zshrc is symlinked
assert_symlink ".zshrc is symlinked" "$SHADOW_HOME/.zshrc"

# Test: .aws is symlinked
assert_symlink ".aws is symlinked" "$SHADOW_HOME/.aws"

# Test: .kube is symlinked
assert_symlink ".kube is symlinked" "$SHADOW_HOME/.kube"

echo ""
echo -e "${BOLD}phantom_sandbox_setup - Isolation boundary${NC}"
echo "────────────────────────────────────────"

# Create .claude.json and .claude/ in real HOME
touch "$HOME/.claude.json"
mkdir -p "$HOME/.claude"

# Re-run setup
phantom_sandbox_setup

# Test: .claude.json is NOT symlinked
assert_not_exists ".claude.json is NOT symlinked in sandbox" "$SHADOW_HOME/.claude.json"

# Test: .claude/ is NOT symlinked
assert_not_exists ".claude/ is NOT symlinked in sandbox" "$SHADOW_HOME/.claude"

# Test: forcibly planted forbidden symlinks are removed
ln -sf "$HOME/.claude.json" "$SHADOW_HOME/.claude.json"
ln -sf "$HOME/.claude" "$SHADOW_HOME/.claude"
# Re-run setup should clean them up
log_warn() { :; }  # suppress warning about removal
phantom_sandbox_setup
assert_not_exists ".claude.json symlink is removed by setup" "$SHADOW_HOME/.claude.json"
assert_not_exists ".claude/ symlink is removed by setup" "$SHADOW_HOME/.claude"

echo ""
echo -e "${BOLD}phantom_sandbox_setup - Non-existent items skipped${NC}"
echo "────────────────────────────────────────"

# Create a fresh HOME without some dotfiles
rm -rf "$SHADOW_HOME"
export HOME="$TEST_TMP/home_sparse"
mkdir -p "$HOME"
export SHADOW_HOME="$HOME/.phantom_env"

# Only create .gitconfig - all other dotfiles missing
touch "$HOME/.gitconfig"

phantom_sandbox_setup

# Test: .gitconfig is still symlinked when present
assert_symlink ".gitconfig present and symlinked" "$SHADOW_HOME/.gitconfig"

# Test: missing items are gracefully skipped (no .ssh means no symlink)
assert_not_exists ".ssh not symlinked when missing from HOME" "$SHADOW_HOME/.ssh"
assert_not_exists ".npmrc not symlinked when missing from HOME" "$SHADOW_HOME/.npmrc"
assert_not_exists ".aws not symlinked when missing from HOME" "$SHADOW_HOME/.aws"

echo ""
echo -e "${BOLD}phantom_sandbox_setup - Idempotency${NC}"
echo "────────────────────────────────────────"

# Run setup twice - should not error
phantom_sandbox_setup
phantom_sandbox_setup
assert_dir_exists "Double setup still has SHADOW_HOME" "$SHADOW_HOME"
assert_symlink ".gitconfig still symlinked after double setup" "$SHADOW_HOME/.gitconfig"

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
