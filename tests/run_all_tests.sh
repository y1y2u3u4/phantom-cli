#!/usr/bin/env bash
# Run all Phantom CLI tests and report results
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║       Phantom CLI - Test Suite Runner        ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0
FAILED_NAMES=()

run_test() {
    local test_file="$1"
    local test_name
    test_name=$(basename "$test_file" .sh)

    ((TOTAL_SUITES++)) || true

    echo -e "${BOLD}▶ Running: ${test_name}${NC}"
    echo ""

    if bash "$test_file"; then
        ((PASSED_SUITES++)) || true
        echo ""
        echo -e "  ${GREEN}✓ ${test_name} passed${NC}"
    else
        ((FAILED_SUITES++)) || true
        FAILED_NAMES+=("$test_name")
        echo ""
        echo -e "  ${RED}✗ ${test_name} FAILED${NC}"
    fi
    echo ""
    echo "──────────────────────────────────────────────"
    echo ""
}

# Run each test suite
for test_file in "$SCRIPT_DIR"/test_*.sh; do
    if [ -f "$test_file" ]; then
        run_test "$test_file"
    fi
done

# ── Overall Summary ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║              Overall Results                 ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Test suites: ${TOTAL_SUITES}"
echo -e "  Passed:      ${GREEN}${PASSED_SUITES}${NC}"
echo -e "  Failed:      ${RED}${FAILED_SUITES}${NC}"

if [ "$FAILED_SUITES" -gt 0 ]; then
    echo ""
    echo -e "  ${RED}Failed suites:${NC}"
    for name in "${FAILED_NAMES[@]}"; do
        echo -e "    ${RED}✗ ${name}${NC}"
    done
    echo ""
    echo -e "${RED}${BOLD}TESTS FAILED${NC}"
    exit 1
else
    echo ""
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
