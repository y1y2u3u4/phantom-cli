#!/usr/bin/env bash
# Phantom CLI - Installer
# Copies phantom + lib/ to /usr/local/bin/phantom-cli/ and creates symlink
#
# Usage:
#   bash install.sh                                  # Install only
#   bash install.sh 1.2.3.4 --key sk-phantom-xxx    # Install + auto-configure
#   bash install.sh 1.2.3.4 --port 9090 --key xxx   # With custom port

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin/phantom-cli"
SYMLINK_PATH="/usr/local/bin/phantom"

log_info()    { echo -e "${CYAN}[info]${NC} $*"; }
log_success() { echo -e "${GREEN}[ok]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
log_error()   { echo -e "${RED}[error]${NC} $*" >&2; }

# Parse install arguments (VPS_IP and setup flags are forwarded to phantom setup)
SETUP_ARGS=()
for arg in "$@"; do
    SETUP_ARGS+=("$arg")
done

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}Phantom CLI Installer${NC}"
echo "────────────────────────────────────────"
echo ""

# Check for required dependencies (autossh only needed for tunnel mode)
check_dep() {
    local name="$1"
    local install_hint="$2"
    if command -v "$name" &>/dev/null; then
        echo -e "  ${GREEN}[ok]${NC} $name found"
    else
        echo -e "  ${YELLOW}[optional]${NC} $name - $install_hint"
        return 1
    fi
}

echo -e "${BOLD}Checking dependencies...${NC}"
check_dep "ssh"     "Should be pre-installed on macOS" || true
check_dep "nc"      "Should be pre-installed on macOS" || true
check_dep "curl"    "brew install curl" || true
check_dep "autossh" "brew install autossh (only needed for tunnel mode)" || true
echo ""

# Install files
log_info "Installing to $INSTALL_DIR..."

if [ -d "$INSTALL_DIR" ]; then
    log_info "Removing previous installation..."
    sudo rm -rf "$INSTALL_DIR"
fi

sudo mkdir -p "$INSTALL_DIR"
sudo cp "$SCRIPT_DIR/phantom" "$INSTALL_DIR/phantom"
sudo mkdir -p "$INSTALL_DIR/lib"
sudo cp "$SCRIPT_DIR/lib/"*.sh "$INSTALL_DIR/lib/"

# Make executable
sudo chmod +x "$INSTALL_DIR/phantom"
sudo chmod +x "$INSTALL_DIR/lib/"*.sh

# Create symlink
if [ -L "$SYMLINK_PATH" ]; then
    sudo rm -f "$SYMLINK_PATH"
fi

if [ -f "$SYMLINK_PATH" ]; then
    log_warn "$SYMLINK_PATH already exists and is not a symlink."
    log_warn "Backing up to ${SYMLINK_PATH}.bak"
    sudo mv "$SYMLINK_PATH" "${SYMLINK_PATH}.bak"
fi

sudo ln -sf "$INSTALL_DIR/phantom" "$SYMLINK_PATH"
log_success "Symlink created: $SYMLINK_PATH -> $INSTALL_DIR/phantom"

# Create config directory
PHANTOM_DIR="$HOME/.phantom"
if [ ! -d "$PHANTOM_DIR" ]; then
    mkdir -p "$PHANTOM_DIR"
    log_success "Created $PHANTOM_DIR"
fi

echo ""
echo "────────────────────────────────────────"
log_success "Phantom CLI installed successfully!"

# Auto-run setup if VPS IP was provided
if [ ${#SETUP_ARGS[@]} -gt 0 ]; then
    echo ""
    log_info "Running setup with provided arguments..."
    echo ""
    "$SYMLINK_PATH" setup "${SETUP_ARGS[@]}" || log_warn "Setup encountered issues. You can retry: phantom setup ${SETUP_ARGS[*]}"
else
    echo ""
    log_info "Next steps:"
    echo -e "  ${GREEN}phantom setup <VPS_IP> --key sk-phantom-xxx${NC}   # Configure (recommended)"
    echo -e "  ${GREEN}phantom setup <VPS_IP> --password P${NC}           # With SSH password"
    echo ""
    echo -e "  Then just run ${GREEN}phantom${NC} to start Claude!"
    echo ""
fi
