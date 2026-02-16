#!/usr/bin/env bash
# Phantom CLI - Installer
# Copies phantom + lib/ to /usr/local/bin/phantom-cli/ and creates symlink

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

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}Phantom CLI Installer${NC}"
echo "────────────────────────────────────────"
echo ""

# Check for required dependencies
check_dep() {
    local name="$1"
    local install_hint="$2"
    if command -v "$name" &>/dev/null; then
        echo -e "  ${GREEN}[ok]${NC} $name found"
    else
        echo -e "  ${RED}[missing]${NC} $name - $install_hint"
        return 1
    fi
}

echo -e "${BOLD}Checking dependencies...${NC}"
deps_ok=true
check_dep "autossh" "brew install autossh" || deps_ok=false
check_dep "ssh"     "Should be pre-installed on macOS" || true
check_dep "nc"      "Should be pre-installed on macOS" || true
check_dep "curl"    "brew install curl" || true

echo ""

if [ "$deps_ok" = false ]; then
    log_warn "Some dependencies are missing. Phantom may not work fully."
    read -rp "Continue anyway? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_info "Aborted. Install missing dependencies and try again."
        exit 1
    fi
fi

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
echo ""
log_info "Next steps:"
echo -e "  1. Run ${GREEN}phantom init${NC} to configure your VPS connection"
echo -e "  2. Run ${GREEN}phantom connect${NC} to start the tunnel"
echo -e "  3. Run ${GREEN}phantom claude${NC} to use Claude through the proxy"
echo ""
