#!/usr/bin/env bash
# Phantom CLI - Installer
# Copies phantom + lib/ to /usr/local/bin/phantom-cli/ and creates symlink
#
# Usage:
#   bash install.sh                                  # Install only
#   bash install.sh 1.2.3.4 --key sk-phantom-xxx    # Install + auto-configure
#   bash install.sh 1.2.3.4 --port 9090 --key xxx   # With custom port

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin/phantom-cli"
SYMLINK_PATH="/usr/local/bin/phantom"
GITHUB_RAW="https://raw.githubusercontent.com/y1y2u3u4/phantom-cli/master/client"

log_info()    { echo -e "${CYAN}[info]${NC} $*"; }
log_success() { echo -e "${GREEN}[ok]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
log_error()   { echo -e "${RED}[error]${NC} $*" >&2; }

# Parse install arguments (VPS_IP and setup flags are forwarded to phantom setup)
SETUP_ARGS=()
for arg in "$@"; do
    SETUP_ARGS+=("$arg")
done

# Detect source: local git clone or remote curl|bash
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
IS_REMOTE=false
if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/phantom" ]; then
    IS_REMOTE=true
fi

echo -e "${BOLD}Phantom CLI Installer${NC}"
echo "────────────────────────────────────────"
echo ""

# ── Platform detection ───────────────────────────────────────────────
OS_TYPE="unknown"
OS_NAME="$(uname -s)"
IS_WSL=false

if [[ "$(uname -s)" == "Darwin" ]]; then
    OS_TYPE="macos"
    OS_NAME="macOS"
elif [[ -f /etc/debian_version ]] || grep -qi 'ubuntu\|debian' /etc/os-release 2>/dev/null; then
    OS_TYPE="debian"
    OS_NAME="Linux (Debian/Ubuntu)"
elif [[ -f /etc/redhat-release ]] || grep -qi 'centos\|rhel\|fedora' /etc/os-release 2>/dev/null; then
    OS_TYPE="rhel"
    OS_NAME="Linux (RHEL/CentOS)"
elif grep -qi 'arch' /etc/os-release 2>/dev/null; then
    OS_TYPE="arch"
    OS_NAME="Linux (Arch)"
elif grep -qi 'alpine' /etc/os-release 2>/dev/null; then
    OS_TYPE="alpine"
    OS_NAME="Linux (Alpine)"
fi

if grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=true
    OS_NAME="WSL ($OS_NAME)"
fi

# ── Auto-install helper ─────────────────────────────────────────────
# Installs a package if the command is not found.
# Usage: auto_install <command_name> <pkg_macos> <pkg_debian> <pkg_rhel> [<pkg_arch>] [<pkg_alpine>]
auto_install() {
    local cmd="$1" pkg_macos="$2" pkg_debian="$3" pkg_rhel="$4"
    local pkg_arch="${5:-$3}" pkg_alpine="${6:-$3}"

    if command -v "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[ok]${NC} $cmd"
        return 0
    fi

    local pkg="" installer=""
    case "$OS_TYPE" in
        macos)
            pkg="$pkg_macos"; installer="brew install" ;;
        debian)
            pkg="$pkg_debian"; installer="sudo apt-get install -y" ;;
        rhel)
            pkg="$pkg_rhel"; installer="sudo yum install -y" ;;
        arch)
            pkg="$pkg_arch"; installer="sudo pacman -S --noconfirm" ;;
        alpine)
            pkg="$pkg_alpine"; installer="sudo apk add" ;;
        *)
            echo -e "  ${YELLOW}[miss]${NC} $cmd — please install manually"
            return 1 ;;
    esac

    echo -ne "  ${CYAN}[install]${NC} $cmd ($pkg)..."
    if $installer $pkg &>/dev/null; then
        echo -e " ${GREEN}done${NC}"
        return 0
    else
        echo -e " ${RED}failed${NC}"
        log_warn "  Could not install $pkg. Install manually: $installer $pkg"
        return 1
    fi
}

# Ensure apt cache is fresh (only once, only on Debian)
_apt_updated=false
ensure_apt_update() {
    if [ "$OS_TYPE" = "debian" ] && [ "$_apt_updated" = false ]; then
        sudo apt-get update -qq &>/dev/null || true
        _apt_updated=true
    fi
}

echo -e "${BOLD}Checking & installing dependencies...${NC} (${OS_NAME})"

# On macOS, check for Homebrew first
if [ "$OS_TYPE" = "macos" ] && ! command -v brew &>/dev/null; then
    log_warn "Homebrew not found. Some dependencies may need manual install."
    log_info "Install Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
fi

# Update apt cache if on Debian (once, before installs)
ensure_apt_update

#                    command    macOS pkg          Debian pkg       RHEL pkg         Arch pkg      Alpine pkg
auto_install "curl"    "curl"             "curl"           "curl"           "curl"        "curl"        || true
auto_install "ssh"     "openssh"          "openssh-client" "openssh-clients" "openssh"    "openssh-client" || true
auto_install "nc"      "netcat"           "netcat-openbsd" "nmap-ncat"      "openbsd-netcat" "netcat-openbsd" || true
auto_install "python3" "python3"          "python3"        "python3"        "python"      "python3"     || true
auto_install "sshpass" "hudochenkov/sshpass/sshpass" "sshpass" "sshpass"  "sshpass"     "sshpass"     || true

if [ "$IS_WSL" = true ]; then
    echo ""
    log_info "WSL detected. Make sure to run Phantom inside WSL, not PowerShell/CMD."
fi
echo ""

# ── Install Phantom CLI files ────────────────────────────────────────
log_info "Installing to $INSTALL_DIR..."

if [ -d "$INSTALL_DIR" ]; then
    log_info "Removing previous installation..."
    sudo rm -rf "$INSTALL_DIR"
fi

sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR/lib"

LIB_FILES="config.sh sandbox.sh hijack.sh tunnel.sh auth.sh doctor.sh"

if [ "$IS_REMOTE" = true ]; then
    log_info "Downloading from GitHub..."
    # Download main script
    sudo curl -fsSL "$GITHUB_RAW/phantom" -o "$INSTALL_DIR/phantom"
    # Download lib files
    for f in $LIB_FILES; do
        sudo curl -fsSL "$GITHUB_RAW/lib/$f" -o "$INSTALL_DIR/lib/$f"
    done
else
    log_info "Copying from local source..."
    sudo cp "$SCRIPT_DIR/phantom" "$INSTALL_DIR/phantom"
    sudo cp "$SCRIPT_DIR/lib/"*.sh "$INSTALL_DIR/lib/"
fi

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
