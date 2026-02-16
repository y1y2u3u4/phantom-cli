#!/usr/bin/env bash
# Phantom CLI - Shadow sandbox management
# Creates ~/.phantom_env/ with symlinked configs for isolation

# Configs to symlink from real HOME
SANDBOX_SYMLINKS=(
    ".gitconfig"
    ".ssh"
    ".npmrc"
    ".yarnrc"
    ".bashrc"
    ".zshrc"
    ".aws"
    ".kube"
)

# NEVER symlink these (isolation boundary)
SANDBOX_NEVER_LINK=(
    ".claude.json"
    ".claude"
)

# Setup or refresh the shadow sandbox
phantom_sandbox_setup() {
    # Create sandbox directory
    if [ ! -d "$SHADOW_HOME" ]; then
        mkdir -p "$SHADOW_HOME"
        log_info "Created shadow sandbox at $SHADOW_HOME"
    fi

    local linked=0
    local skipped=0

    for item in "${SANDBOX_SYMLINKS[@]}"; do
        local source="$HOME/$item"
        local target="$SHADOW_HOME/$item"

        # Skip if source doesn't exist in real HOME
        if [ ! -e "$source" ]; then
            ((skipped++)) || true
            continue
        fi

        # Remove existing target if it's a broken symlink
        if [ -L "$target" ] && [ ! -e "$target" ]; then
            rm -f "$target"
        fi

        # Create symlink if not already present
        if [ ! -e "$target" ]; then
            ln -sf "$source" "$target"
            ((linked++)) || true
        fi
    done

    # Ensure isolated items are NOT symlinked
    for item in "${SANDBOX_NEVER_LINK[@]}"; do
        local target="$SHADOW_HOME/$item"
        if [ -L "$target" ]; then
            rm -f "$target"
            log_warn "Removed forbidden symlink: $target"
        fi
    done

    log_success "Sandbox ready: ${linked} symlinked, ${skipped} skipped (not found in HOME)"
}
