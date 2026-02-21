#!/bin/bash
# phantom-auth: Authenticate a Claude Code account in an isolated Docker container
# Usage: phantom-auth <account_id>
#
# Reads the account's upstream_proxy config from accounts.json,
# launches a Docker container with the proxy as HTTP_PROXY/HTTPS_PROXY,
# and mounts the account's credentials_dir so Claude Code writes
# credentials directly to the right place.

set -euo pipefail

DATA_DIR="${PHANTOM_DATA_DIR:-/opt/phantom-cli/data}"
ACCOUNTS_FILE="$DATA_DIR/accounts.json"
DOCKER_IMAGE="phantom-auth"

# ── Helpers ──────────────────────────────────────────────────────────────────

die() { echo "Error: $*" >&2; exit 1; }

usage() {
    echo "Usage: phantom-auth <account_id>"
    echo ""
    echo "Launches an isolated Docker container to authenticate Claude Code"
    echo "for the specified account, routing through the account's upstream proxy."
    echo ""
    echo "Available accounts:"
    if [ -f "$ACCOUNTS_FILE" ]; then
        python3 -c "
import json, sys
accounts = json.load(open('$ACCOUNTS_FILE'))
for a in accounts:
    proxy = a.get('upstream_proxy', {})
    ptype = proxy.get('type', 'direct')
    pinfo = 'direct' if ptype == 'direct' else f\"{ptype} {proxy.get('host','')}:{proxy.get('port','')}\"
    has_creds = '(has creds)' if a.get('credentials_dir') else '(no creds)'
    print(f\"  {a['id']}  {a['name']:<20s}  {pinfo:<30s}  {has_creds}\")
"
    fi
    exit 1
}

# ── Validate args ────────────────────────────────────────────────────────────

[ $# -lt 1 ] && usage
ACCOUNT_ID="$1"

[ -f "$ACCOUNTS_FILE" ] || die "accounts.json not found at $ACCOUNTS_FILE"

# ── Read account config ──────────────────────────────────────────────────────

ACCOUNT_JSON=$(python3 -c "
import json, sys
accounts = json.load(open('$ACCOUNTS_FILE'))
for a in accounts:
    if a['id'] == '$ACCOUNT_ID':
        json.dump(a, sys.stdout)
        sys.exit(0)
sys.exit(1)
") || die "Account '$ACCOUNT_ID' not found"

CRED_DIR=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('credentials_dir',''))")
PROXY_TYPE=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('upstream_proxy',{}).get('type','direct'))")
PROXY_HOST=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('upstream_proxy',{}).get('host',''))")
PROXY_PORT=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('upstream_proxy',{}).get('port',''))")
PROXY_USER=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('upstream_proxy',{}).get('username',''))")
PROXY_PASS=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('upstream_proxy',{}).get('password',''))")
ACCOUNT_NAME=$(echo "$ACCOUNT_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('name',''))")

[ -z "$CRED_DIR" ] && die "Account has no credentials_dir"

# Ensure credentials directory exists
mkdir -p "$CRED_DIR/.claude"

# ── Build proxy URL ──────────────────────────────────────────────────────────

PROXY_URL=""
if [ "$PROXY_TYPE" != "direct" ]; then
    [ -z "$PROXY_HOST" ] && die "Proxy host not configured for account"
    [ -z "$PROXY_PORT" ] && die "Proxy port not configured for account"

    SCHEME="http"
    [ "$PROXY_TYPE" = "socks5" ] && SCHEME="socks5h"

    if [ -n "$PROXY_USER" ]; then
        PROXY_URL="${SCHEME}://${PROXY_USER}:${PROXY_PASS}@${PROXY_HOST}:${PROXY_PORT}"
    else
        PROXY_URL="${SCHEME}://${PROXY_HOST}:${PROXY_PORT}"
    fi
fi

# ── Check Docker image ───────────────────────────────────────────────────────

if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "Docker image '$DOCKER_IMAGE' not found. Building..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    AUTH_DOCKER_DIR="$SCRIPT_DIR/auth-docker"
    if [ ! -d "$AUTH_DOCKER_DIR" ]; then
        AUTH_DOCKER_DIR="/opt/phantom-cli/auth-docker"
    fi
    [ -f "$AUTH_DOCKER_DIR/Dockerfile" ] || die "Cannot find auth-docker/Dockerfile"
    docker build -t "$DOCKER_IMAGE" "$AUTH_DOCKER_DIR" || die "Failed to build Docker image"
    echo "Image built successfully."
fi

# ── Launch container ─────────────────────────────────────────────────────────

CONTAINER_NAME="phantom_auth_${ACCOUNT_ID}"

echo "============================================"
echo "  Phantom Auth - Isolated Login"
echo "============================================"
echo "  Account:  $ACCOUNT_NAME ($ACCOUNT_ID)"
if [ -n "$PROXY_URL" ]; then
    # Mask password in display
    DISPLAY_URL=$(echo "$PROXY_URL" | sed 's/:[^:@]*@/:***@/')
    echo "  Proxy:    $DISPLAY_URL"
else
    echo "  Proxy:    direct (no proxy)"
fi
echo "  Creds:    $CRED_DIR"
echo "============================================"
echo ""
echo "Claude Code will start. Complete the login flow."
echo "After login, type /exit to quit. Credentials will be saved."
echo ""

DOCKER_ARGS=(
    run -it --rm
    --name "$CONTAINER_NAME"
    -v "$CRED_DIR:/root"
    --hostname "claude-auth"
)

if [ -n "$PROXY_URL" ]; then
    DOCKER_ARGS+=(
        -e "HTTP_PROXY=$PROXY_URL"
        -e "HTTPS_PROXY=$PROXY_URL"
        -e "http_proxy=$PROXY_URL"
        -e "https_proxy=$PROXY_URL"
    )
fi

docker "${DOCKER_ARGS[@]}" "$DOCKER_IMAGE" || true

# ── Verify credentials ───────────────────────────────────────────────────────

echo ""
if [ -f "$CRED_DIR/.claude/.credentials.json" ]; then
    echo "Credentials saved successfully!"
    echo "  $CRED_DIR/.claude/.credentials.json"
    # Fix ownership and permissions
    chown -R root:root "$CRED_DIR" 2>/dev/null || true
    chmod -R 600 "$CRED_DIR"/.claude/.credentials.json 2>/dev/null || true
    chmod 700 "$CRED_DIR"/.claude 2>/dev/null || true
else
    echo "Warning: No credentials found. Login may not have completed."
    echo "Run this command again to retry."
fi
