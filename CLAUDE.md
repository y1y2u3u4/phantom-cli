# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Phantom-CLI is a zero-config AI network wrapper that hijacks at the network layer (L4) via HTTP CONNECT proxy, enabling team sharing of Claude compute through a VPS. Pure Bash client + Docker server architecture.

**Critical discovery:** Node.js `fetch()` does NOT support SOCKS5 proxy via `HTTP_PROXY` env var. The client uses HTTP CONNECT proxy (`http://host:8080`) instead of SOCKS5 (`socks5h://host:1080`).

## Commands

```bash
# Run all tests
bash tests/run_all_tests.sh

# Run a single test suite
bash tests/test_config.sh
bash tests/test_tunnel.sh
bash tests/test_sandbox.sh
bash tests/test_hijack.sh

# Install locally (symlinks to /usr/local/bin/phantom)
bash client/install.sh

# Deploy server on VPS (one-click)
curl -fsSL .../server/install.sh | bash

# Or manually
cd server && docker-compose up -d --build

# Manage SOCKS5 users on VPS
docker exec phantom-server manage-users.sh add <user> <pass>
docker exec phantom-server manage-users.sh list
```

## Architecture

```
client/phantom          → Main CLI entry, subcommand router (setup, auth, init, claude pass-through)
client/lib/hijack.sh    → Core: sets HTTP_PROXY + shadow HOME, then exec's the command
client/lib/sandbox.sh   → Creates ~/.phantom_env/ with symlinks (isolates .claude/ credentials)
client/lib/tunnel.sh    → autossh SOCKS5 tunnel management (tunnel mode only)
client/lib/config.sh    → KEY=VALUE config reader/writer (~/.phantom/config)
client/lib/doctor.sh    → Diagnostics: deps, proxy reachability, DNS leak, conflict detection
client/lib/auth.sh      → Credential sync from VPS (phantom auth sync/status)

server/install.sh       → VPS one-click installer (Docker + HTTP proxy + Claude Code)
server/Dockerfile       → Ubuntu 22.04 + Dante SOCKS5 + iptables
server/entrypoint.sh    → iptables rate limiting (3/s burst 5 on :443) + danted startup
server/danted.conf      → Dante SOCKS5 config with PAM username auth
server/manage-users.sh  → add/remove/list SOCKS5 users (system users with nologin)
```

**Two connection modes:**
- `direct` (default): Client → VPS HTTP proxy (:8080) directly
- `tunnel`: Client → SSH tunnel → localhost proxy (encrypted)

**Default behavior:** `phantom` with no args launches `claude` in interactive mode. Args starting with `-` are passed through to claude (e.g., `phantom -p "hello"`).

**Shadow sandbox** (`~/.phantom_env/`): Symlinks `.gitconfig`, `.ssh`, `.npmrc`, etc. from real HOME, but NEVER symlinks `.claude.json` or `.claude/` — these are isolated per-VPS-account credentials.

## Key Paths

| Path | Purpose |
|------|---------|
| `~/.phantom/config` | Client config (SERVER_HOST, HTTP_PROXY_PORT, CONNECTION_MODE) |
| `~/.phantom_env/` | Shadow sandbox HOME used during hijack |
| `~/.phantom_env/.claude/` | Isolated Claude credentials (VPS subscription) |
| `~/.phantom_env/.phantom_profile` | Sourced before command execution (custom env vars) |
| `/opt/phantom-cli/` | Server installation directory on VPS |

## Testing Patterns

Tests use a custom assertion framework (no external deps). Each test file:
- Creates a temp directory as isolated HOME
- Sources the module under test with mocked dependencies
- Uses `assert_equals`, `assert_contains`, `assert_file_exists`, `assert_dir_exists`, `assert_symlink`
- Cleans up via `trap` on EXIT

Mock pattern for external commands (tunnel.sh, hijack.sh):
```bash
autossh() { echo "MOCK_AUTOSSH $*"; }
export -f autossh
```

## Shell Compatibility

- macOS-first: uses BSD `sed -i ''` syntax (not GNU `sed -i`)
- `set -euo pipefail` in main entry point
- Config tilde expansion: `${value/#\~/$HOME}`
