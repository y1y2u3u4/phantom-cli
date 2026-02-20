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

# Test Phantom Server locally
python3 server/phantom_server.py 8080 /tmp/phantom-test-data

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
client/lib/auth.sh      → Credential sync: --key (API) or --password (SSH legacy)

server/phantom_server.py → Hybrid server: HTTP CONNECT proxy + REST API + Management UI
server/ui.html           → Single-file SPA for API key management (Claude Console style)
server/install.sh        → VPS one-click installer (Docker + Phantom Server + Claude Code)
server/Dockerfile        → Ubuntu 22.04 + Dante SOCKS5 + iptables
server/entrypoint.sh     → iptables rate limiting (3/s burst 5 on :443) + danted startup
server/danted.conf       → Dante SOCKS5 config with PAM username auth
server/manage-users.sh   → add/remove/list SOCKS5 users (system users with nologin)
```

**Two connection modes:**
- `direct` (default): Client → VPS HTTP proxy (:8080) directly
- `tunnel`: Client → SSH tunnel → localhost proxy (encrypted)

**Default behavior:** `phantom` with no args launches `claude` in interactive mode. Args starting with `-` are passed through to claude (e.g., `phantom -p "hello"`).

**Shadow sandbox** (`~/.phantom_env/`): Symlinks `.gitconfig`, `.ssh`, `.npmrc`, etc. from real HOME, but NEVER symlinks `.claude.json` or `.claude/` — these are isolated per-VPS-account credentials.

## Phantom Server (server/phantom_server.py)

Single Python3 process on port 8080, zero external dependencies. Handles three roles:

1. **CONNECT proxy** — bidirectional socket tunneling with upstream proxy routing (HTTP/SOCKS5/direct)
2. **REST API** — API key CRUD, account management, usage tracking, credential download
3. **Web UI** — serves `ui.html` for multi-account management console

### Multi-Account Architecture

Supports multiple Claude Code subscription accounts per VPS, each routed through a different upstream proxy:

```
Client → Phantom Server (:8080) → Upstream Proxy A → api.claude.ai (Account 1)
                                → Upstream Proxy B → api.claude.ai (Account 2)
                                → Direct           → api.claude.ai (Account 3)
```

**CONNECT tunnel identity:** Client embeds API key in proxy URL (`http://sk-phantom-xxx:x@VPS:8080`). Node.js auto-sends `Proxy-Authorization: Basic base64(key:x)`. Server parses this to resolve which account/upstream proxy to use.

**Account resolution order:** (1) Explicit `account_id` on API key → (2) Sticky assignment in `assignments.json` → (3) Round-robin with quota awareness.

**Upstream proxy types:** `direct` (no upstream), `http` (HTTP CONNECT chain), `socks5` (pure stdlib SOCKS5 client).

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| CONNECT | * | Proxy-Auth | HTTP tunnel (proxy), routed via upstream |
| GET | / | Session | Management UI |
| GET | /api/health | None | Health check |
| POST | /api/auth/setup | None (first time) | Set master password |
| POST | /api/auth/login | Password | Login → session cookie (admin or member) |
| GET | /api/auth/check | Session | Check login state (returns role + username) |
| GET | /api/keys | Session | List keys (members see only their own) |
| POST | /api/keys | Session | Create key (members cannot bind account) |
| DELETE | /api/keys/:id | Session | Delete key (members only own keys) |
| PUT | /api/keys/:id/account | Admin | Assign key to account |
| DELETE | /api/keys/:id/account | Admin | Unassign key from account |
| GET | /api/credentials | Bearer API key | Download account-specific credentials |
| GET | /api/accounts | Admin | List accounts (proxy passwords masked) |
| POST | /api/accounts | Admin | Create account |
| PUT | /api/accounts/:id | Admin | Update account |
| DELETE | /api/accounts/:id | Admin | Delete account |
| POST | /api/accounts/:id/test | Admin | Test upstream proxy connectivity |
| POST | /api/accounts/:id/credentials | Admin | Upload credential files |
| GET | /api/usage?month=YYYY-MM | Session | Usage statistics (members see own keys only) |
| GET | /api/assignments | Admin | View sticky session assignments |
| GET | /api/invite/:token | None | Validate invite link |
| POST | /api/invite/:token/register | None | Member registration via invite |
| GET | /api/invites | Admin | List invite links |
| POST | /api/invites | Admin | Create invite link |
| DELETE | /api/invites/:token | Admin | Revoke invite link |
| GET | /api/members | Admin | List team members |
| PUT | /api/members/:id | Admin | Update member (role/status) |
| DELETE | /api/members/:id | Admin | Disable member |

### Data Storage

```
/opt/phantom-cli/data/
├── server_config.json    # {"master_password_hash": "salt:key"} (scrypt)
├── api_keys.json         # [{id, name, key_hash, account_id, ...}]
├── accounts.json         # [{id, name, status, credentials_dir, upstream_proxy, quota}]
├── usage.json            # {"YYYY-MM": {"key_id": {connections, bytes, cost}}}
├── assignments.json      # {"by_api_key": {...}, "by_client_ip": {...}}
├── members.json          # [{id, username, password_hash, role, status, ...}]
├── invites.json          # [{token, created_at, expires_at, max_uses, use_count, used_by}]
└── accounts/
    └── acc_<id>/
        └── credentials/
            ├── .claude/.credentials.json
            ├── .claude.json
            └── .claude/settings.json
```

### Team Member Management

Two roles: **Admin** (master password login) and **Member** (invite-based registration).

- Admin creates invite links (`POST /api/invites`) with configurable expiry (default 7 days) and max uses
- Members register via `/invite/<token>` URL, setting their own username + password
- Members can only see/manage their own API keys and usage data
- Admin has full access to all resources including accounts, assignments, and member management
- Member passwords use the same scrypt hashing as master password
- Session stores `role`, `member_id`, `username` for permission checks
- API keys track `created_by_member` field for ownership filtering
- Backward compatible: pre-existing sessions default to `role="admin"`

### Security

- Master password: scrypt hashed (n=16384, r=8, p=1)
- Member passwords: same scrypt hashing, stored in `members.json`
- API keys: `sk-phantom-<32hex>`, only SHA-256 hash stored
- Sessions: in-memory, HttpOnly + SameSite=Strict cookie, 24h TTL
- Login rate limit: 5 failures / 5 minutes per IP
- File writes: atomic (tmp + rename), 0600 permissions, threading.Lock
- Invite tokens: `inv_<32hex>`, expire after 7 days by default

## Key Paths

| Path | Purpose |
|------|---------|
| `~/.phantom/config` | Client config (SERVER_HOST, HTTP_PROXY_PORT, API_KEY, CONNECTION_MODE) |
| `~/.phantom_env/` | Shadow sandbox HOME used during hijack |
| `~/.phantom_env/.claude/` | Isolated Claude credentials (VPS subscription) |
| `~/.phantom_env/.phantom_profile` | Sourced before command execution (custom env vars) |
| `/opt/phantom-cli/` | Server installation directory on VPS |
| `/opt/phantom-cli/data/` | Server data (config, API keys, accounts, usage) — 0700 permissions |
| `/opt/phantom-cli/data/accounts/` | Per-account credential directories |

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

## Known Pitfalls

**CONNECT proxy must NOT send duplicate 200 response.** `do_CONNECT()` uses `BaseHTTPRequestHandler.send_response()` which already sends the HTTP 200. The `handle_connect()` function must NOT send another 200 on the raw socket — doing so corrupts the TLS handshake (`ERR_SSL_PACKET_LENGTH_TOO_LONG`).

**Large JSON through bash variables breaks.** Credential JSON (~14KB, containing OAuth tokens with special characters) cannot be stored in a bash variable and passed via `<<<` heredoc. Always pipe curl directly to python3: `curl ... | python3 -c "..."`.

**Python 3.9 compatibility.** VPS may run Python 3.9 which lacks `str | None` union type syntax. Use `from __future__ import annotations` at top of all Python files.

**`/api/auth/check` must return HTTP 200 for unauthenticated users.** The UI's fetch wrapper throws on non-2xx status. Return `{"authenticated": false, "needs_setup": bool}` with status 200, not 401.

**Proxy-Authorization for CONNECT identity.** The client embeds the API key as `http://sk-phantom-xxx:x@host:port`. Node.js HTTP client automatically sends `Proxy-Authorization: Basic base64(key:x)` on CONNECT requests. The server extracts the username from the decoded Base64 header to identify which account to route through.

**SOCKS5 client implementation.** The upstream SOCKS5 connector is a pure stdlib implementation (no external deps). It handles: greeting, username/password auth (RFC 1929), domain-based CONNECT, and variable-length bind address responses. Always use domain names (atyp=0x03), not resolved IPs, to let the proxy handle DNS.

## Deployment

**GitHub repo:** `https://github.com/y1y2u3u4/phantom-cli`

**VPS update workflow:**
```bash
# From local: push to GitHub
git push

# On VPS: server files are at /opt/phantom-cli/ (not a git repo)
# Use scp to update, then restart
scp server/phantom_server.py root@VPS_IP:/opt/phantom-cli/
scp server/ui.html root@VPS_IP:/opt/phantom-cli/
ssh root@VPS_IP "systemctl restart phantom-http-proxy"
```

**VPS systemd service:** `phantom-http-proxy` runs `python3 /opt/phantom-cli/phantom_server.py 8080 /opt/phantom-cli/data`
