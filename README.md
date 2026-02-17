# Phantom-CLI

**Zero-Config AI Network Wrapper** — Use Claude Code through your VPS in 4 steps.

Phantom-CLI hijacks at the network layer (L4) via HTTP CONNECT proxy, enabling team sharing of AI compute through a VPS. Pure Bash client + Docker server architecture. 100% native local experience — your tools, your config, your workflow.

## Quick Start (4 Steps)

### Step 1: Deploy on VPS

SSH into your VPS and run:

```bash
curl -fsSL https://raw.githubusercontent.com/y1y2u3u4/phantom-cli/master/server/install.sh | bash
```

This automatically installs Docker, builds the SOCKS5 container, deploys Phantom Server (proxy + API + management UI), and opens ports. You'll be prompted to set a **master password** during installation.

### Step 2: Login on VPS

While still on the VPS, authenticate Claude:

```bash
claude
```

Complete the OAuth login in your browser.

### Step 3: Create API Key

Open the management UI in your browser:

```
http://YOUR_VPS_IP:8080/
```

Log in with your master password, then create an API key. **Copy the key — it's only shown once.**

> **Tip:** For secure access, use SSH tunnel: `ssh -L 8080:localhost:8080 root@VPS_IP`, then visit `http://localhost:8080/`

### Step 4: Install & Setup on Local Mac

```bash
# Install client
curl -fsSL https://raw.githubusercontent.com/y1y2u3u4/phantom-cli/master/client/install.sh | bash

# One-click configure with API key (recommended)
phantom setup YOUR_VPS_IP --key sk-phantom-xxxx

# Or with SSH password (legacy)
phantom setup YOUR_VPS_IP --password YOUR_SSH_PASSWORD
```

### Step 5: Use

```bash
phantom                  # Launch Claude (interactive mode)
phantom -p "hello"       # Single query
phantom --resume         # Resume last conversation
phantom npm install      # Any command through proxy
```

## Architecture

```
Local macOS (Phantom Client)
    │
    ├── $ phantom → Shadow Sandbox + HTTP Proxy Hijack
    │       │
    │       └── HTTP CONNECT proxy → VPS:8080
    │
    ▼
Remote VPS (Phantom Server)
    ├── Phantom Server (:8080)
    │   ├── HTTP CONNECT Proxy ← primary for Claude Code
    │   ├── REST API ← credential sync via API key
    │   └── Management UI ← create/manage API keys
    ├── Dante SOCKS5 Proxy (:1080) ← for curl/other tools
    ├── Docker (iptables rate limiting: 3/s burst 5)
    └── → Anthropic API (transparent proxy)
```

**How it works:**

1. A shadow sandbox (`~/.phantom_env/`) symlinks your existing dotfiles but isolates AI credentials
2. Environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) redirect traffic through VPS
3. Phantom Server on VPS handles HTTP CONNECT proxy (Node.js compatible) + API key management
4. `phantom setup --key` auto-detects proxy, writes config, syncs credentials via API

## Commands

| Command | Description |
|---------|-------------|
| `phantom` | Launch Claude in interactive mode (default) |
| `phantom -p "query"` | Pass arguments directly to Claude |
| `phantom setup <IP> [--key K]` | One-click configure + credential sync (recommended) |
| `phantom setup <IP> [--password P]` | Legacy: setup with SSH password |
| `phantom auth sync [--key K]` | Sync credentials from VPS |
| `phantom auth status` | Check credentials, proxy, and sandbox status |
| `phantom init` | Interactive setup wizard (advanced) |
| `phantom connect` | Establish SSH SOCKS5 tunnel (tunnel mode) |
| `phantom disconnect` | Tear down tunnel |
| `phantom status` | Show connection status and config |
| `phantom doctor` | Full diagnostic — proxy, DNS leak, conflicts |
| `phantom <cmd>` | Hijack any command (e.g., `phantom npm install`) |

## API Key Authentication

The recommended authentication method uses API keys instead of SSH passwords:

1. **Create keys** via the management UI at `http://VPS_IP:8080/`
2. **Use keys** with `--key` flag: `phantom setup VPS_IP --key sk-phantom-xxxx`
3. **Keys are stored** in `~/.phantom/config` as `API_KEY=sk-phantom-xxxx`
4. **Subsequent syncs** use the stored key automatically: `phantom auth sync`

Benefits over SSH password:
- No `sshpass` dependency required
- Keys can be individually revoked
- Usage tracking (last used time/IP)
- No SSH access needed — only HTTP port 8080

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | HTTP CONNECT proxy (direct) or SSH tunnel (encrypted) |
| API Auth | API keys with SHA-256 hashed storage (never stored in plain) |
| Master Password | scrypt hashed, rate-limited login (5 attempts/5 min) |
| DNS | Remote resolution — no local leaks |
| Credential Isolation | Shadow sandbox never touches `~/.claude.json` |
| Rate Limiting | iptables bucket limiting (3/s, burst 5) on VPS |
| Conflict Detection | `phantom doctor` detects Clash/Surge/other proxies |

## Requirements

- **Client**: macOS with `ssh` and `curl` installed (`autossh` for tunnel mode)
- **Server**: Ubuntu/Debian VPS with root access

## License

[MIT](LICENSE)
