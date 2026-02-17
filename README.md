# Phantom-CLI

**Zero-Config AI Network Wrapper** — Use Claude Code through your VPS in 4 steps.

Phantom-CLI hijacks at the network layer (L4) via HTTP CONNECT proxy, enabling team sharing of AI compute through a VPS. Pure Bash client + Docker server architecture. 100% native local experience — your tools, your config, your workflow.

## Quick Start (4 Steps)

### Step 1: Deploy on VPS

SSH into your VPS and run:

```bash
curl -fsSL https://raw.githubusercontent.com/nicegongqing/phantom-cli/main/server/install.sh | bash
```

This automatically installs Docker, builds the SOCKS5 container, deploys HTTP proxy, and opens ports.

### Step 2: Login on VPS

While still on the VPS, authenticate Claude:

```bash
claude
```

Complete the OAuth login in your browser.

### Step 3: Install & Setup on Local Mac

```bash
# Install client
curl -fsSL https://raw.githubusercontent.com/nicegongqing/phantom-cli/main/client/install.sh | bash

# One-click configure (auto-sync credentials from VPS)
phantom setup YOUR_VPS_IP --password YOUR_SSH_PASSWORD
```

### Step 4: Use

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
    ├── HTTP CONNECT Proxy (:8080) ← primary for Claude Code
    ├── Dante SOCKS5 Proxy (:1080) ← for curl/other tools
    ├── Docker (iptables rate limiting: 3/s burst 5)
    └── → Anthropic API (transparent proxy)
```

**How it works:**

1. A shadow sandbox (`~/.phantom_env/`) symlinks your existing dotfiles but isolates AI credentials
2. Environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) redirect traffic through VPS
3. HTTP CONNECT proxy on VPS handles Node.js (Claude Code) compatibility
4. `phantom setup` auto-detects proxy, writes config, syncs credentials

## Commands

| Command | Description |
|---------|-------------|
| `phantom` | Launch Claude in interactive mode (default) |
| `phantom -p "query"` | Pass arguments directly to Claude |
| `phantom setup <IP> [--password P]` | One-click configure + credential sync |
| `phantom auth sync` | Sync credentials from VPS |
| `phantom auth status` | Check credentials, proxy, and sandbox status |
| `phantom init` | Interactive setup wizard (advanced) |
| `phantom connect` | Establish SSH SOCKS5 tunnel (tunnel mode) |
| `phantom disconnect` | Tear down tunnel |
| `phantom status` | Show connection status and config |
| `phantom doctor` | Full diagnostic — proxy, DNS leak, conflicts |
| `phantom <cmd>` | Hijack any command (e.g., `phantom npm install`) |

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | HTTP CONNECT proxy (direct) or SSH tunnel (encrypted) |
| DNS | Remote resolution — no local leaks |
| Credential Isolation | Shadow sandbox never touches `~/.claude.json` |
| Rate Limiting | iptables bucket limiting (3/s, burst 5) on VPS |
| Conflict Detection | `phantom doctor` detects Clash/Surge/other proxies |

## Requirements

- **Client**: macOS with `autossh` and `ssh` installed
- **Server**: Ubuntu/Debian VPS with root access

## License

[MIT](LICENSE)
