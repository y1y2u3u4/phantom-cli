# Phantom-CLI

**Zero-Config AI Network Wrapper**

Phantom-CLI hijacks at the network layer (L4), not the application layer (L7). It enables team sharing of AI compute resources while maintaining a 100% native local experience — your tools, your config, your workflow.

## Architecture

```
Local macOS (Phantom Client)
    │
    ├── $ phantom claude → Shadow Sandbox + SOCKS5 Hijack
    │       │
    │       └── SSH Tunnel (autossh, SOCKS5 :1080)
    │               │
    └───────────────┘
                    │ Encrypted Tunnel
                    ▼
Remote VPS (Phantom Server - Docker)
    ├── Dante SOCKS5 Proxy (user auth)
    ├── iptables rate limiting (3/s burst 5)
    └── → Anthropic API (transparent proxy)
```

**How it works:**

1. A shadow sandbox (`~/.phantom_env/`) symlinks your existing dotfiles but isolates AI credentials
2. An SSH tunnel provides encrypted SOCKS5 transport to your VPS
3. Environment variables (`HTTP_PROXY`, `HTTPS_PROXY`) hijack network traffic through the tunnel
4. Remote DNS resolution (`socks5h://`) prevents local DNS leaks

## Quick Start

### Server Setup (VPS)

```bash
git clone https://github.com/your-org/phantom-cli.git
cd phantom-cli/server
cp .env.example .env    # Edit with your settings
docker-compose up -d
```

### Client Setup (macOS)

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/your-org/phantom-cli/main/client/install.sh | bash

# Configure
phantom init          # Interactive setup wizard

# Use
phantom connect       # Establish tunnel
phantom claude        # Run Claude through the tunnel
```

## Commands

| Command | Description |
|---------|-------------|
| `phantom init` | Interactive setup — VPS host, port, SSH key, SOCKS5 credentials |
| `phantom connect` | Establish SSH SOCKS5 tunnel with autossh keepalive |
| `phantom disconnect` | Tear down the tunnel |
| `phantom status` | Show tunnel status and current configuration |
| `phantom doctor` | Full diagnostic — tunnel, DNS leak, proxy conflicts |
| `phantom <cmd>` | Hijack and execute any command (e.g., `phantom claude`) |

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | SSH tunnel with key-based authentication |
| Proxy Auth | Per-user SOCKS5 username + password (Dante) |
| DNS | Remote resolution via `socks5h://` — no local leaks |
| Credential Isolation | Shadow sandbox never touches `~/.claude.json` |
| Rate Limiting | iptables bucket limiting (3/s, burst 5) on VPS |
| Conflict Detection | `phantom doctor` detects Clash/Surge/other proxies |

## Requirements

- **Client**: macOS with `autossh` and `ssh` installed
- **Server**: Any Linux VPS with Docker and Docker Compose

## License

[MIT](LICENSE)
