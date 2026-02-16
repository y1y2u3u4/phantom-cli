# Phantom-CLI MVP Design Document

**Date**: 2026-02-16
**Version**: 1.0.0
**Approach**: Bash Client + Docker Server (方案 B)

## Overview

Phantom-CLI is a zero-config AI network wrapper that hijacks at the network layer (L4) rather than the application layer (L7). It enables team sharing of Claude compute resources while maintaining 100% native experience.

## Architecture

### System Topology

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

### Project Structure

```
phantom-cli/
├── README.md
├── LICENSE
├── .gitignore
├── server/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── danted.conf
│   ├── entrypoint.sh
│   ├── manage-users.sh
│   └── .env.example
├── client/
│   ├── phantom
│   ├── lib/
│   │   ├── config.sh
│   │   ├── tunnel.sh
│   │   ├── sandbox.sh
│   │   ├── hijack.sh
│   │   └── doctor.sh
│   └── install.sh
└── tests/
    ├── test_tunnel.sh
    ├── test_sandbox.sh
    └── test_hijack.sh
```

## Server Components

### Docker Compose

- **dante-server**: Dante SOCKS5 proxy with username/password authentication
- **entrypoint.sh**: Configures iptables bucket rate limiting on container start
- **manage-users.sh**: CRUD operations for SOCKS5 user accounts

### Rate Limiting (15+ users)

```bash
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 3/s --limit-burst 5 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j DROP
```

### SOCKS5 Authentication

- Each team member gets unique username/password
- Dante server handles authentication at the proxy level
- No anonymous access allowed

## Client Components

### CLI Commands

| Command | Description |
|---------|-------------|
| `phantom init` | Interactive setup wizard - VPS IP, port, credentials |
| `phantom connect` | Establish SSH SOCKS5 tunnel (autossh keepalive) |
| `phantom disconnect` | Tear down tunnel |
| `phantom <cmd>` | Hijack and execute command (e.g., `phantom claude`) |
| `phantom status` | Show tunnel status and current config |
| `phantom doctor` | Full diagnostic - tunnel, DNS leak, proxy, conflicts |

### Shadow Sandbox (`~/.phantom_env/`)

**Inherited (symlinked)**:
- `.gitconfig`, `.ssh`, `.npmrc`, `.yarnrc`
- `.bashrc`, `.zshrc`, `.aws`, `.kube`

**Isolated (NOT inherited)**:
- `.claude.json` - credential isolation
- `.claude/` directory

### Network Hijack

```bash
export HTTP_PROXY="socks5h://127.0.0.1:1080"
export HTTPS_PROXY="socks5h://127.0.0.1:1080"
export ALL_PROXY="socks5h://127.0.0.1:1080"
export NO_PROXY="localhost,127.0.0.1,::1"
export HOME="$SHADOW_HOME"
exec $COMMAND "$@"
```

The `socks5h` scheme forces remote DNS resolution, preventing local DNS leaks.

### Config File (`~/.phantom/config`)

```ini
[server]
host=your-vps-ip
port=22
socks_port=1080

[auth]
ssh_key=~/.ssh/phantom_key
socks_user=dev01
socks_pass=encrypted_password

[options]
auto_connect=true
auto_reconnect=true
```

## Security Design

1. **SOCKS5 auth**: Username + password per user
2. **SSH key auth**: Client connects to VPS via SSH key (no password)
3. **Shadow sandbox isolation**: Never touches `~/.claude.json`
4. **Remote DNS** (socks5h): Eliminates local DNS leaks
5. **Proxy conflict detection**: Identifies running Clash/Surge

## Error Handling

- Tunnel disconnect → autossh auto-reconnect
- SOCKS5 unreachable → friendly message + auto-retry
- Proxy conflict (Clash/Surge) → `phantom doctor` detects and advises

## Success Criteria

1. Team of 15+ people can concurrently use `phantom claude` without rate limiting issues
2. Zero TLS fingerprint anomalies (passes Cloudflare WAF)
3. Local execution environment fully preserved (git, npm, tests all work)
4. One-command server setup: `docker-compose up -d`
5. One-command client setup: `./install.sh && phantom init`
