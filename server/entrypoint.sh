#!/bin/bash
set -e

echo "[phantom-server] Starting Phantom Server..."

# ──────────────────────────────────────────────
# Configure iptables rate limiting
# Limit outbound HTTPS (443) new connections: 3/s burst 5
# Prevents API abuse while supporting 15+ concurrent users
# ──────────────────────────────────────────────
echo "[phantom-server] Configuring iptables rate limiting..."
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 3/s --limit-burst 5 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j DROP
# Allow established connections (critical for long-lived API streams)
iptables -A OUTPUT -p tcp --dport 443 -m state --state ESTABLISHED,RELATED -j ACCEPT
echo "[phantom-server] iptables rules applied."

# ──────────────────────────────────────────────
# Graceful shutdown handler
# ──────────────────────────────────────────────
shutdown() {
    echo "[phantom-server] Shutting down gracefully..."
    if [ -f /var/run/danted.pid ]; then
        kill -TERM "$(cat /var/run/danted.pid)" 2>/dev/null
    fi
    # Flush iptables rules on exit
    iptables -F OUTPUT 2>/dev/null
    echo "[phantom-server] Shutdown complete."
    exit 0
}

trap shutdown SIGTERM SIGINT SIGQUIT

# ──────────────────────────────────────────────
# Start Dante SOCKS5 server
# ──────────────────────────────────────────────
echo "[phantom-server] Starting Dante SOCKS5 server on :1080..."
danted -f /etc/danted.conf -p /var/run/danted.pid &
DANTED_PID=$!

echo "[phantom-server] Dante started (PID: $DANTED_PID). Ready for connections."

# Wait for danted process (keeps container alive)
wait $DANTED_PID
