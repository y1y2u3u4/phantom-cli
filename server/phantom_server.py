#!/usr/bin/env python3
"""
Phantom Server - Hybrid HTTP CONNECT proxy + REST API + Web UI

Handles:
  CONNECT method  -> transparent proxy tunnel (for Claude Code / Node.js)
  GET/POST/DELETE -> REST API + Web UI management interface

Supports multi-account routing through upstream proxies (HTTP CONNECT / SOCKS5).

Usage:
  python3 phantom_server.py [PORT [DATA_DIR]]

Defaults:
  PORT     = 8080
  DATA_DIR = /opt/phantom-cli/data
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

# ── Configuration ────────────────────────────────────────────────────────────

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
DATA_DIR = sys.argv[2] if len(sys.argv) > 2 else "/opt/phantom-cli/data"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(SCRIPT_DIR, "ui.html")
UI_DIR = os.path.join(SCRIPT_DIR, "ui", "out")  # Next.js static export directory

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
    ".map": "application/json",
}

SERVER_CONFIG_FILE = os.path.join(DATA_DIR, "server_config.json")
API_KEYS_FILE = os.path.join(DATA_DIR, "api_keys.json")
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
USAGE_FILE = os.path.join(DATA_DIR, "usage.json")
ASSIGNMENTS_FILE = os.path.join(DATA_DIR, "assignments.json")
ACCOUNTS_DIR = os.path.join(DATA_DIR, "accounts")

BUFFER_SIZE = 65536
SESSION_TTL = 86400  # 24 hours in seconds
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX = 5  # max failed attempts per window

# Legacy credential paths (used when no accounts are configured)
CLAUDE_CREDENTIAL_PATHS = [
    ("/root/.claude/.credentials.json", ".claude/.credentials.json"),
    ("/root/.claude.json", ".claude.json"),
    ("/root/.claude/settings.json", ".claude/settings.json"),
]

# Credential file relative paths within an account's credentials_dir
CREDENTIAL_REL_PATHS = [
    ".claude/.credentials.json",
    ".claude.json",
    ".claude/settings.json",
]

# Token estimation constants
TLS_OVERHEAD_FACTOR = 0.75   # ~25% of bytes are TLS/HTTP overhead
BYTES_PER_CHAR = 1.2         # UTF-8 average including JSON structure
CHARS_PER_TOKEN = 4          # Anthropic's rough guideline

# Default model pricing (USD per million tokens)
MODEL_PRICING = {
    "input": 3.0,
    "output": 15.0,
}

USAGE_FLUSH_INTERVAL = 60    # seconds between usage flushes
QUOTA_CHECK_INTERVAL = 3600  # seconds between quota reset checks
MAX_SESSIONS_PER_KEY = 100   # max session records per key per month

# Anthropic OAuth constants
OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
OAUTH_USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
OAUTH_PROFILE_URL = "https://api.anthropic.com/api/oauth/profile"
OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_USER_AGENT = "claude-cli/2.1.44 (external, cli)"
OAUTH_TOKEN_MARGIN = 300     # refresh token if expiring within 5 minutes
OAUTH_USAGE_CACHE_TTL = 60   # cache usage API responses for 60 seconds
OAUTH_PROFILE_CACHE_TTL = 300  # cache profile responses for 5 minutes

# Concurrency control
MAX_GLOBAL_CONNECTIONS = 50       # max concurrent CONNECT tunnels
MAX_PER_ACCOUNT_CONNECTIONS = 10  # max concurrent tunnels per account
CONNECT_QUEUE_TIMEOUT = 30        # seconds to wait in queue before 503
CONNECT_RATE_BASE = 2.0           # base seconds between new connections per account
CONNECT_RATE_JITTER = 1.5         # random jitter added to rate interval (0 to this value)
STICKY_BREAK_THRESHOLD = 80.0     # break sticky session when five_hour utilization >= this %
QUOTA_REJECT_THRESHOLD = 95.0     # reject new CONNECT when session OR weekly utilization >= this %

# Claude Code usage query via tmux
USAGE_QUERY_MIN_INTERVAL = 600    # 10 minutes minimum between queries
USAGE_QUERY_MAX_INTERVAL = 1800   # 30 minutes maximum
USAGE_QUERY_TMUX_TIMEOUT = 60     # seconds to wait for claude to render /usage
CLAUDE_BIN = shutil.which("claude") or "/usr/local/bin/claude"

# ── Global state (protected by locks) ────────────────────────────────────────

_file_lock = threading.Lock()
_sessions: dict = {}          # {session_id: {"created_at": float}}
_sessions_lock = threading.Lock()
_rate_limit: dict = {}        # {ip: [timestamp, ...]}
_rate_limit_lock = threading.Lock()
_assignments_lock = threading.Lock()
_account_round_robin_idx = 0
_oauth_cache: dict = {}       # {account_id: {"usage": {...}, "usage_at": float, "profile": {...}, "profile_at": float}}

# Concurrency control state
_global_semaphore = threading.Semaphore(MAX_GLOBAL_CONNECTIONS)
_account_semaphores: dict = {}    # {account_id: threading.Semaphore}
_account_semaphores_lock = threading.Lock()
_active_connections = 0           # current global active tunnels
_active_per_account: dict = {}    # {account_id: int}
_connections_lock = threading.Lock()
_account_last_connect: dict = {}  # {account_id: float} last CONNECT timestamp per account
_account_rate_locks: dict = {}    # {account_id: threading.Lock} serialise rate-limit check

# Claude Code usage query cache
# {account_id: {"session_pct": int, "weekly_all_pct": int, "weekly_sonnet_pct": int|None,
#               "weekly_opus_pct": int|None, "session_resets": str, "weekly_all_resets": str,
#               "extra_usage_enabled": bool, "queried_at": float, "error": str|None}}
_claude_usage_cache: dict = {}
_claude_usage_lock = threading.Lock()
_usage_query_running = False       # prevent concurrent queries


# ── Utility: logging ─────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(f"[phantom-server] {msg}", flush=True)


# ── Utility: data directory & files ──────────────────────────────────────────

def ensure_data_dir() -> None:
    """Create DATA_DIR if it does not exist."""
    if not os.path.isdir(DATA_DIR):
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        log(f"Created data directory: {DATA_DIR}")


def _read_json_file(path: str, default):
    """Read a JSON file; return default if missing or corrupt."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_json_file(path: str, data) -> None:
    """Atomically write data as JSON; set permissions to 0o600."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_server_config() -> dict:
    return _read_json_file(SERVER_CONFIG_FILE, {})


def save_server_config(cfg: dict) -> None:
    with _file_lock:
        _write_json_file(SERVER_CONFIG_FILE, cfg)


def load_api_keys() -> list:
    return _read_json_file(API_KEYS_FILE, [])


def save_api_keys(keys: list) -> None:
    with _file_lock:
        _write_json_file(API_KEYS_FILE, keys)


# ── Account & usage data management ─────────────────────────────────────────

def load_accounts() -> list:
    return _read_json_file(ACCOUNTS_FILE, [])


def save_accounts(accounts: list) -> None:
    with _file_lock:
        _write_json_file(ACCOUNTS_FILE, accounts)


def load_usage() -> dict:
    return _read_json_file(USAGE_FILE, {})


def save_usage(usage: dict) -> None:
    with _file_lock:
        _write_json_file(USAGE_FILE, usage)


def load_assignments() -> dict:
    return _read_json_file(ASSIGNMENTS_FILE, {"by_api_key": {}, "by_client_ip": {}})


def save_assignments(assignments: dict) -> None:
    with _file_lock:
        _write_json_file(ASSIGNMENTS_FILE, assignments)


# ── Utility: password hashing (scrypt) ───────────────────────────────────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(
        password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32
    )
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        key = hashlib.scrypt(
            password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32
        )
        return key.hex() == key_hex
    except Exception:
        return False


# ── Utility: API key helpers ──────────────────────────────────────────────────

def generate_api_key() -> tuple[str, str, str, str]:
    """
    Returns (full_key, key_hash, prefix, suffix).
      full_key : sk-phantom-<32 hex chars>
      key_hash : SHA-256 hex digest of full_key
      prefix   : first 12 chars of full_key  ("sk-phantom-XX")
      suffix   : last 4 chars of full_key
    """
    raw = secrets.token_hex(16)           # 32 hex chars = 128-bit entropy
    full_key = "sk-phantom-" + raw
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    prefix = full_key[:12]                # "sk-phantom-X"
    suffix = full_key[-4:]
    return full_key, key_hash, prefix, suffix


def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode()).hexdigest()


def mask_key(prefix: str, suffix: str) -> str:
    return f"{prefix}...{suffix}"


# ── Utility: session management ───────────────────────────────────────────────

def create_session() -> str:
    session_id = secrets.token_hex(16)
    with _sessions_lock:
        _sessions[session_id] = {"created_at": time.time()}
    return session_id


def validate_session(session_id: str) -> bool:
    with _sessions_lock:
        session = _sessions.get(session_id)
        if session is None:
            return False
        if time.time() - session["created_at"] > SESSION_TTL:
            del _sessions[session_id]
            return False
        return True


def delete_session(session_id: str) -> None:
    with _sessions_lock:
        _sessions.pop(session_id, None)


def _purge_expired_sessions() -> None:
    now = time.time()
    with _sessions_lock:
        expired = [sid for sid, s in _sessions.items()
                   if now - s["created_at"] > SESSION_TTL]
        for sid in expired:
            del _sessions[sid]


def parse_session_cookie(cookie_header: str) -> str | None:
    """Extract phantom_session value from Cookie header string."""
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("phantom_session="):
            return part[len("phantom_session="):]
    return None


# ── Utility: rate limiting ────────────────────────────────────────────────────

def check_rate_limit(ip: str) -> bool:
    """Returns True if the IP is within allowed attempts, False if blocked."""
    now = time.time()
    with _rate_limit_lock:
        attempts = _rate_limit.get(ip, [])
        # Keep only attempts within the window
        attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
        _rate_limit[ip] = attempts
        return len(attempts) < RATE_LIMIT_MAX


def record_failed_login(ip: str) -> None:
    now = time.time()
    with _rate_limit_lock:
        attempts = _rate_limit.get(ip, [])
        attempts.append(now)
        _rate_limit[ip] = attempts


def clear_failed_logins(ip: str) -> None:
    with _rate_limit_lock:
        _rate_limit.pop(ip, None)


# ── Upstream proxy connectors ────────────────────────────────────────────────

def connect_direct(host: str, port: int) -> socket.socket:
    """Connect directly to target (no upstream proxy)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    return sock


def connect_via_http_proxy(
    target_host: str, target_port: int,
    proxy_host: str, proxy_port: int,
    proxy_user: str | None = None, proxy_pass: str | None = None,
) -> socket.socket:
    """Connect to target through an upstream HTTP CONNECT proxy."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((proxy_host, proxy_port))

    # Build CONNECT request
    lines = [f"CONNECT {target_host}:{target_port} HTTP/1.1"]
    lines.append(f"Host: {target_host}:{target_port}")
    if proxy_user and proxy_pass:
        creds = base64.b64encode(f"{proxy_user}:{proxy_pass}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {creds}")
    lines.append("")
    lines.append("")

    sock.sendall("\r\n".join(lines).encode())

    # Read response until end of headers
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise ConnectionError("Upstream HTTP proxy closed connection before response")
        response += chunk

    status_line = response.split(b"\r\n")[0].decode(errors="replace")
    try:
        status_code = int(status_line.split()[1])
    except (IndexError, ValueError):
        sock.close()
        raise ConnectionError(f"Upstream HTTP proxy returned invalid response: {status_line}")
    if status_code != 200:
        sock.close()
        raise ConnectionError(f"Upstream HTTP proxy rejected CONNECT (status {status_code}): {status_line}")

    return sock


def connect_via_socks5(
    target_host: str, target_port: int,
    proxy_host: str, proxy_port: int,
    proxy_user: str | None = None, proxy_pass: str | None = None,
) -> socket.socket:
    """Connect to target through a SOCKS5 proxy (pure stdlib implementation)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((proxy_host, proxy_port))

    # SOCKS5 greeting: version=5, number of auth methods, methods
    if proxy_user and proxy_pass:
        sock.sendall(b"\x05\x02\x00\x02")  # no-auth + user/pass
    else:
        sock.sendall(b"\x05\x01\x00")  # no-auth only

    resp = sock.recv(2)
    if len(resp) < 2 or resp[0] != 0x05:
        sock.close()
        raise ConnectionError("Invalid SOCKS5 greeting response")

    # Handle username/password authentication (RFC 1929)
    if resp[1] == 0x02:
        if not proxy_user or not proxy_pass:
            sock.close()
            raise ConnectionError("SOCKS5 proxy requires authentication but no credentials provided")
        user_bytes = proxy_user.encode("utf-8")
        pass_bytes = proxy_pass.encode("utf-8")
        auth_msg = b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes
        sock.sendall(auth_msg)
        auth_resp = sock.recv(2)
        if len(auth_resp) < 2 or auth_resp[1] != 0x00:
            sock.close()
            raise ConnectionError("SOCKS5 authentication failed")
    elif resp[1] == 0xFF:
        sock.close()
        raise ConnectionError("SOCKS5 proxy rejected all auth methods")
    elif resp[1] != 0x00:
        sock.close()
        raise ConnectionError(f"SOCKS5 unsupported auth method: {resp[1]}")

    # CONNECT request: version=5, cmd=1(connect), rsv=0, atyp=3(domain)
    domain_bytes = target_host.encode("utf-8")
    req = b"\x05\x01\x00\x03"
    req += bytes([len(domain_bytes)]) + domain_bytes
    req += struct.pack("!H", target_port)
    sock.sendall(req)

    # Read CONNECT response: at least 4 bytes for header, then variable
    resp = b""
    while len(resp) < 4:
        chunk = sock.recv(256)
        if not chunk:
            sock.close()
            raise ConnectionError("SOCKS5 connection closed during CONNECT response")
        resp += chunk

    if resp[1] != 0x00:
        error_codes = {
            0x01: "general failure", 0x02: "not allowed by ruleset",
            0x03: "network unreachable", 0x04: "host unreachable",
            0x05: "connection refused", 0x06: "TTL expired",
            0x07: "command not supported", 0x08: "address type not supported",
        }
        msg = error_codes.get(resp[1], f"unknown error {resp[1]}")
        sock.close()
        raise ConnectionError(f"SOCKS5 CONNECT failed: {msg}")

    # Consume the rest of the reply (bind address) based on address type
    atyp = resp[3]
    if atyp == 0x01:  # IPv4: 4 bytes addr + 2 bytes port
        need = 4 + 2 - (len(resp) - 4)
    elif atyp == 0x03:  # Domain: 1 byte len + domain + 2 bytes port
        if len(resp) < 5:
            resp += sock.recv(1)
        domain_len = resp[4]
        need = 1 + domain_len + 2 - (len(resp) - 4)
    elif atyp == 0x04:  # IPv6: 16 bytes addr + 2 bytes port
        need = 16 + 2 - (len(resp) - 4)
    else:
        need = 0
    if need > 0:
        sock.recv(need)

    return sock


def connect_to_target(
    host: str, port: int, upstream_proxy: dict | None = None,
) -> socket.socket:
    """Route connection through the appropriate upstream proxy."""
    proxy_type = "direct"
    if upstream_proxy:
        proxy_type = upstream_proxy.get("type", "direct")

    if proxy_type == "direct":
        return connect_direct(host, port)
    elif proxy_type == "http":
        return connect_via_http_proxy(
            host, port,
            upstream_proxy["host"], upstream_proxy["port"],
            upstream_proxy.get("username"), upstream_proxy.get("password"),
        )
    elif proxy_type == "socks5":
        return connect_via_socks5(
            host, port,
            upstream_proxy["host"], upstream_proxy["port"],
            upstream_proxy.get("username"), upstream_proxy.get("password"),
        )
    else:
        raise ValueError(f"Unknown upstream proxy type: {proxy_type}")


# ── Concurrency helpers ───────────────────────────────────────────────────────

def _get_account_semaphore(account_id: str) -> threading.Semaphore:
    """Get or create a per-account semaphore (lazy init)."""
    if account_id not in _account_semaphores:
        with _account_semaphores_lock:
            if account_id not in _account_semaphores:
                _account_semaphores[account_id] = threading.Semaphore(MAX_PER_ACCOUNT_CONNECTIONS)
    return _account_semaphores[account_id]


def _track_connection(account_id: str | None, delta: int) -> None:
    """Adjust active connection counters. delta=+1 on acquire, -1 on release."""
    global _active_connections
    with _connections_lock:
        _active_connections = max(0, _active_connections + delta)
        if account_id:
            cur = _active_per_account.get(account_id, 0)
            _active_per_account[account_id] = max(0, cur + delta)


def _get_connection_stats() -> dict:
    """Return current connection statistics."""
    with _connections_lock:
        return {
            "active": _active_connections,
            "max": MAX_GLOBAL_CONNECTIONS,
            "per_account": dict(_active_per_account),
            "per_account_max": MAX_PER_ACCOUNT_CONNECTIONS,
        }


# ── Quota-aware scoring ──────────────────────────────────────────────────────

def _get_account_load_score(account: dict) -> float:
    """
    Score an account by availability. Higher = more capacity available.
    Uses cached Claude Code /usage data, falls back to local estimation.
    """
    cached = get_cached_claude_usage(account["id"])

    if cached and cached.get("session_pct") is not None:
        return 100.0 - float(cached["session_pct"])
    if cached and cached.get("weekly_all_pct") is not None:
        return 100.0 - float(cached["weekly_all_pct"])

    # Fallback: local USD estimation (returns inf when no limit set)
    remaining = estimate_remaining_quota(account)
    if remaining == float("inf"):
        return 100.0  # no limit configured → full capacity
    return min(100.0, remaining)


def _is_account_overloaded(account: dict) -> bool:
    """Check if an account's session utilization exceeds the sticky-break threshold."""
    cached = get_cached_claude_usage(account["id"])
    if not cached:
        return False
    session_pct = cached.get("session_pct")
    if session_pct is not None:
        return float(session_pct) >= STICKY_BREAK_THRESHOLD
    return False


def _is_account_quota_exhausted(account: dict) -> tuple[bool, str]:
    """Check if account quota is at/near limit. Returns (exhausted, reason)."""
    cached = get_cached_claude_usage(account["id"])
    if not cached:
        return False, ""
    session_pct = cached.get("session_pct")
    weekly_pct = cached.get("weekly_all_pct")
    if session_pct is not None and float(session_pct) >= QUOTA_REJECT_THRESHOLD:
        resets = cached.get("session_resets", "unknown")
        return True, f"Session quota {session_pct}% (>={QUOTA_REJECT_THRESHOLD}%). Resets: {resets}"
    if weekly_pct is not None and float(weekly_pct) >= QUOTA_REJECT_THRESHOLD:
        resets = cached.get("weekly_all_resets", "unknown")
        return True, f"Weekly quota {weekly_pct}% (>={QUOTA_REJECT_THRESHOLD}%). Resets: {resets}"
    return False, ""


# ── Account resolution & sticky sessions ─────────────────────────────────────

def resolve_account(key_record: dict | None, client_ip: str) -> dict | None:
    """
    Determine which account to use for a given API key / client IP.
    Returns the account dict or None (use legacy/direct mode).
    """
    global _account_round_robin_idx

    accounts = load_accounts()
    if not accounts:
        return None  # no accounts configured, legacy mode

    active = [a for a in accounts if a.get("status") == "active"]
    if not active:
        # All accounts exhausted/disabled, try any account as fallback
        active = accounts

    if len(active) == 1:
        return active[0]

    # 1. Explicit account_id on the API key record
    if key_record and key_record.get("account_id"):
        for a in active:
            if a["id"] == key_record["account_id"]:
                return a

    # 2. Sticky assignment lookup (with overload break)
    assignments = load_assignments()
    key_id = key_record["id"] if key_record else None

    sticky_account = None
    if key_id and key_id in assignments.get("by_api_key", {}):
        assigned_id = assignments["by_api_key"][key_id]["account_id"]
        for a in active:
            if a["id"] == assigned_id:
                sticky_account = a
                break

    if not sticky_account and client_ip in assignments.get("by_client_ip", {}):
        assigned_id = assignments["by_client_ip"][client_ip]["account_id"]
        for a in active:
            if a["id"] == assigned_id:
                sticky_account = a
                break

    if sticky_account and not _is_account_overloaded(sticky_account):
        return sticky_account

    if sticky_account:
        log(f"Breaking sticky session: account {sticky_account['id']} overloaded (>={STICKY_BREAK_THRESHOLD}%)")

    # 3. Round-robin with real quota awareness
    with _assignments_lock:
        scored = [(a, _get_account_load_score(a)) for a in active]
        scored.sort(key=lambda x: x[1], reverse=True)

        available = [a for a, q in scored if q > 0]
        if not available:
            available = [a for a, _ in scored]
            log("WARNING: all account quotas exhausted, round-robin across all accounts")

        chosen = available[_account_round_robin_idx % len(available)]
        _account_round_robin_idx += 1

    # Persist sticky assignment (update if broken, create if new)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    reason = "rebalance" if sticky_account else "round_robin"
    by_key = assignments.setdefault("by_api_key", {})
    by_ip = assignments.setdefault("by_client_ip", {})
    if key_id:
        by_key[key_id] = {
            "account_id": chosen["id"], "assigned_at": now, "reason": reason,
        }
    if client_ip:
        by_ip[client_ip] = {
            "account_id": chosen["id"], "assigned_at": now, "reason": reason,
        }
    save_assignments(assignments)
    log(f"Auto-assigned account {chosen['id']} ({chosen.get('name', '?')}) for key={key_id} ip={client_ip} reason={reason}")

    return chosen


# ── Token & cost estimation ──────────────────────────────────────────────────

def estimate_tokens(raw_bytes: int) -> int:
    """Estimate token count from raw TLS byte count."""
    content_bytes = raw_bytes * TLS_OVERHEAD_FACTOR
    chars = content_bytes / BYTES_PER_CHAR
    return int(chars / CHARS_PER_TOKEN)


def estimate_cost(bytes_up: int, bytes_down: int) -> float:
    """Estimate cost in USD from upstream/downstream byte counts."""
    tokens_in = estimate_tokens(bytes_up)
    tokens_out = estimate_tokens(bytes_down)
    cost = (tokens_in / 1_000_000 * MODEL_PRICING["input"] +
            tokens_out / 1_000_000 * MODEL_PRICING["output"])
    return round(cost, 6)


def estimate_remaining_quota(account: dict) -> float:
    """Estimate remaining quota in USD for an account this month."""
    quota = account.get("quota", {})
    limit = quota.get("monthly_limit_usd")
    if limit is None:
        return float("inf")

    month_key = time.strftime("%Y-%m")
    usage = load_usage()
    month_usage = usage.get(month_key, {})

    total_estimated = 0.0
    for _key_id, data in month_usage.items():
        if data.get("account_id") == account["id"]:
            total_estimated += data.get("estimated_cost_usd", 0.0)

    return max(0.0, limit - total_estimated)


# ── Anthropic OAuth token & usage API ────────────────────────────────────────

def _read_oauth_credentials(account: dict) -> dict | None:
    """Read OAuth credentials from account's credentials_dir."""
    cred_dir = account.get("credentials_dir", "")
    if not cred_dir:
        return None
    cred_path = os.path.join(cred_dir, ".claude", ".credentials.json")
    try:
        with open(cred_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("claudeAiOauth")
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None


def _save_oauth_credentials(account: dict, oauth: dict) -> None:
    """Save updated OAuth credentials back to the credentials file."""
    cred_dir = account.get("credentials_dir", "")
    if not cred_dir:
        return
    cred_path = os.path.join(cred_dir, ".claude", ".credentials.json")
    try:
        with open(cred_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["claudeAiOauth"] = oauth
        tmp = cred_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cred_path)
    except Exception as exc:
        log(f"Warning: failed to save OAuth credentials: {exc}")


def refresh_oauth_token(account: dict) -> dict | None:
    """Refresh OAuth token for an account. Returns updated oauth dict or None."""
    oauth = _read_oauth_credentials(account)
    if not oauth or not oauth.get("refreshToken"):
        return None

    payload = json.dumps({
        "grant_type": "refresh_token",
        "refresh_token": oauth["refreshToken"],
        "client_id": OAUTH_CLIENT_ID,
        "scope": "user:inference user:profile user:sessions:claude_code",
    }).encode()

    req = urllib.request.Request(
        OAUTH_TOKEN_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": OAUTH_USER_AGENT,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())

        new_access = result.get("access_token")
        new_refresh = result.get("refresh_token", oauth["refreshToken"])
        expires_in = result.get("expires_in", 28800)

        oauth["accessToken"] = new_access
        oauth["refreshToken"] = new_refresh
        oauth["expiresAt"] = int(time.time() * 1000) + expires_in * 1000

        _save_oauth_credentials(account, oauth)
        log(f"OAuth token refreshed for account {account.get('name', account['id'])}")
        return oauth
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:200]
        except Exception:
            pass
        log(f"OAuth token refresh failed for {account['id']}: HTTP {e.code} {body}")
        return None
    except Exception as exc:
        log(f"OAuth token refresh failed for {account['id']}: {exc}")
        return None


def get_valid_access_token(account: dict) -> str | None:
    """Get a valid OAuth access token, refreshing if expired or expiring soon."""
    oauth = _read_oauth_credentials(account)
    if not oauth:
        return None

    expires_at = oauth.get("expiresAt", 0)
    now_ms = int(time.time() * 1000)

    if now_ms + OAUTH_TOKEN_MARGIN * 1000 < expires_at:
        return oauth.get("accessToken")

    # Token expired or expiring soon — refresh
    refreshed = refresh_oauth_token(account)
    if refreshed:
        return refreshed.get("accessToken")
    return None


def fetch_anthropic_usage(account: dict) -> dict | None:
    """Query Anthropic OAuth usage API. Returns usage dict or None. Cached for 60s."""
    acc_id = account["id"]
    cache = _oauth_cache.get(acc_id, {})
    cached_usage = cache.get("usage")
    cached_at = cache.get("usage_at", 0)

    if cached_usage is not None and time.time() - cached_at < OAUTH_USAGE_CACHE_TTL:
        return cached_usage

    token = get_valid_access_token(account)
    if not token:
        return None

    req = urllib.request.Request(
        OAUTH_USAGE_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": OAUTH_USER_AGENT,
            "anthropic-beta": "oauth-2025-04-20",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())

        if acc_id not in _oauth_cache:
            _oauth_cache[acc_id] = {}
        _oauth_cache[acc_id]["usage"] = result
        _oauth_cache[acc_id]["usage_at"] = time.time()
        return result
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()[:200]
        except Exception:
            pass
        log(f"Anthropic usage API failed for {acc_id}: HTTP {e.code} {body}")
        return None
    except Exception as exc:
        log(f"Anthropic usage API failed for {acc_id}: {exc}")
        return None


def fetch_anthropic_profile(account: dict) -> dict | None:
    """Query Anthropic profile API. Returns profile dict or None. Cached for 5min."""
    acc_id = account["id"]
    cache = _oauth_cache.get(acc_id, {})
    cached_profile = cache.get("profile")
    cached_at = cache.get("profile_at", 0)

    if cached_profile is not None and time.time() - cached_at < OAUTH_PROFILE_CACHE_TTL:
        return cached_profile

    token = get_valid_access_token(account)
    if not token:
        return None

    req = urllib.request.Request(
        OAUTH_PROFILE_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": OAUTH_USER_AGENT,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())

        if acc_id not in _oauth_cache:
            _oauth_cache[acc_id] = {}
        _oauth_cache[acc_id]["profile"] = result
        _oauth_cache[acc_id]["profile_at"] = time.time()
        return result
    except Exception as exc:
        log(f"Anthropic profile API failed for {acc_id}: {exc}")
        return None


def _format_resets_in(resets_at_str: str | None) -> str | None:
    """Convert ISO 8601 timestamp to human-readable 'resets in X' string."""
    if not resets_at_str:
        return None
    try:
        # Parse ISO 8601 with timezone
        resets_at_str = resets_at_str.replace("+00:00", "Z").replace("+0000", "Z")
        if resets_at_str.endswith("Z"):
            # Remove fractional seconds if present
            base = resets_at_str.rstrip("Z").split(".")[0]
            resets_ts = time.mktime(time.strptime(base, "%Y-%m-%dT%H:%M:%S")) - time.timezone
        else:
            return None
        diff = resets_ts - time.time()
        if diff <= 0:
            return "now"
        hours = int(diff // 3600)
        minutes = int((diff % 3600) // 60)
        if hours >= 24:
            days = hours // 24
            hours = hours % 24
            return f"{days}d {hours}h"
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    except Exception:
        return None


# ── Claude Code /usage query via tmux ────────────────────────────────────────

def _parse_usage_output(text: str) -> dict:
    """Parse the text output of Claude Code's /usage command."""
    result: dict = {
        "session_pct": None, "weekly_all_pct": None,
        "weekly_sonnet_pct": None, "weekly_opus_pct": None,
        "session_resets": None, "weekly_all_resets": None,
        "extra_usage_enabled": False, "error": None,
    }

    patterns = [
        (r"Current session.*?(\d+)%\s*used", "session_pct"),
        (r"Current week \(all models\).*?(\d+)%\s*used", "weekly_all_pct"),
        (r"Current week \(Sonnet only\).*?(\d+)%\s*used", "weekly_sonnet_pct"),
        (r"Current week \(Opus only\).*?(\d+)%\s*used", "weekly_opus_pct"),
    ]
    for pattern, key in patterns:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            result[key] = int(m.group(1))

    reset_patterns = [
        (r"Current session.*?Resets\s+(.+?)(?:\n|$)", "session_resets"),
        (r"Current week \(all models\).*?Resets\s+(.+?)(?:\n|$)", "weekly_all_resets"),
    ]
    for pattern, key in reset_patterns:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            result[key] = m.group(1).strip()

    if "not enabled" in text.lower():
        result["extra_usage_enabled"] = False
    elif "extra usage" in text.lower() and "not enabled" not in text.lower():
        result["extra_usage_enabled"] = True

    return result


def _query_claude_usage(account: dict) -> dict | None:
    """
    Query usage for an account by spawning Claude Code in a tmux session.
    Uses the account's credentials_dir as HOME so Claude reads the right credentials.
    Returns parsed usage dict or None on failure.
    """
    cred_dir = account.get("credentials_dir", "")
    if not cred_dir or not os.path.isdir(cred_dir):
        return None

    # Check tmux is available
    tmux_bin = shutil.which("tmux")
    if not tmux_bin:
        log(f"tmux not found, cannot query usage for {account['id']}")
        return None

    claude_bin = CLAUDE_BIN
    if not os.path.isfile(claude_bin):
        log(f"claude binary not found at {claude_bin}")
        return None

    sess_name = f"phantom_usage_{account['id']}"

    # Kill any leftover session
    subprocess.run([tmux_bin, "kill-session", "-t", sess_name],
                   capture_output=True, timeout=5)

    try:
        # Build clean environment for Claude Code
        clean_env = {
            "HOME": cred_dir,
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "TERM": "xterm-256color",
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
        }
        env_args = " ".join(f"{k}={v}" for k, v in clean_env.items())

        # Start tmux session running claude
        subprocess.run(
            [tmux_bin, "new-session", "-d", "-s", sess_name, "-x", "200", "-y", "50",
             f"env -i {env_args} {claude_bin}"],
            capture_output=True, timeout=10,
        )

        # Wait for Claude Code to start
        time.sleep(15)

        # Send /usage then Enter (Enter selects first autocomplete match = /usage)
        # NOTE: Do NOT send Escape — it exits Claude Code entirely
        subprocess.run([tmux_bin, "send-keys", "-t", sess_name, "/usage", ""],
                       capture_output=True, timeout=5)
        time.sleep(3)
        subprocess.run([tmux_bin, "send-keys", "-t", sess_name, "Enter", ""],
                       capture_output=True, timeout=5)

        # Wait for usage to render
        time.sleep(20)

        # Capture the visible terminal content
        cp = subprocess.run(
            [tmux_bin, "capture-pane", "-t", sess_name, "-p", "-S", "-50"],
            capture_output=True, text=True, timeout=10,
        )
        raw_output = cp.stdout

        # Close the usage panel with Escape, then exit claude with /exit
        subprocess.run([tmux_bin, "send-keys", "-t", sess_name, "Escape", ""],
                       capture_output=True, timeout=5)
        time.sleep(1)
        subprocess.run([tmux_bin, "send-keys", "-t", sess_name, "/exit", "Enter"],
                       capture_output=True, timeout=5)
        time.sleep(3)

        if not raw_output or "% used" not in raw_output:
            log(f"Usage query for {account['id']}: no usage data in output ({len(raw_output)} bytes)")
            return {"error": "No usage data in output", "session_pct": None, "weekly_all_pct": None,
                    "weekly_sonnet_pct": None, "weekly_opus_pct": None,
                    "session_resets": None, "weekly_all_resets": None, "extra_usage_enabled": False}

        result = _parse_usage_output(raw_output)
        log(f"Usage query for {account['id']}: session={result.get('session_pct')}% weekly={result.get('weekly_all_pct')}%")
        return result

    except Exception as exc:
        log(f"Usage query failed for {account['id']}: {exc}")
        return {"error": str(exc), "session_pct": None, "weekly_all_pct": None,
                "weekly_sonnet_pct": None, "weekly_opus_pct": None,
                "session_resets": None, "weekly_all_resets": None, "extra_usage_enabled": False}
    finally:
        # Always clean up tmux session
        try:
            subprocess.run([tmux_bin, "kill-session", "-t", sess_name],
                           capture_output=True, timeout=5)
        except Exception:
            pass


def query_all_accounts_usage() -> dict:
    """Query usage for all active accounts. Returns {account_id: usage_dict}."""
    global _usage_query_running
    if _usage_query_running:
        log("Usage query already running, skipping")
        return {}
    _usage_query_running = True

    try:
        accounts = load_accounts()
        active = [a for a in accounts if a.get("status") == "active"]
        results = {}
        for account in active:
            usage = _query_claude_usage(account)
            if usage:
                usage["queried_at"] = time.time()
                with _claude_usage_lock:
                    _claude_usage_cache[account["id"]] = usage
                results[account["id"]] = usage
        return results
    finally:
        _usage_query_running = False


def get_cached_claude_usage(account_id: str) -> dict | None:
    """Get cached usage for an account, or None if not available."""
    with _claude_usage_lock:
        return _claude_usage_cache.get(account_id)


def _usage_query_loop() -> None:
    """Background thread: periodically query usage for all accounts."""
    # Initial delay: 30-60 seconds after server start
    time.sleep(random.uniform(30, 60))

    while True:
        try:
            query_all_accounts_usage()
        except Exception as exc:
            log(f"Usage query loop error: {exc}")

        # Random interval between queries
        interval = random.uniform(USAGE_QUERY_MIN_INTERVAL, USAGE_QUERY_MAX_INTERVAL)
        log(f"Next usage query in {interval:.0f}s")
        time.sleep(interval)


def build_quota_response(account: dict) -> dict:
    """Build a complete quota response for an account from cached Claude usage data."""
    cred_dir = account.get("credentials_dir", "")
    has_credentials = bool(cred_dir) and any(
        os.path.exists(os.path.join(cred_dir, rp))
        for rp in CREDENTIAL_REL_PATHS
    )

    base: dict = {
        "subscription_type": None,
        "five_hour": None,
        "seven_day": None,
        "seven_day_opus": None,
        "seven_day_sonnet": None,
        "extra_usage": None,
        "has_credentials": has_credentials,
        "error": None,
    }

    if not has_credentials:
        base["error"] = "No OAuth credentials found"
        return base

    # Use cached Claude Code /usage data
    cached = get_cached_claude_usage(account["id"])
    if not cached:
        base["error"] = "Usage not yet queried (waiting for background query)"
        return base

    if cached.get("error"):
        base["error"] = cached["error"]

    # Map Claude usage fields to API response
    if cached.get("session_pct") is not None:
        base["five_hour"] = {
            "utilization": cached["session_pct"],
            "resets_at": cached.get("session_resets"),
            "resets_in": cached.get("session_resets"),
        }
    if cached.get("weekly_all_pct") is not None:
        base["seven_day"] = {
            "utilization": cached["weekly_all_pct"],
            "resets_at": cached.get("weekly_all_resets"),
            "resets_in": cached.get("weekly_all_resets"),
        }
    if cached.get("weekly_opus_pct") is not None:
        base["seven_day_opus"] = {"utilization": cached["weekly_opus_pct"]}
    if cached.get("weekly_sonnet_pct") is not None:
        base["seven_day_sonnet"] = {"utilization": cached["weekly_sonnet_pct"]}
    if cached.get("extra_usage_enabled") is not None:
        base["extra_usage"] = {"is_enabled": cached["extra_usage_enabled"]}

    base["queried_at"] = cached.get("queried_at")

    # Try to get profile via OAuth API (this is lightweight, cached 5min)
    profile = fetch_anthropic_profile(account)
    if profile:
        org = profile.get("organization", {})
        org_type = org.get("organization_type", "")
        if "max" in org_type:
            base["subscription_type"] = "max"
        elif "pro" in org_type:
            base["subscription_type"] = "pro"
        elif "enterprise" in org_type:
            base["subscription_type"] = "enterprise"
        elif "team" in org_type:
            base["subscription_type"] = "team"
        else:
            base["subscription_type"] = org_type or None

    return base


# ── Usage tracker (batched writes) ───────────────────────────────────────────

class UsageTracker:
    """Thread-safe usage tracking with periodic flush to disk."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: list[dict] = []
        self._timer: threading.Timer | None = None
        self._start_flush_timer()

    def _start_flush_timer(self) -> None:
        self._timer = threading.Timer(USAGE_FLUSH_INTERVAL, self._timed_flush)
        self._timer.daemon = True
        self._timer.start()

    def _timed_flush(self) -> None:
        self.flush()
        self._start_flush_timer()

    def record_session(
        self, api_key_id: str | None, account_id: str | None,
        target: str, bytes_up: int, bytes_down: int,
        started_at: str, ended_at: str,
    ) -> None:
        with self._lock:
            self._pending.append({
                "api_key_id": api_key_id or "anonymous",
                "account_id": account_id,
                "target": target,
                "bytes_up": bytes_up,
                "bytes_down": bytes_down,
                "started_at": started_at,
                "ended_at": ended_at,
            })

    def flush(self) -> None:
        with self._lock:
            to_flush = self._pending[:]
            self._pending.clear()

        if not to_flush:
            return

        with _file_lock:
            usage = _read_json_file(USAGE_FILE, {})
            month_key = time.strftime("%Y-%m")
            if month_key not in usage:
                usage[month_key] = {}

            for record in to_flush:
                key_id = record["api_key_id"]
                if key_id not in usage[month_key]:
                    usage[month_key][key_id] = {
                        "account_id": record["account_id"],
                        "connections": 0,
                        "bytes_upstream": 0,
                        "bytes_downstream": 0,
                        "estimated_tokens_in": 0,
                        "estimated_tokens_out": 0,
                        "estimated_cost_usd": 0.0,
                        "sessions": [],
                    }

                entry = usage[month_key][key_id]
                entry["connections"] += 1
                entry["bytes_upstream"] += record["bytes_up"]
                entry["bytes_downstream"] += record["bytes_down"]
                entry["estimated_tokens_in"] += estimate_tokens(record["bytes_up"])
                entry["estimated_tokens_out"] += estimate_tokens(record["bytes_down"])
                entry["estimated_cost_usd"] += estimate_cost(record["bytes_up"], record["bytes_down"])
                entry["estimated_cost_usd"] = round(entry["estimated_cost_usd"], 6)

                entry["sessions"].append({
                    "started_at": record["started_at"],
                    "ended_at": record["ended_at"],
                    "target": record["target"],
                    "bytes_up": record["bytes_up"],
                    "bytes_down": record["bytes_down"],
                })
                if len(entry["sessions"]) > MAX_SESSIONS_PER_KEY:
                    entry["sessions"] = entry["sessions"][-MAX_SESSIONS_PER_KEY:]

            _write_json_file(USAGE_FILE, usage)


# Global usage tracker instance (initialized in main())
_usage_tracker: UsageTracker | None = None


# ── Quota management ─────────────────────────────────────────────────────────

def check_quota_resets() -> None:
    """Reset exhausted accounts when the billing month rolls over."""
    accounts = load_accounts()
    changed = False
    today = int(time.strftime("%d"))
    current_month = time.strftime("%Y-%m")

    for account in accounts:
        if account.get("status") != "exhausted":
            continue
        reset_day = account.get("quota", {}).get("reset_day", 1)
        if today >= reset_day:
            last_reset = account.get("last_quota_reset", "")
            if last_reset != current_month:
                account["status"] = "active"
                account["last_quota_reset"] = current_month
                changed = True
                log(f"Account {account['id']} ({account.get('name', '?')}) quota reset for {current_month}")

    if changed:
        save_accounts(accounts)


def _quota_check_loop() -> None:
    """Background thread that periodically checks for quota resets."""
    while True:
        time.sleep(QUOTA_CHECK_INTERVAL)
        try:
            check_quota_resets()
        except Exception as exc:
            log(f"Quota check error: {exc}")


# ── Migration v1 → v2 ───────────────────────────────────────────────────────

def migrate_v1_to_v2() -> None:
    """Create a default account from existing /root/.claude/ credentials if no accounts exist."""
    if os.path.exists(ACCOUNTS_FILE):
        accounts = _read_json_file(ACCOUNTS_FILE, [])
        if accounts:
            return  # already have accounts

    # Check if legacy credentials exist
    has_legacy = any(os.path.exists(p) for p, _ in CLAUDE_CREDENTIAL_PATHS)
    if not has_legacy:
        log("No legacy credentials found, skipping migration")
        return

    account_id = "acc_" + secrets.token_hex(8)
    cred_dir = os.path.join(ACCOUNTS_DIR, account_id, "credentials")
    os.makedirs(os.path.join(cred_dir, ".claude"), exist_ok=True)

    # Copy existing credentials
    copied = 0
    for src_path, rel_path in CLAUDE_CREDENTIAL_PATHS:
        if os.path.exists(src_path):
            dst_path = os.path.join(cred_dir, rel_path)
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            shutil.copy2(src_path, dst_path)
            copied += 1

    default_account = {
        "id": account_id,
        "name": "Default Account",
        "status": "active",
        "credentials_dir": cred_dir,
        "upstream_proxy": {"type": "direct"},
        "quota": {"monthly_limit_usd": 100.0, "reset_day": 1},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    _write_json_file(ACCOUNTS_FILE, [default_account])
    log(f"Migration complete: created default account {account_id} with {copied} credential files")


# ── CONNECT proxy tunnel ──────────────────────────────────────────────────────

def _forward(src: socket.socket, dst: socket.socket, byte_counter: list | None = None) -> None:
    """Forward data from src to dst until connection closes. Optionally count bytes."""
    total = 0
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
            total += len(data)
    except Exception:
        pass
    finally:
        if byte_counter is not None:
            byte_counter.append(total)
        for sock in (src, dst):
            try:
                sock.close()
            except Exception:
                pass


def handle_connect(
    client_socket: socket.socket, target: str,
    upstream_proxy: dict | None = None,
    api_key_id: str | None = None,
    account_id: str | None = None,
) -> None:
    """
    Establish a tunnel for a CONNECT request.
    target is "host:port". Routes through upstream_proxy if provided.
    """
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    bytes_up_counter: list[int] = []
    bytes_down_counter: list[int] = []

    try:
        host, _, port_str = target.rpartition(":")
        port = int(port_str)

        # Connect to target, optionally through upstream proxy
        remote_socket = connect_to_target(host, port, upstream_proxy)

        # Note: 200 response is already sent by do_CONNECT() before calling this function

        t1 = threading.Thread(
            target=_forward,
            args=(client_socket, remote_socket, bytes_up_counter),
            daemon=True,
        )
        t2 = threading.Thread(
            target=_forward,
            args=(remote_socket, client_socket, bytes_down_counter),
            daemon=True,
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Record usage
        ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        up = bytes_up_counter[0] if bytes_up_counter else 0
        down = bytes_down_counter[0] if bytes_down_counter else 0
        if _usage_tracker and (up > 0 or down > 0):
            _usage_tracker.record_session(
                api_key_id, account_id, target, up, down, started_at, ended_at,
            )
            log(f"CONNECT tunnel closed: {target} up={up} down={down} key={api_key_id} account={account_id}")

    except Exception as exc:
        log(f"CONNECT tunnel error for {target}: {exc}")
        exc_msg = str(exc).lower()
        if "authentication" in exc_msg or "auth" in exc_msg:
            status_line = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\nUpstream proxy authentication failed\n"
        elif "timed out" in exc_msg or "timeout" in exc_msg:
            status_line = b"HTTP/1.1 504 Gateway Timeout\r\n\r\nUpstream connection timed out\n"
        elif "refused" in exc_msg or "unreachable" in exc_msg:
            status_line = b"HTTP/1.1 502 Bad Gateway\r\n\r\nUpstream proxy unreachable or target refused\n"
        else:
            status_line = b"HTTP/1.1 502 Bad Gateway\r\n\r\nCould not connect to target\n"
        try:
            client_socket.sendall(status_line)
        except Exception:
            pass
        try:
            client_socket.close()
        except Exception:
            pass


# ── HTTP request handler ──────────────────────────────────────────────────────

class PhantomHandler(BaseHTTPRequestHandler):

    # Silence default access log; we do our own
    def log_message(self, fmt, *args):
        pass

    # ── Low-level helpers ─────────────────────────────────────────────────

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, status: int, content: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _serve_static(self, url_path: str) -> bool:
        """Try to serve a static file from UI_DIR. Returns True if served."""
        if not os.path.isdir(UI_DIR):
            return False

        rel_path = url_path.lstrip("/")
        if not rel_path:
            rel_path = "index.html"

        # Security: prevent directory traversal
        full_path = os.path.normpath(os.path.join(UI_DIR, rel_path))
        if not full_path.startswith(os.path.normpath(UI_DIR)):
            return False

        # Try exact file
        if os.path.isfile(full_path):
            return self._send_static_file(full_path)

        # Try appending .html (for /keys → keys.html)
        html_path = full_path + ".html"
        if os.path.isfile(html_path):
            return self._send_static_file(html_path)

        # Try index.html in directory (for /keys/ → keys/index.html)
        index_path = os.path.join(full_path, "index.html")
        if os.path.isdir(full_path) and os.path.isfile(index_path):
            return self._send_static_file(index_path)

        return False

    def _send_static_file(self, file_path: str) -> bool:
        """Send a static file with appropriate Content-Type and caching."""
        try:
            ext = os.path.splitext(file_path)[1].lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")

            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))

            # Cache hashed static assets aggressively, not HTML
            if "/_next/" in file_path:
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            else:
                self.send_header("Cache-Control", "no-cache")

            self.end_headers()
            self.wfile.write(content)
            return True
        except Exception as exc:
            log(f"Error serving static file {file_path}: {exc}")
            return False

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length)
        return b""

    def _parse_json_body(self) -> dict | None:
        try:
            return json.loads(self._read_body())
        except Exception:
            return None

    def _client_ip(self) -> str:
        return self.client_address[0]

    # ── Auth helpers ──────────────────────────────────────────────────────

    def _get_session_id(self) -> str | None:
        cookie_header = self.headers.get("Cookie", "")
        return parse_session_cookie(cookie_header)

    def _is_authenticated(self) -> bool:
        sid = self._get_session_id()
        if not sid:
            return False
        return validate_session(sid)

    def _get_bearer_token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    def _get_proxy_auth_key(self) -> str | None:
        """Extract API key from Proxy-Authorization: Basic base64(key:x) header."""
        auth = self.headers.get("Proxy-Authorization", "")
        if not auth.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
            # Format: api_key:password (password is ignored)
            username, _, _ = decoded.partition(":")
            if username and username.startswith("sk-phantom-"):
                return username
        except Exception:
            pass
        return None

    def _validate_api_key(self, token: str) -> dict | None:
        """
        Validate a Bearer API key. Returns the matching key record (dict)
        or None if invalid.
        """
        token_hash = hash_api_key(token)
        keys = load_api_keys()
        for k in keys:
            if k.get("key_hash") == token_hash:
                return k
        return None

    # ── CONNECT method ────────────────────────────────────────────────────

    def do_CONNECT(self):
        target = self.path  # "host:port"
        client_ip = self._client_ip()

        # Extract API key from Proxy-Authorization header
        api_key = self._get_proxy_auth_key()
        key_record = self._validate_api_key(api_key) if api_key else None

        # Resolve account for upstream proxy routing
        account = resolve_account(key_record, client_ip)
        upstream_proxy = account.get("upstream_proxy") if account else None
        account_id = account["id"] if account else None
        api_key_id = key_record["id"] if key_record else None

        proxy_info = ""
        if account:
            proxy_type = upstream_proxy.get("type", "direct") if upstream_proxy else "direct"
            proxy_info = f" via account={account.get('name', account_id)} proxy={proxy_type}"

        # ── Quota circuit breaker: reject if account near/at limit ──
        if account:
            exhausted, reason = _is_account_quota_exhausted(account)
            if exhausted:
                log(f"CONNECT {target} from {client_ip} REJECTED: quota exhausted — {reason}")
                self.send_response(429, "Quota Exhausted")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Retry-After", "300")
                self.end_headers()
                try:
                    self.wfile.write(f"Account quota limit reached. {reason}\n".encode())
                except Exception:
                    pass
                return

        # ── Concurrency control: acquire global semaphore ──
        if not _global_semaphore.acquire(timeout=CONNECT_QUEUE_TIMEOUT):
            log(f"CONNECT {target} from {client_ip} REJECTED: server busy ({_active_connections}/{MAX_GLOBAL_CONNECTIONS})")
            self.send_response(503, "Service Unavailable")
            self.send_header("Retry-After", "5")
            self.end_headers()
            try:
                self.wfile.write(b"Server busy, try again later\n")
            except Exception:
                pass
            return

        # ── Concurrency control: acquire per-account semaphore ──
        acct_sem = _get_account_semaphore(account_id) if account_id else None
        if acct_sem and not acct_sem.acquire(timeout=CONNECT_QUEUE_TIMEOUT):
            _global_semaphore.release()
            acct_count = _active_per_account.get(account_id, 0)
            log(f"CONNECT {target} from {client_ip} REJECTED: account {account_id} busy ({acct_count}/{MAX_PER_ACCOUNT_CONNECTIONS})")
            self.send_response(503, "Service Unavailable")
            self.send_header("Retry-After", "5")
            self.end_headers()
            try:
                self.wfile.write(b"Account busy, try again later\n")
            except Exception:
                pass
            return

        # ── Rate limit with jitter: simulate natural human timing ──
        if account_id and CONNECT_RATE_BASE > 0:
            if account_id not in _account_rate_locks:
                _account_rate_locks[account_id] = threading.Lock()
            with _account_rate_locks[account_id]:
                now = time.time()
                last = _account_last_connect.get(account_id, 0)
                interval = CONNECT_RATE_BASE + random.uniform(0, CONNECT_RATE_JITTER)
                wait = interval - (now - last)
                if wait > 0:
                    time.sleep(wait)
                _account_last_connect[account_id] = time.time()

        _track_connection(account_id, +1)
        log(f"CONNECT {target} from {client_ip}{proxy_info} (conns: {_active_connections}/{MAX_GLOBAL_CONNECTIONS})")

        try:
            # Send 200 and detach socket for raw tunnelling
            self.send_response(200, "Connection Established")
            self.end_headers()
            # Detach the underlying socket and hand it to the tunnel handler
            handle_connect(
                self.connection, target,
                upstream_proxy=upstream_proxy,
                api_key_id=api_key_id,
                account_id=account_id,
            )
        finally:
            # Always release semaphores and update counters
            _track_connection(account_id, -1)
            if acct_sem:
                acct_sem.release()
            _global_semaphore.release()

    # ── Routing ───────────────────────────────────────────────────────────

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # ── Public endpoints ──────────────────────────────────────────────

        if method == "GET" and path == "/api/health":
            return self._handle_health()

        if method == "POST" and path == "/api/auth/setup":
            return self._handle_auth_setup()

        if method == "POST" and path == "/api/auth/login":
            return self._handle_auth_login()

        if method == "GET" and path == "/api/auth/check":
            return self._handle_auth_check()

        if method == "POST" and path == "/api/auth/logout":
            return self._handle_auth_logout()

        # ── Credential download (Bearer API key auth) ─────────────────────

        if method == "GET" and path == "/api/credentials":
            return self._handle_credentials()

        # ── Session-protected endpoints ───────────────────────────────────

        if method == "GET" and path == "/api/keys":
            return self._handle_keys_list()

        if method == "POST" and path == "/api/keys":
            return self._handle_keys_create()

        if method == "DELETE" and path.startswith("/api/keys/"):
            key_id = path[len("/api/keys/"):]
            return self._handle_keys_delete(key_id)

        # ── API key ↔ account assignment ──────────────────────────────────

        if method == "PUT" and path.startswith("/api/keys/") and path.endswith("/account"):
            key_id = path[len("/api/keys/"):-len("/account")]
            return self._handle_key_assign_account(key_id)

        if method == "DELETE" and path.startswith("/api/keys/") and path.endswith("/account"):
            key_id = path[len("/api/keys/"):-len("/account")]
            return self._handle_key_unassign_account(key_id)

        # ── Account management ────────────────────────────────────────────

        if method == "GET" and path == "/api/accounts":
            return self._handle_accounts_list()

        if method == "POST" and path == "/api/accounts":
            return self._handle_accounts_create()

        if method == "PUT" and path.startswith("/api/accounts/"):
            parts = path[len("/api/accounts/"):].split("/")
            acc_id = parts[0]
            if len(parts) == 1:
                return self._handle_accounts_update(acc_id)
            if len(parts) == 2 and parts[1] == "test":
                return self._handle_accounts_test(acc_id)
            if len(parts) == 2 and parts[1] == "credentials":
                return self._handle_accounts_upload_credentials(acc_id)

        if method == "GET" and path.startswith("/api/accounts/"):
            parts = path[len("/api/accounts/"):].split("/")
            acc_id = parts[0]
            if len(parts) == 2 and parts[1] == "quota":
                return self._handle_account_quota(acc_id)

        if method == "POST" and path.startswith("/api/accounts/"):
            parts = path[len("/api/accounts/"):].split("/")
            acc_id = parts[0]
            if len(parts) == 2 and parts[1] == "test":
                return self._handle_accounts_test(acc_id)
            if len(parts) == 2 and parts[1] == "credentials":
                return self._handle_accounts_upload_credentials(acc_id)

        if method == "DELETE" and path.startswith("/api/accounts/"):
            acc_id = path[len("/api/accounts/"):]
            return self._handle_accounts_delete(acc_id)

        if method == "POST" and path == "/api/usage/refresh":
            return self._handle_usage_refresh()

        # ── Usage & assignments ───────────────────────────────────────────

        if method == "GET" and path == "/api/usage":
            return self._handle_usage()

        if method == "GET" and path == "/api/assignments":
            return self._handle_assignments_list()

        # ── Static files (Next.js export) ────────────────────────────────

        if method == "GET":
            if self._serve_static(path):
                return

        # ── Fallback: legacy ui.html ─────────────────────────────────────

        if method == "GET" and path == "/":
            return self._handle_ui()

        # ── 404 ───────────────────────────────────────────────────────────
        self._send_json(404, {"error": "Not Found"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    # ── Handlers ──────────────────────────────────────────────────────────

    def _handle_health(self) -> None:
        self._send_json(200, {
            "status": "ok",
            "connections": _get_connection_stats(),
        })

    def _handle_auth_setup(self) -> None:
        """First-time setup: set master password. Only allowed if not yet set."""
        cfg = load_server_config()
        if cfg.get("master_password_hash"):
            self._send_json(409, {"error": "Master password already set"})
            return

        body = self._parse_json_body()
        if not body:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        password = body.get("password", "").strip()
        if len(password) < 8:
            self._send_json(400, {"error": "Password must be at least 8 characters"})
            return

        cfg["master_password_hash"] = hash_password(password)
        save_server_config(cfg)
        log("Master password set via /api/auth/setup")

        # Auto-login after setup: create session + set cookie
        _purge_expired_sessions()
        session_id = create_session()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header(
            "Set-Cookie",
            f"phantom_session={session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
        )
        body_bytes = json.dumps({"message": "Master password set successfully"}).encode()
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def _handle_auth_login(self) -> None:
        ip = self._client_ip()

        if not check_rate_limit(ip):
            log(f"Rate limit hit for {ip}")
            self._send_json(429, {"error": "Too many failed attempts. Try again later."})
            return

        body = self._parse_json_body()
        if not body:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        password = body.get("password", "")
        cfg = load_server_config()
        stored_hash = cfg.get("master_password_hash", "")

        if not stored_hash:
            self._send_json(403, {"error": "Server not configured. Set master password first."})
            return

        if not verify_password(password, stored_hash):
            record_failed_login(ip)
            log(f"Failed login from {ip}")
            self._send_json(401, {"error": "Invalid password"})
            return

        clear_failed_logins(ip)
        _purge_expired_sessions()
        session_id = create_session()
        log(f"Successful login from {ip}")

        payload = json.dumps({"message": "Logged in successfully"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header(
            "Set-Cookie",
            f"phantom_session={session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _handle_auth_check(self) -> None:
        config = load_server_config()
        needs_setup = "master_password_hash" not in config
        if self._is_authenticated():
            self._send_json(200, {"authenticated": True, "needs_setup": False})
        else:
            self._send_json(200, {"authenticated": False, "needs_setup": needs_setup})

    def _handle_auth_logout(self) -> None:
        sid = self._get_session_id()
        if sid:
            delete_session(sid)
        payload = json.dumps({"message": "Logged out"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header(
            "Set-Cookie",
            "phantom_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _handle_keys_list(self) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        keys = load_api_keys()
        accounts = load_accounts()
        accounts_map = {a["id"]: a for a in accounts}

        # Get current month usage
        month_key = time.strftime("%Y-%m")
        usage = load_usage()
        month_usage = usage.get(month_key, {})

        masked = []
        for k in keys:
            account_id = k.get("account_id")
            account_name = None
            if account_id and account_id in accounts_map:
                account_name = accounts_map[account_id].get("name")

            key_usage = month_usage.get(k["id"], {})
            masked.append({
                "id": k["id"],
                "name": k["name"],
                "masked_key": mask_key(k["prefix"], k["suffix"]),
                "account_id": account_id,
                "account_name": account_name,
                "created_at": k["created_at"],
                "last_used_at": k.get("last_used_at"),
                "last_used_ip": k.get("last_used_ip"),
                "usage_this_month": {
                    "connections": key_usage.get("connections", 0),
                    "estimated_cost_usd": round(key_usage.get("estimated_cost_usd", 0.0), 4),
                } if key_usage else None,
            })
        self._send_json(200, {"keys": masked})

    def _handle_keys_create(self) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        body = self._parse_json_body()
        if not body:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        name = body.get("name", "").strip()
        if not name:
            self._send_json(400, {"error": "Key name is required"})
            return
        if len(name) > 100:
            self._send_json(400, {"error": "Key name must be 100 characters or fewer"})
            return

        full_key, key_hash, prefix, suffix = generate_api_key()
        key_id = secrets.token_hex(8)
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        account_id = body.get("account_id")  # optional: bind key to account

        new_key_record = {
            "id": key_id,
            "name": name,
            "key_hash": key_hash,
            "prefix": prefix,
            "suffix": suffix,
            "account_id": account_id,
            "created_at": created_at,
            "last_used_at": None,
            "last_used_ip": None,
        }

        keys = load_api_keys()
        keys.append(new_key_record)
        save_api_keys(keys)
        log(f"API key created: id={key_id} name={name!r}")

        self._send_json(201, {
            "id": key_id,
            "name": name,
            "key": full_key,   # returned once, never stored in plain
            "created_at": created_at,
        })

    def _handle_keys_delete(self, key_id: str) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        if not key_id:
            self._send_json(400, {"error": "Key ID required"})
            return

        keys = load_api_keys()
        new_keys = [k for k in keys if k["id"] != key_id]

        if len(new_keys) == len(keys):
            self._send_json(404, {"error": "Key not found"})
            return

        save_api_keys(new_keys)
        log(f"API key deleted: id={key_id}")
        self._send_json(200, {"message": "Key deleted"})

    def _handle_credentials(self) -> None:
        token = self._get_bearer_token()
        if not token:
            self._send_json(401, {"error": "Bearer token required"})
            return

        key_record = self._validate_api_key(token)
        if not key_record:
            log(f"Invalid API key attempt from {self._client_ip()}")
            self._send_json(401, {"error": "Invalid API key"})
            return

        # Resolve account for this key
        account = resolve_account(key_record, self._client_ip())

        files = {}
        if account and account.get("credentials_dir"):
            # Serve from account-specific credentials directory
            cred_dir = account["credentials_dir"]
            for rel_path in CREDENTIAL_REL_PATHS:
                full_path = os.path.join(cred_dir, rel_path)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        files[rel_path] = f.read()
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    log(f"Warning: could not read {full_path}: {exc}")
        else:
            # Legacy: serve from hardcoded paths
            for abs_path, logical_key in CLAUDE_CREDENTIAL_PATHS:
                try:
                    with open(abs_path, "r", encoding="utf-8") as f:
                        files[logical_key] = f.read()
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    log(f"Warning: could not read {abs_path}: {exc}")

        if not files:
            log(f"No credential files found for key {key_record['id']}")
            self._send_json(404, {"error": "No credential files found on server"})
            return

        # Update last_used metadata
        keys = load_api_keys()
        updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ip = self._client_ip()
        for k in keys:
            if k["id"] == key_record["id"]:
                k["last_used_at"] = updated_at
                k["last_used_ip"] = ip
                break
        save_api_keys(keys)

        account_info = f" account={account['name']}" if account else ""
        log(f"Credentials served to key {key_record['id']} ({key_record['name']}) from {ip}{account_info}")
        self._send_json(200, {"files": files})

    # ── Account management handlers ─────────────────────────────────────

    def _handle_accounts_list(self) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        accounts = load_accounts()
        result = []
        for a in accounts:
            proxy = a.get("upstream_proxy", {})
            masked_proxy = {
                "type": proxy.get("type", "direct"),
                "host": proxy.get("host", ""),
                "port": proxy.get("port", 0),
                "has_auth": bool(proxy.get("username")),
            }
            # Check if credentials exist
            cred_dir = a.get("credentials_dir", "")
            has_credentials = any(
                os.path.exists(os.path.join(cred_dir, rp))
                for rp in CREDENTIAL_REL_PATHS
            ) if cred_dir else False

            # Build quick quota summary from Claude usage cache (non-blocking)
            real_quota = None
            cached = get_cached_claude_usage(a["id"])
            if cached:
                rq: dict = {"subscription_type": None, "five_hour_pct": None, "seven_day_pct": None, "error": cached.get("error")}
                rq["five_hour_pct"] = cached.get("session_pct")
                rq["seven_day_pct"] = cached.get("weekly_all_pct")
                # Try profile from oauth cache for subscription type
                cached_profile = _oauth_cache.get(a["id"], {}).get("profile")
                if cached_profile:
                    org_type = cached_profile.get("organization", {}).get("organization_type", "")
                    if "max" in org_type:
                        rq["subscription_type"] = "max"
                    elif "pro" in org_type:
                        rq["subscription_type"] = "pro"
                    elif "enterprise" in org_type:
                        rq["subscription_type"] = "enterprise"
                    elif "team" in org_type:
                        rq["subscription_type"] = "team"
                real_quota = rq

            result.append({
                "id": a["id"],
                "name": a.get("name", ""),
                "status": a.get("status", "active"),
                "upstream_proxy": masked_proxy,
                "has_credentials": has_credentials,
                "real_quota": real_quota,
                "created_at": a.get("created_at"),
                "updated_at": a.get("updated_at"),
            })
        self._send_json(200, {"accounts": result})

    def _handle_accounts_create(self) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        body = self._parse_json_body()
        if not body:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        name = body.get("name", "").strip()
        if not name:
            self._send_json(400, {"error": "Account name is required"})
            return

        proxy = body.get("upstream_proxy", {"type": "direct"})
        proxy_type = proxy.get("type", "direct")
        if proxy_type not in ("direct", "http", "socks5"):
            self._send_json(400, {"error": "Invalid proxy type. Must be direct, http, or socks5"})
            return
        if proxy_type != "direct":
            if not proxy.get("host") or not proxy.get("port"):
                self._send_json(400, {"error": "host and port are required for http/socks5 proxy"})
                return

        quota = body.get("quota", {"monthly_limit_usd": 100.0, "reset_day": 1})

        account_id = "acc_" + secrets.token_hex(8)
        cred_dir = os.path.join(ACCOUNTS_DIR, account_id, "credentials")
        os.makedirs(os.path.join(cred_dir, ".claude"), exist_ok=True)

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        new_account = {
            "id": account_id,
            "name": name,
            "status": "active",
            "credentials_dir": cred_dir,
            "upstream_proxy": proxy,
            "quota": quota,
            "created_at": now,
            "updated_at": now,
        }

        accounts = load_accounts()
        accounts.append(new_account)
        save_accounts(accounts)
        log(f"Account created: id={account_id} name={name!r} proxy={proxy_type}")
        self._send_json(201, {"id": account_id, "name": name, "credentials_dir": cred_dir})

    def _handle_accounts_update(self, acc_id: str) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        body = self._parse_json_body()
        if not body:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        accounts = load_accounts()
        found = None
        for a in accounts:
            if a["id"] == acc_id:
                found = a
                break

        if not found:
            self._send_json(404, {"error": "Account not found"})
            return

        # Update allowed fields
        if "name" in body:
            found["name"] = body["name"].strip()
        if "upstream_proxy" in body:
            proxy = body["upstream_proxy"]
            proxy_type = proxy.get("type", "direct")
            if proxy_type not in ("direct", "http", "socks5"):
                self._send_json(400, {"error": "Invalid proxy type"})
                return
            if proxy_type != "direct":
                if not proxy.get("host") or not proxy.get("port"):
                    self._send_json(400, {"error": "host and port are required for http/socks5 proxy"})
                    return
            found["upstream_proxy"] = proxy
        if "quota" in body:
            found["quota"] = body["quota"]
        if "status" in body:
            if body["status"] not in ("active", "exhausted", "disabled"):
                self._send_json(400, {"error": "Invalid status"})
                return
            found["status"] = body["status"]

        found["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_accounts(accounts)
        log(f"Account updated: id={acc_id}")
        self._send_json(200, {"message": "Account updated"})

    def _handle_account_quota(self, acc_id: str) -> None:
        """Return real Anthropic quota data for an account."""
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        accounts = load_accounts()
        found = None
        for a in accounts:
            if a["id"] == acc_id:
                found = a
                break

        if not found:
            self._send_json(404, {"error": "Account not found"})
            return

        result = build_quota_response(found)
        self._send_json(200, result)

    def _handle_usage_refresh(self) -> None:
        """Manually trigger usage query for all accounts."""
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        # Run query in background thread to not block the HTTP response
        def _run():
            results = query_all_accounts_usage()
            log(f"Manual usage refresh: queried {len(results)} accounts")

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self._send_json(200, {"status": "querying", "message": "Usage query started in background"})

    def _handle_accounts_delete(self, acc_id: str) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        accounts = load_accounts()
        deleted = None
        new_accounts = []
        for a in accounts:
            if a["id"] == acc_id:
                deleted = a
            else:
                new_accounts.append(a)

        if not deleted:
            self._send_json(404, {"error": "Account not found"})
            return

        save_accounts(new_accounts)

        # Clean up assignments referencing this account
        assignments = load_assignments()
        for mapping in (assignments.get("by_api_key", {}), assignments.get("by_client_ip", {})):
            to_remove = [k for k, v in mapping.items() if v.get("account_id") == acc_id]
            for k in to_remove:
                del mapping[k]
        save_assignments(assignments)

        # Clean up credentials directory on disk
        cred_dir = deleted.get("credentials_dir", "")
        if cred_dir:
            # Remove the account directory (parent of credentials/)
            account_dir = os.path.dirname(cred_dir)
            if account_dir and os.path.isdir(account_dir) and account_dir.startswith(ACCOUNTS_DIR):
                shutil.rmtree(account_dir, ignore_errors=True)
                log(f"Cleaned up credentials directory: {account_dir}")

        log(f"Account deleted: id={acc_id}")
        self._send_json(200, {"message": "Account deleted"})

    def _handle_accounts_test(self, acc_id: str) -> None:
        """Test upstream proxy connectivity for an account."""
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        accounts = load_accounts()
        found = None
        for a in accounts:
            if a["id"] == acc_id:
                found = a
                break

        if not found:
            self._send_json(404, {"error": "Account not found"})
            return

        # Allow custom target host/port via query params, default to api.anthropic.com:443
        query = urlparse(self.path).query
        params = parse_qs(query)
        test_host = params.get("host", ["api.anthropic.com"])[0]
        test_port = int(params.get("port", ["443"])[0])

        proxy = found.get("upstream_proxy", {"type": "direct"})
        proxy_type = proxy.get("type", "direct")

        # Use shorter timeout for test connections
        original_timeout = 30
        test_timeout = 10
        try:
            if proxy_type == "direct":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(test_timeout)
                sock.connect((test_host, test_port))
            elif proxy_type == "http":
                sock = connect_via_http_proxy(
                    test_host, test_port,
                    proxy.get("host", ""), proxy.get("port", 0),
                    proxy.get("username"), proxy.get("password"),
                )
                sock.settimeout(test_timeout)
            elif proxy_type == "socks5":
                sock = connect_via_socks5(
                    test_host, test_port,
                    proxy.get("host", ""), proxy.get("port", 0),
                    proxy.get("username"), proxy.get("password"),
                )
                sock.settimeout(test_timeout)
            else:
                sock = connect_to_target(test_host, test_port, proxy)

            sock.close()
            self._send_json(200, {
                "success": True,
                "message": f"Successfully connected to {test_host}:{test_port} via {proxy_type} proxy",
            })
        except Exception as exc:
            self._send_json(200, {
                "success": False,
                "message": f"Connection to {test_host}:{test_port} failed: {exc}",
            })

    def _handle_accounts_upload_credentials(self, acc_id: str) -> None:
        """Upload credential files for an account."""
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        accounts = load_accounts()
        found = None
        for a in accounts:
            if a["id"] == acc_id:
                found = a
                break

        if not found:
            self._send_json(404, {"error": "Account not found"})
            return

        body = self._parse_json_body()
        if not body or "files" not in body:
            self._send_json(400, {"error": "JSON body with 'files' dict required"})
            return

        cred_dir = found.get("credentials_dir", "")
        if not cred_dir:
            self._send_json(500, {"error": "Account has no credentials directory"})
            return

        written = 0
        for rel_path, content in body["files"].items():
            # Only allow known credential paths for security
            if rel_path not in CREDENTIAL_REL_PATHS:
                continue
            full_path = os.path.join(cred_dir, rel_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(full_path, 0o600)
            written += 1

        log(f"Credentials uploaded for account {acc_id}: {written} files")
        self._send_json(200, {"message": f"{written} credential files written"})

    # ── Key ↔ Account assignment handlers ─────────────────────────────────

    def _handle_key_assign_account(self, key_id: str) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        body = self._parse_json_body()
        if not body or "account_id" not in body:
            self._send_json(400, {"error": "account_id required"})
            return

        account_id = body["account_id"]

        # Verify account exists
        accounts = load_accounts()
        if not any(a["id"] == account_id for a in accounts):
            self._send_json(404, {"error": "Account not found"})
            return

        # Update key record
        keys = load_api_keys()
        found = False
        for k in keys:
            if k["id"] == key_id:
                k["account_id"] = account_id
                found = True
                break

        if not found:
            self._send_json(404, {"error": "Key not found"})
            return

        save_api_keys(keys)

        # Also update sticky assignment
        assignments = load_assignments()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        assignments.setdefault("by_api_key", {})[key_id] = {
            "account_id": account_id, "assigned_at": now, "reason": "explicit",
        }
        save_assignments(assignments)

        log(f"Key {key_id} assigned to account {account_id}")
        self._send_json(200, {"message": "Key assigned to account"})

    def _handle_key_unassign_account(self, key_id: str) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        keys = load_api_keys()
        found = False
        for k in keys:
            if k["id"] == key_id:
                k["account_id"] = None
                found = True
                break

        if not found:
            self._send_json(404, {"error": "Key not found"})
            return

        save_api_keys(keys)

        # Remove sticky assignment
        assignments = load_assignments()
        assignments.get("by_api_key", {}).pop(key_id, None)
        save_assignments(assignments)

        log(f"Key {key_id} unassigned from account")
        self._send_json(200, {"message": "Key unassigned from account"})

    # ── Usage handler ─────────────────────────────────────────────────────

    def _handle_usage(self) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        # Flush pending usage data first
        if _usage_tracker:
            _usage_tracker.flush()

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        month = params.get("month", [time.strftime("%Y-%m")])[0]

        usage = load_usage()
        month_data = usage.get(month, {})

        # Build per-account summary
        accounts = load_accounts()
        accounts_map = {a["id"]: a for a in accounts}
        account_summary = {}

        for key_id, data in month_data.items():
            acc_id = data.get("account_id", "unknown")
            if acc_id not in account_summary:
                acc = accounts_map.get(acc_id, {})
                account_summary[acc_id] = {
                    "account_name": acc.get("name", "Unknown"),
                    "connections": 0,
                    "bytes_upstream": 0,
                    "bytes_downstream": 0,
                    "estimated_cost_usd": 0.0,
                }
            s = account_summary[acc_id]
            s["connections"] += data.get("connections", 0)
            s["bytes_upstream"] += data.get("bytes_upstream", 0)
            s["bytes_downstream"] += data.get("bytes_downstream", 0)
            s["estimated_cost_usd"] += data.get("estimated_cost_usd", 0.0)
            s["estimated_cost_usd"] = round(s["estimated_cost_usd"], 4)

        self._send_json(200, {
            "month": month,
            "by_key": month_data,
            "by_account": account_summary,
            "available_months": sorted(usage.keys()),
        })

    # ── Assignments handler ───────────────────────────────────────────────

    def _handle_assignments_list(self) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized"})
            return

        assignments = load_assignments()
        self._send_json(200, assignments)

    # ── Web UI ────────────────────────────────────────────────────────────

    def _handle_ui(self) -> None:
        if not self._is_authenticated():
            # Return a minimal redirect to login page embedded in ui.html
            # We still serve ui.html; the JS handles auth state via /api/auth/check
            pass  # Fall through and serve ui.html regardless; JS handles it

        try:
            with open(UI_FILE, "rb") as f:
                content = f.read()
            self._send_html(200, content)
        except FileNotFoundError:
            fallback = b"<html><body><h1>Phantom Server</h1><p>ui.html not found.</p></body></html>"
            self._send_html(404, fallback)
        except Exception as exc:
            log(f"Error serving ui.html: {exc}")
            self._send_json(500, {"error": "Could not serve UI"})


# ── Threaded HTTP server ──────────────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    global _usage_tracker

    ensure_data_dir()
    os.makedirs(ACCOUNTS_DIR, exist_ok=True)

    log(f"Starting on 0.0.0.0:{LISTEN_PORT}")
    log(f"Data directory: {DATA_DIR}")

    # Run migration from v1 (single account) to v2 (multi-account)
    migrate_v1_to_v2()

    cfg = load_server_config()
    if cfg.get("master_password_hash"):
        log("Master password: configured")
    else:
        log("Master password: NOT SET - visit /api/auth/setup to configure")

    accounts = load_accounts()
    log(f"Accounts: {len(accounts)} configured")
    for a in accounts:
        proxy_type = a.get("upstream_proxy", {}).get("type", "direct")
        log(f"  - {a.get('name', a['id'])} [{a.get('status', '?')}] proxy={proxy_type}")

    # Initialize usage tracker
    _usage_tracker = UsageTracker()
    log("Usage tracker: started")

    # Start quota reset checker
    quota_thread = threading.Thread(target=_quota_check_loop, daemon=True)
    quota_thread.start()
    log("Quota checker: started")

    # Start Claude Code usage query background thread
    if shutil.which("tmux") and os.path.isfile(CLAUDE_BIN):
        usage_query_thread = threading.Thread(target=_usage_query_loop, daemon=True)
        usage_query_thread.start()
        log(f"Claude usage query: started (interval {USAGE_QUERY_MIN_INTERVAL}-{USAGE_QUERY_MAX_INTERVAL}s)")
    else:
        log("Claude usage query: DISABLED (tmux or claude not found)")

    server = ThreadedHTTPServer(("0.0.0.0", LISTEN_PORT), PhantomHandler)
    log(f"Listening on 0.0.0.0:{LISTEN_PORT} (CONNECT proxy + REST API + multi-account)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Flushing usage data...")
        _usage_tracker.flush()
        log("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
