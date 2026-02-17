#!/usr/bin/env python3
"""
Phantom Server - Hybrid HTTP CONNECT proxy + REST API + Web UI

Handles:
  CONNECT method  -> transparent proxy tunnel (for Claude Code / Node.js)
  GET/POST/DELETE -> REST API + Web UI management interface

Usage:
  python3 phantom_server.py [PORT [DATA_DIR]]

Defaults:
  PORT     = 8080
  DATA_DIR = /opt/phantom-cli/data
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

# ── Configuration ────────────────────────────────────────────────────────────

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
DATA_DIR = sys.argv[2] if len(sys.argv) > 2 else "/opt/phantom-cli/data"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(SCRIPT_DIR, "ui.html")

SERVER_CONFIG_FILE = os.path.join(DATA_DIR, "server_config.json")
API_KEYS_FILE = os.path.join(DATA_DIR, "api_keys.json")

BUFFER_SIZE = 65536
SESSION_TTL = 86400  # 24 hours in seconds
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX = 5  # max failed attempts per window

CLAUDE_CREDENTIAL_PATHS = [
    ("/root/.claude/.credentials.json", ".claude/.credentials.json"),
    ("/root/.claude.json", ".claude.json"),
    ("/root/.claude/settings.json", ".claude/settings.json"),
]

# ── Global state (protected by locks) ────────────────────────────────────────

_file_lock = threading.Lock()
_sessions: dict = {}          # {session_id: {"created_at": float}}
_sessions_lock = threading.Lock()
_rate_limit: dict = {}        # {ip: [timestamp, ...]}
_rate_limit_lock = threading.Lock()


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


# ── CONNECT proxy tunnel ──────────────────────────────────────────────────────

def _forward(src: socket.socket, dst: socket.socket) -> None:
    """Forward data from src to dst until connection closes."""
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.close()
            except Exception:
                pass


def handle_connect(client_socket: socket.socket, target: str) -> None:
    """
    Establish a tunnel for a CONNECT request.
    target is "host:port".
    """
    try:
        host, _, port_str = target.rpartition(":")
        port = int(port_str)

        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.settimeout(30)
        remote_socket.connect((host, port))

        # Note: 200 response is already sent by do_CONNECT() before calling this function

        t1 = threading.Thread(
            target=_forward, args=(client_socket, remote_socket), daemon=True
        )
        t2 = threading.Thread(
            target=_forward, args=(remote_socket, client_socket), daemon=True
        )
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as exc:
        log(f"CONNECT tunnel error for {target}: {exc}")
        try:
            client_socket.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n\r\nCould not connect to target\n"
            )
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
        log(f"CONNECT {target} from {self._client_ip()}")
        # Send 200 and detach socket for raw tunnelling
        self.send_response(200, "Connection Established")
        self.end_headers()
        # Detach the underlying socket and hand it to the tunnel handler
        # We access the raw socket via self.connection
        handle_connect(self.connection, target)

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

        # ── Web UI ────────────────────────────────────────────────────────

        if method == "GET" and path == "/":
            return self._handle_ui()

        # ── 404 ───────────────────────────────────────────────────────────
        self._send_json(404, {"error": "Not Found"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_DELETE(self):
        self._route("DELETE")

    # ── Handlers ──────────────────────────────────────────────────────────

    def _handle_health(self) -> None:
        self._send_json(200, {"status": "ok"})

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
        self._send_json(200, {"message": "Master password set successfully"})

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
        masked = []
        for k in keys:
            masked.append({
                "id": k["id"],
                "name": k["name"],
                "masked_key": mask_key(k["prefix"], k["suffix"]),
                "created_at": k["created_at"],
                "last_used_at": k.get("last_used_at"),
                "last_used_ip": k.get("last_used_ip"),
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

        new_key_record = {
            "id": key_id,
            "name": name,
            "key_hash": key_hash,
            "prefix": prefix,
            "suffix": suffix,
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

        # Collect credential files
        files = {}
        for abs_path, logical_key in CLAUDE_CREDENTIAL_PATHS:
            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    files[logical_key] = f.read()
            except FileNotFoundError:
                pass  # Skip missing files silently
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

        log(f"Credentials served to key {key_record['id']} ({key_record['name']}) from {ip}")
        self._send_json(200, {"files": files})

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
    ensure_data_dir()

    log(f"Starting on 0.0.0.0:{LISTEN_PORT}")
    log(f"Data directory: {DATA_DIR}")

    cfg = load_server_config()
    if cfg.get("master_password_hash"):
        log("Master password: configured")
    else:
        log("Master password: NOT SET - visit /api/auth/setup to configure")

    server = ThreadedHTTPServer(("0.0.0.0", LISTEN_PORT), PhantomHandler)
    log(f"Listening on 0.0.0.0:{LISTEN_PORT} (CONNECT proxy + REST API)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
