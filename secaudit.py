#!/usr/bin/env python3
"""
================================================================================
  SENTINEL-CLI  |  Local Security Auditing & Diagnostics Framework
  Platform: Termux / Linux localhost
  Purpose : Recon + audit tooling for YOUR OWN local machine / dev servers.

  Scope restriction:
    All HTTP/web audit modules REQUIRE the target to resolve to a loopback
    address (127.0.0.1 / ::1 / "localhost"). Non-loopback targets are
    rejected before any request is sent.

  Excluded by design:
    No credential-stuffing, no brute-force, no payload/injection fuzzing,
    no exploitation code of any kind. This tool only observes, measures,
    and reports on things you already control.
================================================================================
"""

import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
import random
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# ============================================================================
#  ANSI COLOR ENGINE
# ============================================================================

SENTINEL_VERSION = "1.1.0"


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    RED = "\033[38;5;196m"
    GREEN = "\033[38;5;46m"
    YELLOW = "\033[38;5;226m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;201m"
    CYAN = "\033[38;5;51m"
    ORANGE = "\033[38;5;208m"
    PURPLE = "\033[38;5;135m"
    GREY = "\033[38;5;245m"
    WHITE = "\033[97m"

    @staticmethod
    def ok(msg):    return f"{C.GREEN}{C.BOLD}[+]{C.RESET} {msg}"
    @staticmethod
    def bad(msg):   return f"{C.RED}{C.BOLD}[-]{C.RESET} {msg}"
    @staticmethod
    def warn(msg):  return f"{C.YELLOW}{C.BOLD}[!]{C.RESET} {msg}"
    @staticmethod
    def info(msg):  return f"{C.CYAN}{C.BOLD}[*]{C.RESET} {msg}"
    @staticmethod
    def head(msg):  return f"{C.MAGENTA}{C.BOLD}{msg}{C.RESET}"


def banner():
    art = f"""
{C.CYAN}{C.BOLD}   _____ _____ _   _ _______ _____ _   _ ______ _
  / ____|  ___| \\ | |__   __|_   _| \\ | |  ____| |
 | (___ | |__ |  \\| |  | |    | | |  \\| | |__  | |
  \\___ \\|  __|| . ` |  | |    | | | . ` |  __| | |
  ____) | |___| |\\  |  | |   _| |_| |\\  | |____| |____
 |_____/|______|_| \\_|  |_|  |_____|_| \\_|______|______|{C.RESET}
{C.GREY}      Local Security Auditing & Diagnostics Framework{C.RESET}
{C.GREY}      Scope: localhost / 127.0.0.1 / ::1 only   |   v{SENTINEL_VERSION}{C.RESET}
"""
    print(art)


# ============================================================================
#  MODULE 1: SECURE LOCAL AUTHENTICATION
# ============================================================================

AUTH_DIR = os.path.join(os.path.expanduser("~"), ".sentinel_cli")
AUTH_FILE = os.path.join(AUTH_DIR, "auth.json")
MIN_PASSWORD_LEN = 16


def _ensure_auth_dir():
    os.makedirs(AUTH_DIR, exist_ok=True)


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def _create_account():
    print(C.info("No local credentials found. Let's create one."))
    while True:
        username = input(f"{C.CYAN}  Choose a username: {C.RESET}").strip()
        if username:
            break
        print(C.bad("Username cannot be empty."))

    while True:
        password = input(f"{C.CYAN}  Choose a password (min {MIN_PASSWORD_LEN} chars): {C.RESET}").strip()
        if len(password) >= MIN_PASSWORD_LEN:
            break
        print(C.bad(f"Password must be at least {MIN_PASSWORD_LEN} characters."))

    salt = os.urandom(16)
    pwd_hash = _hash_password(password, salt)

    _ensure_auth_dir()
    record = {
        "username": username,
        "salt": salt.hex(),
        "hash": pwd_hash,
        "created": datetime.now().isoformat(),
    }
    with open(AUTH_FILE, "w") as f:
        json.dump(record, f)
    os.chmod(AUTH_FILE, 0o600)
    print(C.ok("Account created. Please log in.\n"))


def _reset_account():
    print(C.warn("\nResetting local credentials will erase the current account and let you create a new one."))
    confirm = input(f"{C.CYAN}  Type 'yes' to confirm reset: {C.RESET}").strip().lower()
    if confirm != "yes":
        print(C.info("Reset cancelled."))
        return False
    try:
        os.remove(AUTH_FILE)
    except OSError:
        pass
    print(C.ok("Old credentials removed.\n"))
    _create_account()
    return True


def _load_auth_record():
    """Load the auth record, recovering gracefully from a missing or corrupt file."""
    try:
        with open(AUTH_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _login() -> bool:
    record = _load_auth_record()
    if record is None:
        print(C.bad("Stored credentials are missing or corrupted."))
        if not _reset_account():
            return False
        record = _load_auth_record()
        if record is None:
            print(C.bad("Could not recover a valid credential file."))
            return False

    for attempt in range(5):
        try:
            username = input(f"{C.CYAN}  Username (or type 'reset' if you forgot your password): {C.RESET}").strip()

            if username.lower() == "reset":
                if _reset_account():
                    record = _load_auth_record()
                continue

            password = input(f"{C.CYAN}  Password: {C.RESET}").strip()
        except EOFError:
            print(C.bad("\nInput closed. Exiting."))
            return False

        salt = bytes.fromhex(record["salt"])
        attempt_hash = _hash_password(password, salt)

        if username == record["username"] and hmac.compare_digest(attempt_hash, record["hash"]):
            print(C.ok(f"Welcome back, {username}.\n"))
            return True
        print(C.bad(f"Invalid credentials. {4 - attempt} attempt(s) remaining."))
        print(C.info("Forgot your password? Type 'reset' as the username on your next attempt."))

    return False


def authenticate():
    _ensure_auth_dir()
    if not os.path.exists(AUTH_FILE):
        _create_account()
    if not _login():
        print(C.bad("Authentication failed. Exiting."))
        sys.exit(1)


# ============================================================================
#  SCOPE ENFORCEMENT: LOOPBACK-ONLY VALIDATION FOR ALL HTTP/WEB MODULES
# ============================================================================

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def is_loopback_target(host: str) -> bool:
    host = host.strip().lower().lstrip("[").rstrip("]")
    if host in LOOPBACK_NAMES:
        return True
    try:
        resolved = socket.gethostbyname(host)
        return resolved.startswith("127.") or resolved == "::1"
    except socket.gaierror:
        return False


def require_loopback(prompt_label="Target host") -> str:
    """Prompt for a host and enforce loopback scope. Returns validated host or None."""
    host = input(f"{C.CYAN}  {prompt_label} (default: 127.0.0.1): {C.RESET}").strip() or "127.0.0.1"
    if not is_loopback_target(host):
        print(C.bad(f"Target '{host}' is not a loopback address. This module is restricted to "
                     f"localhost / 127.0.0.1 / ::1 only."))
        return None
    return host


def prompt_int(label, default):
    raw = input(f"{C.CYAN}  {label} (default: {default}): {C.RESET}").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print(C.warn("Invalid number, using default."))
        return default


def pause():
    input(f"\n{C.GREY}Press Enter to return to the menu...{C.RESET}")


# ============================================================================
#  MODULE 2: TCP PORT SCANNER (threaded)
# ============================================================================

def module_port_scanner():
    print(C.head("\n=== TCP Port Scanner ==="))
    target = input(f"{C.CYAN}  Target host (default: 127.0.0.1): {C.RESET}").strip() or "127.0.0.1"
    port_range = input(f"{C.CYAN}  Port range e.g. 1-1024 (default: 1-1024): {C.RESET}").strip() or "1-1024"
    try:
        start, end = (int(x) for x in port_range.split("-"))
    except ValueError:
        print(C.bad("Invalid range format. Use e.g. 1-1024"))
        return

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(C.bad(f"Could not resolve host: {target}"))
        return

    print(C.info(f"Scanning {target} ({ip}) ports {start}-{end}...\n"))
    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    with lock:
                        open_ports.append(port)
                        print(C.ok(f"Port {port:<6} OPEN   ({service})"))
        except socket.error:
            pass

    threads = []
    max_threads = 200
    sem = threading.Semaphore(max_threads)

    def worker(p):
        with sem:
            scan_port(p)

    start_time = time.time()
    for port in range(start, end + 1):
        t = threading.Thread(target=worker, args=(port,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - start_time

    print(f"\n{C.info(f'Scan complete in {elapsed:.2f}s. {len(open_ports)} open port(s) found.')}")


# ============================================================================
#  MODULE 3: BANNER GRABBING (ports 1-1024)
# ============================================================================

def module_banner_grab():
    print(C.head("\n=== Local Service Banner Grabbing (ports 1-1024) ==="))
    target = input(f"{C.CYAN}  Target host (default: 127.0.0.1): {C.RESET}").strip() or "127.0.0.1"
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(C.bad(f"Could not resolve host: {target}"))
        return

    print(C.info(f"Probing {target} ({ip}) for open ports and banners...\n"))
    lock = threading.Lock()
    found = []

    def grab(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                if s.connect_ex((ip, port)) != 0:
                    return
                banner_text = ""
                try:
                    s.settimeout(0.8)
                    data = s.recv(256)
                    banner_text = data.decode(errors="replace").strip()
                except socket.timeout:
                    pass
                except socket.error:
                    pass
                with lock:
                    found.append((port, banner_text))
                    display = banner_text if banner_text else "(no banner / silent service)"
                    print(C.ok(f"Port {port:<6} -> {display[:80]}"))
        except socket.error:
            pass

    sem = threading.Semaphore(200)

    def worker(p):
        with sem:
            grab(p)

    threads = [threading.Thread(target=worker, args=(p,)) for p in range(1, 1025)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"\n{C.info(f'{len(found)} service(s) responded.')}")


# ============================================================================
#  MODULE 4: NETWORK DIAGNOSTICS & SOCKET TEST
# ============================================================================

def module_net_diagnostics():
    print(C.head("\n=== Network Diagnostics & Socket Test ==="))
    target = input(f"{C.CYAN}  Host to diagnose (default: 127.0.0.1): {C.RESET}").strip() or "127.0.0.1"

    # DNS resolution
    print(C.info("Resolving hostname..."))
    try:
        ip = socket.gethostbyname(target)
        print(C.ok(f"Resolved '{target}' -> {ip}"))
    except socket.gaierror as e:
        print(C.bad(f"DNS resolution failed: {e}"))
        return

    # Common port reachability
    common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                     80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                     3306: "MySQL", 5432: "PostgreSQL", 5000: "Dev-Server",
                     8000: "Dev-Server", 8080: "HTTP-Alt", 27017: "MongoDB"}

    print(C.info("Testing common service ports..."))
    for port, name in common_ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                start = time.time()
                result = s.connect_ex((ip, port))
                latency_ms = (time.time() - start) * 1000
                if result == 0:
                    print(C.ok(f"{name:<12} port {port:<6} reachable  ({latency_ms:.1f} ms)"))
        except socket.error:
            continue

    # Socket round-trip test on a chosen port
    port = prompt_int("Port for raw socket round-trip test", 80)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            t0 = time.time()
            s.connect((ip, port))
            rtt = (time.time() - t0) * 1000
            print(C.ok(f"Connected to {ip}:{port} in {rtt:.2f} ms"))
    except socket.error as e:
        print(C.bad(f"Socket connection failed: {e}"))


# ============================================================================
#  HTTP HELPERS (shared by web audit modules)
# ============================================================================

def http_request(host, port, path="/", method="GET", body=None, headers=None,
                  use_tls=False, timeout=5):
    """Low-level HTTP request via http.client. Returns (status, headers, body) or None."""
    headers = headers or {}
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result
    except (ConnectionRefusedError, socket.timeout, http.client.HTTPException,
            OSError, ssl.SSLError):
        return None


def detect_port_and_tls(host):
    """Try to find a reachable port/TLS combo on the loopback target."""
    candidates = [(443, True), (8443, True), (80, False), (8080, False),
                  (5000, False), (8000, False), (3000, False), (4000, False)]
    for port, tls in candidates:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                if s.connect_ex((host if host != "localhost" else "127.0.0.1", port)) == 0:
                    return port, tls
        except socket.error:
            continue
    return None, None


def prompt_target_port_tls():
    host = require_loopback()
    if not host:
        return None, None, None
    detected_port, detected_tls = detect_port_and_tls(host)
    default_port = detected_port or 80
    port = prompt_int("Port", default_port)
    tls_default = "y" if (detected_tls and port == detected_port) else "n"
    tls_in = input(f"{C.CYAN}  Use HTTPS/TLS? (y/n, default {tls_default}): {C.RESET}").strip().lower()
    use_tls = (tls_in or tls_default) == "y"
    return host, port, use_tls


# ============================================================================
#  MODULE 5: HTTP SECURITY HEADERS SCANNER
# ============================================================================

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def module_security_headers():
    print(C.head("\n=== HTTP Security Headers Scanner ==="))
    host, port, use_tls = prompt_target_port_tls()
    if host is None:
        return
    path = input(f"{C.CYAN}  Path (default: /): {C.RESET}").strip() or "/"

    result = http_request(host, port, path, "GET", use_tls=use_tls)
    if result is None:
        print(C.bad(f"Could not connect to {host}:{port}"))
        return

    status, headers, _ = result
    print(C.info(f"Response status: {status}\n"))
    norm_headers = {k.lower(): v for k, v in headers.items()}

    present, missing = [], []
    for h in SECURITY_HEADERS:
        if h.lower() in norm_headers:
            present.append(h)
            print(C.ok(f"{h:<32} -> {norm_headers[h.lower()]}"))
        else:
            missing.append(h)

    print()
    for h in missing:
        print(C.bad(f"{h:<32} -> MISSING"))

    score = int((len(present) / len(SECURITY_HEADERS)) * 100)
    color = C.GREEN if score >= 70 else (C.YELLOW if score >= 40 else C.RED)
    print(f"\n{color}{C.BOLD}Security header coverage: {score}%{C.RESET}")


# ============================================================================
#  MODULE 6: HTTP METHODS ENUMERATION
# ============================================================================

def module_http_methods():
    print(C.head("\n=== HTTP Methods Enumeration ==="))
    host, port, use_tls = prompt_target_port_tls()
    if host is None:
        return
    path = input(f"{C.CYAN}  Path (default: /): {C.RESET}").strip() or "/"

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

    result = http_request(host, port, path, "OPTIONS", use_tls=use_tls)
    if result:
        status, headers, _ = result
        allow = headers.get("Allow") or headers.get("allow")
        if allow:
            print(C.ok(f"OPTIONS response advertises Allow: {allow}"))

    print(C.info("Probing each method individually...\n"))
    for m in methods:
        result = http_request(host, port, path, m, use_tls=use_tls)
        if result is None:
            print(C.bad(f"{m:<8} -> no response / connection failed"))
            continue
        status, _, _ = result
        if status < 400:
            print(C.ok(f"{m:<8} -> {status} (allowed)"))
        elif status in (404, 405):
            print(C.warn(f"{m:<8} -> {status} (not allowed / not found)"))
        else:
            print(C.info(f"{m:<8} -> {status}"))

    if any(m in ("TRACE", "CONNECT") for m in methods):
        print(C.warn("\nNote: TRACE/CONNECT being enabled on a web server is often "
                      "considered poor practice and is worth disabling if unused."))


# ============================================================================
#  MODULE 7: COOKIE SECURITY FLAG AUDITOR
# ============================================================================

def module_cookie_audit():
    print(C.head("\n=== Cookie Security Flag Auditor ==="))
    host, port, use_tls = prompt_target_port_tls()
    if host is None:
        return
    path = input(f"{C.CYAN}  Path (default: /): {C.RESET}").strip() or "/"

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=5, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        raw_cookies = resp.msg.get_all("Set-Cookie") or []
        conn.close()
    except (ConnectionRefusedError, socket.timeout, http.client.HTTPException, OSError, ssl.SSLError) as e:
        print(C.bad(f"Request failed: {e}"))
        return

    if not raw_cookies:
        print(C.warn("No Set-Cookie headers found on this response."))
        return

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0]
        flags_lower = [p.lower() for p in parts[1:]]
        print(C.head(f"\nCookie: {name}"))

        has_secure = "secure" in flags_lower
        has_httponly = "httponly" in flags_lower
        samesite = next((p for p in parts[1:] if p.lower().startswith("samesite")), None)

        print(C.ok("Secure flag set") if has_secure else C.bad("Secure flag MISSING"))
        print(C.ok("HttpOnly flag set") if has_httponly else C.bad("HttpOnly flag MISSING"))
        print(C.ok(f"SameSite: {samesite.split('=')[1] if '=' in samesite else samesite}") if samesite
              else C.bad("SameSite attribute MISSING"))


# ============================================================================
#  MODULE 8: SSL/TLS INSPECTOR
# ============================================================================

def module_tls_inspector():
    print(C.head("\n=== SSL/TLS Inspector ==="))
    host = require_loopback()
    if not host:
        return
    port = prompt_int("HTTPS port", 443)
    connect_host = "127.0.0.1" if host == "localhost" else host

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((connect_host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                print(C.ok(f"TLS handshake successful"))
                print(C.info(f"Protocol version : {version}"))
                if cipher:
                    print(C.info(f"Cipher suite     : {cipher[0]} ({cipher[1]}, {cipher[2]} bits)"))

                if not cert:
                    print(C.warn("Server did not present a verifiable certificate "
                                  "(common for self-signed local dev certs). "
                                  f"Raw cert bytes received: {len(cert_bin) if cert_bin else 0}"))
                else:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    print(C.info(f"Subject          : {subject}"))
                    print(C.info(f"Issuer           : {issuer}"))
                    print(C.info(f"Valid from       : {cert.get('notBefore')}"))
                    print(C.info(f"Valid until      : {cert.get('notAfter')}"))

    except ssl.SSLError as e:
        print(C.bad(f"TLS handshake failed: {e}"))
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        print(C.bad(f"Could not connect to {connect_host}:{port} -> {e}"))


# ============================================================================
#  MODULE 9: RATE-LIMIT & LATENCY TESTER
# ============================================================================

def module_rate_limit_test():
    print(C.head("\n=== Rate-Limit & Latency Tester ==="))
    host, port, use_tls = prompt_target_port_tls()
    if host is None:
        return
    path = input(f"{C.CYAN}  Path (default: /): {C.RESET}").strip() or "/"
    count = prompt_int("Number of sequential requests to send", 30)
    delay_ms = prompt_int("Delay between requests in ms", 0)

    latencies = []
    status_counts = {}

    print(C.info(f"Sending {count} requests to {host}:{port}{path} ...\n"))
    for i in range(count):
        t0 = time.time()
        result = http_request(host, port, path, "GET", use_tls=use_tls)
        elapsed_ms = (time.time() - t0) * 1000
        if result is None:
            status_counts["NO_RESPONSE"] = status_counts.get("NO_RESPONSE", 0) + 1
            print(C.bad(f"Request {i+1:<4} -> no response"))
        else:
            status, _, _ = result
            status_counts[status] = status_counts.get(status, 0) + 1
            latencies.append(elapsed_ms)
            tag = C.bad if status == 429 else (C.warn if status >= 400 else C.ok)
            print(tag(f"Request {i+1:<4} -> {status}  ({elapsed_ms:.1f} ms)"))
        if delay_ms:
            time.sleep(delay_ms / 1000)

    print(C.head("\n--- Summary ---"))
    for status, c in sorted(status_counts.items(), key=lambda x: str(x[0])):
        print(f"  {status}: {c}")
    if latencies:
        print(C.info(f"Avg latency: {sum(latencies)/len(latencies):.1f} ms  |  "
                      f"Min: {min(latencies):.1f} ms  |  Max: {max(latencies):.1f} ms"))
    if 429 in status_counts:
        print(C.ok("Server appears to enforce rate limiting (HTTP 429 observed)."))
    else:
        print(C.warn("No HTTP 429 responses observed - rate limiting may not be active "
                      "(or the threshold wasn't reached)."))


# ============================================================================
#  MODULE 10: API / DIRECTORY ENDPOINT DISCOVERY (passive wordlist)
# ============================================================================

DEFAULT_WORDLIST = [
    "admin", "login", "logout", "api", "api/v1", "api/v2", "health", "status",
    "config", "settings", "dashboard", "register", "signup", "users", "user",
    "static", "assets", "robots.txt", "sitemap.xml", ".env", ".git/HEAD",
    "backup", "test", "debug", "graphql", "swagger", "swagger.json",
    "openapi.json", "docs", "metrics", "actuator", "actuator/health",
    "wp-admin", "wp-login.php", "phpinfo.php", "console",
]


def module_endpoint_discovery():
    print(C.head("\n=== API / Directory Endpoint Discovery (passive) ==="))
    host, port, use_tls = prompt_target_port_tls()
    if host is None:
        return

    custom = input(f"{C.CYAN}  Use custom wordlist file path? (blank = built-in list): {C.RESET}").strip()
    wordlist = DEFAULT_WORDLIST
    if custom:
        try:
            with open(custom) as f:
                wordlist = [line.strip().lstrip("/") for line in f if line.strip()]
        except OSError as e:
            print(C.warn(f"Could not read file ({e}), using built-in wordlist."))

    print(C.info(f"Probing {len(wordlist)} paths on {host}:{port} ...\n"))
    found = []
    lock = threading.Lock()

    def check(word):
        path = "/" + word
        result = http_request(host, port, path, "GET", use_tls=use_tls, timeout=3)
        if result is None:
            return
        status, headers, body = result
        if status != 404:
            with lock:
                found.append((path, status, len(body)))
                tag = C.ok if status < 400 else C.warn
                print(tag(f"{path:<28} -> {status}  ({len(body)} bytes)"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        pool.map(check, wordlist)

    print(f"\n{C.info(f'{len(found)} responsive path(s) out of {len(wordlist)} probed.')}")


# ============================================================================
#  MODULE 11: LOCAL WEBSITE STRENGTH & CAPACITY TESTING
# ============================================================================

def _random_string(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _synthetic_profile():
    first = _random_string(6)
    last = _random_string(6)
    username = f"{first}.{last}"
    email = f"{username}@example.test"
    password = _random_string(14) + "Aa1!"
    return {
        "first_name": first.capitalize(),
        "last_name": last.capitalize(),
        "username": username,
        "email": email,
        "password": password,
    }


def module_load_test():
    print(C.head("\n=== Local Website Strength & Capacity Testing ==="))
    print(f"{C.GREY}Enter a direct local URL, choose how many concurrent synthetic users\n"
          f"to simulate, and this module fires that many requests at once to\n"
          f"measure your local server's throughput, latency, and capacity.{C.RESET}\n")

    # --- Step 1: URL input + strict loopback validation ---
    url = input(f"{C.CYAN}  Target URL (e.g. http://127.0.0.1:8000/index.html): {C.RESET}").strip()
    if not url:
        print(C.bad("No URL entered. Aborting."))
        return
    if "://" not in url:
        url = "http://" + url  # tolerate "127.0.0.1:8000/path" style input

    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or "http").lower()
    hostname = parsed.hostname
    if not hostname:
        print(C.bad("Could not parse a hostname from that URL."))
        return

    if not is_loopback_target(hostname):
        print(C.bad(f"Target host '{hostname}' is not a loopback address. "
                     f"This module is strictly restricted to localhost / 127.0.0.1 / ::1."))
        return

    use_tls = scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    connect_host = "127.0.0.1" if hostname.lower() == "localhost" else hostname

    # --- Step 2: HTTP method ---
    method = input(f"{C.CYAN}  HTTP method [GET/POST] (default: GET): {C.RESET}").strip().upper() or "GET"
    if method not in ("GET", "POST"):
        print(C.warn(f"Unrecognized method '{method}', defaulting to GET."))
        method = "GET"

    content_type = "json"
    if method == "POST":
        content_type = input(f"{C.CYAN}  Content type for POST body [json/form] "
                              f"(default: json): {C.RESET}").strip().lower() or "json"

    # --- Step 3: concurrent user count (1-150) ---
    while True:
        raw = input(f"{C.CYAN}  Number of concurrent users/requests (1-150, default: 25): {C.RESET}").strip()
        if not raw:
            concurrent_users = 25
            break
        try:
            concurrent_users = int(raw)
        except ValueError:
            print(C.bad("Please enter a whole number between 1 and 150."))
            continue
        if 1 <= concurrent_users <= 150:
            break
        print(C.bad("Value must be between 1 and 150."))

    # --- Step 4: fire concurrent requests with a live progress bar ---
    results = {"status_counts": {}, "latencies": [], "errors": 0, "completed": 0}
    lock = threading.Lock()
    bar_width = 30

    def render_progress():
        done = results["completed"]
        frac = done / concurrent_users
        filled = int(bar_width * frac)
        bar = "█" * filled + "░" * (bar_width - filled)
        sys.stdout.write(
            f"\r{C.CYAN}  [{bar}] {done}/{concurrent_users} "
            f"({frac*100:5.1f}%){C.RESET}"
        )
        sys.stdout.flush()

    def fire_one(_):
        headers = {}
        body = None
        if method == "POST":
            profile = _synthetic_profile()
            if content_type == "form":
                body = urllib.parse.urlencode(profile)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(profile)
                headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))

        t0 = time.time()
        try:
            result = http_request(connect_host, port, path, method, body=body,
                                   headers=headers, use_tls=use_tls, timeout=10)
        except Exception:
            result = None
        elapsed_ms = (time.time() - t0) * 1000

        with lock:
            if result is None:
                results["errors"] += 1
            else:
                status, _, _ = result
                results["status_counts"][status] = results["status_counts"].get(status, 0) + 1
                results["latencies"].append(elapsed_ms)
            results["completed"] += 1
            render_progress()

    print(C.info(f"\nFiring {concurrent_users} concurrent {method} requests at "
                 f"{scheme}://{hostname}:{port}{path} ...\n"))
    render_progress()

    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as pool:
        futures = [pool.submit(fire_one, i) for i in range(concurrent_users)]
        concurrent.futures.wait(futures)
    total_elapsed = time.time() - start_time

    print("\n")  # move past the progress bar line

    # --- Step 5: results summary ---
    print(C.head("--- Capacity Test Summary ---"))
    print(C.info(f"Target           : {scheme}://{hostname}:{port}{path}"))
    print(C.info(f"Concurrent users : {concurrent_users}"))
    print(C.info(f"Total time       : {total_elapsed:.2f}s"))
    if total_elapsed > 0:
        print(C.info(f"Throughput       : {concurrent_users/total_elapsed:.2f} req/s"))
    print(C.info(f"Connection errors: {results['errors']}"))

    for status, c in sorted(results["status_counts"].items(), key=lambda x: str(x[0])):
        tag = C.ok if status < 300 else (C.bad if status == 429 else C.warn)
        print(tag(f"  HTTP {status}: {c} response(s)"))

    lat = results["latencies"]
    if lat:
        lat_sorted = sorted(lat)
        p95 = lat_sorted[int(len(lat_sorted) * 0.95) - 1] if len(lat_sorted) >= 20 else max(lat_sorted)
        print(C.info(f"Latency avg/min/max/p95: "
                      f"{sum(lat)/len(lat):.1f} / {min(lat):.1f} / {max(lat):.1f} / {p95:.1f} ms"))

    if 429 in results["status_counts"]:
        print(C.ok("\nRate limiting appears active under load (HTTP 429 observed)."))
    elif results["errors"] > concurrent_users * 0.2:
        print(C.warn("\nHigh connection-error rate - server may be hitting a concurrency ceiling."))
    else:
        print(C.warn("\nNo rate limiting observed at this load level."))


# ============================================================================
#  MENU SYSTEM
# ============================================================================

MENU_ITEMS = [
    ("TCP Port Scanner", module_port_scanner),
    ("Local Service Banner Grabbing (1-1024)", module_banner_grab),
    ("Network Diagnostics & Socket Test", module_net_diagnostics),
    ("HTTP Security Headers Scanner", module_security_headers),
    ("HTTP Methods Enumeration", module_http_methods),
    ("Cookie Security Flag Auditor", module_cookie_audit),
    ("SSL/TLS Inspector", module_tls_inspector),
    ("Rate-Limit & Latency Tester", module_rate_limit_test),
    ("API / Directory Endpoint Discovery", module_endpoint_discovery),
    ("Local Website Strength & Capacity Testing", module_load_test),
]


def print_menu():
    print(C.head(f"\n============ SENTINEL-CLI v{SENTINEL_VERSION} — MAIN MENU ============"))
    for i, (label, _) in enumerate(MENU_ITEMS, start=1):
        print(f"  {C.YELLOW}{i:>2}.{C.RESET} {label}")
    print(f"  {C.YELLOW} 0.{C.RESET} Exit")
    print(C.head("=" * 52))


def show_disclaimer_gate() -> bool:
    """Display a mandatory legal/ethical notice and require explicit acknowledgment."""
    print(C.head("=" * 60))
    print(C.warn("LEGAL & ETHICAL USE NOTICE"))
    print(f"{C.GREY}This tool is for authorized local security auditing only\n"
          f"(127.0.0.1 / localhost / ::1, or systems you own or are\n"
          f"explicitly authorized in writing to test). It must not be\n"
          f"used against any system without proper authorization.\n"
          f"Unauthorized use may be illegal in your jurisdiction. This\n"
          f"tool will not assist with, and its author accepts no\n"
          f"responsibility for, any illegal or unauthorized activity.\n"
          f"See DISCLAIMER.md for the full policy.{C.RESET}")
    print(C.head("=" * 60))
    try:
        confirm = input(f"{C.CYAN}  Type 'I AGREE' to continue: {C.RESET}").strip()
    except EOFError:
        return False
    if confirm.upper() != "I AGREE":
        print(C.bad("Acknowledgment not received. Exiting."))
        return False
    print()
    return True


def main():
    banner()
    if not show_disclaimer_gate():
        sys.exit(1)
    authenticate()

    while True:
        print_menu()
        try:
            choice = input(f"\n{C.CYAN}{C.BOLD}sentinel> {C.RESET}").strip()
        except EOFError:
            print(C.info("\nGoodbye."))
            break

        if choice == "0":
            print(C.info("Goodbye."))
            break

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(MENU_ITEMS):
                raise ValueError
        except ValueError:
            print(C.bad("Invalid selection. Enter a number from the menu."))
            continue

        label, func = MENU_ITEMS[idx]
        try:
            func()
        except KeyboardInterrupt:
            print(C.warn("\nModule interrupted by user."))
        except EOFError:
            print(C.warn("\nInput closed mid-module."))
        except (socket.error, OSError) as e:
            print(C.bad(f"Network/OS error in '{label}': {e}"))
        except Exception as e:
            print(C.bad(f"Unexpected error in '{label}': {type(e).__name__}: {e}"))
        pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.warn('Interrupted. Exiting.')}")
        sys.exit(0)
