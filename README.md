# SENTINEL-CLI

**A single-file, terminal-based security auditing and diagnostics framework for Termux**, built for testing and observing your own local machine and local development servers — in real time, with real concurrency.

```
   _____ _____ _   _ _______ _____ _   _ ______ _
  / ____|  ___| \ | |__   __|_   _| \ | |  ____| |
 | (___ | |__ |  \| |  | |    | | |  \| | |__  | |
  \___ \|  __|| . ` |  | |    | | | . ` |  __| | |
  ____) | |___| |\  |  | |   _| |_| |\  | |____| |____
 |_____/|______|_| \_|  |_|  |_____|_| \_|______|______|
      Local Security Auditing & Diagnostics Framework
      Scope: localhost / 127.0.0.1 / ::1 only
```

---

## Scope

SENTINEL-CLI is a **recon and audit toolkit**, not an exploitation tool. Every HTTP/web module validates that the target resolves to a loopback address (`127.0.0.1`, `::1`, or `localhost`) before sending a single byte. Non-loopback targets are rejected outright.

Read `DISCLAIMER.md` before use.

---

## Requirements

- Termux (Android) or any Linux environment with Python 3.8+
- No third-party packages required to run the core toolkit — pure standard library
- Flask is optional, only needed if you want a quick local server to test *against* (the installer offers to set this up for you)

---

## Installation (Termux)

```bash
pkg update -y
```
```bash
pkg install git
```
```bash
git clone https://github.com/VoidKernel12/cyber-security-ethical-tool.git
```
```bash
cd cyber-security-ethical-tool
```
```bash
chmod +x install.sh
```
```bash
./install.sh
```
The installer will:
- Verify/install Python 3 and pip
- Offer to install Flask, for spinning up a disposable local test target
- Set executable permissions on the script
- Add a `sentinel` shortcut command to your shell

Or run it manually with no installer:

```bash
pkg install python -y
python3 secaudit.py
```

---

## First Run

On first launch, SENTINEL-CLI prompts you to create a local account:

```
$ python3 secaudit.py

No local credentials found. Let's create one.
  Choose a username: analyst
  Choose a password (min 16 chars): ********************
Account created. Please log in.
```

Credentials are stored locally at `~/.sentinel_cli/auth.json` as a SHA-256 hash with a per-account random salt — the password itself is never stored. Forgot your password? Type `reset` at the username prompt to wipe and recreate your local account.

---

## Feature Breakdown

| # | Module | Description |
|---|---|---|
| 1 | Secure Local Authentication | SHA-256 + salt login gate, 16-character minimum password, self-service reset |
| 2 | TCP Port Scanner | Threaded scan of a user-defined port range |
| 3 | Banner Grabbing | Grabs service banners across ports 1–1024 |
| 4 | Network Diagnostics & Socket Test | DNS resolution, common-port reachability, raw socket round-trip timing |
| 5 | HTTP Security Headers Scanner | Checks for CSP, HSTS, X-Frame-Options, and other security headers |
| 6 | HTTP Methods Enumeration | Probes which HTTP verbs (GET/POST/PUT/DELETE/TRACE/etc.) are accepted |
| 7 | Cookie Security Flag Auditor | Flags missing `Secure`, `HttpOnly`, `SameSite` attributes |
| 8 | SSL/TLS Inspector | Reports protocol version, cipher suite, and certificate details |
| 9 | Rate-Limit & Latency Tester | Sends sequential requests and measures latency / HTTP 429 behavior |
| 10 | API / Directory Endpoint Discovery | Passive wordlist probe (built-in or custom file) for common paths |
| 11 | Local Website Strength & Capacity Testing | Fires 1–150 concurrent GET/POST requests at a direct URL, with a live progress bar and full latency/throughput summary |

---

## Verified Output Demo

The run below is a real, unedited capture from Module 11 against a local Flask dev server (`python app.py`, listening on `127.0.0.1:5000`), run entirely inside Termux on Android.

**Flask target server:**
```
* Serving Flask app 'd'
* Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment.
* Running on all addresses (0.0.0.0)
* Running on http://127.0.0.1:5000
* Running on http://100.92.132.37:5000
Press CTRL+C to quit
127.0.0.1 - - [22/Sep/2026 07:51:53] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [22/Sep/2026 07:51:53] "GET / HTTP/1.1" 200 -
... (12 requests total)
```

**SENTINEL-CLI, Module 11 cyber-security-ethical-tool— ad Test:**
```
sentinel> 10

=== Local Application Strength & Concurrency Load Testing ===
Enter a direct local URL, choose how many concurrent synthetic users
to simulate, and this module fires that many requests at once to
measure your local server's throughput, latency, and capacity.

  Target URL (e.g. http://127.0.0.1:8000/index.html): http://127.0.0.1:5000
  HTTP method [GET/POST] (default: GET):
  Number of concurrent users/requests (1-150, default: 25): 12
[*]
Firing 12 concurrent GET requests at http://127.0.0.1:5000/ ...

  [██████████████████████████████] 12/12 (100.0%)

--- Load Test Summary ---
[*] Target           : http://127.0.0.1:5000/
[*] Concurrent users  : 12
[*] Total time        : 0.16s
[*] Throughput        : 76.64 req/s
[*] Connection errors : 0
[+]   HTTP 200: 12 response(s)
[*] Latency avg/min/max/p95: 57.3 / 43.3 / 75.7 / 75.7 ms
[!]
No rate limiting observed at this load level.

Press Enter to return to the menu...
```

**Result:** 12/12 requests succeeded, zero connection errors, 76.64 req/s throughput, sub-80ms max latency — with the Flask server log confirming every single request landed and returned `200`. Real concurrency, real numbers, running entirely on-device.

---

## Usage Examples

**Scan your local dev server's open ports:**
```
sentinel> 1
  Target host (default: 127.0.0.1): 127.0.0.1
  Port range e.g. 1-1024 (default: 1-1024): 1-9000
```

**Check security headers on a local Flask/Django app running on port 5000:**
```
sentinel> 4
  Target host (default: 127.0.0.1): localhost
  Port (default: 80): 5000
  Use HTTPS/TLS? (y/n): n
  Path (default: /): /
```

**Load-test a local endpoint with 100 concurrent synthetic users:**
```
sentinel> 10
  Target URL: http://127.0.0.1:5000/api/register
  HTTP method [GET/POST]: POST
  Content type for POST body [json/form]: json
  Number of concurrent users/requests (1-150): 100
```

---

## File Structure

```
.
├── secaudit.py       # Main framework (single file, all 11 modules)
├── install.sh        # Termux setup script (Python/pip/Flask checks + permissions)
├── README.md         # This file
└── DISCLAIMER.md      # Legal / ethical use disclaimer
```

---

## License & Use

For personal, educational, and authorized local testing only. See `DISCLAIMER.md` for the full acceptable-use policy before running this software.
