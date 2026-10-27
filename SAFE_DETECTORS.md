# Safe Verification Lab — Detectors + Evidence Chain

A detector that cannot prove a vulnerability is worse than no detector: it
wastes triage time and burns trust. This lab is **precision-first and
read-only**. It confirms three classes with deterministic differentials and
records every byte it sends and receives in a tamper-evident chain.

## Safety invariants

| Control | Implementation |
|---|---|
| Read-only | `HttpTransport` exposes only `get()` and `head()`. There is no generic `request(method, ...)`. |
| No proxy leaks | `ProxyHandler({})` — loopback tests never leave the machine. |
| No redirect chasing | A 3xx is recorded as the response, not followed. |
| Bounded | 80-request budget and 512 KB response cap per transport. |
| Policy-gated | Optional `RedTeamPolicyEngine`; an out-of-scope URL raises `PolicyViolation` **before** the socket is opened. |
| Loopback demo | The fake target binds to `127.0.0.1:0` (ephemeral port). |

## Detectors

| Detector | Confirmation rule | False-positive trap |
|---|---|---|
| `SQLiBooleanDetector` | Two independent TRUE/FALSE payload pairs produce a stable body differential. | A control pair (`hnt-control-a` / `hnt-control-b`) must be identical; payloads must not be reflected verbatim. |
| `XSSReflectedDetector` | A unique `"><hntXXXX>` payload appears verbatim in a 200 response. | The marker must be absent from the baseline, and the HTML-escaped form must be absent from the test response. |
| `IDORDetector` | The owner reads an owner-only canary, and a second identity (or an anonymous client) reads the same canary from the same object. | The owner must prove the resource is private; a 403/404 for the second identity is a pass. |

### What the detectors never send

- No `INSERT` / `UPDATE` / `DELETE` / `DROP` / `UNION`.
- No `SLEEP` / `pg_sleep` / time-based payloads.
- No authentication brute force, no credential stuffing.
- No file upload, no shell, no persistence.

The SQLi proof is a read-only boolean differential. The XSS proof is a safe
nonce tag. The IDOR proof is a canary that only the owner should see.

## Evidence chain

Every probe produces a `ProbeExchange` with a SHA-256 request hash and a
SHA-256 response hash. `EvidenceChain` links exchanges and detections:

```
record_hash = sha256(seq, kind, payload_hash, prev_hash, timestamp)
```

Editing any record breaks `verify()`. The chain is tamper-evident (not secret),
and it can be written to JSONL for later re-evaluation.

## Quick start

### Hermetic demo (no external traffic)

```powershell
python -m core.detectors.cli demo
```

Real output from this repository:

```json
{
  "ok": true,
  "only_get_requests": true,
  "requests": 22,
  "chain_verified": true,
  "checks": [
    {"check": "sqli.vulnerable", "confirmed": true},
    {"check": "sqli.safe",       "confirmed": false},
    {"check": "xss.vulnerable",  "confirmed": true},
    {"check": "xss.safe",        "confirmed": false},
    {"check": "idor.vulnerable", "confirmed": true},
    {"check": "idor.safe",       "confirmed": false}
  ]
}
```

### Scan one endpoint

```powershell
# SQLi
python -m core.detectors.cli scan `
  --target https://staging.example.com --path /search --param q --class sqli

# Reflected XSS
python -m core.detectors.cli scan `
  --target https://staging.example.com --path /echo --param name --class xss

# IDOR (two identities + an owner-only canary)
python -m core.detectors.cli scan `
  --target https://staging.example.com --path /api/orders --class idor `
  --id-param id --resource-id 1001 `
  --owner-header "Authorization: Bearer <owner>" `
  --other-header "Authorization: Bearer <other>" `
  --owner-marker "HNT-CANARY-OWNER-7f3a" `
  --out evidence/idor-chain.jsonl
```

### With a signed grant

```powershell
$env:HUNTERAI_POLICY_SECRET = "<engagement secret>"
python -m core.detectors.cli scan `
  --target https://staging.example.com --path /search --param q `
  --grant authorization_grant.json --profile red_team
```

Out of scope:

```json
{"error": "policy_denied", "reason": "target '...' is outside the authorized scope"}
```

No request is sent.

## Use from code

```python
from core.detectors import (
    DetectionContext,
    EvidenceChain,
    HttpTransport,
    SQLiBooleanDetector,
    TransportConfig,
)

transport = HttpTransport(TransportConfig(allowed_hosts={"staging.example.com"}))
detection = SQLiBooleanDetector().detect(
    DetectionContext(
        base_url="https://staging.example.com",
        path="/search",
        parameter="q",
    ),
    transport,
)

chain = EvidenceChain("evidence/chain.jsonl")
chain.append_all(detection)
assert chain.verify()
print(detection.finding.to_hackerone_markdown())
```

## Tests

```powershell
python -m pytest tests/test_detectors_local.py -q
# 14 passed
```

The suite proves:

- vulnerable endpoint → confirmed; safe endpoint → rejected, for all three classes;
- only `GET` reaches the fake server;
- a policy denial happens before the server records a request;
- the evidence chain verifies, detects tampering, and round-trips through disk;
- the CLI demo and scan produce a verifiable chain.

## Files

| File | Role |
|---|---|
| `core/detectors/contract.py` | `Probe`, `ProbeExchange`, `Detection`, `DetectionContext`, `Detector` protocol |
| `core/detectors/transport.py` | read-only, proxy-free, policy-gated HTTP transport |
| `core/detectors/sqli_boolean.py` | two-pair boolean SQLi detector |
| `core/detectors/xss_reflected.py` | nonce-based reflected XSS detector |
| `core/detectors/idor.py` | two-identity IDOR detector |
| `core/detectors/evidence_chain.py` | hash-linked evidence records |
| `core/detectors/local_target.py` | loopback vulnerable/safe fake target |
| `core/detectors/cli.py` | `scan` and `demo` commands |
| `tests/test_detectors_local.py` | 14 hermetic tests |
