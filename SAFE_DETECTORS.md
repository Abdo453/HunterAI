# Safe Verification Lab — Detectors, Evidence Chain, Pipeline

A detector that cannot prove a vulnerability is worse than no detector: it
wastes triage time and burns trust. This lab is **precision-first and
read-only**. It confirms five classes with deterministic differentials and
records every byte it sends and receives in a tamper-evident chain. The same
detectors are wired into the hypothesis → evidence → validation pipeline.

## Safety invariants

| Control | Implementation |
|---|---|
| Read-only | `HttpTransport` exposes only `get()` and `head()`. There is no generic `request(method, ...)`. |
| No proxy leaks | `ProxyHandler({})` — loopback tests never leave the machine. |
| No redirect chasing | A 3xx is recorded as the response, not followed. The open-redirect detector inspects `Location`; it never contacts the external host. |
| Bounded | 80-request budget and 512 KB response cap per transport. |
| Policy-gated | Optional `RedTeamPolicyEngine`; an out-of-scope URL raises `PolicyViolation` **before** the socket is opened. |
| Loopback demo | The fake target binds to `127.0.0.1:0` (ephemeral port). |
| SSRF callback | The canary binds to `127.0.0.1:0`; only the target-under-test is asked to fetch it. The detector itself never contacts an external host. |

## Detectors

| Detector | Confirmation rule | False-positive trap |
|---|---|---|
| `SQLiBooleanDetector` | Two independent TRUE/FALSE payload pairs produce a stable body differential. | A control pair (`hnt-control-a` / `hnt-control-b`) must be identical; payloads must not be reflected verbatim. |
| `XSSReflectedDetector` | A unique `"><hntXXXX>` payload appears verbatim in a 200 response. | The marker must be absent from the baseline, and the HTML-escaped form must be absent from the test response. |
| `IDORDetector` | The owner reads an owner-only canary, and a second identity (or an anonymous client) reads the same canary from the same object. | The owner must prove the resource is private; a 403/404 for the second identity is a pass. |
| `SSRFDetector` | The target fetches a unique loopback canary URL and the canary records the callback. | The canary must receive a path containing the nonce; a 200 from the target alone is not proof. |
| `OpenRedirectDetector` | A 3xx response has a `Location` whose host is the external canary host. | The redirect must be absolute and external; relative `Location` values and 200 responses are rejected. |

### What the detectors never send

- No `INSERT` / `UPDATE` / `DELETE` / `DROP` / `UNION`.
- No `SLEEP` / `pg_sleep` / time-based payloads.
- No authentication brute force, no credential stuffing.
- No file upload, no shell, no persistence.
- No request to the external host used in the open-redirect payload.
- No request from the detector to an arbitrary SSRF destination; only the
  target-under-test is asked to fetch the loopback canary.

The SQLi proof is a read-only boolean differential. The XSS proof is a safe
nonce tag. The IDOR proof is a canary that only the owner should see. The SSRF
proof is an out-of-band callback. The open-redirect proof is an un-followed
`Location` header.

## Evidence chain

Every probe produces a `ProbeExchange` with a SHA-256 request hash and a
SHA-256 response hash. `EvidenceChain` links exchanges and detections:

```
record_hash = sha256(seq, kind, payload_hash, prev_hash, timestamp)
```

Editing any record breaks `verify()`. The chain is tamper-evident (not secret),
and it can be written to JSONL for later re-evaluation.

## Hypothesis → detector → chain → gate

`core/detectors/pipeline.py` maps a hypothesis `vuln_type` to a detector,
runs it through the same policy-gated transport, appends every exchange to the
chain, and builds the evidence dictionary consumed by the 7-Question Gate.

```
HypothesisEngine
  → Hypothesis(vuln_type, endpoint, parameter)
  → detector.detect(context, transport)
  → EvidenceChain.append_all(detection)
  → build_gate_evidence(detection)
  → ValidationGate.validate(...)   # PROVEN | REFUTED | UNPROVEN | INCONCLUSIVE
  → HypothesisEngine.set_verdict(...)
```

The hypothesis is only marked `CONFIRMED` when the detector has a confirmed
differential **and** the gate returns `PROVEN`. A safe endpoint is marked
`REJECTED` without calling the gate.

`LabValidationGate` reuses every production gate question and only relaxes the
scope check for an explicit loopback allowlist. The production
`ValidationGate` still blocks loopback by design.

## Quick start

### Hermetic demo (no external traffic)

```powershell
python -m core.detectors.cli demo
```

Real output from this repository (condensed):

```json
{
  "ok": true,
  "only_get_requests": true,
  "requests": 45,
  "chain_verified": true,
  "checks": [
    {"check": "sqli.vulnerable",          "confirmed": true},
    {"check": "sqli.safe",                "confirmed": false},
    {"check": "xss.vulnerable",           "confirmed": true},
    {"check": "xss.safe",                 "confirmed": false},
    {"check": "idor.vulnerable",          "confirmed": true},
    {"check": "idor.safe",                "confirmed": false},
    {"check": "ssrf.vulnerable",          "confirmed": true},
    {"check": "ssrf.safe",                "confirmed": false},
    {"check": "open_redirect.vulnerable", "confirmed": true},
    {"check": "open_redirect.safe",       "confirmed": false}
  ],
  "pipeline_ok": true,
  "pipeline_checks": [
    {"check": "sqli.pipeline",          "gate": "PROVEN", "verdict": "CONFIRMED", "chain_verified": true},
    {"check": "xss.pipeline",           "gate": "PROVEN", "verdict": "CONFIRMED", "chain_verified": true},
    {"check": "ssrf.pipeline",          "gate": "PROVEN", "verdict": "CONFIRMED", "chain_verified": true},
    {"check": "idor.pipeline",          "gate": "PROVEN", "verdict": "CONFIRMED", "chain_verified": true},
    {"check": "open_redirect.pipeline", "gate": "PROVEN", "verdict": "CONFIRMED", "chain_verified": true}
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

# SSRF (loopback canary; use only on an authorized staging target)
python -m core.detectors.cli scan `
  --target https://staging.example.com --path /fetch --param url --class ssrf

# Open redirect
python -m core.detectors.cli scan `
  --target https://staging.example.com --path /redirect --param next `
  --class open_redirect
```

### Run one hypothesis through the full pipeline

```powershell
python -m core.detectors.cli pipeline `
  --target http://127.0.0.1:8080 --vuln-type SSRF `
  --path /fetch --param url --validate --out evidence/ssrf-chain.jsonl
```

The command exits `0` only when the detector confirms the issue and, with
`--validate`, the gate returns `PROVEN`. Safe endpoints exit `1`; policy
denials exit `2` and send nothing.

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

Full pipeline:

```python
from core.detectors.pipeline import HypothesisPipeline
from hunter_ai.evidence.hypothesis_engine import Hypothesis, HypothesisEngine

engine = HypothesisEngine()
hypothesis = engine.register(
    Hypothesis(
        title="SSRF candidate",
        vuln_type="SSRF",
        endpoint="https://staging.example.com/fetch",
        parameter="url",
    )
)
pipeline = HypothesisPipeline(transport, EvidenceChain(), hypothesis_engine=engine)
result = pipeline.run(
    hypothesis,
    DetectionContext(
        base_url="https://staging.example.com",
        path="/fetch",
        parameter="url",
    ),
)
assert result.chain_verified
```

Pass `validator=ValidationGate()` in production; pass
`validator=LabValidationGate({"127.0.0.1"})` only for the hermetic lab.

## Tests

```powershell
python -m pytest tests/test_detectors_local.py -q
# 25 passed
```

The suite proves:

- vulnerable endpoint → confirmed; safe endpoint → rejected, for all five
  classes;
- only `GET` reaches the fake server;
- the SSRF canary receives a callback only from the vulnerable endpoint;
- the open-redirect detector rejects relative-only redirects;
- a policy denial happens before the server records a request;
- the evidence chain verifies, detects tampering, and round-trips through disk;
- the pipeline maps all supported vuln types, confirms and proves a finding,
  rejects a safe endpoint without calling the gate, and refuses unknown types
  without sending traffic;
- `LabValidationGate` allows its explicit loopback allowlist while the
  production `ValidationGate` still rejects loopback;
- the CLI demo, scan, and pipeline produce verifiable chains.

## Files

| File | Role |
|---|---|
| `core/detectors/contract.py` | `Probe`, `ProbeExchange`, `Detection`, `DetectionContext`, `Detector` protocol |
| `core/detectors/transport.py` | read-only, proxy-free, policy-gated HTTP transport |
| `core/detectors/sqli_boolean.py` | two-pair boolean SQLi detector |
| `core/detectors/xss_reflected.py` | nonce-based reflected XSS detector |
| `core/detectors/idor.py` | two-identity IDOR detector |
| `core/detectors/ssrf.py` | loopback-canary SSRF detector |
| `core/detectors/open_redirect.py` | un-followed `Location` open-redirect detector |
| `core/detectors/canary.py` | loopback out-of-band callback listener |
| `core/detectors/evidence_chain.py` | hash-linked evidence records |
| `core/detectors/validation.py` | `LabValidationGate` (production gate + explicit loopback allowlist) |
| `core/detectors/pipeline.py` | hypothesis → detector → chain → gate integration |
| `core/detectors/local_target.py` | loopback vulnerable/safe fake target |
| `core/detectors/cli.py` | `scan`, `demo`, and `pipeline` commands |
| `tests/test_detectors_local.py` | 25 hermetic tests |
