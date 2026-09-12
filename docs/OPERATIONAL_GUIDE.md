# HunterAI V1.0 — Operational & Architecture Guide
==================================================

HunterAI is an **Evidence-Driven, Deterministic Security Testing Assistant**. 
Unlike conversational AI wrappers that blindly spray payloads or hallucinate vulnerabilities from generic HTTP reflection, HunterAI operates as a rigorous, verifiable scientific instrument governed by three fundamental principles:

1. **Physical Network Scope Enforcement** (Strict egress firewall before every socket).
2. **Deterministic Evidence Court** (No claim is confirmed without Proof of Execution).
3. **Reproducible Finding Contract** (Every confirmed vulnerability is accompanied by immediate `curl` reproduction steps, baseline vs test response comparisons, and CWE/OWASP mappings).

---

## 🚀 1. Quick Start

### Installation & Prerequisites
- Python 3.11+
- Playwright (for authenticated UI and browser sensors)
- Burp Suite Professional or Community (optional, via `:8085` Burp Gateway)

```bash
# Clone the repository
git clone https://github.com/Abdo453/HunterAI.git
cd HunterAI

# Install dependencies
pip install -r requirements.txt

# Run the 12-Lab Validation Arena benchmark
python run_validation_arena.py

# Run all pre-engagement certification gates
python certify.py
```

---

## 🛡️ 2. Physical Scope Firewall & Network Governance

Every outbound network packet must pass through `NetworkScopeGuard` before opening an HTTP socket or transport stream:

```text
EVERY OUTBOUND REQUEST
         │
         ▼
┌─────────────────────────────────┐
│     NetworkScopeGuard           │
│  - Scheme: http/https ONLY      │
│  - Whitelist: In-Scope Domains  │
│  - Blacklist: Loopback / RFC1918│
│  - Blacklist: 169.254.169.254   │
│  - Redirect: Egress Inspection  │
└────────────────┬────────────────┘
                 │
         ┌───────┴───────┐
      ALLOW            DENY
         │               │
         ▼               ▼
     Network        ScopeViolationError
                    + Immutable Audit Log
```

### Configuring `scope.yaml`:
```yaml
scope:
  allowed_targets:
    - "target.company.local"
    - "*.api.company.local"
  excluded_targets:
    - "billing.company.local"
    - "10.0.0.0/8"
  excluded_paths:
    - "/logout"
    - "/delete-account"
    - "/reset-db"
  allow_private_ips_override: false  # Strict default
```

---

## ⚙️ 3. Operational Modes: Passive vs Active

To ensure safety and compliance, HunterAI supports two distinct operational modes:

### `PASSIVE` Mode (Default)
- **Zero offensive payloads sent.**
- Discovers endpoints, crawls sitemaps, analyzes JavaScript bundles, and identifies parameters.
- Inspects response headers (CORS, CSP, cookies) without altering server state.
- Safe to run on production staging or continuous CI/CD pipelines.

### `ACTIVE` Mode (Explicit Authorization)
- Dispatches targeted, differential verification probes (e.g. arithmetic nonces for SQLi/XSS).
- Requires explicit user switch:
  ```python
  from core.execution_modes import ModeManager, ExecutionMode
  modes = ModeManager()
  modes.switch_mode(ExecutionMode.ACTIVE, reason="Authorized bug bounty scope", authorized_by="Lead Pentester")
  ```

---

## 🛑 4. Human Approval Gates for High-Risk Actions

Before executing any dangerous or state-altering probe, HunterAI pauses and invokes `HumanApprovalGate`:

- **Active SQL Injection (`ACTIVE_SQLI`)**
- **SSRF Canary & Cloud Metadata Probes (`SSRF_PROBE`)**
- **File Upload Bypasses (`FILE_UPLOAD`)**
- **High-Frequency Brute Force (`BRUTE_FORCE`)**
- **Mutating Requests (`POST`, `PUT`, `DELETE` to sensitive paths)**

In headless mode, high-risk actions without explicit pre-whitelisting are automatically blocked to prevent unintended service disruption.

---

## 📋 5. The Unified Finding Contract (Reproducible Evidence)

Every confirmed vulnerability produces an identical, structured Finding object:

```json
{
  "id": "FND-A1B2C3D4",
  "vulnerability_type": "xss",
  "title": "Reflected Cross-Site Scripting (XSS) in 'q'",
  "severity": "HIGH",
  "confidence": 0.98,
  "target": "shop.lab.local",
  "endpoint": "/search",
  "parameter": "q",
  "evidence": "Input reflected verbatim with tag breakout: "><hunter_xss_4210>",
  "verification": {
    "verified": true,
    "verifier_name": "EvidenceCourt",
    "methodology": "Deterministic Nonce Context Breakout",
    "proof_token": "hunter_xss_4210"
  },
  "reproducibility": {
    "is_reproducible": true,
    "reproduction_curl": "curl -i -s 'https://shop.lab.local/search?q=%22%3E%3Chunter_xss_4210%3E'"
  },
  "cwe": "CWE-79",
  "owasp": "A03:2021-Injection"
}
```

---

## 🚫 6. How False Positives Are Systematically Refuted

HunterAI strictly adheres to the rule: **Observation != Finding** and **Reflection != Execution**.

| Signal | Naive Scanner Reaction | HunterAI Evidence Court Reaction | Status |
| :--- | :--- | :--- | :---: |
| **HTTP 500 on `'`** | Flags as SQLi | Checks for unhandled app exception vs true syntax/boolean diff | ❌ **REFUTED** (Benign Trap) |
| **Input echoed in HTML** | Flags as XSS | Tests unencoded quote/tag breakout; verifies HTML entities | ❌ **REFUTED** (Safe Encoding) |
| **Cloudflare WAF Block (403)** | Flags as Vulnerable | Recognizes WAF interception; does not claim origin execution | ❌ **REJECTED** (WAF Intercept) |
| **High Entropy in JS** | Flags as Leaked Secret | Validates concrete format (AWS, GitHub, Stripe) + entropy $\ge 3.2$ | ❌ **SUPPRESSED** (False Pattern) |

---

## ⚖️ 7. Legal & Ethical Disclaimer

> **IMPORTANT:** HunterAI is designed exclusively for authorized penetration testing, bug bounty engagements with written permission, security audits, and educational security research. 
> Scanning or probing targets without explicit, documented authorization from the asset owner is illegal and unethical. The authors and maintainers assume no liability for misuse of this tool.\n