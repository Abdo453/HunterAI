# HunterAI Official Blind-Spot Registry (`BLIND_SPOTS.md`)

> **The Golden Axiom:** An AI security agent that claims to detect 100% of vulnerabilities is dishonest. True epistemic maturity requires defining precisely what the system *knows*, what it *does not know*, and where its operational boundaries lie.

---

## 🧭 Attack Surface Visibility Breakdown

| Epistemic Sector | Coverage (%) | Description | Current Strategy |
| :--- | :---: | :--- | :--- |
| **Known & Tested** | `72.0%` | Standard HTTP/1.1 & HTTP/2 REST APIs, JSON endpoints, common injection sinks (SQLi, CMDI, SSRF, XSS), BOLA/IDOR object authorization checks. | Automated sensory verification with tripartite proof contracts. |
| **Known & Untested** | `14.0%` | High-risk endpoints requiring operator consent, multi-factor authenticated routes, payment state mutations. | Queued in operator consent queue (`hunter assets --approve`). |
| **Blocked by Policy** | `8.0%` | External CDNs, cloud metadata boundaries (`169.254.169.254`), out-of-scope third-party dependencies. | Strictly blocked by Scope Firewall and RFC1918 boundary rules. |
| **Official Unknowns** | `6.0%` | Proprietary binary sockets, opaque CAPTCHAs, hardware tokens, undocumented legacy protocols. | Formal status classified as `UNKNOWN` rather than guessing `SAFE`. |

---

## ⚠️ Documented System Boundaries

### 1. `[BS-01]` Complex Business Logic Intent
- **Capability:** `PARTIALLY_SUPPORTED`
- **Epistemic Reason:** HunterAI verifies explicit state transitions, but cannot deduce unspoken business intent (e.g. distinguishing a legitimate bulk discount coupon from an unintended business logic pricing flaw) without formal specification rules.
- **Mitigation:** Operator defines declarative security specifications in `hunter.yaml` (e.g. `unauthenticated_cannot_access_private_resource`).

### 2. `[BS-02]` Proprietary Binary TCP Protocols
- **Capability:** `CURRENTLY_UNSUPPORTED`
- **Epistemic Reason:** Protocol dissectors support HTTP/1.1, HTTP/2, WebSocket, gRPC-Web, and GraphQL. Proprietary binary streams without protocol buffers or schemas cannot be parsed causally.
- **Mitigation:** Operator routes traffic through custom Burp Suite extensions equipped with custom protobuf decoders.

### 3. `[BS-03]` Out-of-Band Multi-Factor Authentication & CAPTCHA
- **Capability:** `REQUIRES_OPERATOR_ASSIST`
- **Epistemic Reason:** HunterAI will never attempt SMS interception, authenticator app token theft, or third-party CAPTCHA solving farms to prevent ethical and legal breaches.
- **Mitigation:** Operator authenticates once in browser or passes active session cookies via `--auth`.

### 4. `[BS-04]` Backend AST Code Attribution without Repository
- **Capability:** `PARTIALLY_SUPPORTED`
- **Epistemic Reason:** In black-box mode, client-side JS is deconstructed via AST, but backend database queries and ORM calls are inferred causally from network inputs and outputs.
- **Mitigation:** Provide repository root via `--repo-path` to unlock full white-box route and sink mapping.

### 5. `[BS-05]` Distributed IP-Rotation WAF Evasion
- **Capability:** `CURRENTLY_UNSUPPORTED`
- **Epistemic Reason:** HunterAI adheres strictly to non-disruptive, responsible testing rules, honoring HTTP 429 Retry-After headers rather than generating distributed botnet traffic.
- **Mitigation:** Request an authorized testing bypass header or IP allowlist from the target infrastructure team.
