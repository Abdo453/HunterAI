# HunterAI OS — Security, Safety & Compliance Standard

This document details the security model, compliance controls, and guardrails enforced across the HunterAI Security Assessment Operating System.

---

## 1. Safety Invariants & Scope Enforcement

| Invariant | Enforcement Level | Mechanism |
| :--- | :--- | :--- |
| **Strict Target Boundary** | Kernel / Policy Gate | Requests to domains not explicitly listed in `in_scope` return hard `403 FORBIDDEN` |
| **Cloud Metadata Protection** | Non-overridable Hard Filter | Absolute rejection of `169.254.169.254`, `metadata.google.internal`, AWS/Azure metadata IPs |
| **Loopback / RFC1918 Isolation** | Non-overridable Hard Filter | `127.0.0.1`, `localhost`, `::1` cannot be targeted unless explicitly run in self-test mode |
| **Catastrophic Shell Blocking** | Regex & AST Interception | `TerminalBridge` blocks `rm -rf /`, `mkfs`, fork bombs (`:(){ :|:& };:`), disk overwrite (`dd if=/dev/zero`) |
| **Directory Sandbox Containment** | OS Path Traversal Guard | `HostBridge` uses `Path.is_relative_to` to restrict disk access strictly within the sandbox folder |

---

## 2. Cryptographic Secret & Credential Sanitization

All HTTP traffic, terminal logs, and cognitive traces pass through the `RequestRecorder` and `SecretSanitizer` prior to display or disk persistence:
- **Bearer Tokens:** Redacted to `Bearer [REDACTED]`
- **Basic Auth:** Redacted to `Basic [REDACTED]`
- **API Keys / Passwords:** Sanitized regex patterns `(?:api_key|token|password|secret)\s*[:=]\s*['"]?([^\s&'"]+)`
- **Burp Lineage:** Captured transactions are indexed by `REQ-XXXXXX` and `trace_id` with salted hashes.

---

## 3. Agent-to-Agent (A2A) Message Integrity

Inter-agent communication over the MCP bus is cryptographically signed:
- **Algorithm:** HMAC-SHA256 with timestamp validation.
- **Nonce & Expiry:** Messages older than 60 seconds are discarded to prevent replay attacks.
- **Tamper Detection:** Invalidation of signature causes immediate silent mailbox drop and security alert.

---

## 4. Compliance & Standards Alignment

- **ISO/IEC 27001 (A.12.6.1 Management of technical vulnerabilities):** Full provenance chain from initial observation to evidence adjudication.
- **GDPR Article 32 (Security of processing):** Deterministic audit trail (`task_logs/`, `snapshots/`, `logs/thinking_traces/`) without raw PII leakage.
- **OWASP ASVS v4.0:** Testing logic aligns with Verification Requirements for Authentication, Authorization, and Input Validation.
