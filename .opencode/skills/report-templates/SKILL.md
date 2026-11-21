---
name: "report-templates"
description: "CVSS 3.1 vector examples, executive summary template, full technical finding template, and remediation language bank for pentest reports"
---

# Report Templates

*Sourced from mukul975-threatswarm*

## CVSS 3.1 Vector Reference

### Format
```
CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]
```

### Score by Severity Tier

| Severity | Score Range | Typical Vector Example | Score |
|---|---|---|---|
| CRITICAL | 9.0–10.0 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| CRITICAL | 9.0–10.0 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |
| HIGH | 7.0–8.9 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 |
| HIGH | 7.0–8.9 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| HIGH | 7.0–8.9 | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 |
| MEDIUM | 4.0–6.9 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| MEDIUM | 4.0–6.9 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 |
| MEDIUM | 4.0–6.9 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | 5.9 |
| LOW | 0.1–3.9 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` | 4.3 |
| LOW | 0.1–3.9 | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` | 2.5 |
| INFO | 0.0 | N/A — informational only | 0.0 |

### Pre-built Vectors by Vulnerability Type

```
Pre-auth RCE (internet-facing):  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  = 9.8
Post-auth RCE (authenticated):   AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  = 8.8
SQLi (data exfil possible):      AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  = 8.1
SQLi (read-only):                AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 6.5
Stored XSS (unauthenticated):    AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1
Stored XSS (post-auth):         AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N  = 5.4
Reflected XSS:                   AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1
SSRF (internal access):         AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N  = 7.2
SSRF (cloud metadata):          AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N  = 9.6
Path traversal (file read):      AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  = 7.5
LPE (local exploit):            AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  = 7.8
Insecure deserialization:        AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H  = 8.1
IDOR (sensitive data):          AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 6.5
IDOR (data modification):       AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  = 8.1
Auth bypass (admin access):      AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = 9.1
Weak JWT (crackable secret):    AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N  = 7.4
Hardcoded credentials:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = 9.1
Open redirect:                   AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1
Directory listing:               AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  = 5.3
Information disclosure:          AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N  = 5.3
Missing HTTPS:                   AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N  = 4.8
CSRF (state-changing):          AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N  = 6.5
```

---

## Executive Summary Template (1 Page)

```markdown
## Executive Summary

[CLIENT NAME] engaged [FIRM NAME] to conduct a [TYPE: internal/external/web application/full-scope]
penetration test of [SCOPE DESCRIPTION] between [START DATE] and [END DATE].

### Risk Posture

During the assessment, [FIRM NAME] identified **[N] findings** across [M] systems,
including **[X] Critical**, **[Y] High**, **[Z] Medium**, **[W] Low**, and **[V] Informational** vulnerabilities.

The overall risk posture is assessed as: **[CRITICAL | HIGH | MEDIUM | LOW]**

### Key Findings

The most significant finding was **[FINDING TITLE]**, which allowed testers to [IMPACT DESCRIPTION —
e.g., "gain unauthenticated remote code execution on the production API server and access
the customer database containing [N] records"].

Additional critical findings included:
- **[Finding 2]**: [One-sentence impact]
- **[Finding 3]**: [One-sentence impact]

### Business Impact

Exploitation of the identified vulnerabilities could result in:
- Unauthorized access to sensitive customer data (regulatory impact: GDPR, PCI-DSS)
- Complete compromise of [SYSTEM] infrastructure
- Reputational damage and loss of customer trust
- [SPECIFIC DOLLAR/OPERATIONAL IMPACT IF QUANTIFIABLE]

### Remediation Priority

| Priority | Timeline | Actions |
|----------|----------|---------|
| Immediate (0-7 days) | Patch [CVE], revoke [credential], disable [service] |
| Short-term (8-30 days) | Implement [control], remediate [N] High findings |
| Medium-term (31-90 days) | Address [N] Medium findings, establish [process] |

[FIRM NAME] is available to provide remediation guidance and conduct a retest upon completion.
```

---

## Technical Finding Template

```markdown
---

## [ID]: [SEVERITY] — [Vulnerability Title]

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **CVSS 3.1 Score** | [SCORE] ([CVSS:3.1/AV:.../...]) |
| **CWE** | CWE-[NUMBER]: [NAME] |
| **ATT&CK TTP** | [T-NUMBER]: [TECHNIQUE NAME] |
| **Affected Asset** | [IP / URL / Component] |
| **CVE** | CVE-XXXX-XXXXX (if applicable) |
| **Date Identified** | [UTC DATE] |

### Description

[2-4 sentence technical description of the vulnerability. Explain what it is, why it exists,
and what conditions allow it to be exploited. Avoid jargon that a non-technical reader
cannot follow in the executive summary.]

### Business Impact

[1-2 sentences describing the business consequence if this vulnerability is exploited.
Frame in terms of data confidentiality, regulatory requirements, operational availability,
or financial impact.]

### Steps to Reproduce

**Prerequisites:** [Access level required, e.g., "Unauthenticated" / "Valid user account"]

1. Navigate to `[URL]` using a web browser or send the following request:
   ```http
   [REQUEST METHOD] [PATH] HTTP/1.1
   Host: [HOST]
   [HEADERS]

   [BODY IF APPLICABLE]
   ```

2. [Step 2 description]

3. The application responds with:
   ```
   [RESPONSE SNIPPET or COMMAND OUTPUT]
   ```

4. [Step describing the impact demonstration]

### Evidence

- **Screenshot/Output**: `evidence/[DATE]/[TARGET]/[category]/[filename]`
- **Request/Response**: `evidence/[DATE]/[TARGET]/[category]/[filename].http`
- **Video recording**: `evidence/[DATE]/[TARGET]/[category]/[filename].mp4` (if captured)

### Remediation

**Immediate Actions:**
1. [Specific immediate mitigation step — e.g., "Disable the affected endpoint at the WAF layer"]
2. [Second immediate step if needed]

**Long-term Fix:**
[Specific code-level or configuration-level remediation. Include version number to upgrade to,
configuration value to set, or code pattern to implement.]

**Verification:**
[How to confirm the fix is effective — e.g., "Re-run the proof of concept steps above;
the server should return HTTP 403 or equivalent error."]

### References

- [CVE link or NVD URL if applicable]
- [Vendor advisory URL]
- [OWASP / CWE / NIST link]
- [ATT&CK technique URL: https://attack.mitre.org/techniques/T-NUMBER/]
```

---

## 5×5 Risk Matrix

```markdown
## Risk Matrix

|  | **Negligible (1)** | **Minor (2)** | **Moderate (3)** | **Major (4)** | **Catastrophic (5)** |
|---|---|---|---|---|---|
| **Almost Certain (5)** | MEDIUM 5 | HIGH 10 | HIGH 15 | CRITICAL 20 | CRITICAL 25 |
| **Likely (4)** | LOW 4 | MEDIUM 8 | HIGH 12 | HIGH 16 | CRITICAL 20 |
| **Possible (3)** | LOW 3 | MEDIUM 6 | MEDIUM 9 | HIGH 12 | HIGH 15 |
| **Unlikely (2)** | LOW 2 | LOW 4 | MEDIUM 6 | MEDIUM 8 | HIGH 10 |
| **Rare (1)** | INFO 1 | LOW 2 | LOW 3 | LOW 4 | MEDIUM 5 |

*Score = Likelihood × Impact*
```

---

## Remediation Language Bank (Top 20 Vulnerability Types)

### SQL Injection
> Implement parameterized queries (prepared statements) for all database interactions.
> Do not construct SQL queries using string concatenation with user-supplied input.
> Apply input validation with allowlists at the application layer. Deploy a WAF rule
> to detect and block common SQL injection patterns as a defense-in-depth measure.

### Cross-Site Scripting (XSS)
> Implement context-sensitive output encoding for all user-controlled data rendered in HTML,
> JavaScript, CSS, and URL contexts. Use a Content Security Policy (CSP) header that restricts
> inline scripts and specifies trusted sources. Validate and sanitize all inputs using an
> allowlist approach. Consider adopting a templating framework that auto-escapes by default.

### Insecure Direct Object Reference (IDOR)
> Implement server-side authorization checks that verify the authenticated user has permission
> to access the requested object before returning it. Replace sequential numeric IDs with
> unpredictable UUIDs where possible. Do not rely solely on obscurity — enforce access controls
> regardless of whether the ID is guessable.

### Server-Side Request Forgery (SSRF)
> Validate and allowlist permitted URL schemes, hosts, and ports before making server-side
> requests. Block requests to RFC 1918 private address ranges, loopback (127.0.0.1), and
> cloud metadata endpoints (169.254.169.254). Use a dedicated network egress proxy and
> disable URL redirects when making outbound connections.

### Broken Authentication / Auth Bypass
> Implement strong multi-factor authentication. Enforce secure session management: use
> cryptographically random session IDs, set Secure and HttpOnly cookie flags, expire sessions
> after inactivity, and invalidate server-side on logout. Audit all authentication code paths
> for logic bypasses including parameter manipulation, host header injection, and JWT algorithm confusion.

### Insecure File Upload
> Validate file type using magic byte inspection (not just extension). Enforce maximum file
> size limits. Store uploaded files outside the web root with non-executable permissions.
> Serve files through a separate subdomain without CGI/PHP processing enabled.
> Scan uploaded files with an antivirus engine before processing.

### Command Injection
> Never pass user input to shell interpreters. Redesign functionality to avoid subprocess
> calls where possible; if unavoidable, use language-native API bindings that do not invoke
> a shell, and apply strict allowlist validation on all parameters.

### Path Traversal
> Resolve the canonical path after user input is appended to the base directory and verify
> the result starts with the expected base path before accessing the file. Never pass
> user-controlled input directly to file system APIs.

### Insecure Deserialization
> Avoid deserializing data from untrusted sources. If required, use a data format that
> does not support arbitrary object deserialization (JSON/XML rather than Java Serialization,
> PHP unserialize, or Python pickle). Implement integrity checking (HMAC) on serialized data
> and apply an allowlist of permitted classes during deserialization.

### Sensitive Data Exposure
> Encrypt sensitive data at rest using AES-256 and in transit using TLS 1.2+ with HSTS.
> Remove sensitive data from responses, logs, and error messages. Apply field-level
> encryption for PII. Implement data classification and enforce access controls
> at the data layer, not just the application layer.

### Security Misconfiguration
> Apply CIS benchmarks to all systems, containers, and cloud services. Remove default
> credentials, sample applications, and unnecessary services. Automate configuration
> baseline enforcement using infrastructure-as-code tools (Terraform, Ansible)
> and validate continuously with configuration scanning tools.

### XML External Entity (XXE)
> Disable XML external entity processing in the XML parser configuration.
> In Java: `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`.
> In PHP: `libxml_disable_entity_loader(true)`. Use less complex data formats (JSON)
> where XML is not required.

### Missing Rate Limiting / Brute Force
> Implement account lockout after N (5–10) failed authentication attempts with
> progressive delay. Apply IP-based rate limiting at the application gateway layer.
> Enable CAPTCHA for high-value authentication flows. Log and alert on abnormal
> login velocity from a single source.

### Hardcoded Credentials
> Remove all hardcoded credentials from source code, configuration files, and
> container images immediately. Rotate any exposed credentials. Store secrets in
> a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
> Implement pre-commit hooks and CI pipeline scanning (gitleaks, truffleHog) to
> prevent future credential exposure.

### JWT Vulnerabilities
> Validate the `alg` header against an allowlist of accepted algorithms; reject `none`.
> Use asymmetric keys (RS256/ES256) rather than symmetric HMAC. Validate `iss`, `aud`,
> `exp`, and `nbf` claims on every request. Use a minimum 256-bit secret for HS256.
> Rotate signing keys periodically.

### CSRF
> Implement anti-CSRF tokens (synchronizer token pattern) for all state-changing requests.
> Use the SameSite=Strict or SameSite=Lax cookie attribute. Validate the Origin and Referer
> headers server-side. For REST APIs, verify the Content-Type is application/json
> (non-simple CORS request) to leverage the preflight mechanism.

### Open Redirect
> Validate redirect URLs against a strict allowlist of permitted destinations.
> Reject any URL that does not match the expected domain exactly. Do not rely
> on URL parsing alone — canonicalize and normalize the URL before comparison.

### Directory Listing
> Disable directory listing in the web server configuration.
> Apache: `Options -Indexes`. Nginx: remove `autoindex on`. Ensure that
> all directories accessible via the web root contain an index document or
> are explicitly denied.

### Unpatched Software / Known CVEs
> Establish a vulnerability management program with defined SLAs by severity
> (Critical: 24h, High: 7 days, Medium: 30 days, Low: 90 days). Deploy
> authenticated vulnerability scanning weekly. Enroll in vendor security advisories
> and subscribe to the CISA Known Exploited Vulnerabilities (KEV) catalog.

### Insecure TLS Configuration
> Enforce TLS 1.2 as the minimum version; prefer TLS 1.3. Disable weak cipher suites
> (RC4, DES, 3DES, export ciphers, NULL). Enable HSTS with a minimum max-age of 31536000
> and include the `preload` directive. Configure OCSP stapling. Use a certificate with
> a minimum 2048-bit RSA or 256-bit ECDSA key signed by a trusted CA.

---

## 30/60/90 Remediation Roadmap Template

```markdown
## Remediation Roadmap

### Phase 1: Immediate (Days 1–30)
**Goal:** Eliminate critical/high risk and contain active exposure

| # | Finding | Owner | Action | Due |
|---|---------|-------|--------|-----|
| 1 | [CRITICAL finding] | [Team] | [Specific action] | Day 7 |
| 2 | [HIGH finding] | [Team] | [Specific action] | Day 14 |
| 3 | [HIGH finding] | [Team] | [Specific action] | Day 30 |

### Phase 2: Short-term (Days 31–60)
**Goal:** Address medium-severity findings and implement preventive controls

| # | Finding | Owner | Action | Due |
|---|---------|-------|--------|-----|
| 1 | [MEDIUM finding] | [Team] | [Specific action] | Day 45 |
| 2 | [MEDIUM finding] | [Team] | [Specific action] | Day 60 |

### Phase 3: Medium-term (Days 61–90)
**Goal:** Harden security program and address low-severity findings

| # | Finding | Owner | Action | Due |
|---|---------|-------|--------|-----|
| 1 | [LOW finding] | [Team] | [Specific action] | Day 75 |
| 2 | [Program improvement] | [Security team] | [Specific action] | Day 90 |

**Retest:** A verification assessment is recommended upon completion of Phase 1.
```

