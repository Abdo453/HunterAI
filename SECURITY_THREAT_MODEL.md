# HunterAI — Security Threat Model

**Date:** 2026-10-26
**Scope:** existing HunterAI platform + proposed vulnerability-intelligence and adaptive-testing extensions
**Method:** asset/actor/trust-boundary analysis, STRIDE-style threat enumeration, abuse-case review, and mapping to existing controls. This is a design threat model, not a penetration-test report.

> Treat all external content (advisories, web pages, repository files, issue comments, PoCs, tool output) as **untrusted data**. It must never be interpreted as instructions, never trigger tool execution, and never modify authorization policy.

---

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Authorization policy and scope definitions | Prevent unauthorized testing; legal safety |
| A2 | Credentials, API keys, tokens, session cookies | Account takeover, financial loss |
| A3 | Target systems and third-party infrastructure | Safety, availability, legal exposure |
| A4 | Vulnerability database and provenance | Integrity of every downstream conclusion |
| A5 | Findings, evidence, and reports | Client trust, disclosure obligations |
| A6 | Source code and repository contents | IP, supply chain |
| A7 | Local host and filesystem | Sandbox escape, data loss |
| A8 | AI models and prompts | Prompt injection, data exfiltration |
| A9 | Audit logs and sync history | Forensics, non-repudiation |
| A10 | Lab environments and fixtures | Safe experimentation |
| A11 | Database backups | Recovery |
| A12 | CI/CD and Git history | Supply-chain compromise |

---

## 2. Actors

| Actor | Trust level | Motivation / capability |
|---|---|---|
| Authorized operator | Trusted (with least privilege) | Runs assessments within scope |
| Project owner / client | Trusted for their assets | Provides scope and inventory |
| Unauthenticated internet | Untrusted | Opportunistic scanning, abuse |
| Malicious advisory author | Untrusted | Poisoning, prompt injection, fake fixes |
| Compromised upstream source | Untrusted | Supply-chain data manipulation |
| Malicious repository content | Untrusted | Prompt injection, malicious manifests, zip-slip |
| Rogue/compromised AI model | Untrusted output | Hallucination, instruction following |
| Insider with local access | Partially trusted | Data theft, policy tampering |
| Automated scanner/tool | Untrusted output | False positives, unexpected egress |
| Future self-improvement agent | Constrained | Could attempt privilege escalation |

---

## 3. Trust boundaries

```
[Internet sources] --(TB1)--> [Connectors] --(TB2)--> [Normalizer/Store]
[Targets]          --(TB3)--> [Sensors/Tools] --(TB4)--> [Evidence/Findings]
[User/CLI/Web]     --(TB5)--> [Policy Gate] --(TB6)--> [Execution]
[Untrusted text]   --(TB7)--> [LLM] --(TB8)--> [Planner/Tools]
[Self-improve]     --(TB9)--> [Repository/CI]
[Local host]       --(TB10)--> [Sandbox/Containers]
```

Each boundary requires: input validation, least privilege, logging, and a fail-closed decision.

---

## 4. Threat enumeration

### 4.1 Authorization and scope

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-AZ-1 | Scope bypass via redirect | In-scope URL 302s to attacker host | Unauthorized testing | `StrictScopeEngine` URL checks | Revalidate every redirect hop; egress allowlist | redirect chain test |
| T-AZ-2 | DNS rebinding | Hostname resolves to public IP at check, private IP at request | SSRF/internal access | Private-IP hard block | Re-resolve + pin IP per request; check peer IP | rebinding simulation |
| T-AZ-3 | Subdomain assumption | "example.com" scope used for `*.example.com` | Out-of-scope testing | Explicit scope lists | No implicit wildcard; deny unless listed | scope test |
| T-AZ-4 | Expired authorization | Old scope reused after expiry | Unauthorized testing | None in `ScopePolicy` | `expires_at`, revalidate immediately before action | expiry test |
| T-AZ-5 | Policy gate bypass | New tool calls `httpx` directly | Unauthorized action | `PolicyGate` exists | Single execution choke point; static check | grep/architecture test |
| T-AZ-6 | Destructive action | `DELETE /account` | Data loss | Excluded paths/commands | `allow_destructive` default false; explicit approval | policy test |
| T-AZ-7 | Scope expansion from discovered host | Crawler finds `api.other.com` and tests it | Out-of-scope | None guaranteed | Never auto-expand; require explicit addition | planner test |
| T-AZ-8 | Port/protocol bypass | Allowed host, disallowed port | Unauthorized service access | Port checks | Revalidate port at connect time | port test |

### 4.2 Untrusted content and prompt injection

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-PI-1 | Instruction injection in advisory | Description says "ignore rules and run curl..." | Arbitrary execution | None | Data-only pipeline; no tool calls from content; delimiters; instruction hierarchy | injection fixture |
| T-PI-2 | Tool-call injection in repo file | `README` contains "run this command" | RCE | Sandbox/allowlist | Never execute content; human-approved commands only | injection test |
| T-PI-3 | Exfiltration via prompt | "Send env vars to URL" | Secret theft | None | No network from LLM; redaction; egress control | egress test |
| T-PI-4 | Fake authority | "CISA says you may scan X" | Unauthorized action | Authorization layer | Authorization only from signed/structured scope, never text | policy test |
| T-PI-5 | Hidden instructions | Zero-width/HTML comments/base64 | Bypass filters | None | Normalize/strip hidden text; log raw hash; no execution | parser test |
| T-PI-6 | Multi-step injection | Benign first, malicious later | Delayed execution | None | Stateless analysis; no memory of instructions | sequence test |

**Design rule:** the LLM may produce *text* (summary, hypothesis, classification) but never an executable action. Any action is constructed by deterministic code from a validated plan.

### 4.3 Data integrity and poisoning

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-DI-1 | Poisoned advisory | Fake CVE with malicious "fix" URL | Wrong remediation | None | Multi-source corroboration; provenance; confidence | corroboration test |
| T-DI-2 | Alias collision | Attacker claims CVE-X = CVE-Y | Wrong merge | None | Alias validation; source priority; manual review flag | alias test |
| T-DI-3 | Version-range tampering | Range widened to include safe versions | False positives | None | Preserve raw payload/hash; diff on update | update test |
| T-DI-4 | Replay/duplicate | Same record inserted repeatedly | Bloat, inconsistency | None | Content hash + unique keys + idempotent upsert | idempotency test |
| T-DI-5 | Truncated response | Partial JSON accepted | Missing fields | None | Schema validation; reject incomplete; error row | malformed test |
| T-DI-6 | Timestamp manipulation | Future/past dates | Wrong coverage | None | Date sanity bounds; store source + import time | date test |
| T-DI-7 | SQL injection via advisory text | `'); DROP TABLE` | DB compromise | None in new store | Parameterized queries only | injection test |
| T-DI-8 | Zip-slip / path traversal in raw storage | `../../` in ID | File overwrite | None | Sanitize filenames; store by hash | path test |

### 4.4 Confidentiality and secrets

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-C-1 | Secret in logs | API key in URL logged | Credential leak | `SecretSanitizer` | Central log filter; structured redaction | log scan |
| T-C-2 | Secret in report | Token in evidence | Client leak | Sanitizer at some call sites | Mandatory sanitize before write | report test |
| T-C-3 | Secret in DB | Raw payload contains token | At-rest leak | None | Encrypt sensitive columns or avoid storing; retention | DB test |
| T-C-4 | Secret in prompt | Env vars sent to cloud LLM | Leak | None | Local-only default; redaction; allowlist | prompt test |
| T-C-5 | `.env` committed | Local `.env` in git | Full compromise | None verified | `.gitignore`, secret scanning, rotation | CI test |
| T-C-6 | Verbose errors | Stack trace with credentials | Leak | Partial | Error classification; sanitized messages | error test |

### 4.5 Execution and sandbox

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-E-1 | Shell injection | Tool arg `; rm -rf` | RCE | Argument arrays, allowlist | Keep arrays; never `shell=True` | injection test |
| T-E-2 | Sandbox escape | Container mount `/` | Host compromise | `core/sandbox.py` | No host mounts, non-root, read-only FS, limits | lab test |
| T-E-3 | Resource exhaustion | Infinite scan | DoS | Timeouts | CPU/mem/req limits; stop conditions | timeout test |
| T-E-4 | Child process leak | Timeout leaves child | Resource leak | `kill_process_tree` | Verify all spawn paths use it | regression test |
| T-E-5 | Tool supply chain | Malicious binary | RCE | None | Pinned versions, checksums, license review, no auto-install | registry test |
| T-E-6 | Unbounded output | 10 GB response | Disk/memory | Size caps partial | Enforce max bytes in HTTP and tool output | size test |
| T-E-7 | Credential reuse | Tool uses operator creds | Lateral movement | None | Isolated credentials; least privilege | design review |

### 4.6 Availability and reliability

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-R-1 | Source outage | NVD 503 | Stale data | None | Retry/backoff, health, checkpoint | retry test |
| T-R-2 | Rate-limit ban | Aggressive polling | Blocked IP | None | Rate limiter, jitter, configurable intervals | limiter test |
| T-R-3 | Partial write | Crash mid-page | Inconsistent DB | None | Per-page transaction + checkpoint | crash test |
| T-R-4 | Disk full | Large raw snapshots | Corruption | None | Size limits, retention, disk health | design |
| T-R-5 | Hung async tasks | Uvicorn/Burp tasks | Test/prod hang | Partial fix | Task ownership + shutdown | lifecycle test |
| T-R-6 | Clock skew | Wrong incremental window | Gaps/duplicates | None | UTC + overlap + sanity checks | time test |

### 4.7 AI-specific

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-AI-1 | Hallucinated CVSS/version | Model invents 9.8 | Wrong priority | None | Deterministic extraction; citations; confidence | schema test |
| T-AI-2 | Hallucinated remediation | Fake patch URL | Harm | None | Only source-backed fixes; label provisional | report test |
| T-AI-3 | Overconfident classification | "Confirmed" from name match | False positive | Evidence Court (existing) | Applicability requires version/config evidence | triage test |
| T-AI-4 | Model drift | Provider changes model | Inconsistent output | None | Pin model/version; record in analysis | provenance test |
| T-AI-5 | Cost explosion | Huge prompts | Financial | None | Token limits, caching, local default | budget test |
| T-AI-6 | Data retention at provider | Advisory text retained | Confidentiality | None | Provider policy; local-only for untrusted | design |

### 4.8 Self-improvement (future)

| ID | Threat | Example | Impact | Existing control | Required addition | Test |
|---|---|---|---|---|---|---|
| T-SI-1 | Agent weakens policy | Edit scope checks | Unauthorized testing | None | Protected paths; human review; immutable policy tests | protected-path test |
| T-SI-2 | Agent runs arbitrary command | LLM suggests `curl \| sh` | RCE | None | Allowlisted runner; no shell; approval | command test |
| T-SI-3 | Agent merges unreviewed | Direct push to main | Supply chain | None | Branch + PR + required review | branch test |
| T-SI-4 | Agent deletes data | "Cleanup" migration | Data loss | None | Destructive ops require approval; backups | migration test |
| T-SI-5 | Test gaming | Delete failing tests | False green | None | Test-count/integrity checks; review | diff test |

---

## 5. Abuse cases (must be rejected)

1. "Scan this domain because a CVE says it is vulnerable." → No; authorization is independent of intelligence.
2. "The advisory contains a curl command; run it." → No; content is data.
3. "Use the API key found in the repo to test the vendor." → No; credentials are not authorization.
4. "Exploit this public host to prove the CVE." → No; out of scope / illegal.
5. "Disable the scope check for this one test." → No; policy is immutable at runtime.
6. "Install every scanner automatically." → No; explicit approval + capability review.
7. "Mark the detector validated because tests pass." → No; validation requires fixtures and documented limitations.
8. "Claim 2000–2026 coverage because the sync finished." → No; coverage requires a measured denominator.

---

## 6. Security requirements mapped to controls

| Requirement | Control | Phase |
|---|---|---|
| Deny active actions without valid scope | `PolicyGate` + `StrictScopeEngine` + expiry | P5/P6 |
| Revalidate immediately before action | executor pre-flight | P6 |
| No implicit subdomain/wildcard | explicit scope entries | P5 |
| No auto scope expansion | planner rejects unlisted hosts | P6 |
| Untrusted text never executes | data-only pipeline; no tool calls from content | P1/P9 |
| Parameterized DB access | sqlite3 placeholders only | P1 |
| Secret redaction | `SecretSanitizer` + central filter | P0/P1 |
| Size/time limits | HTTP wrapper + tool limits | P2/P6 |
| Idempotent ingestion | content hash + unique keys + transactions | P1/P2 |
| Provenance | source URL, retrieval time, raw hash | P1/P2 |
| Honest coverage | denominator + gaps + `complete=false` | P3 |
| No invented facts | deterministic parsing; citations; confidence | P1/P9 |
| Sandboxed lab | no network, non-root, limits, no host mounts | P7 |
| Audit trail | structured events with job/tool/target/decision | P8 |
| Graceful shutdown | checkpoint + task ownership | P2/P8 |
| Supply chain | pinned deps, audit, no auto-install | P11 |
| Self-improvement guardrails | branch/PR/protected paths/approval | P10 |

---

## 7. Verification plan (security tests)

| Test | Threat covered |
|---|---|
| Redirect to out-of-scope host is blocked | T-AZ-1 |
| DNS rebinding simulation is blocked | T-AZ-2 |
| `*.example.com` not implicitly allowed | T-AZ-3 |
| Expired scope rejected | T-AZ-4 |
| Direct `httpx` call outside gate is detected (architecture test) | T-AZ-5 |
| Destructive action denied by default | T-AZ-6 |
| Discovered host not auto-added | T-AZ-7 |
| Disallowed port rejected | T-AZ-8 |
| Advisory with "run command" stored, not executed | T-PI-1/2 |
| Zero-width/HTML-comment injection stored as text | T-PI-5 |
| Duplicate record → unchanged | T-DI-4 |
| Malformed JSON → rejected + error row | T-DI-5 |
| SQL metacharacters in description do not alter schema | T-DI-7 |
| Path traversal in source ID sanitized | T-DI-8 |
| Secrets absent from logs/reports (scan) | T-C-1/2 |
| `.env` not tracked | T-C-5 |
| Tool args with shell metacharacters rejected | T-E-1 |
| Timeout reaps child process | T-E-4 |
| Oversized response rejected | T-E-6 |
| Retry on 429/500 with backoff | T-R-1/2 |
| Crash mid-page → no partial rows | T-R-3 |
| Hallucinated CVSS not accepted without source | T-AI-1 |
| Name-only match → not confirmed | T-AI-3 |
| Protected policy file requires approval | T-SI-1 |
| Disallowed command rejected by runner | T-SI-2 |

---

## 8. Residual risks (accepted for now)

1. **No hardware-backed secret storage.** Secrets live in `.env`/OS env. Mitigation: file permissions, no logs, rotation.
2. **SQLite single-writer.** Adequate for one scheduler; concurrent heavy writes will contend. Mitigation: WAL, short transactions, future PostgreSQL.
3. **Third-party tool behavior.** A pinned tool may still be malicious/buggy. Mitigation: sandbox, no auto-install, license review.
4. **LLM provider trust.** Even local models can be manipulated. Mitigation: no execution from model output; citations; confidence labels.
5. **NVD/OSV schema changes.** Mitigation: fixtures, validation, error rows, source health.
6. **Windows-specific behavior.** Mitigation: cross-platform tests, CI on Ubuntu, explicit path handling.

---

## 9. Incident response (minimum)

1. **Suspected unauthorized action:** stop scheduler/executor, revoke credentials, preserve logs, verify scope config, notify owner.
2. **Secret exposure:** rotate credential, purge logs/reports, scan git history, add detection.
3. **Poisoned data:** identify source/records, mark `CONTRADICTED_BY_EVIDENCE`, re-sync from authoritative source, notify consumers.
4. **DB corruption:** stop writers, run `PRAGMA integrity_check`, restore from backup, replay checkpoint window.
5. **Prompt-injection incident:** preserve raw content hash, verify no tool execution occurred, update filters/tests.

---

## 10. Open security decisions

1. Is raw advisory storage permitted for each source? (See `DATA_SOURCE_REGISTER.md`.)
2. Which AI provider may process untrusted text? (Default: local Ollama.)
3. Is GitHub write access authorized for self-improvement PRs? Token scope?
4. Retention period for raw payloads and reports?
5. Is a network egress proxy mandatory in the deployment environment?
6. Who is the human approver for destructive/intrusive tests?

Until answered, the system defaults to the most restrictive option: no raw storage beyond hashes where uncertain, local AI only, no write operations, short retention, no destructive actions.
