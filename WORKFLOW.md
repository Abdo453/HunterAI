# 🧠 HunterAI — Autonomous Bug Bounty Workflow Specification

## Overview

HunterAI is an autonomous, artifact-driven penetration testing and bug-bounty agent pipeline. Rather than executing disjointed CLI commands, HunterAI operates as a **cognitive state machine** where every stage produces structured, typed **artifacts** consumed by subsequent stages:

$$\text{Scope} \longrightarrow \text{Recon} \longrightarrow \text{Normalization} \longrightarrow \text{Live Assets} \longrightarrow \text{Attack Surface} \longrightarrow \text{Triage} \longrightarrow \text{Testing} \longrightarrow \text{Verification} \longrightarrow \text{Report}$$

---

## 1. System Architecture & State Machine

```text
TARGET
  │
  ▼
[0] SCOPE & SAFETY (ScopeGuard)
  │
  ▼
[1] RECON (Passive + Active + CT + OSINT + ASN)
  ├── subfinder / assetfinder / amass / findomain
  └── crt.sh CT logs
  │
  ▼
[2] ASSET NORMALIZATION & DEDUPLICATION
  ├── Multi-source origin tracking
  ├── Confidence scoring
  └── Asset classification (API, Admin, CDN, Dev, Upload, Auth)
  │
  ▼
[3] LIVE ASSET PROBING (HTTPAgent)
  ├── HTTP / HTTPS probing (httpx / async engine)
  ├── Status code, Page title, Server headers
  ├── Content length & redirects
  └── Technology fingerprinting (WAF, Framework, Language)
  │
  ▼
[4] ATTACK SURFACE & URL DISCOVERY (DiscoveryAgent)
  ├── URL harvesting (Wayback, GAU, Katana, AlienVault)
  ├── Directory & sensitive file fuzzing (gobuster, ffuf, dirsearch)
  ├── Form & upload endpoint discovery
  └── Admin & authenticated route identification
  │
  ▼
[5] JAVASCRIPT & SECRET INTELLIGENCE (JavaScriptAgent)
  ├── JS download & beautification
  ├── Endpoint & API route extraction
  └── Secret detection (API keys, JWT, AWS tokens, Slack webhooks)
  │
  ▼
[6] PARAMETER INTELLIGENCE & CONTEXT MAPPING (ParameterDatabase)
  ├── Parameter classification (numeric, URL, file, path, command)
  └── Vulnerability class hypothesis mapping:
      ├── id, user_id, order_id  ⟶ IDOR / SQLi
      ├── url, dest, redirect, src ⟶ SSRF / Open Redirect
      ├── file, path, doc, page   ⟶ LFI / Path Traversal
      ├── cmd, exec, ping, host   ⟶ OS Command Injection
      └── q, search, query, msg   ⟶ XSS / SSTI
  │
  ▼
[7] VULNERABILITY ROUTER (VulnRouter)
  ├── Routes parameters to specialized skills with rich context
  └── Context includes baseline response, tech stack, and observed behavior
  │
  ▼
[8] SPECIALIZED TESTING SKILLS
  ├── SQLiSkill (Blind, Error, Time, UNION state machine)
  ├── CmdInjectionSkill (Multi-delimiter, In-band reflection filter)
  ├── SSRFSkill (Cloud metadata matrix, filter bypass)
  ├── XSSSkill (Context-aware breakout, CSP evaluator)
  ├── IDORSkill (Cross-tenant matrix, verb tampering)
  ├── LFISkill (Null-byte, traversal bypass)
  ├── CSRFSkill (Samesite, token validation)
  └── SmugglingSkill (CL.TE / TE.CL differential)
  │
  ▼
[9] MULTI-LAYER VERIFICATION ENGINE (VerificationEngine) 🔥
  │
  │  CRITICAL INVARIANT:
  │  Reflection != Injection != Execution
  │  Execution Evidence != Impact
  │
  ├── Negative control baseline comparison
  ├── Arithmetic execution proofs: $((41+1)) ⟶ 42
  ├── Dynamic delay timing differential: t_delayed - t_baseline >= threshold
  ├── Deterministic canary validation
  └── In-band HTML reflection rejection
  │
  ▼
[10] EVIDENCE MODEL & FALSE POSITIVE AUDIT (EvidenceEngine)
  ├── Structured evidence chain
  ├── Reproduction curl / HTTP request & response
  └── Explicit false positive filters
  │
  ▼
[11] MULTI-MODEL AI COUNCIL (ModelCouncil)
  ├── WhiteRabbitNeo (Strategist & Attack planner)
  ├── Qwen 2.5 Coder (Code, JS analysis, Remediation)
  ├── Xploiter (Output classification & Triage)
  └── Cloud APIs (Gemini, OpenRouter, Groq, Anthropic)
  │
  ▼
[12] EXECUTIVE & TECHNICAL REPORTING (ReportAgent)
  ├── Markdown / HTML Executive Reports
  ├── HackerOne-compliant Bug Bounty Reports
  └── Raw tool execution logs (.txt files)
```

---

## 2. Invariant State Machine Transitions

HunterAI strictly prevents premature conclusion or classification:

```text
DISCOVER ──► ENUMERATE ──► NORMALIZE ──► MAP ──► CLASSIFY ──► TRIAGE
                                                               │
                                                               ▼
REPORT ◄── ASSESS_IMPACT ◄── CORRELATE ◄── VERIFY ◄── TEST ◄── HYPOTHESIZE
```

> [!CAUTION]
> **Forbidden Transition**: `TEST ──► REPORT` is strictly prohibited.
> Every candidate vulnerability MUST traverse `TEST ──► VERIFY ──► EVIDENCE ──► REPORT`. If an exploit attempt reflects input without proving shell or database execution, it is rejected as a false positive.

---

## 3. Artifact Directory Structure

For every target and scan session, HunterAI produces a structured artifact repository:

```text
data/scans/{target_slug}_{session_id}/
├── 00_scope/
│   └── scope_config.json
├── 01_recon/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── amass.txt
│   ├── crtsh.txt
│   └── all_subdomains.txt
├── 02_normalized_assets/
│   ├── assets_inventory.json
│   └── classified_assets.json
├── 03_live_assets/
│   ├── httpx_output.txt
│   ├── alive_hosts.txt
│   └── tech_stack.json
├── 04_attack_surface/
│   ├── harvested_urls.txt
│   ├── discovered_endpoints.json
│   ├── discovered_parameters.json
│   └── directory_fuzz.txt
├── 05_js_intelligence/
│   ├── js_files.txt
│   ├── extracted_api_routes.json
│   └── discovered_secrets.json
├── 06_testing/
│   ├── routed_tasks.json
│   └── raw_skill_transcripts/
├── 07_verification/
│   ├── verification_proofs.json
│   └── false_positive_audit.json
├── 08_evidence/
│   ├── reproduction_requests.json
│   └── evidence_chains.json
└── 09_reports/
    ├── final_findings.json
    ├── executive_summary.html
    └── bug_bounty_report.md
```

Additionally, every single tool execution writes full stdout, stderr, commands, and exit codes to:
`data/tool_outputs/{tool}_{target}_{timestamp}.txt`

---

## 4. Parameter Database Schema

```json
{
  "parameter": "dest",
  "endpoint": "/api/v1/redirect",
  "method": "GET",
  "source": "katana",
  "sample_value": "https://example.com/login",
  "potential_classes": ["SSRF", "Open Redirect"],
  "tested_skills": ["SSRFSkill"],
  "status": "TRIAGED"
}
```

---

## 5. Verification Proof Contract

```json
{
  "finding": "OS Command Injection",
  "asset": "api.example.com",
  "endpoint": "/api/system/ping",
  "parameter": "host",
  "status": "CONFIRMED",
  "confidence": 0.98,
  "cvss_v31": {
    "score": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  },
  "evidence": [
    {
      "type": "behavioral",
      "description": "Pipe delimiter altered HTTP response status from 400 to 200"
    },
    {
      "type": "arithmetic_proof",
      "payload": "127.0.0.1;echo $((41+1))",
      "expected_result": "42",
      "actual_output": "42\n",
      "verified": true
    }
  ],
  "reproduction": {
    "curl": "curl -s -X POST 'https://api.example.com/api/system/ping' -d 'host=127.0.0.1%3Becho+%24%28%2841%2B1%29%29'",
    "response_snippet": "42\n"
  },
  "false_positive_checks": {
    "in_band_html_reflection": false,
    "baseline_differential_confirmed": true,
    "reproducible_count": 3
  }
}
```
