---
name: "abh-network-killchain"
description: "Master network pentest kill-chain orchestrator. Give it a target (domain, URL, IP, or CIDR) and it autonomously walks the full attack path \u2014 external recon, port/service mapping, service triage, credential access, exploitation routing, and post-exploitation pivots \u2014 looping until it has validated..."
---

# Network Kill-Chain: Give Target → Break In

> The user hands you ONE thing: a target. You own the rest. Do not ask "what should I do?" — follow the chain below, phase after phase, until you hold validated findings or prove the target is hardened.

---

## FULL-POWER AUTONOMOUS MODE (default when grant is active)

The operator's contract is: **"أنا هديك الـ scope والتفويض — امضي بكل قوتك."** Once that contract is fulfilled, you do NOT ask per-phase permission. You loop the chain autonomously.

### How the contract is fulfilled (any ONE of these)
1. User states scope + authorization explicitly in the conversation ("مصرح لي بكل subdomains لـ example.com"، pasted scope list, SOW reference), OR
2. A signed grant already exists at `data/root_controller/authorization_grant.json` covering the target.

### Startup sequence (execute WITHOUT asking between steps)
```powershell
# 1. Issue (or refresh) the signed grant — one command, full power:
python scripts/authorize_full_power.py issue --scope <targets> --authorized-by "<operator/org from user>" --days 7
# 2. Confirm the grant allows the target before the first packet:
python scripts/authorize_full_power.py check --target <target>
# 3. Then run the chain: Phase 0 -> 7 back-to-back. Do not pause. Do not summarize between phases. Do not ask "shall I continue?".
```

### Autonomous operating rules while the grant is active
- **No permission rituals**: after the `check` reads ALLOWED, proceed phase→phase in one continuous run. Ask only if (a) an action would leave the scope, (b) an interactive/destructive platform is required (msf payload install, anything in `hard_invariants`), or (c) credentials need cracking time longer than the session.
- **Keep the hard invariants** (they are policy-enforced anyway): no persistence, no C2, no destructive writes, no log-clearing, no bulk exfil, nothing outside the grant. When blocked by the invariant: one line report, then keep hunting elsewhere.
- **Artifact cadence**: every tool output → `artifacts/<target>/<phase>/`; every lead → `artifacts/<target>/leads.md`; memory writes at each phase end (`pentest memory-write event <target> phase_<n>_done`).
- **Self-heal**: tool timeout → retry narrower once → if still dead, log and move to the next service. Never silently skip a phase; record why.
- **Termination**: chain runs until (a) every live host × service has been triaged, (b) findings validated through the 7-Question Gate, or (c) operator calls stop. Then deliver the consolidated report WITHOUT being asked.

---

## Execution Mode (WSL Kali)

All tools run through Kali on WSL — three channels, try in this order:

1. **MCP first**: `tools["hunter-arsenal"].kali_<tool>` (e.g. `kali_nmap`, `kali_netexec`, `kali_masscan`). Pass `target` + `extra_args`.
2. **Generic dispatch**: `tools["hunter-arsenal"].kali_dispatch_tool` for anything not in the arsenal list.
3. **WSL direct** (PowerShell): `wsl -d kali-linux -- bash -lc "<command>"`.

Rule: never claim a tool ran if you don't have its output. Every phase ends with an artifact saved under `artifacts/<target>/<phase>/`.

---

## THE CHAIN (run phases in order, never skip)

### Phase 0 — Scope Gate (BLOCKING)

Before any packet leaves this machine:

1. Check for written authorization: `AUTHORIZATION.txt`, scope docs, or explicit user confirmation of scope **in this conversation**.
2. Echo back the target, scope, and window. If the asset is NOT in scope → **STOP. Nothing else runs.**
3. Log to structured memory: `pentest memory-write event <target> scope_approved "<who/when>"`.

### Phase 1 — External Attack-Surface (passive → light active)

| Step | Tool (MCP) | Command essence |
|---|---|---|
| FO / Whois | `kali_whois` | `whois <target>` |
| DNS records | `kali_dnsenum` / `kali_dnsx` | apex, A/AAAA, MX, NS, TXT/SPF |
| Subdomains | `kali_subfinder` → `kali_amass` (passive) | enumerate |
| Live hosts | `kali_httpx` | probe `https://443`, `http://80` |
| Certs | crt.sh / `kali_theHarvester` | SAN reveals extra hosts |
| **Takeover** | Module B (`references/extension-modules.md`) | CNAME inventory + fingerprints, `pentest takeover --recon <dir>` |

**Artifact**: `artifacts/<target>/surface/live-hosts.txt`

### Phase 2 — Port & Service Mapping

Fast broad, then surgical precise:

1. `kali_masscan` `-p1-65535 --rate=1000` on IPs from Phase 1 (per-IP; NOT on domains).
2. `kali_nmap` on the open set **only**: `-sV -Pn -p <open_ports> --scripts=discovery,vulners --version-all`.
3. Record service+version per port into `artifacts/<target>/services.md`.

### Phase 3 — Service Triage (decision tree)

For **each service**, route like this:

```
HTTP/HTTPS (80,443,8080,8443...)
   ├─ whatweb / nikto banner+tech          → kali_whatweb, kali_nikto
   ├─ nuclei -t exposures,vulners,cves     → kali_nuclei
   ├─ dirsearch / gobuster (dirs)          → kali_dirsearch
   └─ juicy params? → fire `references/payload-arsenal-war.md` (Section 1/2/3/4/6/7 per param type) — one payload class at a time, capture response, next

SMB/RPC (139,445)
   ├─ enum4linux-ng -A                     → kali_enum4linux_ng
   ├─ netexec smb  shares/users/policy     → kali_netexec
   └─ nmap --script smb-vuln-*             → kali_nmap

SSH (22)        → ssh_audit --bold         → kali_ssh_audit   (weak algs, old versions)
SSL/TLS         → sslscan / testssl.sh     → kali_sslscan, kali_testssl
SMTP (25,587)   → nmap smtp-enum-users, open relay check
DB ports (3306/1433/5432/27017) → nmap -script db-*, test for public listening only
FTP (21)        → check anonymous login, banner version → searchsploit
RDP (3389)      → nmap rdp-vuln drift, NLA required?
LDAP (389/636)  → anonymous bind? /scripts=ldap-*
```

### Phase 4 — Credential & Access Path

Carry out ONLY with authorization and lockout-safety (spray 1 password per cycle, honor lockout thresholds):

| Path | Tool | Notes |
|---|---|---|
| Web logins | `kali_hydra` / `kali_medusa` | identify login form first |
| SMB password spray | `kali_netexec` `smb <ip> -u users -p 'Season2025!'` | 1 spray/cycle |
| Responder poison (internal) | `kali_responder` | capture NTLMv2 → crack offline w/ john/hashcat |
| sshAudit findings | fetch weak sshd → try user enum | |

### Phase 5 — Exploit Routing (w/ Nuclei Intake Module)

1. **searchsploit** every version string you gathered: `kali_searchsploit` `<service> <version>`.
2. **nuclei intake** (Module A in `references/extension-modules.md`): map Phase 2 fingerprints → matching template families only — never `-t all`. Hits = leads until manually replayed.
3. Only when version+exploit matches: propose the specific exploit; if it's a RAT/interactive tool (`kali_msfconsole`), state blast radius first, wait for user confirmation, then run.
4. **Never** claim exploit success without showing the actual service output/response.
5. WAF/IDS in the way? climb the Evasion Ladder (Module C, Levels L1–L7, repo `waf-*` commands) — cheapest level first.
6. **No tool fits the exact need?** → hand to `abh-script-forge`: forge a single-purpose probe script into `artifacts/<target>/scripts/`, QA-gate it (`py_compile` + `--dry-run` + canary run), then fire it.

### Phase 6 — Foothold → Pivot (optional, internal)

If you obtain valid credentials (not just leaks):

1. BloodHound path: `kali_bloodhound` → shortest Domain Admin path.
2. Kerberoast: `kali_netexec` kerberoast → `kali_hashcat` lib.
3. Relay only where SMB signing is off — verify first via netexec `smb` not `signing required`? Check.
4. **AD Pivot Escalation Ladder** (Module D in `references/extension-modules.md`): L1 situational awareness → L2 privilege checks → L3 escalation proofs; route deep pivots into `offensive-active-directory` / `offensive-lateral-movement` skills.

### Phase 7 — Evidence, Validation, Report

For EVERY finding:
1. Save raw proof (command output, request/response, screenshot path) into `artifacts/<target>/evidence/<id>/`.
2. Run the 7-Question Gate (`abh-triage-validation`). One wrong answer = kill finding, log as "attempted, not exploitable".
3. Compose findings into the report skill (`abh-report-writing` / `pentest report`).

---

## LOOP DISCIPLINE

- **5-minute rule** per service: nothing promising after 5 min → park it, move next.
- **Lead Board**: keep a ranked list of leads in `artifacts/<target>/leads.md` — never lose one.
- **Impact first**: after foothold, demonstrate worst-case (data read, privilege gain), not cosmetic trivia.
- If external surface is hardened → fall back to `abh-web2-recon` (URL/JS/subdomain hunting on the web assets) rather than brute-forcing network.

## HANDOFF TRIGGERS

| Situation | Route to |
|---|---|
| Web-focused target after Phase 2 | `abh-web2-vuln-classes`, `abh-bb-methodology` |
| Wi-Fi in scope | `offensive-wifi`, `offensive-wpa2-psk`, `offensive-wps` |
| Cloud assets discovered (S3/Azure) | `abh-cloud-pentest` |
| AD found on internal | `offensive-active-directory` |
| Report | `abh-report-writing` |
