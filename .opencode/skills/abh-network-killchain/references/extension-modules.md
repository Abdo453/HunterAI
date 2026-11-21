# Extension Modules — Advanced Kill-Chain Boosters

Bolt-on modules for the abh-network-killchain. Each plugs into a phase and
uses repo-native CLI commands (`pentest.py`) or Kali/WSL tools when present.

---

## Module A — Nuclei CVE Intake (plugs into Phase 5)

Purpose: turn collected service versions into a smart, non-spammy nuclei sweep.

Templates corpus is LOCAL: `data/arsenal/nuclei/` (14.5k templates, from
`scripts/arsenal_fetch.py pull nuclei`). Point nuclei at it via `-t`/`-td`:

```bash
# 0) refresh corpus once per session
git -C data/arsenal/nuclei pull --ff-only

# 1) The intake rule — sweep by EVIDENCE, not by everything
#    phase5 matched version strings -> only these template families:
nuclei -u <url> -t /mnt/e/Agant/PentestAI-Unified/data/arsenal/nuclei/http/cves/ -severity critical,high,medium
nuclei -u <url> -t .../nuclei/http/exposures/ -severity critical,high
nuclei -u <url> -tags tech,default-login -severity high
```

Extended payload corpus is LOCAL too: `data/arsenal/payloads/` (PayloadsAllTheThings —
per-class payload files + bypass tables) and `data/arsenal/waf-bypass/` (multi-engine
WAF bypass probes). Reference the matching class directory when firing
`references/payload-arsenal-war.md` weapons (Sections 1–10).

The `pentest.py scan-cves <host>` repo-native equivalent uses the same templates.

---

## Module B — Subdomain Takeover (plugs into Phase 1/3)

Repo command exists: `pentest takeover --recon <dir>`; add the manual layer:

```bash
# 1) CNAME inventory of every subdomain from Phase 1
dnsx -l live_subdomains.txt -cname -resp -o cnames.txt

# 2) candidate = cname points to de-registered/third-party service
#    fingerprints: "NoSuchBucket", "There isn't a GitHub Pages site",
#    "The site can't be reached" + S3/Azure/Heroku/Shopify/Zendesk/Fastly markers
grep -Ei 'NoSuchBucket|github pages|herokuapp|zendesk|fastly|azurewebsites' cnames.txt

# 3) verify claim-ability by ACTUALLY claiming the third-party resource with a
#    canary (operator-owned bucket/site), then remove it — document before/after.
```

Report only when (a) fingerprint matches, (b) canary claim succeeded,
(c) you show the served canary page — fingerprint alone is a lead, not a finding.

---

## Module C — Firewall / WAF Evasion Ladder (plugs into Phase 2–5)

Progressive ladder — always try the cheap level first; log which level worked.

| Level | Technique | Command seed |
|---|---|---|
| L1 | delay/parallelism tuning (`nmap -T2 --scan-delay 300ms`, `masscan --rate 200`) | evade IDS rate triggers |
| L2 | decoy scan `nmap -sV -T2 -D RND:5 <ip>` | mask scanner identity |
| L3 | source-port/fragmentation `--source-port 53 -f` | legacy firewall rules |
| L4 | payload padding / WAF unary tricks | repo: `pentest waf-padding <target> <payload>` |
| L5 | parser-bug (differential parsing) | repo: `pentest waf-parser-bug <target> --bug-id <id> <payload>` |
| L6 | fingerprint spoofing | repo: `pentest waf-fingerprint <target>` |
| L7 | bypass ladder full orchestration | repo: `pentest waf-bypass-ladder <target> <payload>` |

Rules:
- Fingerprint first (`whatweb`, `wafw00f`) — know the engine before evading it.
- Evasion is for LEGITIMATE testing stealth, never log-clearing or EDR tampering
  (that's a hard invariant).
- If L4–L7 unblock a payload, save which level + exact request → evidence.

Supporting scripts (ports, stdlib-only):
- `scripts/waf_encoder.py` — 18 encoding variants of ONE payload (URL×2,
  unicode, case, comment-split, tab/newline fusion, b64, hex) + optional
  `--fire` evidence-probe mode (1 request/variant, 300 ms).
- `scripts/waf_response_analyzer.py` — classify baseline↔variant pairs to NAME
  the blind spot: `edge block → encoder matrix + L4-L7 ladder`,
  `backend parser (400) → HPP/JSON-strictness quirks`,
  `encoded-only → polyglot re-encode`, `NO filter → escalate to proof`.

---

## Module D — AD Pivot Escalation (plugs into Phase 6)

Trigger: any valid domain credential found in Phase 4/5. Route deep work to
`offensive-active-directory` / `offensive-lateral-movement` skills; the ladder here:

```bash
# L1 Situational awareness
bloodhound-python -dc <dc> -u <user> -p <pass> -d <domain>    # shortest DA path
netexec ldap <dc> -u <user> -p <pass> --bugraph               # quick graph

# L2 Not-in-DA privilege checks
netexec ldap <dc> -u <user> -p <pass> --kerberoasting kerb.txt   # roastable SPNs
netexec smb  <dc> -u <user> -p <pass> -M enum_dns                # DNS zone trust

# L3 Escalations (each one: prove, then route deeper)
#  - ACL abuse: GenericAll/GenericWrite/WriteDACL on targets from BloodHound
#  - Shadow credentials / ADCS ESC1-8 -> offensive-active-directory skill
#  - Relay only when SMB signing disabled (verify w/ netexec smb --signing)
```

Guardrails (unchanged):
- Prove least-invasive escalation first (read DA info > reset DA password > ad
  persistence — the last two are hard-invariant and DO NOT run).
- Every cred/hash found → memory namespace `credential_finding` (redacted) +
  `leads.md`; hash values stay out of memory store.
