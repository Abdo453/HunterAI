---
name: "abh-script-forge"
description: ">"
---

# Script Forge — The Agent Writes Its Own武器 (Weapons)

> Rule zero: **tools first, then adaptation, then forging.** A forged script is
> justified only when the mission need is precise and no installed tool/flag
> combination covers it.

---

## 1. Decision Tree (before writing any line)

```
Need identified (e.g. "blind-HTTP-header oracle", "dump dirsearch JSONs → leads.md")
├─ installed tool covers it?  (whatis kali_* MCP / wsl bash -lc "<tool>")
│   └─ YES → run it, format output, done.
├─ tool covers 80%? (needs flags/pipeline glue)
│   └─ YES → one-liner chain in WSL (python/bash) — prefer over a file.
└─ no match / mission-specific logic
    └─ FORGE: write <scripts_mission>/<purpose>.py in artifacts/<target>/scripts/
```

## 2. Forge Rules (hard)

1. **Single purpose.** One script = one mission need. No frameworks, no config files.
2. **Evidence probe pattern.** Script output MUST land in `artifacts/<target>/...`
   and print a machine-readable summary (json lines) the agent can parse.
3. **Timeouts mandatory.** Every network call wrapped with `timeout=` (default 10s);
   whole run under 10 min unless explicitly scoped longer.
4. **Read-only proofs.** No persistence, no C2, no destructive writes, no bulk
   exfil — same hard invariants as the policy engine. If the mission requires
   state change (e.g. upload test), the script does it under a canary name and
   CLEANS UP, and prints "cleanup=done" to the log.
5. **stdlib-first.** On Windows host: `urllib`, `socket`, `hashlib`, `json` only
   (no pip installs mid-mission). In WSL Kali: full toolbox allowed.
6. **Stealth knobs built in.** `--delay`, `--jitter`, `--user-agent`, `--threads`
   defaults conservative (1 thread, 300ms delay).
7. **Dry-run flag.** Every script accepts `--dry-run` printing intended requests
   without sending — run it first.

## 3. Forging Workflow (per mission)

1. **Spec**: write the need as ONE sentence with expected observable
   ("if response A differs from response B by status code").
2. **Template start** (`references/script-templates.md`): pick the closest
   template (http-probe / blind-oracle / raw-socket / parser / jwt-tamper).
3. **Write** into `artifacts/<target>/scripts/`.
4. **QA gate** (fast, no shortcuts):
   - `python -m py_compile <script>`
   - `--dry-run` first
   - run once against CANARY target (localhost is fine)
5. **Fire** against the authorized target; log per-request lines
   (`time | req | status | elapsed | key-finding`).
6. **Adjudicate inside the script**: end-of-run prints
   `SUMMARY: {"proven": X, "leads": Y, "errors": Z}`.

## 4. reusable One-Liners (agna — before forging, try these)

```bash
# custom header fuzz
wsl -d kali-linux -- bash -lc "python3 - <<'PY'
import socket,sys
...inline logic...
PY"

# multi-stage pipeline
wsl -d kali-linux -- bash -lc "curl -s http://t/api | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[\"users\"])'"
```
If an inline heredoc gets > 30 lines → switch to a file (forge rules apply).

## 5. Handoff

- Mission is a **recurring need** (used > 2 engagements)? → promote the script
  into the repo (`tools/` or `agents/`) with its own README + tests.
- Output feeds a kill-chain phase? → append one line to the phase's playbook
  referencing the script path.
