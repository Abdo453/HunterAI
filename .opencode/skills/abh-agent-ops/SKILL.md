---
name: "abh-agent-ops"
description: ">"
---

# Agent Ops — Multi-Platform & Multi-Agent Operations

> Sources: awarexone/Agentic-Bug-Hunter (AGENTS.md command set),
> Likhithsai2580/AI-Bug-Bounty (parallel agents + monitor + plugin scoring),
> Hermes field report (OSS bounty reality check). See `references/sources.md`.
> Many primitives already exist in this repo (pentest.py memory/orchestrator/
> lead-board, abh-credential-attack, abh-bb-methodology) — this skill routes to
> them instead of duplicating.

---

## OP-1 — Platform Scope Aggregation (one-shot program intake)

Before any hunt, pull EVERY in-scope asset for the program, not just the web root:

```bash
# HackerOne
curl -s "https://api.hackerone.com/v1/hackers/programs/<handle>" \
  -u "USERNAME:TOKEN" | python -c "import json,sys; print([a['asset_identifier'] for a in json.load(sys.stdin)['structured_scopes'] if a['eligible_for_bounty']])"

# Bugcrowd — public disclosure endpoints expose scope JSON per program
# Intigriti / YWH / Immunefi — scrape public program page -> asset table
```

Then feed each asset into the signed grant:
```bash
python scripts/authorize_full_power.py issue --scope <asset1>,<asset2>,... --authorized-by "<program>" --days <window>
```
Rule: an asset the program API didn't return is OUT OF SCOPE — never widen by inference.

## OP-2 — Target Stack Intel (before Phase 3 triage)

Backing scripts in `bughunter/tools/`: `learn.py` (CVE/advisories for the
stack), `eol_check.py` (end-of-life escalation signal). Plus live NVD:

```bash
python pentest.py rag-retrieve "<service> <version> known vulnerabilities"
python bughunter/tools/learn.py --target <service> <version>
python bughunter/tools/eol_check.py <product> <version>
gh_grep searchGitHub query "<service> CVE"                                  # PoC hunting
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<service>" | python -m json.tool | head -80
```

EOL check: if the product is end-of-life, escalate scoring (unpatchable surface).
Route results into Phase 5 exploit routing — never into a report without proof.

## OP-3 — Continuous Monitor Mode (long engagements)

Backing script: `scripts/monitor_surface.py` (or command `/monitor`):

```bash
python scripts/monitor_surface.py baseline <target>
python scripts/monitor_surface.py check <target>          # print + log delta groups to alerts.jsonl
python scripts/monitor_surface.py watch <target> --interval 3600
```
Log every delta into memory namespace `event` (`pentest memory-write event ...`).
Alert-worthy: new subdomain, new JS bundle, changed bundle hash, template hit
on a previously-clean host.

## OP-4 — Cross-Target Pattern Memory

Backing script: `scripts/pattern_db.py` (or command `/pattern-db`) —
hash-chained, tamper-evident store at `data/memory/patterns.jsonl`:

```bash
python scripts/pattern_db.py add --class idor --stack "flask,uuid" \
    --sig "..." --bypass "..." --evidence artifacts/<t>/evidence/e1/
python scripts/pattern_db.py query --stack "<new-target stack fp>"
python scripts/pattern_db.py verify      # before any evidentiary reuse
```

## OP-5 — Parallel Per-Class Decomposition

Split a big engagement into per-vuln-class work streams (AI-Bug-Bounty plugin model):

| Stream | Lead source | Route to |
|---|---|---|
| sqli | params w/ reflection | abh-security-arsenal §1-2 |
| idor/access | swagger/api-map diffs | abh-web2-vuln-classes |
| secrets | JS bundles | `pentest secrets-hunt --js-bundle` |
| takeover | CNAME inventory | extension-modules §B |
| cves | service versions | Module A intake |

Run via `tools.opencode.subagent` (parallel background) or the orchestrator
(`pentest orchestrator-create`). Merge streams into ONE leads.md; validate each
finding through the 7-Question Gate independently (parallel ≠ lowered bar).

## OP-6 — Circuit Breaker / Rate Discipline (multi-agent MANDATORY)

Two layers exist:
- In-process: `bughunter/memory/audit_log.py` (RateLimiter + CircuitBreaker class)
- **Cross-process** (parallel subagents = separate processes): `scripts/rate_guard.py`
  file-backed shared budget at `data/memory/rate_budget.json`:

```bash
python scripts/rate_guard.py acquire <host> --rps 10   # exit 0 = go, 2 = wait
python scripts/rate_guard.py fail <host>              # 5-strike → 5-min circuit
python scripts/rate_guard.py status [host]
python scripts/rate_guard.py ok  <host>
```

Rules: max 10 req/s per host, back off on 429/503, circuit opens on storm
(pause stream 5 minutes). WAF present? One serializer per host
(extension-modules Module C). Log per stream → `artifacts/<target>/ops/ratelimit.jsonl`.

## OP-7 — Open-Source GitHub Bounty Triage (Hermes flow)

Backing script: `scripts/oss_bounty_triage.py` (or command `/oss-bounty`):

```bash
python scripts/oss_bounty_triage.py --min-reward 250 --limit 15
```
Blocker detection: OAuth/plugin/account signup → HAND OFF to operator with an
exact list ("create account at X, install Y"). Race assignment with a timer.
Reward clusters change; re-verify each session.

---

## Operating discipline (merged from all sources)

1. Scope from the platform API — never from memory or guessing (OP-1).
2. Intel-before-triage saves 5-minute-rule deaths (OP-2).
3. Long window? monitor beats one-shot (OP-3).
4. Patterns compound across targets — write them (OP-4).
5. Parallelize ONLY with a shared rate budget (OP-5+6).
6. Every claim path with a human blocker gets handed off explicitly (OP-7).
