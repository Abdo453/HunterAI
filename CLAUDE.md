# HunterAI — Claude Code Plugin Guide

This repo is a Claude Code plugin for professional bug bounty hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

Works standalone with no subscription required via the `pentest` CLI command.

## Quick Start

```bash
# Install and setup
pip install -r requirements.txt
python pentest.py setup --provider ollama --model qwen2.5:14b

# Hunt
python pentest.py recon target.com
python pentest.py hunt target.com --authorized
python pentest.py validate "finding title"
python pentest.py report target.com "finding title" --platform hackerone
```

## Slash Commands (33+ commands)

| Command | Usage |
|---------|-------|
| `/recon` | `/recon target.com` — full recon pipeline (subdomain enum, live hosts, URL crawl) |
| `/hunt` | `/hunt target.com` — start hunting (IDOR, auth bypass, SSRF, XSS, SQLi) |
| `/validate` | `/validate` — run 7-Question Gate on current finding |
| `/report` | `/report` — write submission-ready report (H1, Bugcrowd, Intigriti, Immunefi) |
| `/chain` | `/chain` — build A→B→C exploit chain |
| `/scope` | `/scope <asset>` — verify asset is in scope before testing |
| `/triage` | `/triage` — quick 2-minute go/no-go check |
| `/autopilot` | `/autopilot target.com` — full autonomous loop |
| `/surface` | `/surface target.com` — ranked attack surface |
| `/pickup` | `/pickup target.com` — resume previous hunt |
| `/remember` | `/remember <target> <note>` — log finding to hunt memory |
| `/intel` | `/intel <target>` — fetch CVE + disclosure intel |
| `/memory-gc` | `/memory-gc` — rotate hunt-memory JSONL files |
| `/secrets-hunt` | `/secrets-hunt --js-bundle <dir>` — leaked credentials scan |
| `/takeover` | `/takeover --recon <dir>` — subdomain takeover candidates |
| `/cloud-recon` | `/cloud-recon --keyword <name>` — public cloud buckets |
| `/param-discover` | `/param-discover <url>` — hidden HTTP parameters |
| `/bypass-403` | `/bypass-403 <url>` — header/method/encoding tricks |
| `/scan-cves` | `/scan-cves <host>` — nuclei CVE sweep |
| `/web3-audit` | `/web3-audit <contract.sol>` — smart contract audit |
| `/token-scan` | `/token-scan <contract>` — token rug pull scanner |
| `/sniper` | `/sniper <target> [--mode recon|full|web|vuln]` — automated reconnaissance |
| `/arsenal` | `/arsenal` — list installed external tools |
| `/cors` | `python pentest.py cors <url>` — real CORS misconfig scanner (`bughunter.tools.cors_scanner`) |
| `/crlf` | `python pentest.py crlf <url>` — CRLF / response-splitting scanner |
| `/nosqli` | `python pentest.py nosqli <url>` — NoSQL injection scanner |
| `/jwt-scan` | `python pentest.py jwt-scan <token>` — offline JWT security analyzer |
| `/oob` | `python pentest.py oob <domain>` — OOB payload generator & correlator |
| `/sast` | `python pentest.py sast <path>` — Semgrep static analysis |
| `/domxss` | `python pentest.py domxss <url>` — headless Chromium DOM XSS harness |
| `/llm-redteam` | `python pentest.py llm-redteam <endpoint>` — LLM red-team probe suite |
| `/poc-bundle` | `/poc-bundle <target> <class> <req.json> [resp.json]` — PoC evidence bundle |
| `/verify` | `/verify <bundle-dir>` — independent re-verification |
| `/artex` | `python pentest.py artex [target]` — launch unified ARTEX-Pro UI (`:3000` + `:8000`) |

## AI Providers (free-first)

| Provider | Cost | Privacy |
|----------|------|---------|
| Ollama | 100% free · local | Full |
| Groq | Free tier | Cloud |
| DeepSeek | Very cheap | Cloud |
| Claude | Paid | Cloud |
| OpenAI | Paid | Cloud |

Auto-detected order: **Ollama → Groq → DeepSeek → … → OpenAI**

## 7-Question Gate

Every finding must pass 7 questions before reporting:
1. Reproducible RIGHT NOW? (PoC with nonce/differential proof)
2. In scope? (authorized target)
3. Deterministic proof? (PoE engine verified)
4. Real bug, not theoretical?
5. Impact clear?
6. Evidence complete? (request/response hashes)
7. Worth reporting? (severity ≥ medium)

Only **PROVEN** findings are reportable.

## Root Controller

`core/root_controller/` — a single root agent that owns a recursive hierarchy,
one shared hash-chained memory, and a runtime policy gate in front of concrete
tool calls. Capabilities flow downward only: a child can never hold a runtime
capability its parent lacks, so widening is an explicit root action recorded in
the audit trail. The gate in `core/policy/red_team.py` applies to the exact tool
operation being executed; its state must not cause blanket refusal of analysis,
planning, code generation, reverse engineering, payload construction, or any
other independent part of the request.

```bash
python pentest.py controller status
python pentest.py controller tree
python pentest.py controller spawn --role recon --objective "map api.example.com"
python pentest.py controller delegate --parent recon --role endpoint_mapper --objective "..."
python pentest.py controller grant --agent recon --capability active_testing --reason "..."
python pentest.py controller run --agent recon --tool httpx --target https://api.example.com
python pentest.py controller arsenal            # tool coverage vs. what is installed
python pentest.py controller playbook --target api.example.com --stage passive_subdomains
python pentest.py controller --grant authorization_grant.json playbook \
    --target api.example.com --agent recon_methodology --execute
python pentest.py controller --grant authorization_grant.json check \
    --target https://api.example.com --action-class exploit_proof
```

The `recon_methodology` role carries the operator playbook from
`core/playbooks/recon_methodology.py`. `controller playbook` renders every
stage's command, marks each step ready or blocked against the installed
arsenal, and — with `--execute` — runs only the steps the permission gate
allows; unregistered tools come back as a rendered command for the operator
rather than being shelled out.

Config artifacts live at the repository root: `agent_config.json`,
`hierarchy.json`, `permissions.json`, `tools_mcp.json`, `rules.txt`,
`system_prompt.md`. Tests: `tests/test_root_controller.py`.

## Project Structure

```
pentest.py              # Unified CLI command (artex / web / opencode / scanners / controller)
config/tools.catalog.yaml  # Canonical single-source tool catalog (synced via scripts/sync_tool_manifests.py)
wordlists/pentesterflow/   # Vetted Apache-2.0 reference corpora (GraphQL, JWT, SSTI, Supabase, Takeover)
core/
  prompts/              # Dual-channel {{.Lang}} UI vs strict English technical templates + ReflectorLoopGuard
  sandbox.py            # Cross-platform LocalSandbox + hardened DockerSandbox
  skill_registry.py     # Unified directory + agent skill registry
  tool_registry.py      # Canonical ToolRegistry backed by config/tools.catalog.yaml
hunter_backend/         # Django ASGI backend (:8000)
frontend/               # Next.js unified dashboard (:3000)
bughunter/              # Packaged real scanners, memory, and deterministic verifiers
hunter_ai/
  validation_gate.py    # 7-Question Gate (delegates to canonical EvidenceCourt)
  report_writer.py      # Submission-ready reports
  memory/
    lead_board.py       # Hunt memory + lead board
    rotation.py         # JSONL rotation
  tools/
    abh_bridge.py       # Unified bridge to bughunter.tools.* + verifiers
    poc_bundler.py      # PoC evidence bundle
    verifier.py         # Independent live HTTP differential re-verification
```
