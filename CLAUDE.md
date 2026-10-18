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
| `/poc-bundle` | `/poc-bundle <target> <class> <req.json> [resp.json]` — PoC evidence bundle |
| `/verify` | `/verify <bundle-dir>` — independent re-verification |

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

## Project Structure

```
pentest.py              # Unified CLI command (like bughunter)
main.py                 # Web UI entry point
hunter_ai/
  validation_gate.py    # 7-Question Gate
  report_writer.py      # Submission-ready reports
  memory/
    lead_board.py       # Hunt memory + lead board
    rotation.py         # JSONL rotation
  core/
    scope_engine.py     # Scope firewall (fail-closed)
    tool_arsenal.py     # Installed tools registry
  brain/
    ai_providers.py     # Multi-provider LLM layer
  pipeline/
    recon_engine.py     # Recon pipeline
    hunt_engine.py      # Vulnerability hunt pipeline
  tools/
    poc_bundler.py      # PoC evidence bundle
    verifier.py         # Independent re-verification
```
