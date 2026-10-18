# Bug Bounty Agent Toolkit — Plugin Guide

This repo is an agent-portable bug bounty plugin for professional hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

Supports Claude Code, OpenCode, Pi Agent, Codex-style Agent Skills, and shared `.agents/skills` harnesses.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Setup AI provider (Ollama recommended, free + local)
python pentest.py setup --provider ollama --model qwen2.5:14b

# Full hunt workflow
python pentest.py recon target.com
python pentest.py hunt target.com --authorized
python pentest.py validate "finding"
python pentest.py report target.com "finding" --platform hackerone
```

## Slash Commands

| Command | Usage |
|---------|-------|
| `/recon target.com` | Subdomain enum · live host discovery · URL crawl |
| `/hunt target.com` | IDOR · auth bypass · SSRF · XSS · SQLi · logic flaws |
| `/validate` | 7-Question Gate — kills weak findings |
| `/report` | H1 · Bugcrowd · Intigriti · Immunefi submission |
| `/autopilot target.com` | Full autonomous loop |
| `/surface target.com` | Ranked attack surface |
| `/scope <asset>` | Verify asset is in scope |
| `/triage` | Quick 2-minute go/no-go |
| `/pickup target.com` | Resume previous hunt |
| `/remember <target> <note>` | Log finding to hunt memory |
| `/memory-gc` | Rotate hunt-memory JSONL files |
| `/arsenal` | List installed external tools |
| `/secrets-hunt --js-bundle <dir>` | Leaked credentials scan |
| `/takeover --recon <dir>` | Subdomain takeover candidates |
| `/cloud-recon --keyword <name>` | Public cloud buckets |
| `/param-discover <url>` | Hidden HTTP parameters |
| `/bypass-403 <url>` | Bypass 403/401 tricks |
| `/scan-cves <host>` | Nuclei CVE sweep |
| `/web3-audit <contract.sol>` | Smart contract audit |
| `/token-scan <contract>` | Token rug pull scanner |
| `/poc-bundle <target> <class> <req.json> [resp.json]` | PoC evidence bundle |
| `/verify <bundle-dir>` | Independent re-verification |

## Agents (9 specialists)

- `recon-agent` — subdomain enum + live host discovery
- `report-writer` — submission-ready reports
- `validator` — 7-Question Gate validation
- `web3-auditor` — smart contract audit
- `chain-builder` — A→B→C exploit chains
- `autopilot` — full autonomous hunt loop
- `recon-ranker` — attack surface ranking
- `token-auditor` — token rug pull scan
- `credential-hunter` — credential attack pipeline

## Critical Rules (Always Active)

1. READ FULL SCOPE before touching any asset
2. NEVER hunt theoretical bugs — "Can attacker do this RIGHT NOW?"
3. Run 7-Question Gate BEFORE writing any report
4. KILL weak findings fast
5. 5-minute rule — nothing after 5 min = move on
6. LEAD BOARD — never lose a lead
7. Impact first — test worst consequences first
