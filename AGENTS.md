# Bug Bounty Agent Toolkit — Plugin Guide

This repo is an agent-portable bug bounty plugin for professional hunting across HackerOne, Bugcrowd, Intigriti, and Immunefi.

Supports Claude Code, OpenCode, Pi Agent, Codex-style Agent Skills, and shared `.agents/skills` harnesses.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Setup AI provider (Ollama recommended, free + local)
python pentest.py setup --provider ollama --model qwen2.5:14b

# ── TWO MASTER COMMANDS (Launch everything with your preferred interface) ──
# Command 1: All Skills + Unified Web Control Center (:8000)
python pentest.py web target.com
# (Or using alias: python pentest.py ui target.com or python pentest.py all target.com --web)

# Command 2: All 217 Skills + OpenCode Studio Hub & MCP Arsenal (:8000/opencode)
python pentest.py opencode target.com
# (Or using alias: python pentest.py opencode-ui target.com or python pentest.py all target.com --opencode)

# Headless CLI Master (All 169 Skills, AI Browser, Burp, Exploit Chaining, Reports)
python pentest.py all target.com
# (Or using alias: python pentest.py run target.com)

# Individual workflows (if needed)
python pentest.py recon target.com
python pentest.py hunt target.com
python pentest.py validate "finding"
python pentest.py report target.com "finding" --platform hackerone
```

## Slash Commands

| Command | Usage |
|---------|-------|
| `/web [target]` | Dual Master 1: All skills + Unified Web Control Center (`http://127.0.0.1:8000`) |
| `/opencode [target]` | Dual Master 2: All 217 skills + OpenCode Studio Hub (`http://127.0.0.1:8000/opencode`) |
| `/all target.com` | Headless Master: All skills + AI Browser + Burp + Report |
| `/burp-logs <file_or_live>` | Professional Burp Suite log & HTTP history inspector (XML/JSON/HAR/live) |
| `/wordlist <query>` | Cognitive SecLists & Wordlist Resolver (AI/LLM, Passwords, Discovery, Fuzzing) |
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
| `/sniper <target> [--mode recon|full|web|vuln]` | Automated reconnaissance |
| `/poc-bundle <target> <class> <req.json> [resp.json]` | PoC evidence bundle |
| `/verify <bundle-dir>` | Independent re-verification |
| `/waf-padding <target> <payload>` | WAF Payload Padding (inspection blind spot) |
| `/waf-parser-bug <target> --bug-id <id> <payload>` | WAF Parser Bug exploitation |
| `/waf-semantic <target> <waf-product> <payload>` | WAF Semantic Pollution (LLM-based WAF) |
| `/waf-protocol <target> <websocket|grpc> <payload>` | WAF Protocol Bypass |
| `/waf-fingerprint <target> [profile]` | WAF Fingerprint Spoofing |
| `/waf-bypass-ladder <target> <payload>` | WAF Bypass Ladder (progressive levels) |
| `/waf-autowafuzzer <target> <payload> [--rounds N]` | Multi-Agent WAF Fuzzing |
| `/waf-rl-train <target>` | Train RL Policy Offline |
| `/waf-rag-status` | RAG Sources Status |
| `/waf-rag-add <source> <file>` | Add Local RAG Source |
| `/plan-difficulty <target> <technique>` | TDA — Difficulty-Aware Planning |
| `/mitre-tree [--technique <id>] [--tactic <name>]` | MITRE ATT&CK Task Tree |
| `/safety-check <command> <target>` | Neuro-Symbolic Safety Check |
| `/memory-write <type> <target> <key> <value>` | Write to Structured Memory |
| `/memory-read <type> <target> <key>` | Read from Structured Memory |
| `/memory-stats` | Structured Memory Stats |
| `/rag-retrieve <query>` | RAG Knowledge Retrieval |
| `/orchestrator-create <target> <role> <desc> <technique>` | Create Orchestration Task |
| `/orchestrator-next [--role]` | Next Pending Task |
| `/orchestrator-stats` | Orchestrator Stats |
| `/orchestrator-export` | Export Orchestrator State |

## Agents (10 specialists)

- `recon-agent` — subdomain enum + live host discovery
- `recon-methodology` — full operator recon playbook: passive/active subdomains, URLs, JS/params, secrets, ports (plan/dry-run/run)
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

## OpenCode Integration (Active)

- Skills: 217 curated cyber skills installed in `.opencode/skills/` from `skills_library/` (including 19 Agentic Bug Hunter skills: `abh-agentic-app-audit`, `abh-argus`, `abh-bb-methodology`, `abh-bug-bounty`, `abh-cicd-security`, `abh-client-reverse`, `abh-cloud-pentest`, `abh-credential-attack`, `abh-graphql-audit`, `abh-llm-redteam`, `abh-mcp-server-audit`, `abh-meme-coin-audit`, `abh-mobile-pentest`, `abh-report-writing`, `abh-security-arsenal`, `abh-triage-validation`, `abh-web2-recon`, `abh-web2-vuln-classes`, `abh-web3-audit`) — see `.opencode/skills/MANIFEST.json` and `docs/OPENCODE_INTEGRATION.md`
- MCP: `opencode.json` — `hunter-arsenal` (63 Kali tools) + `filesystem` + `context7` + `gh_grep` enabled; offensive MCP servers are MANUAL-gated (README first, never guess commands)
- Install/refresh everything: `.\install_agent.ps1` (one file: deps، uv، skill packs، skills، MCP validation) — flags `-CheckOnly` `-Full` `-Profiles` `-KaliTools`
