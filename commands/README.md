# Commands

Project-local slash command references under `commands/`, routed through the central `hunterai-redteam` skill (`skills/registry.json`) and wired to `pentest.py` / `bughunter`.

## Direct `pentest.py` CLI Subcommands

### Core Workflow
| Slash Command | CLI Invocation | What It Does |
|:---|:---|:---|
| `/recon` | `python pentest.py recon <target>` | Full recon pipeline — subdomain enum, live hosts, URL crawl, nuclei sweep |
| `/hunt` | `python pentest.py hunt <target>` | Vulnerability testing — IDOR, SSRF, XSS, SQLi, auth bypass, logic flaws |
| `/validate` | `python pentest.py validate <finding>` | 7-Question Gate + EvidenceCourt pre-submission gates |
| `/report` | `python pentest.py report <target> <finding>` | Submission-ready report for H1 · Bugcrowd · Intigriti · Immunefi |
| `/autopilot` | `python pentest.py autopilot <target>` | Autonomous loop: scope → recon → hunt → validate → report |

### Recon & Enumeration
| Slash Command | CLI Invocation |
|:---|:---|
| `/surface` | `python pentest.py surface <target>` |
| `/cloud-recon` | `python pentest.py cloud-recon <keyword>` |
| `/param-discover` | `python pentest.py param-discover <url>` |
| `/secrets-hunt` | `python pentest.py secrets-hunt <path>` |
| `/takeover` | `python pentest.py takeover <recon_dir>` |
| `/scan-cves` | `python pentest.py scan-cves <host>` |
| `/bypass-403` | `python pentest.py bypass-403 <url>` |

### Vulnerability Scanners (delegated via `ABHToolBridge` / `bughunter.tools.*`)
| Slash Command | CLI Invocation | What It Does |
|:---|:---|:---|
| `/cors` | `python pentest.py cors <url>` | CORS misconfig — origin reflection, null-origin, credentialed read, suffix/prefix regex bypass |
| `/crlf` | `python pentest.py crlf <url>` | CRLF / response-splitting + host-header injection (Set-Cookie canary) |
| `/nosqli` | `python pentest.py nosqli <url>` | NoSQL injection — operator auth-bypass, `$where` time-based blind |
| `/jwt-scan` | `python pentest.py jwt-scan <token>` | JWT `alg:none`, RS256→HS256 confusion, weak-secret audit (offline) |
| `/oob` | `python pentest.py oob <domain>` | Out-of-band payloads & correlation for blind SSRF/XXE/SQLi/RCE (interactsh) |
| `/sast` | `python pentest.py sast <path>` | Semgrep static analysis over source / JS bundles |
| `/domxss` | `python pentest.py domxss <url>` | Headless Chromium DOM XSS execution verification |
| `/llm-redteam` | `python pentest.py llm-redteam <endpoint>` | LLM red-team corpus — injection, jailbreak, prompt leak, exfil |

### Smart Contract & Verification
| Slash Command | CLI Invocation |
|:---|:---|
| `/web3-audit` | `python pentest.py web3-audit <contract.sol>` |
| `/token-scan` | `python pentest.py token-scan <contract>` |
| `/poc` | `python pentest.py poc-bundle <target> <class> <req.json>` |
| `/verify` | `python pentest.py verify <bundle-dir>` |

### Session & Utility
`/pickup` (`pentest.py pickup`) · `/scope` (`pentest.py scope`) · `/triage` (`pentest.py triage`) · `/remember` (`pentest.py remember`) · `/memory-gc` (`pentest.py memory-gc`) · `/arsenal` (`pentest.py arsenal`)

## Agent & BugHunter Playbook Workflows (Skill-Routed)

These slash commands are interactive agent playbooks (or `bughunter` workflows) routed via `skills/hunterai-redteam`:

- **Discovery & Recon**: `/portscan` · `/scope-aggregate` · `/screenshot` · `/monitor` · `/oss-bounty`
- **Credential & OSINT**: `/wordlist-gen` · `/osint-employees` · `/breach-check` · `/spray`
- **Analysis & Chaining**: `/chain` · `/intel` · `/oracle` · `/llm-app-audit` · `/pattern-db` · `/scorer` · `/waf-encoder` · `/dashboard`
