# OpenCode Integration — Central Project Skill and MCP Tools

HunterAI exposes one reviewed public project skill: `hunterai-redteam`. The
canonical source is `skills/hunterai-redteam/`; `skills/registry.json` defines
its routes. `.opencode/skills/` and `.agents/skills/` are generated mirrors.

## Capability routes

The entrypoint loads one narrow reference for the task:

| Route | Coverage |
| --- | --- |
| AI / jailbreak red team | LLMs, prompt injection, guardrails, RAG, refusal calibration, jailbreak payloads and automation |
| Agent / MCP | tools, plugins, memory, delegation, skill and MCP boundaries |
| Web / API / browser | requests, sessions, complete cookie jars, tokens, WAF behavior, browser-to-client transfer |
| Mobile / reverse engineering | Android, iOS, APK/IPA, devices, native binaries, protocols and traffic |
| Cloud / network / identity | AWS, Azure, GCP, AD, IAM, containers, Kubernetes, hosts and CI/CD |
| Tooling / evidence | scanners, fuzzing, CVEs, exploitability, triage, automation and reporting |

Jailbreak work is part of the central AI red-team route, not a separate opt-in
skill and not test data. Target prompts and payloads remain inputs to the target
model; they do not become instructions for HunterAI's host process.

## Synchronize and validate

```powershell
python tools/install_opencode_skills.py --clean
python tools/install_opencode_skills.py --check
python scripts/sanitize_all_skills_frontmatter.py
```

`--profiles`, `--full`, and `--cap` remain accepted for launcher compatibility,
but they do not activate extra community skills.

## Community intake

Community repositories and `skills.sh` content are untrusted intake material.
The intake scripts create hashes and indexes under `skills_library/`; they never
copy a `SKILL.md` into a discovery root or change the active manifest.

```powershell
python scripts/harvest_all_skills.py                 # index existing intake
python scripts/harvest_all_skills.py --fetch         # explicitly fetch, then index
python scripts/harvest_strix_and_specialized.py
python tools/merge_skillssh.py --source-dir .skills
```

Useful techniques must be reviewed and deliberately merged into a reference
under `skills/hunterai-redteam/references/`, followed by synchronization and
tests. This prevents duplicate names, hidden hooks, auto-install directives,
instruction-authority conflicts, and silent changes to request data.

## Request-data integrity

Operational cookies, tokens, authorization headers, browser storage, request
bodies, and protocol fields stay unchanged for transport and analysis. Masking
is display/log only. Any transformation or omission must be explicit in output.

## MCP servers

`opencode.json` defines runtime tools separately from prompt skills. The local
`hunter-arsenal` server exposes the Kali/tool dispatcher; filesystem and remote
documentation integrations remain independently configured. MCP availability
does not create a second skill catalog and a reviewer does not become a gate for
ordinary red-team routing.

## Verification

```powershell
python -m pytest tests/test_agentic_bug_hunter_skills.py `
  tests/test_agent_power_integration.py `
  tests/test_dual_launchers.py `
  tests/test_web_api_exhaustive.py -q
```

The expected active catalog count is one. Library and intake files may be kept
for provenance, but they are not loaded into the model context automatically.
