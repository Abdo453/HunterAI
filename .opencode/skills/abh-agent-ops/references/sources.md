# Sources — Agent Ops Field Research

Links mined on 2026-11-10. Kept for provenance and re-verification when
upstream projects change.

| Source | What was taken |
|---|---|
| https://github.com/awarexone/Agentic-Bug-Hunter (AGENTS.md) | Command set: `/intel`, `/scope-aggregate`, `/chain`, credential pipeline (`/wordlist-gen`, `/osint-employees`, `/breach-check`, `/spray`), tools `waf_encoder.py` / `waf_response_analyzer.py` / `multipart_mutator.py` / `eol_check.py`, hunt-memory architecture (`pattern_db.py` cross-target learning, `audit_log.py` rate limiter + circuit breaker), 17 hunting rules |
| https://github.com/Likhithsai2580/AI-Bug-Bounty | Multi-agent parallel scanner, plugin-per-vuln-class architecture, vulnerability scorer, monitor mode (continuous intervals), notification channels (Telegram/Discord opcional), NVD integration |
| https://dev.to/hermesxclawctrl/how-my-ai-agent-hunts-triages-and-claims-real-bug-bounties-step-by-step-3nin | OSS GitHub bounty triage flow: layered `api.github.com/search/issues` filtering (bounty=$ + unclaimed + zero-reward skip), acceptance-path analysis before sinking time, human-blocker handoff pattern, honest reward clusters (Expensify ~$250, UnsafeLabs $600-800) |
| https://www.bugcrowd.com/blog/what-i-learned-building-ai-agents-for-bug-bounty-hunting/ | Lesson absorbed into discipline block: agents need hard rate discipline and human-bit gates on state-changing actions |
| https://xhack.io/blog/xhack-ai-agent-for-bug-bounty | Marketing-page only; no portable technique worth porting |
| https://skillsllm.com/skill/bug-hunter | Index page only (skill listing directory); no unique content |
| https://www.wiz.io/bug-bounty-masterclass/foundations/ai-bug-bounty | Educational framing; concepts already covered by `abh-bb-methodology` + `abh-llm-redteam` |

## Overlap map (what NOT to duplicate here)

- Spray modes / lockout tactics / breach-check pipeline → `abh-credential-attack`
- 5-phase hunting workflow + developer psychology → `abh-bb-methodology`
- LLM/AI feature testing (ASI01-ASI10) → `abh-llm-redteam`
- Exploit chain building → `agents/chain-builder` + `/chain` command family in pentest.py
- Orchestrator/memory primitives → pentest.py `memory-*`, `orchestrator-*`, `rag-retrieve`

=> This skill only holds the operational glue the others don't: OP-1..OP-7.
