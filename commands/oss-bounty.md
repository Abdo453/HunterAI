---
description: Open-source GitHub bounty sweep — layered search over api.github.com for open, unassigned bounty-tagged issues, zero-reward bot noise filtered by a min-$ threshold, ranked by reward and age, with acceptance-path hints (CODEOWNERS/CONTRIBUTING) and human-blocker handoff rules. Usage /oss-bounty [--repo owner/repo] [--min-reward 250] [--limit 15]
---

# /oss-bounty

## Usage

```
/oss-bounty
/oss-bounty --repo expensify/expensify --min-reward 250 --limit 15
```

Env: `GITHUB_TOKEN` optional (higher rate limits only — no scope grants needed).

## Workflow (OP-7)

1. Sweep issues → shortlist by reward ≥ threshold and age.
2. For the top candidate, verify acceptance path BEFORE sinking time:
   - repo has external-fixer bounties paid lately? (consider `repo killer` claims)
   - needs OAuth signup / plugin install / account creation → **hand off to
     operator explicitly** ("create account at X, install Y — needed to claim").
   - unclaimed-but-in-progress is fair game with a visible timer.
3. Effort labels are triage info, not permission — a 2-line fix with a $600 tag
   beats a 3-day rewrite with $300.
4. Reward clusters change; re-verify current state each session.
