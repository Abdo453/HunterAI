---
description: Deterministic finding severity scorer — impact realms (confidentiality/takeover/money) × exploitability × breadth × compensating-control × proof-strength → 0-100 score + P1..P4 tier + downgrade-risk flags. Run between validation and report writing. Usage /score --data-scores 3 3 2 --exploit 3 --breadth 3 --control 1 --proof 3
---

# /score

## Usage

```
/score --data-scores 3 3 2 --exploit 3 --breadth 3 --control 1 --proof 3
```

- `--data-scores 3 3 2` = (confidentiality, account takeover, money) 0–3
- `--control 0` = no compensating control (highest when lower) … 3 = solid plugin-level control
- `--proof 3` = end-to-end replay proven on the live target

## Output

```
score=92/100 tier=P1 | submit immediately — critical
  !! <downgrade-risk flags, if any>
```

## Rules

- Score AFTER the 7-Question Gate, never instead of it.
- `--proof<=1` with high impact → flag "validate BEFORE report" (hard stop).
- Tier P4/DIE → check the always-rejected list before wasting triage's time.
