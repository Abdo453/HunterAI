---
description: Cross-target root-cause pattern memory (hash-chained, tamper-evident). After a VALIDATED finding write the pattern (class + stack files + signature + bypass that worked, NO target names); before a new engagement replay past patterns against the stack fingerprint. Usage /pattern-db add|query|list|verify
---

# /pattern-db

## Usage

```
/pattern-db add --class idor --stack "flask,uuid,postgres" \
    --sig "detail/{uuid} missing ownership check" --bypass "second-object-id" \
    --evidence artifacts/t1/evidence/e1/
/pattern-db query --stack "flask,jwt" --classes "idor,auth-bypass"
/pattern-db list [--class idor]
/pattern-db verify     # hash-chain integrity check
```

## Discipline

- Store ROOT CAUSE + the bypass that actually worked — never store victim names.
- Call it right after the 7-Question Gate passes (validated only).
- On each new mission step 0: `query --stack <fingerprint>` → replay known
  patterns before cold exploration.
- Ledger is hash-chained (`data/memory/patterns.jsonl`); `verify` before any
  hand-off or evidentiary reuse.
