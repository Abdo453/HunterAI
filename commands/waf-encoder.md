---
description: WAF payload encoding matrix + response-pair classification. First generate every encoding transformation of a payload (URL 2x, unicode, case, comment-split, newline/tab fusion, b64, hex...); then feed response pairs back into the analyzer to identify WHERE the blind spot is (edge block vs backend parser vs encoded-only). Usage /waf-encoder "<payload> [--fire https://t/x?q=] | /waf-analyzer --baseline 200,120 --variant 403,48"
---

# /waf-encoder · /waf-analyzer

Backing scripts: `scripts/waf_encoder.py`, `scripts/waf_response_analyzer.py`
(upstream ports from awarexone/Agentic-Bug-Hunter, stdlib-only).

## Usage

```
/waf-encoder "<script>alert(1)</script>"                    # dump 18 variants
/waf-encoder "' UNION SELECT 1,2,3--" --fire https://t/x?q= # probe each variant
/waf-analyzer --baseline 200,120 --variant 403,48           # classify the pair
/waf-analyzer --compare baseline.html variant.html          # body-level diff
```

## Ladder integration

analyser verdict → next move:

| verdict | next |
|---|---|
| NO FILTER | grep payload in content, escalate to real proof |
| edge WAF block | fire full encoder matrix; then `/waf-bypass-ladder` L1→L7 |
| backend parser rejection (400) | probe parser quirks: HPP, JSON strictness, unicode-fold |
| partial / absorbed | find surviving chars → polyglot re-encode |

Fire mode is an evidence probe: one request per variant, 300ms delay.
