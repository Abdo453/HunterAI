# HunterAI skill catalog audit

Generated: `2026-11-25T16:16:58.734083+00:00`

The audit reads every discovered `SKILL.md` line by line. It does not execute skill content.

## Inventory

- Entrypoints: **2**
- Unique raw files: **1**
- Unique normalized contents: **1**
- Duplicate copies: **1**
- Invalid or mismatched frontmatter: **0**

## Line-level signals

| Category | Matching lines | Affected skills |
| --- | ---: | ---: |
| `authorization_gate` | 0 | 0 |
| `blanket_refusal` | 0 | 0 |
| `mode_downgrade` | 0 | 0 |
| `instruction_override` | 0 | 0 |
| `request_data_mutation` | 0 | 0 |
| `auto_install_or_download` | 0 | 0 |
| `hooks_persistence_telemetry` | 0 | 0 |
| `secret_or_credential_access` | 0 | 0 |

## Interpretation

A signal is not automatically a defect. Quoted test payloads, warnings, and examples can match the same words as operating instructions. The JSON report preserves file, line, and surrounding text so reviewers can distinguish data from reachable behavior.

The active catalog should be generated from the reviewed project source under `skills/hunterai-redteam/`. Community packages remain intake material and must not be copied directly into discovery roots.
