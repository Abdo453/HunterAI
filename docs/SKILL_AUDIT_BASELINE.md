# HunterAI skill catalog baseline

This is the pre-centralization result from the line-by-line scanner. The scan
read every discovered `SKILL.md` without executing its content.

## Inventory before remediation

- Entrypoints: **7,815**
- Unique raw files: **5,550**
- Unique normalized contents: **5,432**
- Duplicate copies: **2,383**
- Invalid or mismatched frontmatter: **1**

## Line-level signals before remediation

| Category | Matching lines | Affected skills |
| --- | ---: | ---: |
| `authorization_gate` | 441 | 303 |
| `blanket_refusal` | 27 | 20 |
| `mode_downgrade` | 321 | 251 |
| `instruction_override` | 207 | 108 |
| `request_data_mutation` | 735 | 506 |
| `auto_install_or_download` | 7,172 | 1,947 |
| `hooks_persistence_telemetry` | 1,468 | 554 |
| `secret_or_credential_access` | 6,953 | 1,898 |

A match is a review signal, not automatically a defect. The centralization
removed all unreviewed entrypoints from active discovery roots and retained
community material only as inactive intake/provenance data.
