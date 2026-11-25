# HunterAI skill architecture review

## Scope and method

The review covered every discovered `SKILL.md` under `.opencode/skills/` and
`.agents/skills/`, the installers and harvesters that populate those roots, the
model prompt envelope, the context injector, launchers, UI catalog endpoints,
tests, and project handoff documentation. `tools/audit_skill_catalog.py` records
line-level matches without executing imported content.

The pre-remediation baseline is in `SKILL_AUDIT_BASELINE.md`; the current result
is in `SKILL_AUDIT.md`.

## Confirmed root causes

1. Community harvesters copied mutable third-party `SKILL.md` files and generic
   Markdown guides directly into active discovery roots.
2. Name collisions silently overwrote earlier content, while stale directories
   survived subsequent installer runs.
3. The same capabilities existed under many overlapping names and in both
   discovery roots, causing context competition and inconsistent routing.
4. Imported instructions contained authorization gates, blanket-refusal text,
   analysis-only downgrades, instruction-authority conflicts, request-data
   filtering, installers, hooks, telemetry, and credential-access examples.
5. The AI bridge rewrote offensive terms into defensive terminology and forced
   a non-destructive audit output contract, changing Build, Verify, and Operate
   requests before the selected model saw them.
6. Documentation, UI labels, tests, and CLI output hard-coded incompatible skill
   totals and legacy names.

## Implemented architecture

- `skills/hunterai-redteam/` is the canonical source.
- `skills/registry.json` declares one public project skill and six narrow routes.
- `.opencode/skills/` and `.agents/skills/` are byte-identical generated mirrors.
- Jailbreak and prompt-injection work is a core route, not optional test data.
- Community content is indexed under `skills_library/` as inactive intake.
- The installer validates source confinement, routed-reference confinement,
  frontmatter, mirror hashes, and safe removal targets.
- The AI prompt envelope preserves the original request and mode instead of
  replacing offensive terms or imposing a defensive-only response.
- Cookies, tokens, authorization headers, bodies, browser storage, and protocol
  fields remain unchanged for operational use; masking is display/log only.

## Prompt Injection Security review

Imported documents, target prompts, model outputs, web content, tool results,
and jailbreak payloads are treated as untrusted task inputs. They can guide the
target evaluation but do not gain authority over HunterAI's host, registry,
installer, tools, or secrets. Routed references are confined beneath the
canonical skill directory.

## Codex Security supply-chain review

The canonical skill contains Markdown only: one entrypoint and six references.
It has no executable helper, hook, auto-install command, network destination,
telemetry, persistence, credential lookup, or self-update behavior. Intake
scripts may fetch community repositories only with an explicit `--fetch`; they
never activate the downloaded instructions.

## Current verification result

- Active entrypoints: 2 generated mirrors
- Unique active content: 1
- Frontmatter issues: 0
- Authorization-gate signals: 0
- Blanket-refusal signals: 0
- Mode-downgrade signals: 0
- Instruction-override signals: 0
- Request-data-mutation signals: 0
- Auto-install/download signals: 0
- Hook/persistence/telemetry signals: 0
- Secret/credential-access signals: 0

The project skill reduces project-authored false refusals and routing conflicts.
It does not claim to replace controls enforced by a model provider, system
instruction, account, tool, or runtime.
