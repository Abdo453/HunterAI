# HunterAI Platform Unification — Phase 0 Migration Baseline

This document records the **Executed / Observed** pre-unification safety baseline, upstream reference provenance, isolation boundaries, and verification outputs established during Phase 0.

> All counts and statuses below reflect commands actually executed in this workspace. Unrun suites are explicitly marked as not executed.

---

## 1. Git Safety Baseline & Environment

| Property | Observed Value |
|---|---|
| Active Branch | `feat/platform-unification` |
| Base Branch | `codex/centralize-redteam-skills` |
| Base Commit SHA | `97a1cd5597c55016d610617eb9791b18b39f1132` (`feat(scanner): add native Go/Django live scan fallbacks and surface run results`) |
| Safety Baseline Tag | `baseline/pre-unification` (annotated tag at `97a1cd5597c55016d610617eb9791b18b39f1132`) |
| Phase 0 Gate Tag | `phase/0-green` (annotated tag on the Phase 0 commit) |
| Python | `Python 3.10.11` |
| Go | `go1.26.1 windows/amd64` |
| Node.js / npm | `v16.20.2` / `8.19.4` |
| Git | `2.51.0.windows.1` |

---

## 2. Pinned External Reference Clones (Read-Only, Gitignored)

Both upstream reference repositories were cloned **after** `.gitignore`, `.dockerignore`, and `pyproject.toml` isolation boundaries were verified in place.

| Upstream Repository | Local Path | Pinned Commit SHA | Commit Summary | License | Archived License Copy & SHA-256 |
|---|---|---|---|---|---|
| `https://github.com/PentesterFlow/agent.git` (`v0.3.0`) | `external/pentesterflow-agent` | `0759d873a07350a70283c9751f7d136905f777c7` | `0759d87 fix: harden UI and release packaging` | Apache-2.0 | `THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt` (`C06BB4D4E66880CA4E976974049E02AA2141FE7806AE3AE6FA9CD573FD346BE6`) |
| `https://github.com/vxcontrol/pentagi.git` | `external/pentagi` | `cffed9485aa1cca70762cd08a57ac62a80406258` | `cffed94 docs: the README links Graphiti to its public repository and names the image PentAGI runs` | MIT (AGPL-3.0 `github.com/vxcontrol/cloud` banned) | `THIRD_PARTY_LICENSES/PENTAGI_MIT.txt` (`79384D50C593FACF0D20FEA5C43037C55374A37BDDCC55C65C070BB590CE86D2`) |

Provenance and AGPL-3.0 ban policy are documented in root [`NOTICE`](../NOTICE).

---

## 3. Isolation Boundaries Established

1. **Git Isolation (`.gitignore`)**:
   - Added `/external/` under `# External upstream reference codebases (local intake/audit only — never commit)`.
   - Added `data/root_controller/.django_secret` and `data/control_settings.json` under local runtime secrets & settings ignores.
   - Verified via `git check-ignore -v`:
     - `.gitignore:97:/external/ -> external/pentesterflow-agent/LICENSE`
     - `.gitignore:97:/external/ -> external/pentagi/LICENSE`
     - `.gitignore:26:data/root_controller/.django_secret -> data/root_controller/.django_secret`
     - `.gitignore:27:data/control_settings.json -> data/control_settings.json`
2. **Container Context Isolation (`.dockerignore`)**:
   - Created root `.dockerignore` excluding `/external/`, `.git/`, `skills_library/`, `frontend/node_modules/`, `frontend/.next/`, `frontend/out/`, `data/`, `.env`, `*.env`, `__pycache__/`, `.pytest_cache/`, `logs/`, `artifacts/`, `snapshots/`, `task_logs/`, `backend/bin/`, `*.exe`, `*.sqlite*`, `*.db`.
3. **Python Packaging & Pytest Collection Isolation (`pyproject.toml`)**:
   - Added `"external*"` to `[tool.setuptools.packages.find].exclude`.
   - Added `norecursedirs = ["external", "skills_library", "node_modules", ".next", ".git"]` under `[tool.pytest.ini_options]`.
4. **Automated Enforcement (`tests/test_external_isolation.py`)**:
   - Verifies `.gitignore` + `git check-ignore`, root `.dockerignore`, `pyproject.toml` excludes, `tools/install_opencode_skills.py --check`, zero external skills loaded by `core/skill_registry.py` and `SkillMatrixViewer`, and zero `.py` / `.go` / `backend/go.mod` references to `github.com/vxcontrol/cloud`, `external.pentesterflow`, or `external.pentagi`.

---

## 4. Executed / Observed Verification Results

| Check | Command | Exit Code | Observed Output |
|---|---|---|---|
| Phase 0 Isolation Suite | `python -m pytest tests/test_external_isolation.py -q` | `0` | `5 passed in 6.71s` |
| OpenCode Skill Registry Check | `python tools/install_opencode_skills.py --check` | `0` | `[+] Project skill registry valid: 1 active skill(s)` |
| Go Backend Test Suite | `cd backend && go test ./...` | `0` | `ok artex-pro/internal/api 8.712s`; `ok artex-pro/internal/arsenal 2.507s`; `[no test files]` for `cmd/server`, `internal/agent`, `internal/database` |
| Frontend TypeScript Check | `cd frontend && npx tsc --noEmit` | `0` | Clean (0 TypeScript errors; transient `frontend/tsconfig.tsbuildinfo` removed after check) |
| Representative Core Pytest Baseline | `python -m pytest tests/test_skills_catalog.py tests/test_action_evaluator_and_policy.py tests/test_artifact_secret_sanitization.py tests/test_agentic_bug_hunter_skills.py -q` | `0` | `20 passed in 3.50s` |

### Scope Notes
- Total test files present under `tests/test_*.py` at baseline: `353` files (observed via directory listing).
- Full 353-file Python test suite was **not executed** in Phase 0; only the checks recorded in the table above were executed and observed.
