# Agent & Integration Systems

> **Status:** Integration of Project Muteki concepts into HunterAI — completed.
> **License:** All code here is original (MIT), implementing the same architecture and concepts **without** copying any code from Muteki (licensed under AGPL-3.0) to preserve license compatibility with this project.

This document covers the seven added systems and how to use them.

---

## 1. CLI Engine Workers — `engines/`

Runs external CLI agents (Claude Code / Codex / OpenCode) as **Workers** alongside local models under HunterAI governance.

| File | Role |
|---|---|
| `engines/types.py` | Shared types: `LaunchContext`, `EngineResult`, `StreamStep` |
| `engines/base.py` | Abstract `EngineDriver` — argv contract, output normalization, health checks |
| `engines/drivers/` | Concrete drivers: `claude`, `codex`, `opencode` |
| `engines/registry.py` | Registry and personal profile/endpoint wrappers |
| `engines/runner.py` | Asynchronous subprocess runner (streaming, timeouts, cancellation) |
| `engines/worker.py` | `EngineWorker` — integrates the engine with `ScopeGuard` and `PolicyGate` |
| `engines/selfcheck.py` | End-to-end health check (single-turn live probe) |

### Security Properties
- **Secrets via `env`, never `argv`** (kept out of the process table).
- **`build_worker_env`** forwards only a minimal base environment rather than inheriting the full host environment.
- Every task passes through **ScopeGuard** (is the target in scope?) and **PolicyGate** (is the action category authorized?) — **fail-closed**.
- Drivers advertise capabilities (`secure_prompt_transport`, `offline_web_isolation`, etc.) so the scheduler selects a matching engine.

### Usage (REST)
```http
GET  /api/engines                 # List engines and capabilities
POST /api/engines/selfcheck       # {"engines": ["claude"]} (optional)
POST /api/engines/run             # Run a single task
```
Example `POST /api/engines/run` payload:
```json
{
  "engine": "claude",
  "target": "https://lab.example.com",
  "prompt": "Inspect /login for SQL injection",
  "in_scope": ["lab.example.com"],
  "model": "claude-sonnet-4-5",
  "web_access": true
}
```

### UI
Web UI tab **"CLI Engines"**: lists registered engines, runs self-checks, and provides a task execution form.

---

## 2. CTF Flag Pipeline — `flags/`

- `extractor.py`: Extracts flag candidates from raw output using explicit templates, common patterns (`flag{}`, `htb{}`, `ctf{}`, etc.), and context signals that raise or lower confidence.
- `store.py`: Store with SHA-256 **deduplication**, ranking, and **false-positive** filtering.
- `service.py`: Unified service — `ingest()` → validate → store, plus `progress()` for **multi-flag** tracking.

Integration: `EngineWorker` automatically extracts flags from engine output when `flag_format` is configured in `EngineWorkerConfig`.

```python
from flags import FlagService
svc = FlagService(flag_format=r"flag\{[a-f0-9]{32}\}", expected_count=3)
svc.ingest(monitor_output)
if svc.progress().complete:
    ...
```

---

## 3. Run Control & Cost Budget — `core/run_control.py`, `core/cost_budget.py`

### Run Controller
Replaces untracked `asyncio.create_task` calls with managed runs supporting immediate **pause / resume / stop** and cooperative checkpoints (`checkpoint()`).

```http
GET  /api/runs                          # ?active_only=true&kind=mission
POST /api/runs/{id}/pause|resume|stop
```

### Cost Budget
`CostController` tracks per-model pricing (USD per 1M tokens) and enforces a **circuit breaker**:

```http
GET  /api/budget       # Current spend snapshot and limits
POST /api/budget       # {"per_run_usd": 5.0, "per_day_usd": 20.0}
```
Every LLM invocation goes through `charge_call()`; the scheduler checks `is_over_budget(scope)` before each new call (fail-closed when exceeded).

---

## 4. CTF Platform Integrations — `ctf/`

- `base.py`: Unified `CTFPlatform` interface (`auth` / `list_challenges` / `submit`).
- `ctfd.py`, `rctf.py`, `gzctf.py`: Clients for CTFd, rCTF, and GZCTF.
- `throttler.py`: **Anti-ban rate limiter** (minimum interval, rate window, `Retry-After` handling).
- `bridge.py`: `FlagSubmitter` — submits candidates from `FlagService` to the platform, updates status (`accepted`/`wrong`/`duplicate`/`throttled`), and stops early once the target count is reached.

```python
from ctf import CTFdPlatform, FlagSubmitter
from flags import FlagService
svc = FlagService(expected_count=1); svc.ingest(text)
sub = FlagSubmitter(svc, CTFdPlatform(url, token), challenge_title="Web 100")
summary = sub.submit_pending()   # Automatically respects cooldown
```

---

## 5. Docker & Packaging — `Dockerfile`, `docker/`, `pyproject.toml`

- **`Dockerfile`**: Web image (Python 3.11 + Playwright + nmap) — fixes `docker-compose build`.
- **`docker/worker.Dockerfile`**: Lightweight worker with core tools.
- **`docker/worker-kali.Dockerfile`**: Full **Kali Rolling** worker image.
- **`pyproject.toml`**: `hunterai` package definition with `hunter` and `hunterai` entry points.

```bash
docker compose up --build                  # Web only
docker compose --profile worker up         # + lightweight worker
docker compose --profile worker-kali up    # + Kali worker
```

---

## 6. Extensions System — `extensions_ext/`

Extensions with a **strict manifest (fail-closed)**, **trust levels**, and **restricted permissions**.

| File | Role |
|---|---|
| `manifest.py` | Parses and validates `plugin.json` (rejects invalid permissions, names, or paths) |
| `trust.py` | Evaluates trust (`HIGH`/`MEDIUM`/`LOW`/`NONE`) — enforced before enabling |
| `loader.py` | Isolated loader + `HostAPI` enforcing permission checks on every call |
| `registry.py` | Install, enable, disable, and list operations |

**Allowed permissions:** `read_workspace`, `write_workspace`, `call_llm`, `run_tool`, `network`, `read_env` — unknown permissions are rejected. Unauthorized calls or path traversal attempts raise `PermissionDenied`.

```python
from extensions_ext import ExtensionRegistry, TrustLevel
reg = ExtensionRegistry(min_trust=TrustLevel.LOW)
reg.install("path/to/ext"); reg.enable("my-ext")
```

---

## 7. Shared Evidence Graph — `core/shared_evidence.py`

Unifies multi-agent collaboration (replacing duplicated blackboards):
- **Facts**: Verified findings merged by `confidence` (highest confidence wins).
- **Intents**: Planned actions that prevent agents from duplicating work.
- **Locks**: Thread-safe resource locks (single winner per lock).
- **InsightBus**: Real-time pub/sub feed for newly discovered insights.

```python
from core.shared_evidence import SharedEvidenceGraph, Fact
g = SharedEvidenceGraph(min_confidence=0.5)
g.add_fact(Fact(key="vuln:sqli:/login", value="confirmed", source="nmap", confidence=0.9))
if g.acquire_lock("target:web1", "worker-a"): ...
```

---

## Tests

All systems are covered by **120 passing tests**:

```bash
pytest tests/test_engines_cli_workers.py tests/test_flags_pipeline.py \
       tests/test_run_control_and_budget.py tests/test_ctf_platforms.py \
       tests/test_ctf_flag_bridge.py tests/test_extensions_system.py \
       tests/test_shared_evidence_graph.py
```

---

## Deduplication Plan (Scoped — Not Yet Executed)

The repository has **pre-existing** duplication unrelated to the additive systems above:

1. **4 orchestration layers:** `hunter_ai/brain/orchestrator_workers.py`, `core/multi_agent/orchestrator.py`, `core/swarm/swarm_coordinator.py`, `core/system/task_scheduler.py`.
2. **3 dashboards:** `ui/web/app.py`, `ui/web/dashboard.py`, `ui/tui/hunter_os.py`.
3. **2 skill frameworks:** `agents/skills/`, `skills/`.

**Recommendation:** Adopt the new `core/shared_evidence.py` as an optional shared knowledge layer first, then consolidate the orchestration layers incrementally while running all 185 test files after each step. **This refactor carries regression risk — each layer requires manual review and was intentionally not automated to avoid breaking existing behavior.**
