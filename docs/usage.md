# HunterAI OS — Operator Usage Guide & API Reference

HunterAI can be operated via the interactive Terminal UI (HunterOS), headless REST/FastAPI endpoints, or programmatic Python APIs.

---

## 1. Quick Start

### Starting the HunterOS Terminal UI
```bash
python -m ui.tui.hunter_os --target https://target.com --scope target.com,*.target.com
```

### Starting the Unified Web Dashboard
```bash
uvicorn ui.web.dashboard:app --host 0.0.0.0 --port 8080 --reload
```
Navigate to `http://localhost:8080` to access the live dashboard with real-time SSE stream, metrics, and pause/resume/snapshot controls.

---

## 2. Running Verification & Certification

### Run the 10-Step Phase 17 E2E Suite
```bash
python tests/test_e2e_phase17.py
```

### Run the Master Integration Harness (15 Gates + Golden Trace GT-001 to GT-017)
```bash
python validate_full_integration.py
```

---

## 3. Programmatic Usage

### Launching an Assessment with Claude Extended Thinking
```python
from core.cognitive import ClaudeThinkingEngine, ThinkingMode
from hunter_ai.agents import AgentGraph

# 1. Initialize Thinking Engine with Extended Mode
thinking_engine = ClaudeThinkingEngine(mode=ThinkingMode.EXTENDED)
system_steering = thinking_engine.generate_system_prompt_steering("SecurityStrategist")

# 2. Run Autonomous Assessment Loop
graph = AgentGraph(target="https://target.com", ollama_host="http://127.0.0.1:11434")
results = await graph.run_engagement(max_cycles=5)

# 3. Export Verified Report
from core.report_engine import ReportEngine
re = ReportEngine(target="https://target.com", scope=["target.com"])
report = re.build(
    findings=results["findings"],
    attack_surface=results["surface"],
    evidence_summary={"traces": len(thinking_engine.trace_history)},
    request_summary={"total": len(results["trace"])},
)
print(re.to_markdown(report))
```

---

## 4. REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /api/status` | `GET` | Returns real-time system state, active agents, and surface metrics |
| `GET /api/metrics` | `GET` | Returns counts for domains, live hosts, endpoints, APIs, and findings |
| `GET /api/events` | `GET` | Retrieves recent activity log items |
| `GET /api/stream/events`| `GET` | Server-Sent Events (SSE) live activity stream |
| `POST /api/control/pause` | `POST` | Suspends active agent turns |
| `POST /api/control/resume`| `POST` | Resumes agent execution |
| `POST /api/control/snapshot` | `POST` | Generates a persistent SHA-256 state checkpoint |
