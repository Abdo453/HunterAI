# HunterAI Pre-Kali Test Baseline

> **Current status (2026-10-28):** the hermetic suite is **2,336 passed, 1 skipped, 0 failed**; the opt-in live NVD test (1 passed) and OSV test (2 passed) ran separately. One test (`tests/test_enterprise_casm.py::test_orchestrator_passive_profile_and_diff`) requires a local Ollama server to be running — it aborts with `status=aborted` when the AI preflight gate cannot reach `127.0.0.1:11434`. See `REPOSITORY_ASSESSMENT.md` §Test baseline. The dated baseline below is kept as historical evidence and is not the current count.

- **Date:** 2026-09-12
- **Environment:** Windows Host / Python 3.11.9
- **Baseline Test Suite Results:** 38 / 38 Passed (100%)
- **Runtime:** ~159 seconds
- **Active Suites:**
  1. `tests/test_evidence_graph_and_lab_mode.py` (5 passed)
  2. `tests/test_program_intelligence_and_triad.py` (6 passed)
  3. `tests/test_enterprise_casm.py` (9 passed)
  4. `tests/test_artifact_based_recon.py` (4 passed)
  5. `tests/test_full_computer_agent.py` (14 passed)
- **Local AI Model Baseline:**
  - `WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest`: Active & verified
  - `xploiter/pentester:latest`: Active & verified
  - `qwen2.5-coder:14b`: Active & verified
