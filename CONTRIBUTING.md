# Contributing to HunterAI

Thank you for your interest in contributing to HunterAI!
HunterAI is built on an **Evidence-Driven Security Testing Platform** philosophy.
To maintain the mathematical rigor, safety invariants, and 0.0% false-positive standard of the project, all contributions must adhere to the rules in this guide.

---

## 1. The Core Philosophy

> **"Every security claim has a provenance."**
> An AI model cannot declare a finding true. Truth is established exclusively through deterministic verification, tripartite differential analysis, and independent re-testability.

---

## 2. Inviolable Plugin Acceptance Criteria

Before submitting a new probe, sensor, or assessment plugin, verify that your contribution meets all 5 acceptance rules:

1. **Air-Gapped Network Execution**:
   - Plugins are **strictly prohibited** from opening raw sockets (`socket`, `requests`, `httpx`, `urllib`) directly.
   - All actions must be emitted as a `ProposedAction` to the Policy Engine and executed exclusively by the authorized Executor upon issuance of an `ExecutionPermit`.

2. **Mandatory Capability Declarations**:
   - Plugins must specify their exact required capability tokens (e.g. `CAP_READ_DISCOVERY` or `CAP_PROPOSE_TEST`).
   - Any state-mutating (`POST`/`PUT`/`DELETE`) action must be marked with `ActionRiskLevel.HIGH` and route through the `ApprovalQueue`.

3. **Explicit Negative Controls**:
   - A plugin cannot rely on single-probe reflection.
   - Probes must implement the tripartite test equation:
     `Baseline ≈ Harmless Control` AND `Active Test ≠ Harmless Control`.

4. **1-Click Standalone Replayability**:
   - Findings produced by your plugin must be freezable by `ReplayLab` into standalone self-contained reproduction scripts (`replay.py`) requiring zero external AI dependencies.

5. **Resource Budget Enforcement**:
   - Plugins must specify their maximum request budget (e.g. `max_probes = 10`). Unbounded fuzzing loops are rejected at review.

---

## 3. Development & Verification Workflow

1. Clone the repository and install development dependencies:
   ```bash
   git clone https://github.com/Abdo453/HunterAI.git
   cd HunterAI
   pip install -r requirements.txt
   ```

2. Run the automated test suites:
   ```bash
   python -m pytest tests/test_v4_evidence_os.py -v
   python -m pytest tests/test_v3_provenance_platform.py -v
   python -m pytest tests/test_v2_deep_architecture.py -v
   ```

3. Run the Pre-Kali Certification Pipeline (all 15 gates must pass):
   ```bash
   python certify.py
   ```

4. Run the Validation Arena Benchmark (must maintain 0.0% False Positive Rate):
   ```bash
   python run_validation_arena.py
   ```

---

## 4. Code Standards & Style

- Type annotations (`typing`) are mandatory on all public methods and data structures.
- Use Python 3.10+ dataclasses with explicit defaults.
- Always sanitize output strings with `SecretSanitizer` before logging.
- Preserve backward compatibility across the unified `EvidenceOS` model.
