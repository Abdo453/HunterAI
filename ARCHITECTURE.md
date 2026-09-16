# HunterAI — The Unified Epistemic Cognitive Architecture
## Autonomous Security Investigation Operating System

---

### 🌟 Architectural Overview
HunterAI is an **Autonomous Security Investigation Operating System (Evidence OS)**. It departs completely from traditional vulnerability scanners:
- **Scanners** execute rigid payload checklists and report subjective heuristic percentages (e.g. "Confidence: 65%").
- **HunterAI** models the target application's state, identity, and business logic, formulates competing hypotheses, schedules experiments via Active Information Gain, evaluates counterfactual evidence through an Adversarial Evidence Court, and confirms findings only when backed by reproducible physical proof ($E_2 \rightarrow E_5$).

```text
                                  HUNTERAI CORE
                                        │
    ┌───────────────────────────────────┼───────────────────────────────────┐
    ↓                                   ↓                                   ↓
[PERCEPTION & SENSORS]         [REASONING & WORLD MODEL]         [EVIDENCE & GOVERNANCE]
  • Sensory Triad (Burp/Play/AST)    • Security Digital Twin           • Adversarial Evidence Court
  • Unified Tool Normalizer          • IdentityGraph & AuthZ Matrix    • Forensic Tiers (E0 -> E5)
  • Causal Wire Lineage              • Business Logic State Machine    • Machine Constitution (P0-P4)
                                     • Attack Opportunity Graph        • Sealed Replay Bundles
```

---

## 🏛️ The 5 Cognitive Layers

```text
                             HUNTERAI PLATFORM
                                     │
┌────────────────────────────────────┴────────────────────────────────────┐
│ 1. PERCEPTION PLANE (Sensory Triad & Ingestion)                         │
│    • BurpSensor (HTTP wire reality, response deltas, repeater streams)   │
│    • BrowserWorker / Playwright (DOM mutations, forms, UI intent)        │
│    • CodeIntel (AST parsing, route decorators, source-to-sink dataflows) │
│    • Unified Tool Normalizer (Nuclei, Subfinder, Httpx, Katana, FFUF)    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Canonical SIR Signals (E0/E1)
┌────────────────────────────────────▼────────────────────────────────────┐
│ 2. WORLD MODELING PLANE (Digital Twin & Identity)                       │
│    • Security Intermediate Representation (SIR Graph)                   │
│    • IdentityGraph (Anonymous, User A, User B, Admin, Support contexts)  │
│    • Authentication & Business Logic State Machine                      │
│    • Attack Opportunity Graph (Multi-vector opportunity mapping)         │
│    • Blind-Spot & Negative Space Ledger (Explicit tracking of unknowns) │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ High-Entropy Opportunities
┌────────────────────────────────────▼────────────────────────────────────┐
│ 3. EPISTEMIC REASONING PLANE (Hypothesis & Planning)                     │
│    • Bayesian Hypothesis Engine (Priors, Likelihoods, Posteriors)       │
│    • Analysis of Competing Hypotheses (ACH - Pitting H1 against noise)  │
│    • Active Information-Gain Scheduler (Score = ΔI / Cost)              │
│    • Closed-Loop Re-Investigation Engine (Inconclusive -> New Research) │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Admissible Controlled Experiments
┌────────────────────────────────────▼────────────────────────────────────┐
│ 4. EXECUTION PLANE (Differential & Mutation Testing)                   │
│    • Response Differential Engine (Status, Length, Semantic Data Leaks) │
│    • State Mutation Tester (Step-skipping, post-refund re-use)          │
│    • Race Condition Engine (Parallel burst requests, double spend)      │
│    • Governed Tool Adapters (Air-gapped execution)                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Empirical Artifacts & Nonces
┌────────────────────────────────────▼────────────────────────────────────┐
│ 5. ADVERSARIAL ADJUDICATION PLANE (Evidence Court & Provenance)         │
│    • Adversarial Tribunal:                                              │
│      Finder → Advocate → Adversarial Prosecutor → Verifier → Justice    │
│    • Security Finding Contracts (26 Web2 Classes, N >= 2 Repro, Zero LLM│
│    • Forensic Evidence Levels: E0 (Obs) -> E2 (Repro) -> E5 (Sealed)   │
│    • Tamper-Resistant Replay Lab (1-click standalone replay.py)         │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
┌────────────────────────────────────┴────────────────────────────────────┐
│ 0. INVIOLABLE MACHINE CONSTITUTION & GOVERNANCE LAYER                   │
│    • P0: Zero Out-of-Scope Egress (RFC1918 / Cloud Metadata 169.254.x)   │
│    • P1: Zero Unapproved State Mutations in Production                  │
│    • P2: Zero Plaintext Secret Disclosure                               │
│    • P3: Zero Unverifiable / Hallucinated Claims                        │
│    • P4: Principle of Least Privilege & Emergency Kill Switch           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Core Invariants & Operating Guarantees

### 1. Zero LLM Heuristic Confirmation
An LLM never has the authority to declare a vulnerability "CONFIRMED". LLMs function solely as **Hypothesis Generators**. A vulnerability can only be confirmed if:
1. It satisfies a formal **Security Finding Contract**.
2. It passes independent verification with deterministic arithmetic nonces or control comparisons.
3. It survives the cross-examination of the **Adversarial Evidence Prosecutor** in `EvidenceCourtV2`.
4. It is deterministically reproduced at least $N \ge 2$ times.

### 2. The Golden Rule of Differential Testing
A status code of `200 OK` on an unauthenticated or unauthorized request is **NEVER** flagged as an authorization or authentication bypass unless private/tenant data present in the authenticated baseline leaks into the unauthorized response. Benign public pages and error responses returning `200 OK` are strictly shielded to maintain a **0.0% False Positive Rate (FPR)**.

### 3. Attack Surface vs Attack Opportunity
HunterAI distinguishes between passive surface and active opportunity:
- **Surface**: `GET /api/orders/42`
- **Opportunity Matrix**:
  - `IDOR/BOLA`: Substitute ID with Tenant B object.
  - `AuthZ Matrix`: Replay with Anonymous, User A, User B, Admin.
  - `Mass Assignment`: Inject `{"status": "paid", "discount": 100}` on `PUT`.
  - `State Mutation`: Attempt refund, then replay coupon redemption.
  - `Race Condition`: Fire concurrent checkout requests to test double-spending.

### 4. Radical Epistemic Transparency (Negative Space Ledger)
HunterAI never implies security from the absence of findings:
$$\text{No Findings Reported} \ne \text{Application is Secure}$$
Instead, it maintains a **Negative Space Ledger** explicitly documenting every unprobed route, parameter, and state transition alongside the causal reason (`SKIPPED_POLICY_RESTRICTION`, `SKIPPED_AUTH_MISSING`, `OPERATOR_APPROVAL_REQUIRED`).

---

## 🚀 CLI Commands & Subsystems

HunterAI provides a comprehensive unified CLI (`python cli/hunter_cli.py`):

| Subsystem | Command | Purpose |
| :--- | :--- | :--- |
| **Auth Reasoning** | `hunter auth-audit --target <url>` | Full 19-archetype state machine and session audit |
| **Sensory Wire** | `hunter sensor-status` | Tri-sensor status (Browser, Burp, Code) |
| **Investigation** | `hunter investigate-loop --target <url>` | Closed-loop hypothesis-to-verdict cycle |
| **Evidence Court** | `hunter court-status` | Deliberation records and prosecutor verdicts |
| **Epistemic Trace**| `hunter trace --last` | Step-by-step observable decision trace |
| **Negative Space** | `hunter coverage --ledger` | Complete tested vs untested breakdown |
| **Replay Lab** | `hunter replay --finding <id>` | 1-click standalone reproduction verification |
| **Validation** | `hunter external-arena` | Ground-truth benchmark verification |
| **Certification** | `hunter certify` | 15 systematic Pre-Kali certification gates |
