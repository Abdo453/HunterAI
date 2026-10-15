# HunterAI OS — System Architecture & Design Specification

HunterAI is an enterprise-grade **Security Assessment Operating System** engineered around evidence-first causality, deterministic verification, human-like cognitive reasoning (Anthropic Claude Thinking Protocol), and sandboxed execution.

---

## 1. High-Level Architecture Diagram

```mermaid
graph TD
    User["Operator / Security Engineer"] --> UI["UI Layer (TUI HunterOS & Web Dashboard)"]
    
    subgraph CognitiveLayer["Cognitive & Strategy Plane"]
        Thinking["Claude Thinking Protocol Engine\n(Extended Thinking / Adaptive Steering / Scratchpad)"]
        Strategist["Strategist Agent (Qwen3:8b / Claude / WRN)"]
        IGP["Information Gain Planner (EIG Optimizer)"]
        Recov["Recovery Engine & Model Rerouter"]
    end

    UI --> Thinking
    Thinking --> Strategist
    Strategist <--> IGP
    Strategist <--> Recov

    subgraph AgentGraph["HunterAI Agent Graph"]
        ReconAgent["Recon Agent (Subfinder / Httpx / Naabu)"]
        WebAgent["Web Agent (Endpoint / Param / JS Analysis)"]
        BrowserAgent["Browser Agent (Playwright + DOM Annotator)"]
        VerifierAgent["Verifier Agent (Metamorphic Differential Fuzzing)"]
    end

    Strategist --> ReconAgent
    Strategist --> WebAgent
    Strategist --> BrowserAgent
    Strategist --> VerifierAgent

    subgraph ControlPlane["Execution & Safety Sandbox"]
        PolicyGate["Strict Scope Engine & Policy Gate"]
        ToolRouter["Tool Router (Rate Limiting / Audit / RBAC)"]
        TermBridge["Terminal Bridge (Catastrophic Command Blocking)"]
        HostBridge["Host Bridge (Sandbox Traversal Guard)"]
        A2ABus["MCP A2A Signed Message Bus (HMAC-SHA256)"]
    end

    ReconAgent --> ToolRouter
    WebAgent --> ToolRouter
    BrowserAgent --> HostBridge
    VerifierAgent --> ToolRouter
    ToolRouter --> PolicyGate
    PolicyGate --> TermBridge

    subgraph EvidenceEngine["Evidence Court & Causal Intelligence"]
        CaptureStore["Burp Capture Store (Lineage REQ-XXXXXX)"]
        EvGraph["Evidence Graph (Host -> Ep -> Req -> Resp)"]
        HypEngine["Hypothesis Engine (Anti-Premature Closure)"]
        EvCourt["Evidence Court (Deterministic Response Diff Verdicts)"]
        RepEngine["Report Engine (Markdown / JSON / SARIF 2.1)"]
        SnapManager["Snapshot & Time Travel Manager (SHA-256)"]
    end

    BrowserAgent --> CaptureStore
    TermBridge --> CaptureStore
    CaptureStore --> EvGraph
    EvGraph --> HypEngine
    HypEngine --> VerifierAgent
    VerifierAgent --> EvCourt
    EvCourt --> RepEngine
    SnapManager -.-> EvGraph
```

---

## 2. Core Architectural Pillars

### A. Cognitive Thinking Layer (Anthropic Claude Extended Thinking)
HunterAI implements the Anthropic Extended Thinking architecture:
- **Inner Monologue Scratchpad:** Raw, stream-of-consciousness reasoning inside `<thinking>` blocks before any action is executed.
- **Adaptive Thinking Framework:** Scales cognitive effort parameter ($0.0 \le \text{effort} \le 1.0$) and token ceiling ($1\text{k} - 16\text{k}$ tokens) depending on task complexity and stakes.
- **8-Stage Cognitive Sequence:** Initial Engagement $\to$ Problem Decomposition $\to$ Multiple Competing Hypotheses $\to$ Detective Discovery $\to$ Pre-Tool Reflection $\to$ Post-Tool Reflection $\to$ Error Course Correction $\to$ Strategic Meta-Cognition.
- **Anti-Premature Closure:** Requires maintaining multiple competing hypotheses (e.g. IDOR vs Public Data vs Caching Anomaly) rather than confirmation bias.

### B. Evidence Court & Zero LLM Hallucination
- **Deterministic Response Diff Rules:** LLMs generate hypotheses and execution commands, but are strictly forbidden from deciding vulnerability verdicts.
- **Court Adjudication:** Verdicts (`CONFIRMED`, `REJECTED`, `INCONCLUSIVE`) are awarded strictly by deterministic differential verification ($A/B$ testing, status code diffs, payload length thresholds, PoE token reflection).

### C. Hard Scope Enforcement & Sandboxing
- **Inviolable Scope Engine:** Blocks localhost, loopback (`127.0.0.1`), metadata services (`169.254.169.254`), and unauthorized hostnames at the network and process level.
- **Terminal Bridge:** Intercepts and denies catastrophic commands (`rm -rf /`, fork bombs, mkfs, dd). Automatically masks secrets, bearer tokens, and API credentials from all outputs.

### D. Time Travel & Resilience
- **State Snapshots:** Full checkpoint captures with SHA-256 integrity hashes for instantaneous rollback.
- **Recovery Engine:** Autonomous rerouting to fallback model tiers, automatic tool process restarts, and exponential-backoff retries for network fluctuations.
