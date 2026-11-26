# OSINT Identity Subsystem Plan — HunterAI
> **Codex-Ready Implementation Specification**
> Version: 1.0 | Date: 2026-09-30 | Status: PROPOSED

---

## 1. Executive Summary

Add a complete **OSINT Identity Subsystem** to HunterAI: a multi-vector digital identity discovery pipeline (Username + Email + GitHub + Domains + Breach Indicators) feeding an **Evidence Graph** and an **Identity Correlation Engine** that computes confidence scores for each identity link.

**Governing Principle:**

```text
OSINT outputs = Evidence only, never confirmed Findings.
"Sharing the same username alone does not prove two accounts belong to the same person."
Confidence scores are computed exclusively by the Correlation Engine — never by the LLM or individual tools.
```

This aligns 100% with the invariant in `ARCHITECTURE.md`:
> *Zero LLM Heuristic Confirmation* — the LLM acts solely as a Hypothesis Generator.

---

## 2. Gap Analysis

| Currently Exists | Location | Problem |
|:---|:---|:---|
| `OSINTTools.sherlock(username)` | `tools/osint_tools.py` | Raw execution — no normalization, interpretation, or confidence scoring |
| `CorrelationEngine` | `hunter_ai/pipeline/correlation.py` | Scoped to endpoints/secrets — no awareness of identity data |
| `IdentityGraph` (referenced) | `ARCHITECTURE.md` — Layer 2 | **No module feeds it** real identity evidence |
| `BugBountyMethodology.generate_dorks()` | `core/playbooks/` | Passive dorks only — does not correlate results to actual accounts |

**Summary:** The codebase has disconnected tools with no reasoning layer. It needs an agent that knows **when** to run OSINT, **what** input to pass, **how** to interpret outputs, and **how** to block false positives.

---

## 3. Governing Principles

### P-OSINT-1: Evidence ≠ Finding
Every username/email match is recorded as an `IdentityEvidenceRecord` at **E0 (Observation)**, or at most **E1 (Corroborated)**. Reaching E2 (Repro) requires:
- Active inspection of the discovered account (page/content/API) by a Browser Worker or independent second-source tool.
- Review by the **Adversarial Evidence Court**, like any other finding.

### P-OSINT-2: Multi-Tool Fan-Out — No Single Core Tool
Tools referenced in older writeups (such as CB UserHunter) are **outdated** compared to 2026 tooling like `user-scanner v1.5.1` (hundreds of vectors, username/email cross-scanning, and mobile app APIs instead of relying solely on web HTTP status codes). Therefore:

```text
                HunterAI
                   │
          ┌────────┴────────┐
          │                 │
     Username OSINT      Email OSINT
          │                 │
     ┌────┼────┐        ┌───┼────┐
     │    │    │        │   │    │
   Tool1 Tool2 Tool3   Tool1 Tool2 Tool3
     │    │    │        │   │    │
     └────┴────┘        └───┴────┘
             │
             ▼
      Evidence Normalizer   ← All tools normalize into one schema
             │
             ▼
      Identity Correlation
             │
             ▼
        Evidence Graph
```

- Every vector runs at least 2–3 tools; no single tool is trusted in isolation.
- Tools are **pluggable** — newer tools can be integrated via adapters without changing the pipeline.

### P-OSINT-3: Scope & Egress Governance (P0 Constitution)
OSINT queries external services (GitHub, Reddit, Instagram, etc.). Therefore:
- Every external query passes through the **Policy Gate** and is logged in the Negative Space Ledger (`PROBED_EXTERNAL`, `SKIPPED_POLICY_RESTRICTION`).
- Any lookup outside the declared authorization scope is blocked (P0: Zero Out-of-Scope Egress).
- Per-platform rate limiting is mandatory to prevent abuse and detection.

### P-OSINT-4: Agent Epistemics
The agent—not the underlying tool—decides when to trigger scans, what inputs to use, how to interpret outputs, and how to suppress false positives using explicit reasoning rules (Section 8).

---

## 4. Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                     OSINT IDENTITY SUBSYSTEM                     │
│                                                                  │
│  ┌──────────────┐   ┌───────────────────────────────────────┐  │
│  │ Trigger      │   │  VECTOR FAN-OUT LAYER                  │  │
│  │ Conditions   │──▶│                                       │  │
│  │ (Agent rules)│   │  Username Vector:                     │  │
│  └──────────────┘   │    sherlock + maigret + blackbird     │  │
│                     │  Email Vector:                         │  │
│  ┌──────────────┐   │    holehe + ghunt + h8mail(indicator)  │  │
│  │ Input        │──▶│  GitHub Vector:                        │  │
│  │ Contract     │   │    github-dorks + enumerepo + API     │  │
│  └──────────────┘   │  Domain Vector:                        │  │
│                     │    whois + DNS + cert transparency      │  │
│                     └───────────────────┬───────────────────┘  │
│                                         ▼                      │
│                     ┌───────────────────────────────────────┐  │
│                     │  EVIDENCE NORMALIZER (canonical schema)│  │
│                     │  normalize → dedupe → E0 tagging       │  │
│                     └───────────────────┬───────────────────┘  │
│                                         ▼                      │
│                     ┌───────────────────────────────────────┐  │
│                     │  IDENTITY CORRELATION ENGINE          │  │
│                     │  cross-vector matching + weighted     │  │
│                     │  confidence scoring (0.0 → 1.0)       │  │
│                     └───────────────────┬───────────────────┘  │
│                                         ▼                      │
│                     ┌───────────────────────────────────────┐  │
│                     │  IDENTITY EVIDENCE GRAPH               │  │
│                     │  → feeds IdentityGraph (Layer 2)       │  │
│                     │  → Evidence Court (Layer 5)            │  │
│                     │  → Evidence Graph (control plane)      │  │
│                     └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. File-Level Changes

### 5.1 New Package: `core/osint/`

```
core/osint/
├── __init__.py
├── schemas.py               # IdentityEvidenceRecord, IdentityCluster, ...
├── evidence_normalizer.py   # Normalizes all tool outputs into one canonical schema
├── identity_correlation.py  # Correlation engine + confidence scoring
├── confidence_model.py      # Signal weights
├── fp_guards.py             # False-positive prevention rules
└── platform_registry.py     # Platform catalog + per-platform requirements
```

### 5.2 Extending `tools/osint_tools.py` (Matching Existing Tool Pattern)

```python
# ── Username Vector ──────────────────────────────────────────
async def maigret(self, username: str) -> ToolResult:
    """Hundreds of sites + Cloudflare bypass — stronger than sherlock in 2026."""

async def blackbird(self, username: str) -> ToolResult:
    """Fast username scan across APIs."""

# ── Email Vector ─────────────────────────────────────────────
async def holehe(self, email: str) -> ToolResult:
    """Detects platforms where an email is registered (uses password-reset flows)."""

async def ghunt(self, email: str) -> ToolResult:
    """Google account enumeration from an email address."""

# ── Breach Indicators (metadata only — see Section 11) ───────
async def breach_indicator(self, email_or_username: str) -> ToolResult:
    """Surface check for presence in known breaches — downloads no breach data."""

# ── Cross-Scan (user-scanner style) ──────────────────────────
async def cross_scan(self, username: str, email: str) -> ToolResult:
    """Derives username from email and vice versa + dual scan — v1.5.1 style."""
```

### 5.3 New Agent: `agents/osint_identity_agent.py`

Follows the existing `BaseAgent` / `AgentTask` / `AgentResult` pattern:

```python
class OSINTIdentityAgent(BaseAgent):
    """
    OSINT Identity Agent — digital identity discovery + account correlation.
    Produces IdentityEvidence (E0/E1) only — never confirmed Findings.
    """
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "osint_identity_agent",
            "OSINT Identity — username/email enumeration + correlation",
            mgr, cb
        )
        self.osint = OSINTTools(mgr)

    async def run(self, task: AgentTask) -> AgentResult:
        # task.extra: {"username": str?, "email": str?, "source": str}
        # 1. Verify trigger conditions + policy gate (P0)
        # 2. Fan out across available vectors
        # 3. Normalize → Correlate → Score
        # 4. Emit IdentityCluster(s) as evidence findings (severity=Info)
        ...
```

### 5.4 Integrating the Subsystem into the Existing Pipeline

| Integration Point | File | Change |
|:---|:---|:---|
| Schemas | `hunter_ai/pipeline/schemas.py` | Add `IdentityEvidenceRecord` + `IdentityCluster` |
| Correlation | `hunter_ai/pipeline/correlation.py` | Add `correlate_identity_evidence()` alongside existing functions |
| Capabilities | `hunter_ai/agents/capabilities.py` | Add `OSINT_IDENTITY = auto()` |
| Registry | `hunter_ai/agents/registry.py` | Register `OSINTIdentityAgent` |
| Task Classifier | `orchestrator/task_classifier.py` | Add keywords: `username`, `email osint`, `identity`, `holehe`, `maigret` |
| Playbook | `core/playbooks/master_recon_playbook.md` | Add "Public Identity Discovery" phase after Recon |
| CLI | `cli/hunter_cli.py` | Add `hunter osint-identity` command |

---

## 6. Data Schemas (Canonical)

```python
@dataclass
class IdentityEvidenceRecord:
    """Single result from one tool on one platform — always E0."""
    record_id: str                  # uuid
    vector: str                     # "username" | "email" | "github" | "domain" | "breach"
    platform: str                   # "github" | "reddit" | "tiktok" | ...
    query_value: str                # Queried identifier
    match_url: str                  # URL of discovered account/profile
    detection_method: str           # "web_status" | "mobile_api" | "password_reset" | "api_enumeration"
    raw_response_digest: str        # Hash of the response (avoids storing excess PII)
    tool_name: str                  # "sherlock" | "maigret" | "holehe" | ...
    evidence_level: str = "E0"     # E0 Observation — always the default
    captured_at: float              # timestamp
    validation_note: str = ""       # Validation notes (soft-404? redirect?)

@dataclass
class IdentityCluster:
    """Group of evidence records linked to the same candidate identity."""
    cluster_id: str
    anchor: str                     # Reference username or email
    members: List[IdentityEvidenceRecord]
    correlation_signals: Dict[str, float]   # Detected signals and their weights
    confidence: float                # 0.0 → 1.0 (computed by Correlation Engine only)
    confidence_label: str            # "weak" | "possible" | "probable" | "strong"
    open_questions: List[str]        # Unresolved questions → Negative Space Ledger
```

**Strict rule:** If `confidence_label != "strong"`, the cluster never enters the findings report; it remains graph evidence for further investigation.

---

## 7. Confidence Scoring Model (Correlation Signals)

The Correlation Engine aggregates signals across discovered accounts into a weighted composite score:

| Signal | Weight | Capture Method |
|:---|:---:|:---|
| Username exact match | +0.15 | Baseline only — **weak on its own** |
| Display name match | +0.10 | Cross-platform display name comparison |
| Bio cross-links (account mentions another) | +0.25 | Strongest signal — explicit link |
| Avatar similarity (pHash) | +0.20 | Perceptual hash across profile images |
| Shared linked website | +0.20 | Same URL in bio across multiple platforms |
| GitHub references (commit emails, org overlap) | +0.15 | High-confidence technical correlation |
| Email → Username cross-scan hit | +0.15 | `user-scanner`-style cross-validation |
| Registration date proximity | +0.05 | Supporting signal only |
| **Negative signals (penalties):** | | |
| Generic username (`admin`/`test`/`user`/...) | −0.30 | Blacklist check |
| Soft-404 / generic profile page | −0.50 | Unreliable match indicator |
| Single platform with no second source | −0.20 | Single-source penalty |

```text
Score = Σ(positive signals) − Σ(negative signals)
Label mapping:
  0.00 – 0.25 → weak       (evidence only — omitted from report)
  0.25 – 0.50 → possible   (evidence + open question)
  0.50 – 0.75 → probable   (candidate for E1 corroboration)
  0.75 – 1.00 → strong     (eligible for display as "probable identity link" — not "confirmed")
```

> **Note:** Even `strong` does not mean CONFIRMED in HunterAI terms (which requires E2+ reproducible proof) — it only means the correlation is strong enough to surface as **identity intelligence**.

---

## 8. Agent Reasoning Rules

The agent—not the tool—enforces these explicit rules:

### 8.1 Trigger Conditions
```text
TRIGGER when at least one condition holds:
  T1. A username appears during recon (git commits, JS author tags, package.json authors, HTML meta)
  T2. An email appears in crawled JS, leaked strings, DNS TXT, or WHOIS registrant data
  T3. The task explicitly requests identity mapping (scope includes "employees" or "public identities")
  T4. Initial correlation: the same identifier appears across multiple target assets

NEVER trigger:
  X1. Without a policy gate allowing external egress (P0)
  X2. Against out-of-scope targets
  X3. As an unprompted fishing expedition with no trigger
```

### 8.2 Input Contract
```python
task.extra = {
    "username": "abdo453",          # Optional
    "email": "abdo@example.com",    # Optional
    "source": "git_commit_metadata", # Required — discovery source (recorded for provenance)
    "vectors": ["username", "email"],  # Optional — defaults to all available
    "max_platforms": 60             # Platform cap (rate-limit governance)
}
```

### 8.3 Result Interpretation
```text
R1. Every match starts as an E0 observation until corroborated.
R2. Seeing the same username on N platforms ≠ same person — treat it as a hypothesis (H), not a conclusion.
R3. Format output as: "Hypothesis: accounts X, Y, Z may share an operator —
    confidence: possible (0.42) — signals: display_name(+0.10), avatar_phash(+0.20)..."
R4. Log every uninspected discovered account in the Negative Space Ledger:
    "ACCOUNT_DISCOVERED_NOT_VERIFIED: github.com/abdo453 (reason: content scan pending)"
R5. The LLM must never raise a cluster's confidence — updates happen exclusively
    through new deterministic correlation signals.
```

### 8.4 False-Positive Prevention (`fp_guards.py`)
```text
G1. Generic-username blacklist: admin, test, user, info, root, support, null, ...
G2. Soft-404 detection: pages returning HTTP 200 with "profile not found" are rejected.
G3. Status-code unreliability: platforms that always return 200 (React SPAs) require
    mobile app APIs or password-reset flows whenever available.
G4. Redirect chains: any match redirecting to a homepage is invalid.
G5. Single-source rule: a cluster backed by only one platform never exceeds label=weak.
G6. Per-platform rate limiting: cap at N queries/minute to avoid false bans
    that return misleading anti-bot pages.
```

---

## 9. Evidence Level Mapping in HunterAI

```text
E0 (Observation)      ← Every tool match upon discovery (default)
E1 (Corroborated)     ← Match corroborated by an independent second source
                         (e.g., maigret + live profile inspection in a browser)
E2 (Repro)            ← ⚠️ Rare and deliberate: only when content inspection proves linkage
                         (identical avatar bytes + mutual bio links) — requires Evidence Court
E3+                   ← Unreachable via OSINT alone — requires active account interaction,
                         which is out of scope (Section 11)
```

---

## 10. Implementation Phases & Acceptance Criteria

### Phase 1 — Username Vector + Evidence Normalizer
- Add `core/osint/schemas.py` and `evidence_normalizer.py`
- Extend `OSINTTools` (`maigret`, `blackbird`) and route `sherlock` through the normalizer
- Add initial `agents/osint_identity_agent.py`
- ✅ **Acceptance:** Running a single username produces one normalized JSON evidence file from 2+ tools, with no duplicate platform entries and every record tagged `E0`.

### Phase 2 — Email Vector + Cross-Scanning
- Add `holehe` and `ghunt` adapters plus `cross_scan()`
- Derive username candidates from email and vice versa (regex + heuristics)
- ✅ **Acceptance:** Scanning one email produces vector records and cross-scan hits merged into the same cluster graph.

### Phase 3 — Identity Correlation + Confidence Scoring
- Build `identity_correlation.py`, `confidence_model.py`, and `fp_guards.py`
- Implement avatar perceptual hashing (pHash) and bio cross-link matching
- ✅ **Acceptance:** Against a known test-identity benchmark:
  - True clusters (same person) score ≥ 0.5
  - False clusters (different people sharing a username) score ≤ 0.25
  - Zero generic usernames exceed `weak`.

### Phase 4 — World Model + Evidence Court Integration
- Emit clusters to `IdentityGraph` (Layer 2) and `Evidence Graph` (control plane)
- Auto-generate hypotheses from clusters for the investigation loop
- ✅ **Acceptance:** `hunter trace --last` shows when and why the agent triggered OSINT, and each cluster includes confidence, signals, and open questions.

### Phase 5 — MCP Tools + CLI + Documentation
- MCP tools: `osint_username_scan`, `osint_email_scan`, `osint_identity_correlate`
- CLI: `hunter osint-identity --username X --email Y --vectors all`
- Update `AGENT_CONTEXT.md` (new section: OSINT Identity Subsystem) and `ARCHITECTURE.md`
- ✅ **Acceptance:** Every MCP tool and CLI command runs standalone and returns the same canonical schema.

---

## 11. Non-Goals & Legal/Ethical Boundaries

```text
NG1. No downloading or storing breach data (passwords or personal records) —
     emit breach indicators only (boolean + indicator source) with zero raw content.
NG2. No interacting with discovered accounts (login, follow, message) — E3+ is out of scope.
NG3. No OSINT on individuals unrelated to the authorized engagement scope (P0 constitution).
NG4. Respect platform ToS: enforce rate limits, avoid aggressive scraping, and
     prefer legitimate mobile/public APIs over HTML scraping.
NG5. Never label an output "confirmed identity" in any report — cap wording at
     "probable identity link (correlation-based)".
NG6. Store collected PII (avatars, bios) as digests/hashes wherever possible,
     and purge them at engagement end (retention policy).
```

---

## 12. Test Plan (Summary)

| Test Case | Type | Proposed File |
|:---|:---|:---|
| Normalizer merges outputs from 3 distinct tools without data loss | unit | `tests/test_osint_normalizer.py` |
| Generic usernames never exceed `weak` | unit | `tests/test_fp_guards.py` |
| Soft-404 responses are rejected and not counted as matches | unit | `tests/test_fp_guards.py` |
| True cluster (same person across platforms) scores above 0.5 | integration | `tests/test_identity_correlation.py` |
| Policy gate blocks out-of-scope scans | integration | `tests/test_osint_policy.py` |
| E2E: username → clusters → evidence graph → hypotheses | e2e | `tests/test_osint_e2e.py` |

---

## 13. References

- **CB UserHunter** (referenced article tool): username enumeration across dozens of sites — **not the core engine**, just one signal in the fan-out layer.
- **user-scanner v1.5.1 (2026)**: hundreds of username/email scan vectors, automated cross-scanning, native MCP support, and mobile app API vectors — architectural reference for vectors and cross-scanning.
- **arXiv:1101.5578** — *How Unique and Traceable are Usernames?*: empirical basis — username reuse is traceable, not proof of identity.
- HunterAI invariants: `ARCHITECTURE.md` (Zero LLM Heuristic Confirmation, E0→E5, P0–P4, Negative Space Ledger).

---

> **Ready for Codex handoff** — this specification is self-contained: all paths, patterns, existing architectural conventions, and acceptance criteria are included above or referenced in repository files.
