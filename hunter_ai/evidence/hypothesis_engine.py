"""
Hypothesis Engine — Scientific method for security findings.

NO LLM opinion becomes a finding.
Every finding MUST pass through:
  Observation → Hypothesis → Experiment → Evidence → Verdict

Pattern-matching generates hypotheses deterministically.
Verdict is set ONLY by VerifierAgent with real execution evidence.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class HypothesisStatus(str, Enum):
    CREATED      = "CREATED"
    ASSIGNED     = "ASSIGNED"      # initial confidence assigned
    DESIGNING    = "DESIGNING"     # experiment being designed
    TESTING      = "TESTING"       # experiment running
    EVIDENCE     = "EVIDENCE"      # evidence collected, awaiting verdict
    VERIFIED     = "VERIFIED"      # verdict: CONFIRMED
    REJECTED     = "REJECTED"      # verdict: REJECTED
    INCONCLUSIVE = "INCONCLUSIVE"  # verdict: INCONCLUSIVE


@dataclass
class Hypothesis:
    hyp_id: str = field(default_factory=lambda: f"H-{str(abs(hash(uuid.uuid4().hex)))[:3].zfill(3)}")
    title: str = ""
    vuln_type: str = ""           # IDOR, CORS_MISCONFIGURATION, SQL_INJECTION, …
    observation: str = ""         # The raw observation that triggered this
    endpoint: str = ""
    parameter: str = ""
    status: HypothesisStatus = HypothesisStatus.CREATED
    confidence: float = 0.0       # 0.0–1.0
    evidence_ids: List[str] = field(default_factory=list)   # EvidenceGraph node IDs
    experiment_plan: str = ""     # What controlled test to run
    refutation_criteria: str = "" # What response would REJECT this hypothesis
    verdict: Optional[str] = None # CONFIRMED | REJECTED | INCONCLUSIVE
    verdict_reason: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hyp_id":             self.hyp_id,
            "title":              self.title,
            "vuln_type":          self.vuln_type,
            "observation":        self.observation,
            "endpoint":           self.endpoint,
            "parameter":          self.parameter,
            "status":             self.status.value,
            "confidence":         self.confidence,
            "evidence_ids":       self.evidence_ids,
            "experiment_plan":    self.experiment_plan,
            "refutation_criteria":self.refutation_criteria,
            "verdict":            self.verdict,
            "verdict_reason":     self.verdict_reason,
        }


class HypothesisEngine:
    """
    Manages the full hypothesis lifecycle.

    Hypothesis generation is PATTERN-BASED (deterministic) — no LLM hallucination.
    Verdict is set ONLY by VerifierAgent with measured response differences.
    """

    # Deterministic observation → vulnerability pattern mapping
    PATTERNS = [
        {
            "keywords":    ["id", "user_id", "object_id", "account_id", "uid"],
            "vuln_type":   "IDOR",
            "title":       "Object authorization may depend only on {param}",
            "confidence":  0.55,
            "experiment":  "Swap {param} value between two controlled accounts and compare full responses",
            "refutation":  "Response returns 403 or identical body regardless of {param} value",
        },
        {
            "keywords":    ["cors", "origin", "access-control-allow"],
            "vuln_type":   "CORS_MISCONFIGURATION",
            "title":       "CORS policy may reflect arbitrary Origin header",
            "confidence":  0.60,
            "experiment":  "Send Origin: https://evil.attacker.com — inspect Access-Control-Allow-Origin response header",
            "refutation":  "Response does not echo the attacker origin or omits CORS headers",
        },
        {
            "keywords":    ["sql", "query", "search", "filter", "where", "select"],
            "vuln_type":   "SQL_INJECTION",
            "title":       "Parameter {param} may pass unsanitized input to SQL engine",
            "confidence":  0.50,
            "experiment":  "Inject: ' AND 1=1-- vs ' AND 1=2-- and compare response length/content",
            "refutation":  "Responses are identical or return a generic error for both payloads",
        },
        {
            "keywords":    ["xss", "script", "html", "reflected", "markup"],
            "vuln_type":   "XSS",
            "title":       "Parameter {param} may reflect unescaped markup",
            "confidence":  0.55,
            "experiment":  "Inject a unique nonce tag into {param} and check for unescaped reflection",
            "refutation":  "The response entity-encodes or strips the tag",
        },
        {
            "keywords":    ["fetch", "webhook", "callback", "proxy", "ssrf", "image_url"],
            "vuln_type":   "SSRF",
            "title":       "Parameter {param} may fetch a server-side URL",
            "confidence":  0.60,
            "experiment":  "Point {param} at an operator-owned loopback canary and wait for a callback",
            "refutation":  "No callback is received, or the URL is rejected",
        },
        {
            "keywords":    ["redirect", "next", "return_to", "goto", "url", "location"],
            "vuln_type":   "OPEN_REDIRECT",
            "title":       "Redirect parameter {param} may accept external URLs",
            "confidence":  0.65,
            "experiment":  "Set {param}=https://evil.attacker.com — inspect Location response header",
            "refutation":  "Redirect is blocked, normalized, or does not reflect the external URL",
        },
        {
            "keywords":    ["token", "csrf", "xsrf", "nonce", "state"],
            "vuln_type":   "CSRF",
            "title":       "State-changing request may lack proper CSRF token validation",
            "confidence":  0.50,
            "experiment":  "Replay the POST request without the token field or with a blank value",
            "refutation":  "Server returns 403 or error when token is absent/invalid",
        },
        {
            "keywords":    ["upload", "file", "filename", "content-type", "multipart"],
            "vuln_type":   "UNRESTRICTED_FILE_UPLOAD",
            "title":       "File upload may accept dangerous content types via {param}",
            "confidence":  0.55,
            "experiment":  "Upload a .php / .jsp file with text/plain Content-Type — check if stored/executed",
            "refutation":  "Server rejects non-whitelisted extensions or MIME types",
        },
    ]

    def __init__(self) -> None:
        self._hypotheses: Dict[str, Hypothesis] = {}

    # ── Generation ────────────────────────────────────────────────────────────

    def generate_from_observation(
        self,
        observation: str,
        endpoint: str,
        params: List[str],
    ) -> List[Hypothesis]:
        """
        Pattern-match observation text to produce Hypothesis objects.
        Returns only NEW hypotheses (de-duplicated by vuln_type + endpoint).
        """
        obs_lower = observation.lower()
        existing_keys = {(h.vuln_type, h.endpoint) for h in self._hypotheses.values()}
        generated: List[Hypothesis] = []

        for pat in self.PATTERNS:
            if not any(kw in obs_lower for kw in pat["keywords"]):
                continue

            key = (pat["vuln_type"], endpoint)
            if key in existing_keys:
                continue  # already have this hypothesis for this endpoint

            # Pick the most relevant parameter
            matched_param = next(
                (p for p in params if any(kw in p.lower() for kw in pat["keywords"])),
                params[0] if params else "param",
            )

            h = Hypothesis(
                title=pat["title"].format(param=matched_param),
                vuln_type=pat["vuln_type"],
                observation=observation,
                endpoint=endpoint,
                parameter=matched_param,
                confidence=pat["confidence"],
                experiment_plan=pat["experiment"].format(param=matched_param),
                refutation_criteria=pat["refutation"].format(param=matched_param),
                status=HypothesisStatus.ASSIGNED,
            )
            self._hypotheses[h.hyp_id] = h
            existing_keys.add(key)
            generated.append(h)

        return generated

    def register(self, hypothesis: Hypothesis) -> Hypothesis:
        """Register an externally constructed hypothesis for lifecycle updates."""
        self._hypotheses[hypothesis.hyp_id] = hypothesis
        return hypothesis

    # ── Lifecycle updates ─────────────────────────────────────────────────────

    def update_status(
        self,
        hyp_id: str,
        status: HypothesisStatus,
        evidence_id: str = "",
    ) -> bool:
        h = self._hypotheses.get(hyp_id)
        if not h:
            return False
        h.status = status
        h.updated_at = time.time()
        if evidence_id:
            h.evidence_ids.append(evidence_id)
        return True

    def set_verdict(
        self,
        hyp_id: str,
        verdict: str,
        reason: str,
        confidence_delta: float = 0.0,
    ) -> bool:
        """
        Set final verdict. ONLY called by VerifierAgent with measured evidence.
        verdict must be: CONFIRMED | REJECTED | INCONCLUSIVE
        """
        if verdict not in ("CONFIRMED", "REJECTED", "INCONCLUSIVE"):
            return False
        h = self._hypotheses.get(hyp_id)
        if not h:
            return False
        h.verdict = verdict
        h.verdict_reason = reason
        h.confidence = min(1.0, max(0.0, h.confidence + confidence_delta))
        h.status = {
            "CONFIRMED":    HypothesisStatus.VERIFIED,
            "REJECTED":     HypothesisStatus.REJECTED,
            "INCONCLUSIVE": HypothesisStatus.INCONCLUSIVE,
        }[verdict]
        h.updated_at = time.time()
        return True

    # ── Queries ───────────────────────────────────────────────────────────────

    def get(self, hyp_id: str) -> Optional[Hypothesis]:
        return self._hypotheses.get(hyp_id)

    def get_all(self) -> List[Hypothesis]:
        return list(self._hypotheses.values())

    def get_active(self) -> List[Hypothesis]:
        terminal = {HypothesisStatus.VERIFIED, HypothesisStatus.REJECTED, HypothesisStatus.INCONCLUSIVE}
        return [h for h in self._hypotheses.values() if h.status not in terminal]

    def get_confirmed(self) -> List[Hypothesis]:
        return [h for h in self._hypotheses.values() if h.verdict == "CONFIRMED"]

    def summary(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for h in self._hypotheses.values():
            by_status[h.status.value] = by_status.get(h.status.value, 0) + 1
        return {
            "total":     len(self._hypotheses),
            "by_status": by_status,
            "confirmed": len(self.get_confirmed()),
            "active":    len(self.get_active()),
        }
