"""
HunterAI Runtime: Meta-Reasoning, Capability Graph & Behavioral Fingerprinting
==============================================================================
Implements the highest cognitive layer of HunterAI:
1. Capability Graph: Replaces rigid roles with fine-grained capability sets and
   detects privilege creep across identity boundaries.
2. Multi-Dimensional Behavioral Fingerprinting: Builds comprehensive baseline profiles
   (structural JSON/DOM hashes, cookie changes, redirects, headers) to detect true
   semantic deviations rather than raw length jitter.
3. Four-Persona Reasoning Council:
   - Explorer: Brainstorms potential system anomalies.
   - Tester: Devises targeted differential experiments.
   - Skeptic: Actively seeks alternative benign explanations.
   - Judge: Requires formal evidentiary proof before confirming any finding.
4. Meta-Reasoner: Observes the agent's own research velocity, identifies analytical
   stagnation, and automatically pivots the search strategy.
"""
from __future__ import annotations

import time
import hashlib
import json
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("hunter_ai.meta_reasoning")


# ─── 1. Capability Graph ─────────────────────────────────────────────────────
@dataclass
class Capability:
    """A granular permission grant on a specific resource type"""
    action: str             # e.g., "read", "create", "modify", "delete", "export"
    resource_type: str      # e.g., "profile", "order", "invoice", "user"
    scope: str = "own"      # "own", "tenant", "global"

    def signature(self) -> str:
        return f"{self.action}:{self.resource_type}:{self.scope}"


class CapabilityGraph:
    """
    Maps identities to explicit capability sets and verifies permission boundaries.
    """

    def __init__(self):
        self._grants: Dict[str, Set[str]] = {}

    def grant_capability(self, actor_id: str, action: str, resource_type: str, scope: str = "own"):
        cap = Capability(action=action, resource_type=resource_type, scope=scope)
        if actor_id not in self._grants:
            self._grants[actor_id] = set()
        self._grants[actor_id].add(cap.signature())

    def has_capability(self, actor_id: str, action: str, resource_type: str, scope: str = "own") -> bool:
        cap_sig = f"{action}:{resource_type}:{scope}"
        # Global capability implies tenant and own
        global_sig = f"{action}:{resource_type}:global"
        user_caps = self._grants.get(actor_id, set())
        return (cap_sig in user_caps) or (global_sig in user_caps)

    def detect_privilege_creep(
        self,
        actor_id: str,
        attempted_action: str,
        resource_type: str,
        target_scope: str = "own"
    ) -> Tuple[bool, str]:
        """Checks whether an executed action exceeds the actor's authorized capability set"""
        if not self.has_capability(actor_id, attempted_action, resource_type, target_scope):
            return True, f"PRIVILEGE_CREEP: Actor '{actor_id}' executed '{attempted_action}:{resource_type}:{target_scope}' without granted capability."
        return False, "AUTHORIZED: Action is within the actor's granted capability set."


# ─── 2. Multi-Dimensional Behavioral Fingerprinting ──────────────────────────
@dataclass
class BehavioralFingerprint:
    """Multi-dimensional baseline signature of an endpoint response"""
    endpoint: str
    status_code: int
    content_type: str
    header_keys: Set[str]
    structural_hash: str        # Hash of keys/tags, ignoring volatile values
    redirect_location: Optional[str] = None
    cookie_names: Set[str] = field(default_factory=set)


@dataclass
class DeviationReport:
    """Analytical report of differences between observed response and baseline"""
    has_semantic_deviation: bool
    status_changed: bool
    structural_changed: bool
    new_cookies: Set[str]
    redirect_diverged: bool
    summary: str


class BehavioralFingerprinter:
    """
    Creates structural, non-volatile fingerprints and identifies true security deviations.
    """

    @classmethod
    def _compute_structure_hash(cls, text: str) -> str:
        """Extracts JSON keys or HTML tag skeleton to generate structural hash"""
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                skeleton = sorted(list(parsed.keys()))
                return hashlib.md5(json.dumps(skeleton).encode()).hexdigest()
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                skeleton = sorted(list(parsed[0].keys()))
                return hashlib.md5(json.dumps(skeleton).encode()).hexdigest()
        except Exception:
            pass

        # For HTML / text, compute simple tag skeleton hash
        import re
        tags = re.findall(r"<([a-zA-Z0-9]+)", text)
        return hashlib.md5(",".join(tags[:50]).encode()).hexdigest()

    @classmethod
    def create_fingerprint(
        cls,
        endpoint: str,
        status_code: int,
        headers: Dict[str, str],
        body: str
    ) -> BehavioralFingerprint:
        content_type = headers.get("content-type", headers.get("Content-Type", "")).split(";")[0]
        header_keys = set(headers.keys())
        struct_hash = cls._compute_structure_hash(body)
        redirect = headers.get("location", headers.get("Location"))
        cookies = {k for k in headers.keys() if "cookie" in k.lower() or "set-cookie" in k.lower()}

        return BehavioralFingerprint(
            endpoint=endpoint,
            status_code=status_code,
            content_type=content_type,
            header_keys=header_keys,
            structural_hash=struct_hash,
            redirect_location=redirect,
            cookie_names=cookies
        )

    @classmethod
    def compare(cls, baseline: BehavioralFingerprint, observed: BehavioralFingerprint) -> DeviationReport:
        status_diff = (baseline.status_code != observed.status_code)
        struct_diff = (baseline.structural_hash != observed.structural_hash)
        redirect_diff = (baseline.redirect_location != observed.redirect_location)
        new_cookies = observed.cookie_names - baseline.cookie_names

        is_semantic = status_diff or struct_diff or redirect_diff or bool(new_cookies)

        diffs = []
        if status_diff:
            diffs.append(f"Status changed from {baseline.status_code} to {observed.status_code}")
        if struct_diff:
            diffs.append("Response body structural skeleton altered")
        if redirect_diff:
            diffs.append(f"Redirect location shifted to '{observed.redirect_location}'")
        if new_cookies:
            diffs.append(f"New session cookies issued: {list(new_cookies)}")

        summary = "; ".join(diffs) if diffs else "No semantic deviation detected from baseline."

        return DeviationReport(
            has_semantic_deviation=is_semantic,
            status_changed=status_diff,
            structural_changed=struct_diff,
            new_cookies=new_cookies,
            redirect_diverged=redirect_diff,
            summary=summary
        )


# ─── 3. Four-Persona Reasoning Council ───────────────────────────────────────
class PersonaVerdict(str, Enum):
    APPROVED = "APPROVED"
    CHALLENGED = "CHALLENGED"
    DISMISSED = "DISMISSED"


@dataclass
class CouncilJudgment:
    verdict: PersonaVerdict
    explorer_hypothesis: str
    tester_method: str
    skeptic_challenge: str
    judge_ruling: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "explorer_hypothesis": self.explorer_hypothesis,
            "tester_method": self.tester_method,
            "skeptic_challenge": self.skeptic_challenge,
            "judge_ruling": self.judge_ruling,
            "confidence": round(self.confidence, 2)
        }


class FourPersonaCouncil:
    """
    Executes a structured adversarial debate across 4 personas:
    Explorer -> Tester -> Skeptic -> Judge.
    """

    @classmethod
    def evaluate_candidate(
        cls,
        vulnerability_type: str,
        observed_deviation: DeviationReport,
        has_falsification_proof: bool,
        reproducibility_rate: float
    ) -> CouncilJudgment:
        # 1. Explorer
        explorer_h = f"Observed semantic deviation ({observed_deviation.summary}) indicates potential {vulnerability_type}."

        # 2. Tester
        tester_m = f"Constructed differential probe with control negative and evaluated reproducibility across trials."

        # 3. Skeptic
        if not has_falsification_proof:
            skeptic_c = "Alternative explanation: the deviation is an unvalidated client reflection or benign redirect."
        elif reproducibility_rate < 0.75:
            skeptic_c = f"Alternative explanation: the phenomenon is flaky (reproducibility only {reproducibility_rate:.1%})."
        else:
            skeptic_c = "All standard counter-hypotheses (public resource, input reflection, noise) have been tested and falsified."

        # 4. Judge
        if has_falsification_proof and reproducibility_rate >= 0.75 and observed_deviation.has_semantic_deviation:
            verdict = PersonaVerdict.APPROVED
            ruling = "Finding proven beyond reasonable doubt with repeatable semantic differential and surviving counter-tests."
            confidence = min(0.99, reproducibility_rate * 0.95)
        elif not observed_deviation.has_semantic_deviation:
            verdict = PersonaVerdict.DISMISSED
            ruling = "Dismissed: No meaningful structural or status deviation detected."
            confidence = 0.1
        else:
            verdict = PersonaVerdict.CHALLENGED
            ruling = "Challenged by Skeptic: Insufficient falsification evidence or low reproducibility."
            confidence = 0.4

        return CouncilJudgment(
            verdict=verdict,
            explorer_hypothesis=explorer_h,
            tester_method=tester_m,
            skeptic_challenge=skeptic_c,
            judge_ruling=ruling,
            confidence=confidence
        )


# ─── 4. Meta-Reasoner & Strategy Evolution ───────────────────────────────────
class StrategyState(str, Enum):
    SURFACE_PROBING = "SURFACE_PROBING"
    DEEP_PARAM_PROBING = "DEEP_PARAM_PROBING"
    WORKFLOW_CHAIN_PIVOT = "WORKFLOW_CHAIN_PIVOT"
    AUTH_MATRIX_PIVOT = "AUTH_MATRIX_PIVOT"
    RECON_EXPANSION = "RECON_EXPANSION"


@dataclass
class MetaStrategyStatus:
    current_strategy: StrategyState
    consecutive_stagnant_steps: int
    is_stagnant: bool
    recommended_pivot: StrategyState
    rationale: str


class MetaReasoner:
    """
    Monitors research velocity, detects analytical stagnation, and dynamically
    pivots the testing strategy.
    """

    def __init__(self, stagnation_threshold: int = 4):
        self.stagnation_threshold = stagnation_threshold
        self.current_strategy: StrategyState = StrategyState.SURFACE_PROBING
        self.consecutive_stagnant_steps: int = 0

    def evaluate_velocity(self, step_yielded_signals: bool) -> MetaStrategyStatus:
        """Evaluates whether the current research approach is making progress"""
        if step_yielded_signals:
            self.consecutive_stagnant_steps = 0
            return MetaStrategyStatus(
                current_strategy=self.current_strategy,
                consecutive_stagnant_steps=0,
                is_stagnant=False,
                recommended_pivot=self.current_strategy,
                rationale="Progress sustained: active signals being generated."
            )

        self.consecutive_stagnant_steps += 1
        is_stagnant = (self.consecutive_stagnant_steps >= self.stagnation_threshold)

        if is_stagnant:
            # Shift to next logical research strategy
            pivot_map = {
                StrategyState.SURFACE_PROBING: StrategyState.DEEP_PARAM_PROBING,
                StrategyState.DEEP_PARAM_PROBING: StrategyState.AUTH_MATRIX_PIVOT,
                StrategyState.AUTH_MATRIX_PIVOT: StrategyState.WORKFLOW_CHAIN_PIVOT,
                StrategyState.WORKFLOW_CHAIN_PIVOT: StrategyState.RECON_EXPANSION,
                StrategyState.RECON_EXPANSION: StrategyState.SURFACE_PROBING
            }
            new_strategy = pivot_map.get(self.current_strategy, StrategyState.RECON_EXPANSION)
            self.current_strategy = new_strategy
            self.consecutive_stagnant_steps = 0
            logger.info(f"[MetaReasoner] STAGNATION DETECTED. Pivoting strategy to '{new_strategy.value}'")
            return MetaStrategyStatus(
                current_strategy=new_strategy,
                consecutive_stagnant_steps=0,
                is_stagnant=True,
                recommended_pivot=new_strategy,
                rationale=f"Stagnation threshold ({self.stagnation_threshold}) reached without signal. Pivoting strategy to explore unexamined vectors."
            )

        return MetaStrategyStatus(
            current_strategy=self.current_strategy,
            consecutive_stagnant_steps=self.consecutive_stagnant_steps,
            is_stagnant=False,
            recommended_pivot=self.current_strategy,
            rationale=f"Continuing strategy '{self.current_strategy.value}' ({self.consecutive_stagnant_steps}/{self.stagnation_threshold} stagnant steps)."
        )
