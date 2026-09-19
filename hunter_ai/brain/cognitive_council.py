"""
HunterAI Cognitive Council V2: Multi-Model AI Dialectic Council
===============================================================
Coordinates a collaborative council of 3 specialized local AI models:
1. WhiteRabbitNeo 8B (Master Offensive Strategist & Hypothesis Generator)
2. Qwen 2.5 Coder 14B (Code Auditor, AST Parser & JavaScript Specialist)
3. xploiter/pentester (Adversarial Critic, Triage Scout & Evidence Challenger)

Features:
- Shared Working Blackboard State (`CouncilState`)
- Structured Dialectic Debate Protocol (`Observation -> Hypothesis -> Debate -> Test -> Evidence -> Verdict`)
- Disagreement & Contradiction Detection
- Deterministic Evidence Court Adjudication
- Graceful offline & heuristic fallback tolerance
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.cognitive_council")


class CouncilRole(str, Enum):
    OFFENSIVE_STRATEGIST = "offensive_strategist"  # WhiteRabbitNeo
    CODE_AUDITOR         = "code_auditor"          # Qwen 2.5 Coder
    CRITIC_JUDGE         = "critic_judge"          # xploiter / pentester
    CHAIRMAN             = "chairman"              # Meta-Orchestrator


class VoteVerdict(str, Enum):
    CONFIRM_VULN        = "CONFIRM_VULN"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    SKEPTICAL_REJECT    = "SKEPTICAL_REJECT"
    HEURISTIC_PASS      = "HEURISTIC_PASS"


class HypothesisStatus(str, Enum):
    OBSERVATION    = "OBSERVATION"
    HYPOTHESIS     = "HYPOTHESIS"
    UNDER_DEBATE   = "UNDER_DEBATE"
    ACTIVE_PROBING = "ACTIVE_PROBING"
    CONFIRMED      = "CONFIRMED"
    REJECTED       = "REJECTED"
    UNPROVEN       = "UNPROVEN"


@dataclass
class ModelVote:
    model_name: str
    role: CouncilRole
    verdict: VoteVerdict
    confidence: float
    rationale: str
    counter_arguments: List[str] = field(default_factory=list)
    proposed_probe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "role": self.role.value,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
            "counter_arguments": self.counter_arguments,
            "proposed_probe": self.proposed_probe,
        }


@dataclass
class CouncilHypothesis:
    claim_id: str
    vuln_type: str
    endpoint: str
    parameter: Optional[str] = None
    initial_observation: str = ""
    status: HypothesisStatus = HypothesisStatus.HYPOTHESIS
    votes: Dict[str, ModelVote] = field(default_factory=dict)
    consensus_score: float = 0.0
    disagreement_detected: bool = False
    debate_transcript: List[Dict[str, Any]] = field(default_factory=list)
    court_verdict: Optional[str] = None
    evidence_proof: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "initial_observation": self.initial_observation,
            "status": self.status.value,
            "votes": {k: v.to_dict() for k, v in self.votes.items()},
            "consensus_score": round(self.consensus_score, 2),
            "disagreement_detected": self.disagreement_detected,
            "debate_transcript": self.debate_transcript,
            "court_verdict": self.court_verdict,
            "evidence_proof": self.evidence_proof,
        }


class CouncilState:
    """
    Shared Blackboard Working Memory for the Cognitive Council.
    Holds structured target data and delivers tailored context slices to each model.
    """

    def __init__(self, target_domain: str):
        self.domain = target_domain
        self.subdomains: Set[str] = set()
        self.live_assets: List[Dict[str, Any]] = []
        self.detected_technologies: Set[str] = set()
        self.endpoints: List[Dict[str, Any]] = []
        self.parameters: List[Dict[str, Any]] = []
        self.javascript_secrets: List[Dict[str, Any]] = []
        self.hypotheses: Dict[str, CouncilHypothesis] = {}
        self.confirmed_findings: List[Dict[str, Any]] = []
        self.rejected_claims: List[Dict[str, Any]] = []

    def update_recon(
        self,
        subdomains: Optional[List[str]] = None,
        live_assets: Optional[List[Dict[str, Any]]] = None,
        technologies: Optional[List[str]] = None,
    ) -> None:
        if subdomains:
            self.subdomains.update(subdomains)
        if live_assets:
            self.live_assets.extend(live_assets)
        if technologies:
            self.detected_technologies.update([t.lower().strip() for t in technologies if t])

    def update_surface(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        parameters: Optional[List[Dict[str, Any]]] = None,
        secrets: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if endpoints:
            self.endpoints.extend(endpoints)
        if parameters:
            self.parameters.extend(parameters)
        if secrets:
            self.javascript_secrets.extend(secrets)

    def get_context_slice_for_role(self, role: CouncilRole, claim: Optional[CouncilHypothesis] = None) -> Dict[str, Any]:
        """Provides a tailored, compact context slice suited for the model's specialty."""
        base_ctx = {
            "target": self.domain,
            "technologies": sorted(list(self.detected_technologies)),
        }

        if role == CouncilRole.OFFENSIVE_STRATEGIST:
            # WhiteRabbitNeo gets attack surface, parameter risk classifications & tech stack
            return {
                **base_ctx,
                "claim": claim.to_dict() if claim else None,
                "high_risk_params": [p for p in self.parameters if p.get("context", {}).get("risk_level") in ("CRITICAL", "HIGH")][:15],
                "active_endpoints": [e.get("url") for e in self.endpoints if e.get("category") in ("API", "ADMIN")][:20],
            }

        elif role == CouncilRole.CODE_AUDITOR:
            # Qwen Coder gets JavaScript secrets, API parameter schemas & code endpoints
            return {
                **base_ctx,
                "claim": claim.to_dict() if claim else None,
                "js_secrets": self.javascript_secrets[:10],
                "api_endpoints": [e.get("url") for e in self.endpoints if "/api" in str(e.get("url", ""))][:20],
            }

        elif role == CouncilRole.CRITIC_JUDGE:
            # xploiter / Critic gets hypotheses, evidence snippets, baseline differential requirements
            return {
                **base_ctx,
                "claim": claim.to_dict() if claim else None,
                "subdomains_count": len(self.subdomains),
                "live_assets_count": len(self.live_assets),
                "verification_mandate": "Challenge soft-404, verify reflection vs execution, demand differential proof.",
            }

        return base_ctx


class DisagreementDetector:
    """
    Evaluates peer reviews from the 3 models, identifies conflicting assessments,
    and computes consensus metrics.
    """

    @staticmethod
    def evaluate_consensus(votes: Dict[str, ModelVote]) -> Tuple[float, bool, str]:
        """
        Returns (consensus_score, is_disagreement, synthesis_reason).
        """
        if not votes:
            return (0.0, False, "No votes recorded.")

        verdicts = [v.verdict for v in votes.values()]
        confidences = [v.confidence for v in votes.values()]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

        confirms = verdicts.count(VoteVerdict.CONFIRM_VULN)
        rejects = verdicts.count(VoteVerdict.SKEPTICAL_REJECT)
        needs_evidence = verdicts.count(VoteVerdict.NEEDS_MORE_EVIDENCE)

        # Unanimous Confirmation
        if confirms == len(verdicts):
            return (avg_conf, False, "Unanimous Council Consensus: Confirmed candidate vulnerability.")

        # Unanimous Rejection
        if rejects == len(verdicts):
            return (avg_conf, False, "Unanimous Council Consensus: Rejected as false positive / noise.")

        # Disagreement: Split between confirmation and rejection
        if confirms > 0 and rejects > 0:
            return (
                round(avg_conf * 0.6, 2),
                True,
                f"Disagreement Detected: {confirms} model(s) confirmed, {rejects} model(s) skeptical. Differential probing required."
            )

        # Cautious review
        if needs_evidence > 0:
            return (
                round(avg_conf * 0.75, 2),
                False,
                f"Council Caution: {needs_evidence} model(s) require active differential evidence."
            )

        return (avg_conf, False, "Standard consensus achieved.")


class CognitiveCouncil:
    """
    Master Cognitive Council Coordinator for HunterAI.
    Drives multi-model dialectic debate across the 3 local models.
    """

    DEFAULT_MODELS = {
        CouncilRole.OFFENSIVE_STRATEGIST: "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
        CouncilRole.CODE_AUDITOR: "qwen2.5-coder:14b",
        CouncilRole.CRITIC_JUDGE: "xploiter/pentester:latest",
    }

    def __init__(
        self,
        target_domain: str,
        ollama_host: Optional[str] = None,
        custom_models: Optional[Dict[CouncilRole, str]] = None,
    ):
        raw = (ollama_host or os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")).strip().rstrip("/")
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        self.ollama_host = raw.replace("://0.0.0.0:", "://127.0.0.1:")
        self.models = {**self.DEFAULT_MODELS, **(custom_models or {})}
        self.state = CouncilState(target_domain)
        self._online_status: Optional[bool] = None

    async def _query_model(
        self,
        role: CouncilRole,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        timeout: int = 15,
    ) -> str:
        """Asynchronously queries an individual model in the council via Ollama HTTP API."""
        if self._online_status is False:
            return ""

        model_name = self.models.get(role, self.DEFAULT_MODELS[role])
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "keep_alive": "5m",
            "options": {
                "temperature": temperature,
                "num_ctx": 4096,
            }
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        loop = asyncio.get_running_loop()

        def _do_http():
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    self._online_status = True
                    return res.get("message", {}).get("content", "").strip()
            except Exception as e:
                if self._online_status is None:
                    logger.debug(f"[Council] Ollama query failed for {role.value} ({e})")
                return ""

        return await loop.run_in_executor(None, _do_http)

    # ── 1. DIALECTIC DEBATE WORKFLOW ──────────────────────────────────────────
    async def debate_hypothesis(
        self,
        vuln_type: str,
        endpoint: str,
        parameter: Optional[str] = None,
        initial_observation: str = "",
        evidence_snippet: str = "",
    ) -> CouncilHypothesis:
        """
        Executes a full 3-model dialectic peer review:
        1. Model 1 (WhiteRabbitNeo): Formulates attack rationale & exploit hypothesis.
        2. Model 2 (Qwen Coder): Inspects code, parameter role & AST context.
        3. Model 3 (xploiter / Critic): Challenges the claim and demands proof.
        4. Detects disagreements & computes final council verdict.
        """
        claim_id = f"claim_{hash(f'{endpoint}:{parameter}:{vuln_type}') & 0xFFFFFFFF:08x}"
        hypothesis = CouncilHypothesis(
            claim_id=claim_id,
            vuln_type=vuln_type,
            endpoint=endpoint,
            parameter=parameter,
            initial_observation=initial_observation,
            status=HypothesisStatus.UNDER_DEBATE,
        )

        # Slices for each role
        ctx_offensive = self.state.get_context_slice_for_role(CouncilRole.OFFENSIVE_STRATEGIST, hypothesis)
        ctx_code = self.state.get_context_slice_for_role(CouncilRole.CODE_AUDITOR, hypothesis)
        ctx_critic = self.state.get_context_slice_for_role(CouncilRole.CRITIC_JUDGE, hypothesis)

        # ── Parallel Query Dispatch to the 3 Models ──
        async def _query_offensive() -> ModelVote:
            sys = (
                "You are WhiteRabbitNeo, Master Offensive Strategist on the AI Cognitive Council. "
                "Evaluate the attack hypothesis, assess impact, formulate payload rationale, and give a verdict."
            )
            usr = f"""Target Endpoint: {endpoint}
Parameter: {parameter or 'N/A'}
Vuln Class: {vuln_type}
Observation: {initial_observation}
Evidence Snippet: {evidence_snippet}
Target Tech: {ctx_offensive.get('technologies')}

Provide your assessment in JSON:
{{"verdict": "CONFIRM_VULN" | "NEEDS_MORE_EVIDENCE" | "SKEPTICAL_REJECT", "confidence": 0.0-1.0, "rationale": "...", "proposed_probe": "curl command or payload"}}
"""
            raw = await self._query_model(CouncilRole.OFFENSIVE_STRATEGIST, sys, usr, temperature=0.2)
            parsed = self._parse_vote_json(raw, CouncilRole.OFFENSIVE_STRATEGIST, self.models[CouncilRole.OFFENSIVE_STRATEGIST])
            return parsed

        async def _query_code() -> ModelVote:
            sys = (
                "You are Qwen 2.5 Coder, Code Intelligence Specialist on the AI Cognitive Council. "
                "Analyze the endpoint URL, parameter role, serialization format, and AST context."
            )
            usr = f"""Endpoint: {endpoint}
Parameter: {parameter or 'N/A'}
Vuln Type: {vuln_type}
Observation: {initial_observation}

Provide your assessment in JSON:
{{"verdict": "CONFIRM_VULN" | "NEEDS_MORE_EVIDENCE" | "SKEPTICAL_REJECT", "confidence": 0.0-1.0, "rationale": "...", "proposed_probe": "..."}}
"""
            raw = await self._query_model(CouncilRole.CODE_AUDITOR, sys, usr, temperature=0.1)
            parsed = self._parse_vote_json(raw, CouncilRole.CODE_AUDITOR, self.models[CouncilRole.CODE_AUDITOR])
            return parsed

        async def _query_critic() -> ModelVote:
            sys = (
                "You are xploiter/Critic Judge on the AI Cognitive Council. "
                "Your job is to AGGRESSIVELY CHALLENGE this claim: check for soft-404, reflection without execution, and generic 200 OK pages."
            )
            usr = f"""Claim: {vuln_type} on {endpoint} (param={parameter})
Evidence Snippet: {evidence_snippet}

Evaluate if this is genuine or false positive. Output JSON:
{{"verdict": "CONFIRM_VULN" | "NEEDS_MORE_EVIDENCE" | "SKEPTICAL_REJECT", "confidence": 0.0-1.0, "rationale": "...", "counter_arguments": ["..."]}}
"""
            raw = await self._query_model(CouncilRole.CRITIC_JUDGE, sys, usr, temperature=0.2)
            parsed = self._parse_vote_json(raw, CouncilRole.CRITIC_JUDGE, self.models[CouncilRole.CRITIC_JUDGE])
            return parsed

        # Run all 3 in parallel with timeout protection
        results = await asyncio.gather(
            _query_offensive(),
            _query_code(),
            _query_critic(),
            return_exceptions=True
        )

        vote_offensive = results[0] if isinstance(results[0], ModelVote) else self._default_fallback_vote(CouncilRole.OFFENSIVE_STRATEGIST)
        vote_code = results[1] if isinstance(results[1], ModelVote) else self._default_fallback_vote(CouncilRole.CODE_AUDITOR)
        vote_critic = results[2] if isinstance(results[2], ModelVote) else self._default_fallback_vote(CouncilRole.CRITIC_JUDGE)

        hypothesis.votes[CouncilRole.OFFENSIVE_STRATEGIST.value] = vote_offensive
        hypothesis.votes[CouncilRole.CODE_AUDITOR.value] = vote_code
        hypothesis.votes[CouncilRole.CRITIC_JUDGE.value] = vote_critic

        # Disagreement and consensus adjudication
        score, is_conflict, synth_reason = DisagreementDetector.evaluate_consensus(hypothesis.votes)
        hypothesis.consensus_score = score
        hypothesis.disagreement_detected = is_conflict
        hypothesis.debate_transcript.append({
            "stage": "peer_review",
            "synthesis": synth_reason,
            "votes": {k: v.to_dict() for k, v in hypothesis.votes.items()}
        })

        if is_conflict or score < 0.6:
            hypothesis.status = HypothesisStatus.UNPROVEN
            hypothesis.court_verdict = "HELD_FOR_DIFFERENTIAL_PROBE"
        elif score >= 0.8:
            hypothesis.status = HypothesisStatus.CONFIRMED
            hypothesis.court_verdict = "CONFIRMED_BY_COUNCIL"
        else:
            hypothesis.status = HypothesisStatus.ACTIVE_PROBING
            hypothesis.court_verdict = "ACTIVE_PROBING"

        self.state.hypotheses[claim_id] = hypothesis
        return hypothesis

    def _parse_vote_json(self, raw_text: str, role: CouncilRole, model_name: str) -> ModelVote:
        """Extracts JSON structure from model response or falls back to heuristic extraction."""
        if not raw_text:
            return self._default_fallback_vote(role)

        try:
            m = re.search(r"\{.*\}", raw_text, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                v_str = str(data.get("verdict", "")).upper()
                verdict = (
                    VoteVerdict.CONFIRM_VULN if "CONFIRM" in v_str else (
                        VoteVerdict.SKEPTICAL_REJECT if "REJECT" in v_str or "FALSE" in v_str else VoteVerdict.NEEDS_MORE_EVIDENCE
                    )
                )
                conf = float(data.get("confidence", 0.75))
                return ModelVote(
                    model_name=model_name,
                    role=role,
                    verdict=verdict,
                    confidence=max(0.1, min(1.0, conf)),
                    rationale=str(data.get("rationale", raw_text[:200])),
                    counter_arguments=data.get("counter_arguments", []),
                    proposed_probe=data.get("proposed_probe"),
                )
        except Exception:
            pass

        # Fallback text heuristics
        low = raw_text.lower()
        if "false positive" in low or "soft-404" in low or "reject" in low:
            verdict = VoteVerdict.SKEPTICAL_REJECT
            conf = 0.80
        elif "vulnerable" in low or "confirmed" in low or "exploit" in low:
            verdict = VoteVerdict.CONFIRM_VULN
            conf = 0.85
        else:
            verdict = VoteVerdict.NEEDS_MORE_EVIDENCE
            conf = 0.70

        return ModelVote(
            model_name=model_name,
            role=role,
            verdict=verdict,
            confidence=conf,
            rationale=raw_text[:250],
        )

    def _default_fallback_vote(self, role: CouncilRole) -> ModelVote:
        """Deterministic heuristic vote when model server is unreachable."""
        return ModelVote(
            model_name=self.models.get(role, "heuristic_engine"),
            role=role,
            verdict=VoteVerdict.HEURISTIC_PASS,
            confidence=0.75,
            rationale=f"Deterministic fallback evaluation for {role.value}.",
        )


# Global helper factory
def create_cognitive_council(target_domain: str, ollama_host: Optional[str] = None) -> CognitiveCouncil:
    return CognitiveCouncil(target_domain=target_domain, ollama_host=ollama_host)
