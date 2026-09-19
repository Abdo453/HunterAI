"""
Adaptive Recon Feedback Loop
============================
Ingests reconnaissance discoveries from active stages, extracts new tokens,
and dynamically generates next-phase wordlists.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List

from core.wordlist_intelligence.context import ContextAnalyzer
from core.wordlist_intelligence.models import (
    GeneratedCandidate,
    TargetContext,
    WordlistCategory,
)
from core.wordlist_intelligence.mutator import CandidateMutator

logger = logging.getLogger("hunter_ai.wordlist_feedback")


class AdaptiveFeedbackLoop:
    """
    Coordinates adaptive learning: discoveries in Stage N generate targeted wordlists for Stage N+1.
    """

    def __init__(self, context: TargetContext):
        self.context = context
        self.history: List[Dict[str, Any]] = []

    def on_subdomains_discovered(self, subdomains: Iterable[str]) -> List[GeneratedCandidate]:
        """Triggered when new subdomains are found: ingests tokens and builds mutations."""
        ContextAnalyzer.ingest_subdomains(self.context, subdomains)
        mutated = CandidateMutator.generate_subdomain_candidates(self.context, max_candidates=250)
        self.history.append({
            "stage": "subdomains",
            "ingested_count": len(list(subdomains)),
            "generated_candidates": len(mutated),
        })
        logger.debug(f"[FeedbackLoop] Ingested subdomains -> Generated {len(mutated)} custom mutated candidates.")
        return mutated

    def on_technologies_discovered(self, technologies: Iterable[str]) -> List[GeneratedCandidate]:
        """Triggered when web technologies are detected: generates technology-specific paths."""
        for tech in technologies:
            ContextAnalyzer.ingest_technology(self.context, tech)
        path_cands = CandidateMutator.generate_path_candidates(self.context, max_candidates=250)
        self.history.append({
            "stage": "technologies",
            "ingested_tech": list(technologies),
            "generated_candidates": len(path_cands),
        })
        return path_cands

    def on_endpoints_discovered(self, endpoints: Iterable[str]) -> List[GeneratedCandidate]:
        """Triggered when new URL endpoints are found: extracts route tokens and generates parameter candidates."""
        ContextAnalyzer.ingest_endpoints(self.context, endpoints)
        param_cands = CandidateMutator.generate_parameter_candidates(self.context, max_candidates=150)
        self.history.append({
            "stage": "endpoints",
            "ingested_count": len(list(endpoints)),
            "generated_candidates": len(param_cands),
        })
        return param_cands

    def on_parameters_discovered(self, parameters: Iterable[str]) -> None:
        """Triggered when parameters are cataloged."""
        ContextAnalyzer.ingest_parameters(self.context, parameters)
