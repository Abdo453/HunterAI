"""
Master Wordlist Intelligence Agent
==================================
Autonomous agent coordinating wordlist discovery, context analysis,
intelligent selection, mutation generation, and feedback learning.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.wordlist_intelligence.classifier import WordlistClassifier
from core.wordlist_intelligence.context import ContextAnalyzer
from core.wordlist_intelligence.deduplicator import WordlistDeduplicator
from core.wordlist_intelligence.feedback import AdaptiveFeedbackLoop
from core.wordlist_intelligence.inventory import WordlistInventory
from core.wordlist_intelligence.models import (
    AttackPhase,
    GeneratedCandidate,
    TargetContext,
    WordlistCategory,
    WordlistMetadata,
)
from core.wordlist_intelligence.mutator import CandidateMutator
from core.wordlist_intelligence.selector import WordlistSelector

logger = logging.getLogger("hunter_ai.wordlist_agent")


class WordlistIntelligenceAgent:
    """
    Unified Wordlist Intelligence Agent for HunterAI.
    """

    def __init__(
        self,
        target: Optional[str] = None,
        custom_roots: Optional[List[str | Path]] = None,
        auto_index: bool = True,
    ):
        self.inventory = WordlistInventory(custom_roots=custom_roots)
        if auto_index:
            self.inventory.refresh_inventory()

        self.selector = WordlistSelector(self.inventory)
        self.context = ContextAnalyzer.create_initial_context(target or "example.com")
        self.feedback = AdaptiveFeedbackLoop(self.context)

    def set_target(self, target: str) -> TargetContext:
        """Initializes or resets target context."""
        self.context = ContextAnalyzer.create_initial_context(target)
        self.feedback = AdaptiveFeedbackLoop(self.context)
        return self.context

    # ── 1. CONTEXTUAL RESOLUTION API ──────────────────────────────────────────
    def resolve_wordlist_path(
        self,
        category: str | WordlistCategory,
        profile: str = "standard",
        context: Optional[TargetContext] = None,
    ) -> str:
        """
        Resolves the absolute path to the optimal wordlist matching category & context.
        """
        ctx = context or self.context
        if isinstance(category, str):
            try:
                cat_enum = WordlistCategory(category.lower())
            except ValueError:
                cat_enum = WordlistCategory.GENERIC
        else:
            cat_enum = category

        best = self.selector.select_best_wordlist(cat_enum, context=ctx, profile=profile)
        if best and os.path.isfile(best.path):
            return best.path

        # Fallback to default common.txt in local_fallback_root
        fallback = self.inventory.local_fallback_root / "common.txt"
        return str(fallback.resolve())

    def get_wordlist_for_phase(
        self,
        phase: AttackPhase,
        profile: str = "standard",
        context: Optional[TargetContext] = None,
    ) -> str:
        """Resolves wordlist specifically for an attack phase."""
        cat = self.selector.get_phase_category(phase)
        return self.resolve_wordlist_path(cat, profile=profile, context=context)

    # ── 2. MUTATION & CUSTOM WORDLIST GENERATION ──────────────────────────────
    def generate_custom_candidates(
        self,
        category: WordlistCategory = WordlistCategory.SUBDOMAINS,
        max_candidates: int = 300,
    ) -> List[str]:
        """Generates dynamic, context-derived wordlist candidates."""
        if category in (WordlistCategory.SUBDOMAINS, WordlistCategory.DNS):
            cands = CandidateMutator.generate_subdomain_candidates(self.context, max_candidates=max_candidates)
        elif category in (WordlistCategory.PARAMETERS,):
            cands = CandidateMutator.generate_parameter_candidates(self.context, max_candidates=max_candidates)
        else:
            cands = CandidateMutator.generate_path_candidates(self.context, max_candidates=max_candidates)

        return [c.candidate for c in cands]

    def build_custom_wordlist_file(
        self,
        destination_path: str | Path,
        category: WordlistCategory = WordlistCategory.DIRECTORIES,
        include_base_static: bool = True,
        max_candidates: int = 500,
    ) -> str:
        """
        Creates a hybrid wordlist combining static high-priority terms + mutated target tokens.
        """
        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        items: List[str] = []

        # 1. Add generated dynamic candidates first (highest context specificity)
        custom_cands = self.generate_custom_candidates(category, max_candidates=max_candidates)
        items.extend(custom_cands)

        # 2. Append base static list if requested
        if include_base_static:
            static_list_path = self.resolve_wordlist_path(category, profile="safe")
            if static_list_path and os.path.isfile(static_list_path):
                try:
                    with open(static_list_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            cleaned = line.strip()
                            if cleaned and not cleaned.startswith("#"):
                                items.append(cleaned)
                except Exception:
                    pass

        WordlistDeduplicator.write_deduplicated_file(
            items,
            dest,
            header_comment=f"HunterAI Custom Wordlist for {self.context.domain} ({category.value})"
        )
        logger.info(f"[WordlistAgent] Generated custom wordlist with {len(items)} items at: {dest}")
        return str(dest.resolve())

    # ── 3. ADAPTIVE FEEDBACK INGESTION ────────────────────────────────────────
    def ingest_discovery(self, discovery_type: str, items: Iterable[str]) -> List[str]:
        """
        Ingests findings and returns immediately generated next-stage mutations.
        """
        d_type = discovery_type.lower().strip()
        if d_type in ("subdomain", "subdomains"):
            cands = self.feedback.on_subdomains_discovered(items)
            return [c.candidate for c in cands]
        elif d_type in ("technology", "technologies", "tech"):
            cands = self.feedback.on_technologies_discovered(items)
            return [c.candidate for c in cands]
        elif d_type in ("endpoint", "endpoints", "urls", "url"):
            cands = self.feedback.on_endpoints_discovered(items)
            return [c.candidate for c in cands]
        elif d_type in ("parameter", "parameters", "param"):
            self.feedback.on_parameters_discovered(items)
            return []
        return []

    # ── 4. EXPORT & DIAGNOSTICS ───────────────────────────────────────────────
    def export_inventory_summary(self) -> Dict[str, Any]:
        """Returns structured inventory diagnostics."""
        cat_counts: Dict[str, int] = {}
        for m in self.inventory.catalog.values():
            c = m.category.value
            cat_counts[c] = cat_counts.get(c, 0) + 1

        return {
            "total_wordlists": len(self.inventory.catalog),
            "active_roots": [str(r) for r in self.inventory.get_active_roots()],
            "categories_breakdown": cat_counts,
            "target_context": self.context.to_dict(),
        }
