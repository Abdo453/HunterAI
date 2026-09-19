"""
Context-Aware Wordlist Selector
================================
Selects the optimal wordlist or wordlist combination for a given attack phase,
target context, and profile budget.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from core.wordlist_intelligence.inventory import WordlistInventory
from core.wordlist_intelligence.models import (
    AttackPhase,
    TargetContext,
    WordlistCategory,
    WordlistMetadata,
    WordlistTier,
)

logger = logging.getLogger("hunter_ai.wordlist_selector")


class WordlistSelector:
    """
    Selects wordlists tailored to target context and execution profile.
    """

    def __init__(self, inventory: WordlistInventory):
        self.inventory = inventory

    def select_best_wordlist(
        self,
        category: WordlistCategory,
        context: Optional[TargetContext] = None,
        profile: str = "standard",
        max_lines_override: Optional[int] = None,
    ) -> Optional[WordlistMetadata]:
        """
        Selects the single best wordlist for the category matching target context.
        """
        candidates = self.inventory.find_by_category(category)
        if not candidates:
            # Fallback to generic or all catalog entries
            candidates = list(self.inventory.catalog.values())

        if not candidates:
            return None

        # Determine target tier based on profile
        profile_lower = (profile or "standard").lower()
        if profile_lower in ("safe", "fast", "passive"):
            target_tier = WordlistTier.SMALL
            max_lines = max_lines_override or 5000
        elif profile_lower in ("deep", "hunter", "full", "patient"):
            target_tier = WordlistTier.LARGE
            max_lines = max_lines_override or 250000
        else:
            target_tier = WordlistTier.MEDIUM
            max_lines = max_lines_override or 50000

        # Score candidates
        scored: List[tuple[float, WordlistMetadata]] = []
        for m in candidates:
            if m.line_count > max_lines:
                continue

            score = m.priority_score

            # Tier score alignment
            if m.tier == target_tier:
                score += 2.5
            elif profile_lower in ("safe", "fast", "passive") and m.tier in (WordlistTier.LARGE, WordlistTier.MEDIUM):
                score -= 3.0
            elif profile_lower in ("deep", "hunter", "full") and m.tier == WordlistTier.SMALL:
                score -= 0.5

            # Boost technology match if context is present
            if context and context.detected_tech:
                for tech in context.detected_tech:
                    if tech in m.tech_affinity:
                        score += 3.0

            # Specific high-value list boosts
            fname_lower = m.filename.lower()
            if category in (WordlistCategory.DNS, WordlistCategory.SUBDOMAINS):
                if "best-dns-wordlist" in fname_lower:
                    score += 2.5
                elif "subdomains-top1million-110000" in fname_lower:
                    score += 2.0 if profile_lower in ("deep", "hunter", "full") else -2.0
                elif "subdomains-top1million-20000" in fname_lower:
                    score += 1.8 if profile_lower == "standard" else 0.5
                elif "subdomains-top1million-5000" in fname_lower or "top5000" in fname_lower:
                    score += 2.5 if profile_lower in ("safe", "fast", "passive") else 0.5
                elif "subdomains" in fname_lower or "dns" in fname_lower:
                    score += 1.0
            elif category in (WordlistCategory.DIRECTORIES, WordlistCategory.WEB_CONTENT):
                if "directory-list-2.3-medium" in fname_lower:
                    score += 2.0
                elif "raft-medium" in fname_lower:
                    score += 1.8
                elif "common.txt" in fname_lower:
                    score += 2.0 if profile_lower in ("safe", "fast", "passive") else 1.0

            scored.append((score, m))

        if not scored:
            # If all were above max_lines, pick the smallest available
            candidates.sort(key=lambda x: x.line_count)
            return candidates[0]

        scored.sort(key=lambda x: x[0], reverse=True)
        best = scored[0][1]
        logger.debug(f"[WordlistSelector] Selected '{best.filename}' for category '{category.value}' (Score: {scored[0][0]:.2f})")
        return best

    def select_tech_specific_wordlists(self, context: TargetContext) -> List[WordlistMetadata]:
        """Returns specialized wordlists for any detected technologies (e.g. GraphQL, Spring, Next.js)."""
        tech_lists: List[WordlistMetadata] = []
        for tech in context.detected_tech:
            matches = self.inventory.find_by_tech(tech)
            tech_lists.extend(matches)
        return tech_lists

    def select_technology_specific_wordlists(self, context: TargetContext) -> List[WordlistMetadata]:
        """Alias for select_tech_specific_wordlists."""
        return self.select_tech_specific_wordlists(context)

    def get_phase_category(self, phase: AttackPhase) -> WordlistCategory:
        mapping = {
            AttackPhase.PASSIVE_RECON: WordlistCategory.DNS,
            AttackPhase.ACTIVE_DNS: WordlistCategory.DNS,
            AttackPhase.LIVE_PROBING: WordlistCategory.WEB_CONTENT,
            AttackPhase.CRAWL_AND_SURFACE: WordlistCategory.DIRECTORIES,
            AttackPhase.CONTENT_DISCOVERY: WordlistCategory.DIRECTORIES,
            AttackPhase.PARAMETER_FUZZING: WordlistCategory.PARAMETERS,
            AttackPhase.API_DISCOVERY: WordlistCategory.API,
            AttackPhase.VULNERABILITY_PROBE: WordlistCategory.FUZZING,
            AttackPhase.LLM_ASSESSMENT: WordlistCategory.LLM_SECURITY,
        }
        return mapping.get(phase, WordlistCategory.GENERIC)
