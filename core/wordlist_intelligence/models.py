"""
Wordlist Intelligence Models & Schemas
======================================
Defines categories, phases, metadata, target contexts, and generated candidates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class WordlistCategory(str, Enum):
    DNS = "dns"
    SUBDOMAINS = "subdomains"
    WEB_CONTENT = "web_content"
    DIRECTORIES = "directories"
    FILES = "files"
    API = "api"
    PARAMETERS = "parameters"
    FUZZING = "fuzzing"
    PAYLOADS = "payloads"
    AUTHENTICATION = "authentication"
    SECRETS = "secrets"
    LLM_SECURITY = "llm_security"
    CUSTOM = "custom"
    GENERIC = "generic"


class AttackPhase(str, Enum):
    PASSIVE_RECON = "passive_recon"
    ACTIVE_DNS = "active_dns"
    LIVE_PROBING = "live_probing"
    CRAWL_AND_SURFACE = "crawl_and_surface"
    CONTENT_DISCOVERY = "content_discovery"
    PARAMETER_FUZZING = "parameter_fuzzing"
    API_DISCOVERY = "api_discovery"
    VULNERABILITY_PROBE = "vulnerability_probe"
    LLM_ASSESSMENT = "llm_assessment"


class WordlistTier(str, Enum):
    SMALL = "small"      # <= 5,000 words
    MEDIUM = "medium"    # <= 50,000 words
    LARGE = "large"      # > 50,000 words


@dataclass
class WordlistMetadata:
    path: str
    filename: str
    category: WordlistCategory
    line_count: int = 0
    tier: WordlistTier = WordlistTier.SMALL
    tech_affinity: List[str] = field(default_factory=list)
    source_root: str = ""
    description: str = ""
    priority_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "category": self.category.value,
            "line_count": self.line_count,
            "tier": self.tier.value,
            "tech_affinity": self.tech_affinity,
            "source_root": self.source_root,
            "description": self.description,
            "priority_score": round(self.priority_score, 2),
        }


@dataclass
class GeneratedCandidate:
    candidate: str
    category: WordlistCategory
    origin_token: str = ""
    strategy: str = "direct"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate": self.candidate,
            "category": self.category.value,
            "origin_token": self.origin_token,
            "strategy": self.strategy,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class TargetContext:
    domain: str
    brand_tokens: List[str] = field(default_factory=list)
    detected_tech: Set[str] = field(default_factory=set)
    discovered_subdomains: Set[str] = field(default_factory=set)
    discovered_endpoints: Set[str] = field(default_factory=set)
    discovered_parameters: Set[str] = field(default_factory=set)
    discovered_words: Set[str] = field(default_factory=set)
    is_api_target: bool = False
    is_llm_target: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "brand_tokens": list(self.brand_tokens),
            "detected_tech": list(self.detected_tech),
            "discovered_subdomains_count": len(self.discovered_subdomains),
            "discovered_endpoints_count": len(self.discovered_endpoints),
            "discovered_parameters_count": len(self.discovered_parameters),
            "discovered_words_count": len(self.discovered_words),
            "is_api_target": self.is_api_target,
            "is_llm_target": self.is_llm_target,
        }
