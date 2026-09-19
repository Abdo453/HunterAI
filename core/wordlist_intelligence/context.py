"""
Target Context & Attack Surface Intelligence State
==================================================
Maintains runtime context of discovered technologies, subdomains,
endpoints, and vocabulary tokens.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

from core.wordlist_intelligence.models import TargetContext

STOP_WORDS = {
    "com", "net", "org", "mx", "io", "co", "uk", "de", "us", "app", "dev",
    "http", "https", "www", "html", "htm", "php", "jsp", "asp", "aspx", "js", "css"
}


class ContextAnalyzer:
    """
    Analyzes targets, extracts semantic tokens, and maintains real-time context.
    """

    @classmethod
    def create_initial_context(cls, target_url_or_domain: str) -> TargetContext:
        """Initializes target context with extracted domain and brand tokens."""
        raw = target_url_or_domain.strip().lower()
        if "://" in raw:
            parsed = urlparse(raw)
            domain = parsed.hostname or raw.split("/")[0]
        else:
            domain = raw.split("/")[0].split(":")[0]

        # Tokenize domain
        brand_tokens = cls.extract_domain_tokens(domain)

        return TargetContext(
            domain=domain,
            brand_tokens=brand_tokens,
            detected_tech=set(),
            discovered_subdomains={domain},
            discovered_endpoints=set(),
            discovered_parameters=set(),
            discovered_words=set(brand_tokens),
        )

    @classmethod
    def extract_domain_tokens(cls, domain: str) -> List[str]:
        """Extracts brand and vocabulary roots from domain name."""
        tokens: Set[str] = set()
        clean = domain.lower()
        parts = clean.split(".")

        for part in parts:
            if not part or part in STOP_WORDS:
                continue
            tokens.add(part)
            # Sub-split hyphens/underscores (e.g. banco-plata -> banco, plata, bancoplata)
            subparts = re.split(r"[-_]", part)
            for sp in subparts:
                if len(sp) >= 3 and sp not in STOP_WORDS:
                    tokens.add(sp)

            # Common compound splitting (e.g., bancoplata -> banco, plata if recognized)
            if "banco" in part:
                tokens.add("banco")
                rem = part.replace("banco", "")
                if len(rem) >= 3:
                    tokens.add(rem)

        return sorted(list(tokens))

    @classmethod
    def ingest_technology(cls, context: TargetContext, tech_name: str) -> None:
        """Ingests a detected technology and updates context flags."""
        t_clean = tech_name.lower().strip()
        context.detected_tech.add(t_clean)
        norm = re.sub(r"[^a-z0-9]", "", t_clean)
        if norm and norm != t_clean:
            context.detected_tech.add(norm)
        if t_clean in ("api", "graphql", "swagger", "openapi", "rest", "fastapi") or "api" in t_clean or "graphql" in t_clean:
            context.is_api_target = True
        if t_clean in ("llm", "ai", "ollama", "openai", "claude", "langchain") or "llm" in t_clean or "ai" in t_clean:
            context.is_llm_target = True

    @classmethod
    def ingest_subdomains(cls, context: TargetContext, subdomains: Iterable[str]) -> None:
        """Extracts sub-tokens from discovered subdomains."""
        for sub in subdomains:
            if not sub:
                continue
            sub_clean = sub.strip().lower()
            context.discovered_subdomains.add(sub_clean)

            # Extract prefix tokens (e.g. api.banco.mx -> api, banco)
            parts = sub_clean.split(".")
            for p in parts:
                if p and p not in STOP_WORDS and len(p) >= 2:
                    context.discovered_words.add(p)
                    for chunk in re.split(r"[-_0-9]", p):
                        if len(chunk) >= 2 and chunk not in STOP_WORDS:
                            context.discovered_words.add(chunk)

            if "api" in sub_clean:
                context.is_api_target = True

    @classmethod
    def ingest_endpoints(cls, context: TargetContext, endpoints: Iterable[str]) -> None:
        """Extracts route tokens from discovered endpoints."""
        for ep in endpoints:
            if not ep:
                continue
            context.discovered_endpoints.add(ep)
            try:
                parsed = urlparse(ep if "://" in ep else f"http://{context.domain}/{ep.lstrip('/')}")
                path_parts = [p for p in parsed.path.split("/") if p]
                for seg in path_parts:
                    clean_seg = re.sub(r"\.[a-zA-Z0-9]+$", "", seg)  # strip extension
                    if len(clean_seg) >= 2 and clean_seg not in STOP_WORDS:
                        context.discovered_words.add(clean_seg)
                        if clean_seg in ("api", "v1", "v2", "graphql", "swagger"):
                            context.is_api_target = True
            except Exception:
                pass

    @classmethod
    def ingest_parameters(cls, context: TargetContext, params: Iterable[str]) -> None:
        """Ingests observed query parameter names."""
        for p in params:
            if not p:
                continue
            p_clean = p.strip().lower()
            context.discovered_parameters.add(p_clean)
            context.discovered_words.add(p_clean)
