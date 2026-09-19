"""
Candidate Mutation & Permutation Engine
=======================================
Generates intelligent, context-aware permutations from observed tokens,
brand terms, and discovered technologies.
"""
from __future__ import annotations

from typing import List, Set

from core.wordlist_intelligence.models import (
    GeneratedCandidate,
    TargetContext,
    WordlistCategory,
)

ENV_PREFIXES = ["dev", "staging", "test", "stage", "prod", "uat", "qa", "internal", "corp", "vpn", "admin", "api", "auth", "portal", "app"]
ENV_SUFFIXES = ["dev", "staging", "test", "prod", "uat", "qa", "internal", "corp", "vpn", "admin", "api", "auth", "portal", "app", "v1", "v2", "beta"]
SEPARATORS = ["-", "_", ""]

TECH_SPECIFIC_PATHS = {
    "graphql": [
        "graphql", "graphiql", "graphql/console", "api/graphql", "v1/graphql",
        "v2/graphql", "gql", "query", "graphql.php", "graphql/schema.json"
    ],
    "spring": [
        "actuator", "actuator/health", "actuator/env", "actuator/metrics",
        "actuator/mappings", "actuator/beans", "actuator/heapdump", "actuator/info",
        "actuator/logfile", "swagger-ui.html", "v2/api-docs", "v3/api-docs"
    ],
    "nextjs": [
        "_next/static", "_next/data", "api/auth/[...nextauth]", "api/trpc",
        "api/hello", "_next/image", "api/health"
    ],
    "wordpress": [
        "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
        "wp-json/wp/v2/users", "xmlrpc.php", "wp-config.php.bak"
    ],
    "django": [
        "admin", "admin/login", "api", "static", "media", "__debug__"
    ],
}


class CandidateMutator:
    """
    Generates tailored permutation candidates based on target context.
    """

    @classmethod
    def generate_subdomain_candidates(cls, context: TargetContext, max_candidates: int = 500) -> List[GeneratedCandidate]:
        """Generates mutated subdomain prefix candidates based on observed tokens."""
        candidates: List[GeneratedCandidate] = []
        seen: Set[str] = set()

        base_tokens = list(context.brand_tokens) + list(context.discovered_words)
        filtered_tokens = [t for t in base_tokens if len(t) >= 2 and len(t) <= 20][:30]

        # 1. Environment combinations (e.g., api-dev, dev-api, bancoplata-dev)
        for token in filtered_tokens:
            for env in ENV_SUFFIXES:
                for sep in ["-", ""]:
                    cand1 = f"{token}{sep}{env}"
                    if cand1 not in seen:
                        seen.add(cand1)
                        candidates.append(GeneratedCandidate(
                            candidate=cand1,
                            category=WordlistCategory.SUBDOMAINS,
                            origin_token=token,
                            strategy="suffix_env",
                            confidence=0.90 if env in ("dev", "api", "staging") else 0.75
                        ))

            for env in ENV_PREFIXES:
                for sep in ["-", ""]:
                    cand2 = f"{env}{sep}{token}"
                    if cand2 not in seen:
                        seen.add(cand2)
                        candidates.append(GeneratedCandidate(
                            candidate=cand2,
                            category=WordlistCategory.SUBDOMAINS,
                            origin_token=token,
                            strategy="prefix_env",
                            confidence=0.85
                        ))

        # 2. Numbered variations (e.g., api1, api2, dev1, dev2)
        for token in filtered_tokens[:15]:
            for i in range(1, 4):
                cand = f"{token}{i}"
                if cand not in seen:
                    seen.add(cand)
                    candidates.append(GeneratedCandidate(
                        candidate=cand,
                        category=WordlistCategory.SUBDOMAINS,
                        origin_token=token,
                        strategy="numeric_version",
                        confidence=0.70
                    ))

        # Sort by confidence
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates[:max_candidates]

    @classmethod
    def generate_path_candidates(cls, context: TargetContext, max_candidates: int = 500) -> List[GeneratedCandidate]:
        """Generates mutated web path & endpoint candidates."""
        candidates: List[GeneratedCandidate] = []
        seen: Set[str] = set()

        base_tokens = list(context.brand_tokens) + list(context.discovered_words)
        filtered_tokens = [t for t in base_tokens if len(t) >= 2 and len(t) <= 20][:30]

        # 1. Technology specific paths
        for tech in context.detected_tech:
            t_lower = tech.lower()
            if t_lower in TECH_SPECIFIC_PATHS:
                for path in TECH_SPECIFIC_PATHS[t_lower]:
                    if path not in seen:
                        seen.add(path)
                        candidates.append(GeneratedCandidate(
                            candidate=path,
                            category=WordlistCategory.DIRECTORIES,
                            origin_token=tech,
                            strategy=f"tech_specific_{tech}",
                            confidence=0.95
                        ))

        # 2. API & Routing Permutations
        for token in filtered_tokens:
            for prefix in ["api", "api/v1", "api/v2", "v1", "v2", "admin", "dashboard", "portal", "internal"]:
                cand = f"{prefix}/{token}"
                if cand not in seen:
                    seen.add(cand)
                    candidates.append(GeneratedCandidate(
                        candidate=cand,
                        category=WordlistCategory.DIRECTORIES,
                        origin_token=token,
                        strategy="api_route",
                        confidence=0.85
                    ))

        # 3. Direct tokens
        for token in filtered_tokens:
            if token not in seen:
                seen.add(token)
                candidates.append(GeneratedCandidate(
                    candidate=token,
                    category=WordlistCategory.DIRECTORIES,
                    origin_token=token,
                    strategy="direct_token",
                    confidence=0.80
                ))

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates[:max_candidates]

    @classmethod
    def generate_parameter_candidates(cls, context: TargetContext, max_candidates: int = 200) -> List[GeneratedCandidate]:
        """Generates mutated query/body parameter name candidates."""
        candidates: List[GeneratedCandidate] = []
        seen: Set[str] = set()

        base_tokens = list(context.brand_tokens) + list(context.discovered_words)
        filtered_tokens = [t for t in base_tokens if len(t) >= 2 and len(t) <= 20][:25]

        param_suffixes = ["id", "key", "token", "url", "type", "name", "file", "path", "code", "secret", "user"]
        for token in filtered_tokens:
            for suff in param_suffixes:
                for sep in ["_", ""]:
                    cand = f"{token}{sep}{suff}"
                    if cand not in seen:
                        seen.add(cand)
                        candidates.append(GeneratedCandidate(
                            candidate=cand,
                            category=WordlistCategory.PARAMETERS,
                            origin_token=token,
                            strategy="param_suffix",
                            confidence=0.85
                        ))

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates[:max_candidates]
