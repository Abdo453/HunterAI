"""
Wordlist Classifier & Tagging Engine
====================================
Heuristic and pattern-based classification of wordlist files by category,
size tier, and technology affinity.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Tuple

from core.wordlist_intelligence.models import (
    WordlistCategory,
    WordlistMetadata,
    WordlistTier,
)

# Technology affinity detection patterns
TECH_PATTERNS = {
    "graphql": [r"graphql", r"gql", r"schema"],
    "spring": [r"spring", r"actuator", r"boot", r"jvm"],
    "nextjs": [r"nextjs", r"next", r"_next", r"vercel"],
    "wordpress": [r"wordpress", r"wp-", r"plugins", r"themes"],
    "django": [r"django", r"admin"],
    "rails": [r"rails", r"ruby"],
    "api": [r"api", r"swagger", r"openapi", r"v1", r"v2", r"rest", r"json", r"routes"],
    "aws": [r"aws", r"s3", r"cloud", r"bucket"],
    "firebase": [r"firebase", r"firestore"],
    "jwt": [r"jwt", r"token", r"oauth", r"openid"],
    "llm_testing": [r"llm", r"ai", r"prompt", r"bias", r"leakage", r"divergence", r"recall"],
    "lfi": [r"lfi", r"traversal", r"etc-passwd", r"win-ini"],
    "sqli": [r"sqli", r"sql-injection", r"generic-sqli"],
    "xss": [r"xss", r"cross-site-scripting"],
    "ssti": [r"ssti", r"template-injection", r"jinja", r"twig"],
}


class WordlistClassifier:
    """
    Analyzes wordlist file paths and metadata to classify their category and technology tags.
    """

    @classmethod
    def classify_file(cls, file_path: str | Path, source_root: str = "") -> WordlistMetadata:
        path_obj = Path(file_path)
        path_str = str(path_obj).replace("\\", "/")
        filename = path_obj.name.lower()
        full_lower = path_str.lower()

        # 1. Determine Category
        category = cls._determine_category(full_lower, filename)

        # 2. Estimate line count / size tier
        line_count = cls._estimate_line_count(path_obj)
        tier = cls._determine_tier(line_count, filename=filename)

        # 3. Detect technology affinity
        tech_affinity = cls._detect_tech_affinity(full_lower, filename)

        # 4. Calculate Priority Score (higher = better general-purpose list)
        priority = cls._calculate_priority(full_lower, filename, line_count, category)

        return WordlistMetadata(
            path=str(path_obj.resolve()),
            filename=path_obj.name,
            category=category,
            line_count=line_count,
            tier=tier,
            tech_affinity=tech_affinity,
            source_root=source_root,
            description=f"{category.value.upper()} wordlist ({line_count} entries)",
            priority_score=priority,
        )

    @staticmethod
    def _determine_category(full_lower: str, filename: str) -> WordlistCategory:
        # LLM / AI Testing
        if "ai/llm_testing" in full_lower or "llm_testing" in full_lower or "prompt" in filename:
            return WordlistCategory.LLM_SECURITY

        # DNS / Subdomains
        if "discovery/dns" in full_lower or "dns" in filename or "subdomain" in filename or "subdomains" in full_lower:
            return WordlistCategory.DNS

        # API
        if "discovery/web-content/api" in full_lower or "api" in filename or "swagger" in filename or "openapi" in filename:
            return WordlistCategory.API

        # Parameters
        if "parameter" in full_lower or "params" in filename or "burp-parameter" in filename:
            return WordlistCategory.PARAMETERS

        # Web Content / Directories / Files
        if "discovery/web-content" in full_lower or "directory-list" in filename or "directories" in filename:
            return WordlistCategory.DIRECTORIES
        if "raft-" in filename and "-files" in filename:
            return WordlistCategory.FILES
        if "discovery/web-content" in full_lower or "common.txt" in filename or "raft-" in filename:
            return WordlistCategory.WEB_CONTENT

        # Fuzzing & Payloads
        if "fuzzing" in full_lower or "payloads" in full_lower or "fuzz" in filename:
            return WordlistCategory.FUZZING

        # Passwords / Auth
        if "passwords" in full_lower or "password" in filename or "rockyou" in filename or "credential" in filename:
            return WordlistCategory.AUTHENTICATION

        if "secrets" in full_lower or "leak" in full_lower or "key" in filename:
            return WordlistCategory.SECRETS

        return WordlistCategory.GENERIC

    @staticmethod
    def _estimate_line_count(path: Path) -> int:
        try:
            # Fast binary line counting
            lines = 0
            has_bytes = False
            last_byte = b""
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    if chunk:
                        has_bytes = True
                        lines += chunk.count(b"\n")
                        last_byte = chunk[-1:]
            if has_bytes and last_byte != b"\n":
                lines += 1
            return max(lines, 1 if has_bytes else 0)
        except Exception:
            return 0

    @staticmethod
    def _determine_tier(line_count: int, filename: str = "") -> WordlistTier:
        f_lower = filename.lower()
        if "110000" in f_lower or "100000" in f_lower or "-large" in f_lower or "_large" in f_lower:
            return WordlistTier.LARGE
        if "50000" in f_lower or "20000" in f_lower or "-medium" in f_lower or "_medium" in f_lower:
            return WordlistTier.MEDIUM
        if "5000" in f_lower or "1000" in f_lower or "-small" in f_lower or "_small" in f_lower or "common" in f_lower:
            return WordlistTier.SMALL
        if line_count <= 5000:
            return WordlistTier.SMALL
        elif line_count <= 50000:
            return WordlistTier.MEDIUM
        return WordlistTier.LARGE

    @staticmethod
    def _detect_tech_affinity(full_lower: str, filename: str) -> List[str]:
        affinities = []
        for tech, patterns in TECH_PATTERNS.items():
            if any(p in full_lower or re.search(p, filename) for p in patterns):
                affinities.append(tech)
        return affinities

    @staticmethod
    def _calculate_priority(full_lower: str, filename: str, line_count: int, category: WordlistCategory) -> float:
        score = 1.0
        # Highly regarded lists in SecLists
        if "jhaddix" in full_lower:
            score += 0.8
        if "raft-" in full_lower:
            score += 0.7
        if "top1million" in full_lower:
            score += 0.6
        if "best-dns-wordlist" in full_lower or "best-dns" in filename:
            score += 1.0
        if "common.txt" in filename:
            score += 0.5
        if "directory-list-2.3-medium" in filename:
            score += 0.9

        # Balance utility: lists between 2k and 50k have high practical utility
        if 2000 <= line_count <= 50000:
            score += 0.3
        elif line_count > 200000:
            score -= 0.2  # Massive lists penalized for initial fast passes

        return max(0.1, score)
