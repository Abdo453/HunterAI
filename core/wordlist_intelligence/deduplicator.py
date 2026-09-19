"""
Wordlist Deduplication & Stream Normalizer
==========================================
Provides memory-efficient streaming deduplication, normalization,
and sorting for wordlists and generated candidate sets.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Set


class WordlistDeduplicator:
    """
    Normalizes and deduplicates wordlist tokens.
    """

    @staticmethod
    def deduplicate_list(items: Iterable[str], lowercase: bool = True, strip_comments: bool = True) -> List[str]:
        """Deduplicates list while preserving first-seen order."""
        seen: Set[str] = set()
        results: List[str] = []

        for raw in items:
            if not raw:
                continue
            item = raw.strip()
            if strip_comments and (item.startswith("#") or item.startswith("//")):
                continue
            if not item:
                continue

            normalized = item.lower() if lowercase else item
            if normalized not in seen:
                seen.add(normalized)
                results.append(normalized if lowercase else item)

        return results

    @staticmethod
    def write_deduplicated_file(
        items: Iterable[str],
        destination_path: str | Path,
        lowercase: bool = True,
        header_comment: str = ""
    ) -> int:
        """Writes deduplicated words directly to a file."""
        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        deduped = WordlistDeduplicator.deduplicate_list(items, lowercase=lowercase)
        with open(dest, "w", encoding="utf-8") as f:
            if header_comment:
                f.write(f"# {header_comment}\n")
            for line in deduped:
                f.write(f"{line}\n")

        return len(deduped)
