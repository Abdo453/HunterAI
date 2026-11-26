"""
HunterAI Prompt Injection Firewall & Untrusted Data Isolation
=============================================================
Treats all data originating from target web applications, tool outputs,
external feeds, and external RAG entries strictly as UNTRUSTED_DATA.
Strips invisible zero-width / bidi / Unicode tag smuggling characters,
scans for adversarial instruction overrides, neutralizes delimiter-escape
attempts, and wraps content in random per-call nonce-delimited tags:
``<untrusted_data nonce="..." source="..." trust_tier="...">``.
"""
from __future__ import annotations

import logging
import re
import secrets
import unicodedata
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("hunter_ai.prompt_injection_firewall")

# Zero-width, bidi override/isolate, soft hyphen, BOM, and Unicode tag smuggling chars
_INVISIBLE_AND_BIDI_RE = re.compile(
    r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]"
)

_DELIMITER_ESCAPE_RE = re.compile(
    r"(?i)</?\s*untrusted_(?:web_)?data\b[^>]*>"
)

ADVERSARIAL_PATTERNS = [
    r"(?i)\bignore\s+(?:all\s+)?(?:previous\s+|prior\s+|above\s+)?instructions\b",
    r"(?i)\bforget\s+(?:all\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules)\b",
    r"(?i)\byou\s+are\s+now\s+(?:a|an)\s+[a-z0-9_\-\s]+",
    r"(?i)\bsystem\s+prompt\s+override\b",
    r"(?i)\bnew\s+system\s+instructions\b",
    r"(?i)\bdisregard\s+(?:all\s+)?(?:rules|instructions|policies)\b",
    r"(?i)\bleak\s+(?:your\s+)?(?:secrets|api\s*key|tokens|credentials)\b",
    r"(?i)\boutput\s+(?:all\s+)?(?:environment\s+variables|env)\b",
    r"(?i)\bact\s+as\s+a\s+rogue\s+agent\b",
    r"(?i)<\|(?:im_start|im_end|system)\|>",
]


class PromptInjectionFirewall:
    """Protects LLM cognitive layer from malicious target web, feed, and RAG content."""

    @classmethod
    def strip_invisible_and_bidi(cls, text: str) -> Tuple[str, int]:
        """Remove zero-width, bidi-override/isolate, and Unicode tag smuggling characters."""
        if not text:
            return "", 0
        cleaned, count = _INVISIBLE_AND_BIDI_RE.subn("", text)
        return cleaned, count

    @classmethod
    def inspect(
        cls,
        raw_content: str,
        source_label: str = "web_response",
        trust_tier: str = "untrusted_external",
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Inspects content and wraps it in random per-call nonce framing.
        Returns ``(is_safe, isolated_content, audit_record)``.
        """
        if not raw_content:
            return True, "", {}

        safe_source = re.sub(r"[^A-Za-z0-9._:/-]", "_", str(source_label or "unknown"))[:80]
        safe_tier = re.sub(r"[^A-Za-z0-9_-]", "_", str(trust_tier or "untrusted_external"))[:40]
        nonce = secrets.token_hex(12)

        # 1. Strip invisible zero-width and bidi override characters before inspection
        cleaned, stripped_count = cls.strip_invisible_and_bidi(str(raw_content))

        # 2. Neutralize any attacker attempt to forge/close untrusted_data framing tags
        delimiter_escape_found = bool(_DELIMITER_ESCAPE_RE.search(cleaned))
        cleaned = _DELIMITER_ESCAPE_RE.sub("[NEUTRALIZED_DELIMITER_TAG]", cleaned)

        # 3. Scan NFKC-normalized text so homoglyph/fullwidth obfuscations are still caught
        normalized_for_scan = unicodedata.normalize("NFKC", cleaned)
        found_patterns: List[str] = []
        for pat in ADVERSARIAL_PATTERNS:
            if re.search(pat, cleaned) or re.search(pat, normalized_for_scan):
                found_patterns.append(pat)

        if found_patterns or delimiter_escape_found:
            audit = {
                "event": "PROMPT_INJECTION_DETECTED",
                "source": safe_source,
                "trust": "UNTRUSTED",
                "trust_tier": safe_tier,
                "nonce": nonce,
                "action": "NEUTRALIZE_AND_ISOLATE",
                "matched_patterns": found_patterns,
                "delimiter_escape_attempt": delimiter_escape_found,
                "stripped_invisible_chars": stripped_count,
                "snippet": cleaned[:200],
            }
            logger.warning(
                "🛡️ [PROMPT INJECTION BLOCKED] Source: %s | Tier: %s | Matches: %d | Stripped: %d",
                safe_source, safe_tier, len(found_patterns), stripped_count,
            )

            # Neutralize instruction attempts on cleaned text (and NFKC text if obfuscated)
            sanitized = cleaned
            for pat in ADVERSARIAL_PATTERNS:
                sanitized = re.sub(pat, "[BLOCKED_ADVERSARIAL_INSTRUCTION]", sanitized)
            if found_patterns and "[BLOCKED_ADVERSARIAL_INSTRUCTION]" not in sanitized:
                # Matched only after NFKC normalization — sanitize normalized form
                sanitized = normalized_for_scan
                for pat in ADVERSARIAL_PATTERNS:
                    sanitized = re.sub(pat, "[BLOCKED_ADVERSARIAL_INSTRUCTION]", sanitized)

            isolated = (
                f'<untrusted_data nonce="{nonce}" source="{safe_source}" trust_tier="{safe_tier}">\n'
                f"{sanitized}\n"
                f"</untrusted_data>"
            )
            return False, isolated, audit

        isolated = (
            f'<untrusted_data nonce="{nonce}" source="{safe_source}" trust_tier="{safe_tier}">\n'
            f"{cleaned}\n"
            f"</untrusted_data>"
        )
        audit_clean: Dict[str, Any] = {}
        if stripped_count > 0:
            audit_clean = {
                "event": "INVISIBLE_CHARS_STRIPPED",
                "source": safe_source,
                "trust_tier": safe_tier,
                "nonce": nonce,
                "stripped_invisible_chars": stripped_count,
            }
        return True, isolated, audit_clean
