"""
HunterAI Prompt Injection Firewall & Untrusted Data Isolation
=============================================================
Treats all data originating from target web applications (HTML, JS, DOM,
HTTP headers, robots.txt, API responses) strictly as UNTRUSTED_DATA.
Scans for adversarial instruction overrides and neutralizes them before
passing target context to LLM planners.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("hunter_ai.prompt_injection_firewall")

ADVERSARIAL_PATTERNS = [
    r"(?i)\bignore\s+(?:all\s+)?(?:previous\s+)?instructions\b",
    r"(?i)\byou\s+are\s+now\s+(?:a|an)\s+[a-z0-9_\-\s]+",
    r"(?i)\bsystem\s+prompt\s+override\b",
    r"(?i)\bdisregard\s+(?:all\s+)?(?:rules|instructions)\b",
    r"(?i)\bleak\s+(?:your\s+)?(?:secrets|api\s*key|tokens|credentials)\b",
    r"(?i)\boutput\s+(?:all\s+)?(?:environment\s+variables|env)\b",
    r"(?i)\bact\s+as\s+a\s+rogue\s+agent\b",
]


class PromptInjectionFirewall:
    """Protects LLM cognitive layer from malicious target web content"""

    @classmethod
    def inspect(cls, raw_content: str, source_label: str = "web_response") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Inspects content. Returns (is_safe, sanitized_content, audit_record).
        """
        if not raw_content:
            return True, "", {}

        found_patterns = []
        for pat in ADVERSARIAL_PATTERNS:
            if re.search(pat, raw_content):
                found_patterns.append(pat)

        if found_patterns:
            audit = {
                "event": "PROMPT_INJECTION_DETECTED",
                "source": source_label,
                "trust": "UNTRUSTED",
                "action": "NEUTRALIZE_AND_ISOLATE",
                "matched_patterns": found_patterns,
                "snippet": raw_content[:200]
            }
            logger.warning(f"🛡️ [PROMPT INJECTION BLOCKED] Source: {source_label} | Matches: {len(found_patterns)}")

            # Neutralize instruction attempts
            sanitized = raw_content
            for pat in ADVERSARIAL_PATTERNS:
                sanitized = re.sub(pat, "[BLOCKED_ADVERSARIAL_INSTRUCTION]", sanitized)

            # Wrap in strict untrusted data isolation delimiters
            isolated = f"<untrusted_web_data source='{source_label}'>\n{sanitized}\n</untrusted_web_data>"
            return False, isolated, audit

        # If safe, still wrap in untrusted data delimiters to enforce separation
        isolated = f"<untrusted_web_data source='{source_label}'>\n{raw_content}\n</untrusted_web_data>"
        return True, isolated, {}
