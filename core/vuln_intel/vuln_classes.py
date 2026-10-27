"""Deterministic vulnerability-class extraction.

Tool selection needs a *stable* notion of "what kind of bug is this?".  This
module maps a stored advisory to one or more canonical vulnerability classes
using:

1. **CWE identifiers** (primary evidence) - the machine-readable signal.
2. **Explicit advisory phrases** (supporting evidence) - only unambiguous
   multi-word phrases or well-known acronyms such as ``XSS``.

A bare word such as ``sql`` or ``php`` is never enough.  When neither source
yields a class, the result is empty and the caller must not guess.
"""
from __future__ import annotations

import re
from typing import Dict, List, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field

from .models import VulnerabilityRecord

__all__ = [
    "CWE_CLASS_MAP",
    "TEXT_SIGNALS",
    "VulnClassAnalysis",
    "classify_vuln_classes",
]


CWE_CLASS_MAP: Dict[str, str] = {
    # Injection
    "CWE-89": "sqli",
    "CWE-564": "sqli",
    "CWE-943": "sqli",
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-83": "xss",
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-94": "code_injection",
    "CWE-95": "code_injection",
    "CWE-1336": "template_injection",
    "CWE-1236": "template_injection",
    # Server-side requests and paths
    "CWE-918": "ssrf",
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-36": "path_traversal",
    "CWE-73": "path_traversal",
    "CWE-434": "file_upload",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-444": "request_smuggling",
    "CWE-362": "race_condition",
    "CWE-367": "race_condition",
    # Access control and auth
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-384": "auth_bypass",
    "CWE-613": "auth_bypass",
    "CWE-620": "auth_bypass",
    "CWE-640": "auth_bypass",
    "CWE-269": "authorization_flaw",
    "CWE-284": "authorization_flaw",
    "CWE-285": "authorization_flaw",
    "CWE-425": "authorization_flaw",
    "CWE-441": "authorization_flaw",
    "CWE-732": "authorization_flaw",
    "CWE-639": "idor",
    "CWE-862": "missing_authorization",
    "CWE-863": "missing_authorization",
    "CWE-352": "csrf",
    "CWE-601": "open_redirect",
    "CWE-346": "origin_validation",
    # Information and crypto
    "CWE-200": "info_disclosure",
    "CWE-203": "info_disclosure",
    "CWE-208": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-212": "info_disclosure",
    "CWE-311": "info_disclosure",
    "CWE-312": "info_disclosure",
    "CWE-319": "info_disclosure",
    "CWE-532": "info_disclosure",
    "CWE-538": "info_disclosure",
    "CWE-668": "info_disclosure",
    "CWE-327": "weak_crypto",
    "CWE-326": "weak_crypto",
    "CWE-328": "weak_crypto",
    "CWE-330": "weak_crypto",
    "CWE-307": "weak_credentials",
    "CWE-521": "weak_credentials",
    "CWE-916": "weak_credentials",
    "CWE-259": "hardcoded_credentials",
    "CWE-321": "hardcoded_credentials",
    "CWE-798": "hardcoded_credentials",
    "CWE-522": "weak_credentials",
    "CWE-1004": "sensitive_cookie",
    # Availability
    "CWE-400": "denial_of_service",
    "CWE-770": "denial_of_service",
    "CWE-1333": "denial_of_service",
    # Supply chain
    "CWE-1104": "known_vulnerable_dependency",
    "CWE-1035": "known_vulnerable_component",
    # Configuration
    "CWE-16": "misconfiguration",
    "CWE-942": "misconfiguration",
    "CWE-1188": "misconfiguration",
}

# Supporting text signals.  Keep them explicit: no single generic words.
TEXT_SIGNALS: Sequence[Tuple[str, str]] = (
    ("sql injection", "sqli"),
    ("cross-site scripting", "xss"),
    ("cross site scripting", "xss"),
    ("xss", "xss"),
    ("server-side request forgery", "ssrf"),
    ("server side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("command injection", "command_injection"),
    ("os command injection", "command_injection"),
    ("remote code execution", "command_injection"),
    ("arbitrary file upload", "file_upload"),
    ("file upload", "file_upload"),
    ("object injection", "deserialization"),
    ("deserialization", "deserialization"),
    ("unserialize", "deserialization"),
    ("insecure direct object reference", "idor"),
    ("idor", "idor"),
    ("authorization bypass", "missing_authorization"),
    ("missing authorization", "missing_authorization"),
    ("cross-site request forgery", "csrf"),
    ("csrf", "csrf"),
    ("open redirect", "open_redirect"),
    ("xml external entity", "xxe"),
    ("template injection", "template_injection"),
    ("hardcoded credential", "hardcoded_credentials"),
    ("hard-coded credential", "hardcoded_credentials"),
    ("exposed secret", "secret_exposure"),
    ("secret leak", "secret_exposure"),
    ("known vulnerable", "known_vulnerable_dependency"),
    ("vulnerable dependency", "known_vulnerable_dependency"),
    ("outdated dependency", "known_vulnerable_dependency"),
    ("prototype pollution", "prototype_pollution"),
)

_WORD_RE = re.compile(r"[a-z0-9_]+")


class VulnClassAnalysis(BaseModel):
    """The classes extracted from an advisory, with their evidence."""

    model_config = ConfigDict(extra="forbid")

    classes: List[str] = Field(default_factory=list)
    cwe_classes: List[str] = Field(default_factory=list)
    text_classes: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return self.model_dump(mode="json")


def _contains_phrase(text: str, phrase: str) -> bool:
    """True when ``phrase`` appears as a word/phrase inside ``text``."""
    needle = phrase.strip().lower()
    if not needle:
        return False
    if " " in needle or "-" in needle:
        return needle in text
    return needle in _WORD_RE.findall(text)


def classify_vuln_classes(
    record: VulnerabilityRecord,
    *,
    use_text: bool = True,
) -> VulnClassAnalysis:
    """Extract canonical vulnerability classes from a stored advisory."""
    cwe_classes: List[str] = []
    evidence: List[str] = []

    for cwe in record.cwes or []:
        key = str(cwe or "").strip().upper()
        if not key:
            continue
        mapped = CWE_CLASS_MAP.get(key)
        if mapped is None:
            continue
        if mapped not in cwe_classes:
            cwe_classes.append(mapped)
        evidence.append(f"{key} -> {mapped}")

    text_classes: List[str] = []
    if use_text:
        parts = [record.title or "", record.summary or "", record.description or ""]
        text = " ".join(part for part in parts if part).lower()
        if text:
            for phrase, mapped in TEXT_SIGNALS:
                if mapped in cwe_classes or mapped in text_classes:
                    continue
                if _contains_phrase(text, phrase):
                    text_classes.append(mapped)
                    evidence.append(f"advisory phrase {phrase!r} -> {mapped}")

    classes = sorted(set(cwe_classes) | set(text_classes))
    return VulnClassAnalysis(
        classes=classes,
        cwe_classes=sorted(set(cwe_classes)),
        text_classes=sorted(set(text_classes)),
        evidence=evidence,
    )
