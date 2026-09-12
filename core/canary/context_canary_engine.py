"""
Context-Aware Injection Escaping & Minimal Canary Engine
Analyzes reflection context (HTML Body, Attribute, Script Block, URL Href, JSON String),
calculates the exact minimal non-destructive escaping sequence, and proves context breakout
without firing harmful exploit payloads.
"""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ReflectionContext(str, Enum):
    HTML_BODY = "html_body"
    ATTRIBUTE_VALUE = "attribute_value"
    SCRIPT_BLOCK = "script_block"
    URL_HREF = "url_href"
    JSON_BODY = "json_body"
    NO_REFLECTION = "no_reflection"


@dataclass
class CanaryAnalysisResult:
    marker: str
    context: ReflectionContext
    surrounding_snippet: str
    recommended_safe_escape: str
    breakout_confirmed: bool = False
    evidence_proof: str = ""


class ContextCanaryEngine:
    """
    محرك الـ Canaries الذكي حسب سياق الانعكاس (Context-Aware Canary Engine):
    - يرسل علامة بريئة تماماً (Zero-Noise Marker) لتحديد موضع الانعكاس بدقة.
    - يحدد نوع السياق (داخل خاصية، داخل سكربت، داخل HTML، داخل JSON).
    - يصمم اختبار كسر آمن مقتضب (Minimal Safe Breakout) بدون أي كود تخريبي.
    """

    @classmethod
    def generate_unique_marker(cls, prefix: str = "HNT") -> str:
        """توليد علامة فريدة آمنة مكونة من حروف وأرقام"""
        return f"{prefix}_{secrets.token_hex(4)}"

    @classmethod
    def detect_reflection_context(cls, marker: str, response_html: str) -> CanaryAnalysisResult:
        """تحليل موضع انعكاس العلامة في شجرة الـ HTML"""
        if marker not in response_html:
            return CanaryAnalysisResult(
                marker=marker,
                context=ReflectionContext.NO_REFLECTION,
                surrounding_snippet="",
                recommended_safe_escape=""
            )

        # Extract snippet surrounding the marker
        idx = response_html.find(marker)
        start = max(0, idx - 40)
        end = min(len(response_html), idx + len(marker) + 40)
        snippet = response_html[start:end]

        # 1. Script block check
        script_pattern = re.compile(rf"<script[^>]*>[^<]*?{re.escape(marker)}[^<]*?</script>", re.IGNORECASE | re.DOTALL)
        if script_pattern.search(response_html):
            # Check if inside single quotes or double quotes
            if f"'{marker}'" in snippet:
                escape = "'-hnt_canary-'"
            elif f'"{marker}"' in snippet:
                escape = '"-hnt_canary-"'
            else:
                escape = "</script><hnt_canary>"
            return CanaryAnalysisResult(
                marker=marker,
                context=ReflectionContext.SCRIPT_BLOCK,
                surrounding_snippet=snippet,
                recommended_safe_escape=escape
            )

        # 2. Attribute value check: e.g. <input value="MARKER">
        attr_pattern = re.compile(rf"<[a-zA-Z0-9_\-]+[^>]*=['\"][^'\">]*?{re.escape(marker)}[^'\">]*?['\"][^>]*>", re.IGNORECASE)
        if attr_pattern.search(response_html):
            escape = '"><b>hnt_canary</b>'
            return CanaryAnalysisResult(
                marker=marker,
                context=ReflectionContext.ATTRIBUTE_VALUE,
                surrounding_snippet=snippet,
                recommended_safe_escape=escape
            )

        # 3. URL Href check: <a href="MARKER">
        if f'href="{marker}"' in response_html or f"href='{marker}'" in response_html:
            escape = "javascript:void('hnt_canary')"
            return CanaryAnalysisResult(
                marker=marker,
                context=ReflectionContext.URL_HREF,
                surrounding_snippet=snippet,
                recommended_safe_escape=escape
            )

        # 4. JSON Body check: {"key": "MARKER"}
        if f'"{marker}"' in snippet and ("{" in snippet or "}" in snippet or ":" in snippet):
            escape = '", "hnt_canary": true'
            return CanaryAnalysisResult(
                marker=marker,
                context=ReflectionContext.JSON_BODY,
                surrounding_snippet=snippet,
                recommended_safe_escape=escape
            )

        # 5. Default HTML Body
        return CanaryAnalysisResult(
            marker=marker,
            context=ReflectionContext.HTML_BODY,
            surrounding_snippet=snippet,
            recommended_safe_escape="<b>hnt_canary</b>"
        )

    @classmethod
    def verify_safe_breakout(
        cls,
        safe_payload: str,
        response_html: str,
        expected_token: str = "hnt_canary"
    ) -> Tuple[bool, str]:
        """التحقق من أن اختبار الـ Breakout الآمن قد انعكس دون تشفير مع الحفاظ على الأمان"""
        if expected_token not in response_html:
            return False, "Token not reflected in response."

        # Check if tags were stripped or sanitized to &lt; &gt;
        if "<b>hnt_canary</b>" in safe_payload and "<b>hnt_canary</b>" in response_html:
            return True, "CONFIRMED: Safe <b> tag rendered unencoded in HTML context."

        if "'-hnt_canary-'" in safe_payload and "'-hnt_canary-'" in response_html:
            return True, "CONFIRMED: Script string breakout executed safely."

        if expected_token in response_html:
            return True, f"CONFIRMED: Benign canary reflected ({expected_token})."

        return False, "Sanitized by server."
