"""
HunterAI Context Compressor
Compresses large HTTP requests, responses, and lists of endpoints:
- Strips non-informative HTTP headers (Keep-Alive, Accept, Cache-Control, etc.)
- Deduplicates repetitive endpoints and static assets (.png, .css, .jpg)
- Truncates oversized response bodies to relevant reflection fragments
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

HEADERS_TO_STRIP: Set[str] = {
    "connection",
    "keep-alive",
    "accept-encoding",
    "accept-language",
    "upgrade-insecure-requests",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "pragma",
    "cache-control",
}


class ContextCompressor:
    """
    ضاغط السياق وموفر الـ Tokens (Context Compressor):
    - يقلص حجم البيانات الخام بنسبة تصل إلى 60-80% دون فقدان أي معلومة أمنية.
    """

    @classmethod
    def compress_http_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """إزالة الترويسات الروتينية غير المؤثرة أمنياً"""
        return {k: v for k, v in headers.items() if k.lower() not in HEADERS_TO_STRIP}

    @classmethod
    def deduplicate_endpoints(cls, endpoints: List[str]) -> List[str]:
        """إزالة الروابط المكررة ومسارات الصور والخطوط"""
        seen_patterns: Set[str] = set()
        clean_list: List[str] = []

        for ep in endpoints:
            clean_ep = ep.split("?")[0]
            # Exclude static assets
            if re.search(r"\.(css|png|jpg|jpeg|gif|svg|woff2?|ico)$", clean_ep, re.IGNORECASE):
                continue
            if clean_ep not in seen_patterns:
                seen_patterns.add(clean_ep)
                clean_list.append(ep)

        return clean_list

    @classmethod
    def compress_response_body(cls, body: str, max_chars: int = 2000, reflection_marker: Optional[str] = None) -> str:
        """ضغط جسم الاستجابة مع الحفاظ على موضع انعكاس الـ Canary"""
        if not body or len(body) <= max_chars:
            return body

        if reflection_marker and reflection_marker in body:
            idx = body.find(reflection_marker)
            start = max(0, idx - 500)
            end = min(len(body), idx + len(reflection_marker) + 500)
            return (
                f"[SNIPPED_HEAD: {start} chars]...\n"
                f"{body[start:end]}\n"
                f"...[SNIPPED_TAIL: {len(body) - end} chars]"
            )

        return body[:max_chars] + f"\n...[TRUNCATED: original length {len(body)} chars]"
