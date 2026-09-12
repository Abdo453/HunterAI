"""
HunterAI Context Manager
Orchestrates raw data filtering, deduplication, compression, and token budgeting.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from hunter_ai.context.compressor import ContextCompressor

logger = logging.getLogger(__name__)


class ContextManager:
    """
    مدير السياق والذاكرة اللحظية (Context Manager):
    - يستقبل البيانات الخام من الـ Agents (الطلبات، ملفات الـ JS، نقاط النهاية).
    - يمررها عبر الفلترة والضغط لضمان ملاءمتها لحدود الـ Context Window.
    """

    @classmethod
    def estimate_tokens(cls, text_or_data: Any) -> int:
        """تقدير تقريبي لعدد الـ Tokens (حوالي 4 حروف لكل Token)"""
        if isinstance(text_or_data, str):
            return max(1, len(text_or_data) // 4)
        elif isinstance(text_or_data, (dict, list)):
            dumped = json.dumps(text_or_data)
            return max(1, len(dumped) // 4)
        return 100

    @classmethod
    def prepare_compact_task_context(
        cls,
        raw_payload: Dict[str, Any],
        max_token_budget: int = 8000
    ) -> Dict[str, Any]:
        """تجهيز سياق مضغوط ونظيف للمهمة"""
        compact = dict(raw_payload)

        # 1. Compress headers if present
        if "headers" in compact and isinstance(compact["headers"], dict):
            compact["headers"] = ContextCompressor.compress_http_headers(compact["headers"])

        # 2. Compress endpoints if present
        if "endpoints" in compact and isinstance(compact["endpoints"], list):
            compact["endpoints"] = ContextCompressor.deduplicate_endpoints(compact["endpoints"])

        # 3. Compress response body if present
        if "response_body" in compact and isinstance(compact["response_body"], str):
            marker = compact.get("canary_marker")
            compact["response_body"] = ContextCompressor.compress_response_body(
                compact["response_body"],
                max_chars=3000,
                reflection_marker=marker
            )

        # 4. Check if token budget is still exceeded
        est = cls.estimate_tokens(compact)
        if est > max_token_budget:
            logger.info(f"[ContextManager] Estimated tokens ({est}) exceed budget ({max_token_budget}). Truncating payload...")
            dumped = json.dumps(compact)
            trimmed = dumped[: max_token_budget * 4]
            compact = {"truncated_context": trimmed, "note": "Payload compressed to fit token budget"}

        return compact
