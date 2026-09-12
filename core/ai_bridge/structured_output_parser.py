"""
Structured Output & JSON Parser
Extracts, cleans, and parses JSON and structured data from any AI model output (Local or Cloud).
Handles markdown code blocks (```json ... ```), preambles, and malformed trailing text.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class StructuredOutputParser:
    """
    معالج ومستخرج المخرجات المنظمة (Structured Output Parser):
    - يضمن استخراج كائنات الـ JSON حتى لو كان النموذج يطبع نصوصاً تمهيدية أو تنسيقات Markdown.
    - يعمل بكفاءة مع النماذج المحلية (Ollama) والنماذج السحابية على حد سواء.
    """

    @classmethod
    def extract_json(cls, raw_text: str) -> Optional[Dict[str, Any]]:
        if not raw_text:
            return None

        text = raw_text.strip()

        # 1. Direct JSON parse
        try:
            return json.loads(text)
        except Exception:
            pass

        # 2. Extract from ```json ... ``` code fence
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if fence_match:
            fence_content = fence_match.group(1).strip()
            try:
                return json.loads(fence_content)
            except Exception:
                pass

        # 3. Find outermost curly braces { ... }
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            substring = text[start_idx : end_idx + 1]
            try:
                return json.loads(substring)
            except Exception:
                pass

        # 4. Find outermost square brackets [ ... ]
        start_arr = text.find("[")
        end_arr = text.rfind("]")
        if start_arr != -1 and end_arr != -1 and end_arr > start_arr:
            sub_arr = text[start_arr : end_arr + 1]
            try:
                arr_data = json.loads(sub_arr)
                return {"items": arr_data}
            except Exception:
                pass

        logger.debug(f"[StructuredOutputParser] Failed to parse JSON from AI response: {text[:100]}...")
        return None
