"""
منسق تجاوز WAF مع بنك جينات وذاكرة 실패
يعمل كمعزز (Enhancer) لمحرك الفرضيات عند مواجهة WAF.
"""
from __future__ import annotations

import time
import urllib.parse
from typing import Any, Dict, List, Optional

from core.memory.triple_memory import TripleMemory, MemoryType


class WAFBypassCoordinator:
    """
    ينسق محاولات تجاوز WAF عبر مستويات متدرجة، ويسجل النجاحات في بنك الجينات.
    """

    def __init__(self, target: str):
        self.target = target
        self.memory = TripleMemory()
        self.levels: List[str] = [
            "plain",
            "url_encoding",
            "double_encoding",
            "case_variation",
            "whitespace_variation",
            "comment_injection",
            "null_byte",
            "protocol_switch",
            "fragment_split",
        ]

    def attempt_bypass(
        self,
        payload: str,
        waf_type: str = "unknown",
        vuln_type: str = "xss",
    ) -> Dict[str, Any]:
        """
        محاولة تجاوز WAF باستخدام مستويات متدرجة.
        يعيد النتيجة الأولى التي تنجح، أو تقرير فشل بعد تجربة جميع المستويات.
        """
        for level in self.levels:
            if self.memory.has_recent_failure(
                target=self.target,
                technique=f"waf_bypass-{level}-{vuln_type}",
                within_seconds=3600,
            ):
                continue

            variant = self._apply_level(payload, level)
            result = self._send_request(variant, waf_type)

            if result.get("success"):
                self.memory.write_semantic(
                    target=self.target,
                    key=f"waf_success-{waf_type}-{level}-{vuln_type}",
                    value={
                        "payload": variant,
                        "level": level,
                        "waf_type": waf_type,
                        "vuln_type": vuln_type,
                        "timestamp": time.time(),
                    },
                    tags=["waf_success", waf_type, level, vuln_type],
                )
                return {
                    "success": True,
                    "level": level,
                    "payload": variant,
                    "waf_type": waf_type,
                    "vuln_type": vuln_type,
                }
            else:
                self.memory.record_failure(
                    target=self.target,
                    technique=f"waf_bypass-{level}-{vuln_type}",
                    reason=result.get("reason", "blocked"),
                    context={
                        "waf_type": waf_type,
                        "vuln_type": vuln_type,
                        "payload": variant,
                        "level": level,
                    },
                )

        return {
            "success": False,
            "levels_tried": len(self.levels),
            "waf_type": waf_type,
            "vuln_type": vuln_type,
        }

    def _apply_level(self, payload: str, level: str) -> str:
        if level == "plain":
            return payload
        if level == "url_encoding":
            return urllib.parse.quote(payload, safe="")
        if level == "double_encoding":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        if level == "case_variation":
            return "".join(
                c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
            )
        if level == "whitespace_variation":
            return payload.replace(" ", "/**/").replace("=", " = ")
        if level == "comment_injection":
            return payload.replace("<", "<!--").replace(">", "-->")
        if level == "null_byte":
            return payload + "%00"
        if level == "protocol_switch":
            return payload.replace("http://", "https://")
        if level == "fragment_split":
            return payload + "#" + payload[:3]
        return payload

    def _send_request(self, variant: str, waf_type: str) -> Dict[str, Any]:
        """
        إرسال الطلب فعلياً عبر المستشعرات الحالية (Burp Sensor، إلخ).
        هنا هيكل عام يتم ربطه بالمنفّذ الفعلي لاحقاً.
        """
        return {"success": False, "reason": "not_implemented"}

    def get_gene_bank_summary(self) -> Dict[str, Any]:
        """إرجاع ملخص بنك الجينات للهدف الحالي."""
        successes = self.memory.read_all_by_target(
            MemoryType.SEMANTIC, self.target
        )
        waf_successes = [
            s for s in successes if s.tags and "waf_success" in s.tags
        ]
        return {
            "target": self.target,
            "total_waf_successes": len(waf_successes),
            "by_waf_type": {
                tag: len([s for s in waf_successes if tag in s.tags])
                for tag in set(
                    t for s in waf_successes for t in s.tags if t != "waf_success"
                )
            },
        }
