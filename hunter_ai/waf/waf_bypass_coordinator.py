"""
منسق تجاوز WAF مع بنك جينات وذاكرة失败
يعمل كمعزز (Enhancer) لمحرك الفرضيات عند مواجهة WAF.
يدعم غير المتزامن (async)، السجلات، والتكامل مع محكمة الأدلة
"""
from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Any, Dict, List, Optional

import httpx

from core.config.settings import config
from core.exceptions import WAFError, HunterAIError
from core.logging.logger import logger
from core.memory.triple_memory import TripleMemory, MemoryType
from hunter_ai.evidence.evidence_court import EvidenceCourt, BypassContext


class WAFBypassCoordinator:
    """
    ينسق محاولات تجاوز WAF عبر مستويات متدرجة، ويسجل النجاحات في بنك الجينات.
    يربط كل محاولة ناجحة بمحكمة الأدلة للتحقق النهائي.
    """

    def __init__(self, target: str):
        self.target = target
        self.memory = TripleMemory()
        self.court = EvidenceCourt()
        self.waf_config = config.waf
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
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """الحصول على عميل HTTP مشترك."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.waf_config.timeout_seconds,
                follow_redirects=self.waf_config.follow_redirects,
                headers={
                    "User-Agent": self.waf_config.user_agent,
                },
            )
        return self._client

    async def close(self) -> None:
        """إغلاق عميل HTTP."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def attempt_bypass_async(
        self,
        payload: str,
        waf_type: str = "unknown",
        vuln_type: str = "xss",
        endpoint: str = "/",
        method: str = "GET",
    ) -> Dict[str, Any]:
        """
        محاولة تجاوز WAF بشكل غير متزامن باستخدام مستويات متدرجة.
        يربط كل نتيجة ناجحة بمحكمة الأدلة للتحقق.
        """
        for level in self.levels:
            if self.memory.has_recent_failure(
                target=self.target,
                technique=f"waf_bypass-{level}-{vuln_type}",
                within_seconds=3600,
            ):
                logger.debug(f"[WAF] تخطي المستوى '{level}' بسبب فشل سابق")
                continue

            variant = self._apply_level(payload, level)
            request_result = await self._send_request_async(
                variant, endpoint=endpoint, method=method
            )

            waf_detected = request_result.get("waf_detected", False)

            # Build context for Evidence Court
            context = BypassContext(
                target=self.target,
                endpoint=endpoint,
                original_payload=payload,
                bypass_payload=variant,
                waf_type=waf_type,
                waf_detected=waf_detected,
                status_code=request_result.get("status_code", 0),
                response_body=request_result.get("body", ""),
                response_headers=request_result.get("headers", {}),
                request_headers=request_result.get("request_headers", {}),
                response_time_ms=request_result.get("response_time_ms", 0.0),
                technique_level=level,
            )

            # Verify with Evidence Court
            court_result = self.court.verify_bypass(context)

            if court_result.bypass_confirmed or court_result.direct_vuln_confirmed:
                # Success — record in gene bank
                self.memory.write_semantic(
                    target=self.target,
                    key=f"waf_success-{waf_type}-{level}-{vuln_type}",
                    value={
                        "payload": variant,
                        "level": level,
                        "waf_type": waf_type,
                        "vuln_type": vuln_type,
                        "court_verdict": court_result.verdict.value,
                        "court_confidence": court_result.confidence,
                        "timestamp": time.time(),
                    },
                    tags=["waf_success", waf_type, level, vuln_type],
                )
                logger.info(
                    f"[WAF] نجاح التجاوز! الهدف={self.target}, المستوى={level}, "
                    f"الحكم={court_result.verdict.value}, الثقة={court_result.confidence:.2f}"
                )
                return {
                    "success": True,
                    "level": level,
                    "payload": variant,
                    "waf_type": waf_type,
                    "vuln_type": vuln_type,
                    "court_verdict": court_result.verdict.value,
                    "court_confidence": court_result.confidence,
                    "court_reasoning": court_result.reasoning,
                    "status_code": context.status_code,
                }
            else:
                # Failure — record in failure memory
                self.memory.record_failure(
                    target=self.target,
                    technique=f"waf_bypass-{level}-{vuln_type}",
                    reason=request_result.get("reason", "blocked"),
                    context={
                        "waf_type": waf_type,
                        "vuln_type": vuln_type,
                        "payload": variant,
                        "level": level,
                        "status_code": context.status_code,
                    },
                )
                logger.debug(
                    f"[WAF] فشل المستوى '{level}': السبب={request_result.get('reason', 'blocked')}"
                )

        logger.warning(f"[WAF] فشل جميع مستويات التجاوز ({len(self.levels)} مستوى) للهدف {self.target}")
        return {
            "success": False,
            "levels_tried": len(self.levels),
            "waf_type": waf_type,
            "vuln_type": vuln_type,
            "court_stats": self.court.stats(),
        }

    def attempt_bypass(
        self,
        payload: str,
        waf_type: str = "unknown",
        vuln_type: str = "xss",
        endpoint: str = "/",
        method: str = "GET",
    ) -> Dict[str, Any]:
        """نسخة متزامنة من attempt_bypass_async."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(
            self.attempt_bypass_async(payload, waf_type, vuln_type, endpoint, method)
        )

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

    async def _send_request_async(
        self,
        payload: str,
        endpoint: str = "/",
        method: str = "GET",
    ) -> Dict[str, Any]:
        """
        إرسال الطلب فعلياً عبر httpx واكتشاف WAF من الاستجابة.
        """
        url = self.target.rstrip("/") + endpoint
        start_time = time.time()

        try:
            client = await self._get_client()
            if method == "GET":
                resp = await client.get(
                    url,
                    params={"x": payload},
                )
            else:
                resp = await client.post(
                    url,
                    data={"x": payload},
                )

            response_time_ms = (time.time() - start_time) * 1000
            waf_detected = self._detect_waf(resp)

            return {
                "success": False,
                "status_code": resp.status_code,
                "body": resp.text,
                "headers": dict(resp.headers),
                "request_headers": dict(resp.request.headers),
                "response_time_ms": response_time_ms,
                "waf_detected": waf_detected,
                "reason": f"HTTP {resp.status_code}",
            }

        except httpx.TimeoutException:
            return {
                "success": False,
                "status_code": 0,
                "body": "",
                "headers": {},
                "request_headers": {},
                "response_time_ms": (time.time() - start_time) * 1000,
                "waf_detected": False,
                "reason": "timeout",
            }
        except Exception as e:
            return {
                "success": False,
                "status_code": 0,
                "body": "",
                "headers": {},
                "request_headers": {},
                "response_time_ms": (time.time() - start_time) * 1000,
                "waf_detected": False,
                "reason": str(e),
            }

    def _detect_waf(self, response: httpx.Response) -> bool:
        """كشف WAF من رؤوس الاستجابة وجسدها."""
        waf_signatures = [
            "cloudflare",
            "akamai",
            "imperva",
            "incapsula",
            "f5",
            "barracuda",
            "sucuri",
            "modsecurity",
            "aws waf",
            "azure waf",
        ]
        headers_str = str(response.headers).lower()
        body_str = response.text.lower()

        for sig in waf_signatures:
            if sig in headers_str or sig in body_str:
                return True
        return False

    def get_gene_bank_summary(self) -> Dict[str, Any]:
        """إرجاع ملخص بنك الجينات للهدف الحالي."""
        successes = self.memory.read_all_by_target(
            MemoryType.SEMANTIC, self.target
        )
        waf_successes = [
            s for s in successes if s.tags and "waf_success" in s.tags
        ]
        court_stats = self.court.stats()
        return {
            "target": self.target,
            "total_waf_successes": len(waf_successes),
            "by_waf_type": {
                tag: len([s for s in waf_successes if tag in s.tags])
                for tag in set(
                    t for s in waf_successes for t in s.tags if t != "waf_success"
                )
            },
            "court_stats": court_stats,
        }
