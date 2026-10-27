"""
HunterAI wafrift Integration — رابر للأداة الخارجية wafryt (WAF Bypass Engine)
===============================================================================
توفر هذه الواجهة ربط wafryt بالوكيل عبر ToolManager، مع دعم:
- بصمة WAF متعددة المحاور (wafryt detect)
- تجاوز payload عبر محرك الطفرة (wafryt bypass / mutate)
- إرجاع نتائج منظمة يمكن للوكيل استهلاكها مباشرة في شجرة قرار السلم وبنك الجينات.

ملاحظة: wafryt لا تزال في مرحلة BETA وتُفضل على WAFs محلية (ModSecurity / Coraza /
BunkerWeb / naxsi). على WAFs سحابية (Cloudflare / AWS / Akamai) النتائج أولية.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from tools.tool_manager import ToolManager


@dataclass
class WafriftResult:
    """نتيجة موحّدة من تنفيذ wafryt."""
    tool: str = "wafryt"
    action: str = ""  # detect | bypass | mutate
    target: str = ""
    success: bool = False
    waf_detected: Optional[str] = None          # نوع WAF الذي تم بصمته
    waf_families: List[str] = field(default_factory=list)  #families محتملة
    confidence: float = 0.0
    payload: Optional[str] = None               # payload जो نجح (في حالة bypass)
    technique_level: Optional[int] = None       # درجة السلم التي نجحت فيها (1-5)
    raw_output: str = ""
    error: Optional[str] = None
    duration_ms: float = 0.0


class WafriftIntegration:
    """
    واجهة로运行 wafryt كأداة خارجية.
    لا تحتفظ بأي حالة خاصة بها — كل 기록 يُخزن في WAFGeneBank (الذاكرة المشتركة).
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """تفحص ما إذا كان wafryt مثبتاً ومتاحاً في PATH."""
        if self._available is None:
            self._available = self.mgr.is_available("wafryt")
        return self._available

    async def detect_waf(self, url: str) -> WafriftResult:
        """
        تشغيل `wafryt detect <url>` لبصمة WAF متعددة المحاور.
        يعيد نتيجة تحتوي على نوع WAF المتوقع ومستوى الثقة.
        """
        if not self.is_available():
            return WafriftResult(
                action="detect",
                target=url,
                success=False,
                error="wafryt is not installed. Install it first (pip install wafryt or from source).",
            )

        try:
            res = await self.mgr.execute("wafryt", ["detect", url], timeout=120)
        except Exception as exc:  # pragma: no cover - defensive
            return WafriftResult(
                action="detect",
                target=url,
                success=False,
                error=str(exc),
                raw_output="",
            )

        parsed = self._parse_detect_output(res.stdout or "", res.stderr or "")
        parsed.raw_output = (res.stdout or "") + "\n" + (res.stderr or "")
        parsed.duration_ms = round(res.duration * 1000.0, 2)
        parsed.success = res.returncode == 0 and not res.error
        return parsed

    async def bypass(self, url: str, payload: str, technique: str = "auto") -> WafriftResult:
        """
        تشغيل `wafryt bypass <url> --payload <payload> [--technique <t>]`
        لمحاولة تجاوز WAF باستخدام محرك الطفرة التطوري.
        """
        if not self.is_available():
            return WafriftResult(
                action="bypass",
                target=url,
                success=False,
                error="wafryt is not installed.",
                payload=payload,
            )

        args: List[str] = ["bypass", url, "--payload", payload]
        if technique and technique != "auto":
            args.extend(["--technique", technique])

        try:
            res = await self.mgr.execute("wafryt", args, timeout=180)
        except Exception as exc:  # pragma: no cover - defensive
            return WafriftResult(
                action="bypass",
                target=url,
                success=False,
                error=str(exc),
                payload=payload,
            )

        parsed = self._parse_bypass_output(res.stdout or "", res.stderr or "")
        parsed.raw_output = (res.stdout or "") + "\n" + (res.stderr or "")
        parsed.duration_ms = round(res.duration * 1000.0, 2)
        parsed.success = res.returncode == 0 and not res.error and parsed.payload is not None
        parsed.payload = parsed.payload or payload
        return parsed

    # ------------------------------------------------------------------ #
    # parsing helpers
    # ------------------------------------------------------------------ #
    def _parse_detect_output(self, stdout: str, stderr: str) -> WafriftResult:
        text = (stdout + "\n" + stderr).strip()
        result = WafriftResult(action="detect", raw_output=text)

        # محاولة استخراج نوع WAF من نصوص شائعة
        patterns = [
            r"(?i)(?:WAF|firewall|protection)\s*[:=]\s*([A-Za-z0-9_\-]+)",
            r"(?i)detected\s+([A-Za-z0-9_\-]+)",
            r"(?i)([A-Za-z0-9_\-]+)\s+WAF",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                result.waf_detected = m.group(1).strip()
                result.waf_families.append(result.waf_detected)
                result.confidence = 0.7
                break

        # لو لقينا ملف JSON مخرج (بعض إصدارات wafryt تدعم --json)
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                result.waf_detected = data.get("waf") or data.get("waf_name") or result.waf_detected
                result.waf_families = data.get("families", []) or result.waf_families
                result.confidence = float(data.get("confidence", result.confidence))
                result.success = True
        except (json.JSONDecodeError, ValueError):
            pass

        if result.waf_detected:
            result.success = True
        return result

    def _parse_bypass_output(self, stdout: str, stderr: str) -> WafriftResult:
        text = (stdout + "\n" + stderr).strip()
        result = WafriftResult(action="bypass", raw_output=text)

        # wafryt قد يُعيد payload ناجح في سطر أو JSON
        m = re.search(r"(?i)(?:bypass|success|payload)\s*[:=]\s*(.+)", text)
        if m:
            result.payload = m.group(1).strip().strip("'\"")
            result.success = True
            # محاولة استخراج درجة السلم إن وُجدت
            lm = re.search(r"level\s*[:=]\s*([1-5])", text, re.IGNORECASE)
            if lm:
                result.technique_level = int(lm.group(1))
            return result

        # JSON مخرج محتمل
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                result.payload = data.get("payload") or data.get("bypass_payload")
                result.technique_level = data.get("level")
                result.waf_detected = data.get("waf")
                result.success = bool(result.payload)
        except (json.JSONDecodeError, ValueError):
            pass

        return result


__all__ = ["WafriftIntegration", "WafriftResult"]
