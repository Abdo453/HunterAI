"""
Browser Skill Adapters
======================
تُغلّف مهارات `skills/browser/` (واجهة `execute(ctx)` من خط الأنابيب الحالي)
داخل واجهة `run(target_url, param_name)` الخاصة بنظام `agents/skills/` الموحّد،
حتى تُسجَّل في `SkillRegistry` وتُستدعى من `autonomous_brain.TOOL_REGISTRY`
وبوابة `IVulnRouter` بدون كسر أي كود قائم.

كل محوّل يُعيد `SkillResult` من `agents.skills.base_skill` مع:
  - verified  = نجاح التنفيذ مع وجود نتائج/ملفات مخرجات (ليس Reflection فقط)
  - evidence  = تلخيص findings المُكتشفة
  - extra     = مخرجات الملفات + النتائج الخام للمراجعة اليدوية
"""
from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.browser_adapters")

# ─── الاستيرادات المتأخرة لتجنب إجبار توافر المتصفح في الاستيراد الثابت ───

# مهارات المهاجم (البرمجيات المرصودة للمستعرض)


class _BrowserSkillAdapter(BaseSkill):
    """
    محوّل عام: يستقبل كائن Skill من skills.base_skill.BaseSkill
    ويُقدِّمه بواجهة run(target_url, param_name, **kwargs).
    """

    def __init__(
        self,
        wrapped: BaseSkill,
        name: str,
        vuln_type: str = "browser",
        cwe: str = "CWE-000",
        owasp_top10: str = "A00:2021",
        default_severity: str = "Info",
        proxy: Optional[str] = None,
        timeout: float = 120.0,
    ):
        super().__init__(proxy=proxy, timeout=timeout)
        self._wrapped = wrapped
        self.name = name
        self.vuln_type = vuln_type
        self.cwe = cwe
        self.owasp_top10 = owasp_top10
        self.default_severity = default_severity

    # ─── execution ─────────────────────────────────────────────────────────
    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        from core.workspace_manager import WorkspaceManager
        from skills.base_skill import SkillContext
        from tools.tool_manager import ToolManager

        tmp_root = Path(tempfile.mkdtemp(prefix=f"browser_adapter_{self.name}_"))
        wm = WorkspaceManager(root=tmp_root)

        ctx = SkillContext(
            target=target_url,
            session_id=f"{self.name}_adapter",
            workspace=wm,
            tool_manager=ToolManager(),
            extra=kwargs,
        )

        try:
            res = await asyncio.wait_for(self._wrapped.execute(ctx), timeout=self.timeout)
        except asyncio.TimeoutError:
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title=f"{self.name} timed out", severity=self.default_severity,
                endpoint=target_url, param_name=param_name,
                evidence=f"{self.name} exceeded {self.timeout}s budget",
                tool=self.name, cwe=self.cwe,
                logs=[f"{self.name} timed out"],
            )
        except Exception as exc:  # لا نسمح لمشاكل المتصفح بإسقاط الخط بأكمله
            log.exception("[BrowserAdapter] %s failed on %s", self.name, target_url)
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title=f"{self.name} error", severity=self.default_severity,
                endpoint=target_url, param_name=param_name,
                evidence=str(exc), tool=self.name, cwe=self.cwe,
                logs=[f"{self.name} failed: {exc}"],
            )

        # ─── تحويل نتيجة الـ skills/ إلى عقدة agents/skills/ ───────────────
        wrapped_success = bool(getattr(res, "success", False))
        wrapped_findings = getattr(res, "findings", None) or []
        wrapped_output_files = getattr(res, "output_files", None) or {}
        verified = wrapped_success and (bool(wrapped_findings) or bool(wrapped_output_files))
        evidence_parts: list[str] = []
        for f in wrapped_findings:
            evidence_parts.append(f"{f.get('title', '')}: {f.get('evidence', '')}")
        evidence = " | ".join(evidence_parts) or f"{self.name} executed on {target_url}"

        severity = self.default_severity
        if any("critical" in str(f.get("severity", "")).lower() for f in wrapped_findings):
            severity = "Critical"
        elif any("high" in str(f.get("severity", "")).lower() for f in wrapped_findings):
            severity = "High"
        elif any("medium" in str(f.get("severity", "")).lower() for f in wrapped_findings):
            severity = "Medium"

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"{self.name} on {urlparse(target_url).netloc or target_url}",
            severity=severity,
            endpoint=target_url,
            param_name=param_name,
            evidence=evidence,
            tool=self.name,
            evidence_sources=["browser_adapter"],
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            logs=[f"{self.name} executed in {getattr(res, 'duration', 0):.1f}s"],
            extra={
                "output_files": wrapped_output_files,
                "raw_output": getattr(res, "raw_output", None) or {},
                "findings": wrapped_findings,
                "duration": getattr(res, "duration", 0.0),
            },
        )

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        """مهارة على مستوى الهدف/المتصفح — لا تشارك في التوجيه التلقائي للمعاملات."""
        return 0.0


# ════════════════════════════════════════════════════════════════════════════
# المحوّلات الفردية
# ════════════════════════════════════════════════════════════════════════════


class BrowserReconAdapterSkill(_BrowserSkillAdapter):
    """مُحكّم DOM/الروابط/النماذج/الكوكيز من skills.browser.browser_recon."""
    name = "browser_recon"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 120.0):
        from skills.browser.browser_recon.skill import BrowserReconSkill
        super().__init__(
            wrapped=BrowserReconSkill(),
            name=self.name,
            vuln_type="browser_recon",
            cwe="CWE-000",
            owasp_top10="A01:2021 — Broken Access Control",
            default_severity="Info",
            proxy=proxy,
            timeout=timeout,
        )


class FormIntelligenceAdapterSkill(_BrowserSkillAdapter):
    """تجميع النماذج وخرائط سطح المصادقة من skills.browser.form_intelligence."""
    name = "form_intelligence"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 90.0):
        from skills.browser.form_intelligence.skill import FormIntelligenceSkill
        super().__init__(
            wrapped=FormIntelligenceSkill(),
            name=self.name,
            vuln_type="auth_surface",
            cwe="CWE-306",
            owasp_top10="A07:2021 — Identification and Authentication Failures",
            default_severity="Low",
            proxy=proxy,
            timeout=timeout,
        )


class NetworkIntelligenceAdapterSkill(_BrowserSkillAdapter):
    """اعتراض حركة XHR/Fetch واستخراج نقاط API من skills.browser.network_intelligence."""
    name = "network_intelligence"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 120.0):
        from skills.browser.network_intelligence.skill import NetworkIntelligenceSkill
        super().__init__(
            wrapped=NetworkIntelligenceSkill(),
            name=self.name,
            vuln_type="api_surface",
            cwe="CWE-000",
            owasp_top10="A01:2021 — Broken Access Control",
            default_severity="Low",
            proxy=proxy,
            timeout=timeout,
        )


class BehaviorAnalysisAdapterSkill(_BrowserSkillAdapter):
    """محاكاة سلوك المستخدم ورسم حالات التطبيق من skills.browser.behavior_analysis."""
    name = "behavior_analysis"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 120.0):
        from skills.browser.behavior_analysis.skill import BehaviorAnalysisSkill
        super().__init__(
            wrapped=BehaviorAnalysisSkill(),
            name=self.name,
            vuln_type="behavior_graph",
            cwe="CWE-000",
            owasp_top10="A00:2021",
            default_severity="Info",
            proxy=proxy,
            timeout=timeout,
        )


class BrowserSensorAdapterSkill(_BrowserSkillAdapter):
    """المستشعر المستمر للمتصفح (BrowserBrainLoop) من skills.browser.browser_sensor."""
    name = "browser_sensor"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 180.0):
        from skills.browser.browser_sensor.skill import BrowserSensorSkill
        super().__init__(
            wrapped=BrowserSensorSkill(),
            name=self.name,
            vuln_type="browser_sensor",
            cwe="CWE-000",
            owasp_top10="A00:2021",
            default_severity="Info",
            proxy=proxy,
            timeout=timeout,
        )
