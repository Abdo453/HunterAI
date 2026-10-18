"""
Mission Readiness Gate — بوابة بدء المهمة (Phase 1)
====================================================
يربط ReadinessChecker بنقطة بدء المهمة:

  - mission_gate_config(data): يحدد (strict, components) من طلب المهمة
    — دالة نقية قابلة للاختبار بدون FastAPI.
  - run_mission_gate(data): ينفذ الفحص ويرفع ReadinessGateError في الوضع الصارم.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.readiness.checker import ReadinessChecker, enforce_strict

DEFAULT_COMPONENTS = ("kali_tools", "ollama")


def mission_gate_config(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    يترجم إعدادات المهمة إلى (strict?، أي مكونات تُفحص):

    - require_ready=True        → strict + الفحص الكامل
    - use_proxy / use_browser   → يفرض فحص burp_proxy/burp_gateway/playwright
      (لا معنى للاعتماد على بروك ما يشتغل)
    - الافتراضي                 → kali_tools + ollama (العقل والأدوات)
    """
    require_ready = bool(data.get("require_ready", False))
    strict = require_ready or bool(data.get("strict", False))

    components: List[str] = list(DEFAULT_COMPONENTS)
    use_proxy = bool(data.get("use_proxy", False)) or bool(data.get("use_browser", False))
    if data.get("require_burp_browser", False) or use_proxy:
        if "burp_proxy" not in components:
            components.append("burp_proxy")
        if "burp_gateway" not in components:
            components.append("burp_gateway")
        if data.get("use_browser", False) and "playwright" not in components:
            components.append("playwright")

    if not require_ready:
        # الوضع الافتراضي: لا strict gate — تقرير إرشادي فقط
        return False, components
    return True, components


async def run_mission_gate(
    data: Dict[str, Any],
    target: str,
    session_id: str,
    checker: ReadinessChecker | None = None,
) -> "Any":  # ReadinessReport
    """
    تنفيذ بوابة بدء المهمة:
    - strict والفحص لم يكتمل → ReadinessGateError (لا تبدأ المهمة).
    - كتابة الـ Artifact لكل جلسة باشتراط النجاح.
    """
    strict, components = mission_gate_config(data)
    checker = checker or ReadinessChecker()
    report = await checker.run_all(target=target, session_id=session_id, strict=strict,
                                   components=components)
    if strict:
        enforce_strict(report)
    return report
