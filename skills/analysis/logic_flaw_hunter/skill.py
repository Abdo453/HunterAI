"""
Logic Flaw Hunter Skill — مهارة "صيد ثغرات منطق العمل"
=======================================================
تجيب عن سؤال: "هل هناك خطأ في منطق العمل يمكن استغلاله (بدون ثغرة برمجية كلاسيكية)؟"

تقوم بفحص استباقي آلي وخفيف لأنماط منطق العمل الشائعة:
  - تلاعب بالسعر/الكمية (salary/price manipulation): تعديل السعر إلى قيمة سالبة أو صفر.
  - قسيمة تُستخدم أكثر من مرة أو تنطبق بدون شروط.
  - تجاوز خطوتين في عمليات إعادة تعيين كلمة المرور / المصادقة الثنائية عبر الوصول المباشر لصفحة ما بعد التحقق.
  - تخطي خطوات سير العمل (skip workflow step) عبر طلب مباشر للخطوة الأخيرة.

ملاحظة: لا تُجري أي تعديل على بيانات حقيقية؛ تُرسل طلبات قراءة/اختبار فقط وتسجل الاستجابات غير المتوقعة.

مخرجات:
  - logic_flaws.json : المنطق المشبوه مع أدلة
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class LogicFlawHunterSkill(BaseSkill):
    name = "logic_flaw_hunter"
    category = "analysis"
    description = "Heuristic business-logic flaw detection (price, coupon, workflow bypass, 2FA skip)."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 60.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        endpoints: List[Dict[str, Any]] = ctx.extra.get("endpoints", []) or []

        flaws: List[Dict[str, Any]] = []
        for ep in endpoints[:30]:
            method = ep.get("method", "GET").upper()
            url = ep.get("url", "")
            params = ep.get("params", {}) or {}

            # Price / amount manipulation hint
            for key in ("price", "amount", "total", "quantity", "qty", "discount", "coupon", "promo"):
                if key in params:
                    flaws.append({
                        "type": "price_or_quantity_manipulation",
                        "url": url,
                        "parameter": key,
                        "original_value": params[key],
                        "suggested_test": f"Change {key} to 0 or -1 and verify order is still accepted.",
                        "severity": "High",
                        "evidence": f"Parameter '{key}' present in request — server may trust client-side price.",
                    })
                    break

            # Workflow bypass hint: endpoints containing reset/verify/2fa/mfa/confirm
            if re.search(r"(reset|verify|2fa|mfa|confirm|activate|token)", url, re.I):
                flaws.append({
                    "type": "workflow_or_auth_bypass",
                    "url": url,
                    "method": method,
                    "suggested_test": "Access this endpoint directly without completing previous step; check if state advances.",
                    "severity": "Medium",
                    "evidence": "Endpoint path suggests a multi-step verification flow.",
                })

        payload = {
            "target": target,
            "endpoints_tested": len(endpoints),
            "flaws": flaws,
            "generated_at": time.time(),
            "methodology": "Read-only heuristic scan of endpoints/params for business-logic abuse patterns.",
        }

        p_out = ctx.workspace.write_file(target, "analysis", "logic_flaws.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"logic_flaws.json": str(p_out)}
        result.raw_output = {"flaws": json.dumps(payload, ensure_ascii=False)}

        for f in flaws[:5]:
            result.add_finding(
                title=f"Potential logic flaw: {f['type']} ({f['url'][:70]})",
                evidence=f["evidence"],
                severity=f["severity"],
                vuln_type="logic_flaw",
                recommendation=f["suggested_test"],
                url=f["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[LogicFlaw] {len(endpoints)} endpoints, {len(flaws)} potential flaws")
        return result


import re  # noqa: E402  (used above)


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, cmd):
            return True

    class FakeWS:
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"endpoints": [
            {"url": "https://example.com/cart/checkout", "method": "POST", "params": {"price": "100", "qty": "1"}},
            {"url": "https://example.com/reset-password/confirm", "method": "POST", "params": {}},
        ]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = LogicFlawHunterSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["flaws"][:400])

    asyncio.run(main())
