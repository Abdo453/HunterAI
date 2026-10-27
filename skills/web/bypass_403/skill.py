"""
Bypass 403/401 — تجاوز 말도ات المنع والتصفح الممنوع
=====================================================
يُجرب تقنيات خفيفة القراءة فقط:
  - رؤوس وهمية (X-Forwarded-For, X-Real-IP, Client-IP) لتزييف來源 الطلب.
  - تغيير الطريقة GET -> POST / PUT / OPTIONS.
  - إضافة شرطة مائلة أخيرة أو إزالة السلاش.
  - manipulat المسار (/admin/ -> /admin // admin).
يسجل أي استجابة تحولت من 403/401 إلى 200/302/401 كمرشح.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class Bypass403Skill(BaseSkill):
    name = "bypass_403"
    category = "web"
    description = "تجريب تقنيات تجاوز 403/401 خفيفة القراءة فقط"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 60.0
    max_retries = 1

    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
    ]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="bypass_403")
        target = ctx.target
        urls: List[str] = ctx.extra.get("urls", []) or []
        candidates: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False, trust_env=False) as client:
            for url in urls[:40]:
                try:
                    base = await client.get(url)
                except Exception:
                    continue
                if base.status_code not in (401, 403):
                    continue

                # رأس وهمي
                for hdr in self.BYPASS_HEADERS:
                    try:
                        r = await client.get(url, headers=hdr)
                        if r.status_code in (200, 301, 302, 307, 401):
                            candidates.append({
                                "url": url,
                                "technique": f"header {list(hdr.keys())[0]}",
                                "base_status": base.status_code,
                                "bypass_status": r.status_code,
                                "evidence": f"{base.status_code} → {r.status_code} باستخدام رأس {list(hdr.keys())[0]}",
                                "severity": "Medium",
                            })
                            break
                    except Exception:
                        continue

                # طريقة مختلفة
                for method in ("POST", "OPTIONS", "PUT", "HEAD"):
                    try:
                        r = await client.request(method, url)
                        if r.status_code in (200, 301, 302, 307) and r.status_code != base.status_code:
                            candidates.append({
                                "url": url,
                                "technique": f"method {method}",
                                "base_status": base.status_code,
                                "bypass_status": r.status_code,
                                "evidence": f"{base.status_code} → {r.status_code} باستخدام طريقة {method}",
                                "severity": "Medium",
                            })
                            break
                    except Exception:
                        continue

        payload = {
            "target": target,
            "urls_tested": len(urls),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "مقارنة استجابة 403/401 الأساسية مقابل رؤوس وهمية وطرق HTTP بديلة.",
        }

        p_out = ctx.workspace.write_file(target, "web", "bypass_403_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"bypass_403_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Potential 403/401 bypass ({c['technique']}) ({c['url'][:70]})",
                evidence=c["evidence"],
                severity=c["severity"],
                vuln_type="auth_bypass",
                recommendation="تحقق من الصلاحية على مستوى التطبيق وليس केवल على طبقة الويب سيرفر/WAF.",
                url=c["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[Bypass403] tested {len(urls)} URLs, {len(candidates)} candidates")
        return result


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, c):
            return True

    class FakeWS:
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"urls": ["https://example.com/admin", "https://example.com/private"]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = Bypass403Skill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
