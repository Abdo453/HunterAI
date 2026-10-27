"""
SQLi Hunter — صيد حقن قواعد البيانات (آمن، قراءة فقط)
=======================================================
يكشف SQLi عبر التحليل التفاضلي differential دون تعديل أي بيانات:
  - يقارن الاستجابة العادية مقابل حقن "صحيحة" (1 AND 1=1) و"خاطئة" (1 AND 1=2).
  - إن اختلف الطول/الحالة/الجسم بشكل ملحوظ يُسجّل مرشحًا.
  - لا يستخدم أوامر تدميرية (DROP, INSERT, UPDATE, DELETE).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class SQLiHunterSkill(BaseSkill):
    name = "sqli_hunter"
    category = "web"
    description = "كشف SQLi آمن عبر المقارنة التفاضلية (읽ة فقط، بدون تعديل بيانات)"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 90.0
    max_retries = 1

    SAFE_TRUE = "1 AND 1=1"
    SAFE_FALSE = "1 AND 1=2"

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="sqli_hunter")
        target = ctx.target
        urls: List[str] = ctx.extra.get("urls", []) or []
        candidates: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=12, verify=False, follow_redirects=True, trust_env=False) as client:
            for url in urls[:40]:
                param = self._find_injective_param(url)
                if not param:
                    continue
                try:
                    normal = await self._fetch(client, url, param, "1")
                    true_v = await self._fetch(client, url, param, f"1 {self.SAFE_TRUE}")
                    false_v = await self._fetch(client, url, param, f"1 {self.SAFE_FALSE}")
                except Exception as exc:
                    self.logger.warning(f"SQLi request failed {url}: {exc}")
                    continue

                diff = self._compare_sql(normal, true_v, false_v)
                if diff["suspicious"]:
                    candidates.append({
                        "url": url,
                        "parameter": param,
                        "diff": diff,
                        "severity": diff["severity"],
                        "evidence": f"استجابة مختلفة بين 1 AND 1=1 و 1 AND 1=2 في المعامل {param}: {diff['summary']}",
                    })

        payload = {
            "target": target,
            "urls_tested": len(urls),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "مقارنة استجابة معلمة رقم 1 مقابل (1 AND 1=1) و (1 AND 1=2) للكشف عن SQLi تفاضلي.",
        }

        p_out = ctx.workspace.write_file(target, "web", "sqli_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"sqli_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Potential SQLi via {c['parameter']} ({c['url'][:70]})",
                evidence=c["evidence"],
                severity=c["severity"],
                vuln_type="sqli",
                recommendation="استخدم استعلامات معلمّات (parameterized queries) وتحقق من المدخلات من الخادم. aplic البوابة السباعية قبل الإبلاغ.",
                url=c["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[SQLi] tested {len(urls)} URLs, {len(candidates)} candidates")
        return result

    def _find_injective_param(self, url: str) -> Optional[str]:
        m = re.search(r"[?&](\w+)=(\d+)", url)
        return m.group(1) if m else None

    async def _fetch(self, client: httpx.AsyncClient, url: str, param: str, value: str) -> Dict[str, Any]:
        new_url = re.sub(rf"([?&]{re.escape(param)}=)[^&]+", rf"\g<1>{value}", url, flags=re.I)
        if new_url == url:
            new_url = url + (("&" if "?" in url else "?") + f"{param}={value}")
        resp = await client.get(new_url)
        return {
            "url": new_url,
            "status": resp.status_code,
            "length": len(resp.content),
            "body_hash": self._hash(resp.text),
        }

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]

    def _compare_sql(self, normal: Dict, true_v: Dict, false_v: Dict) -> Dict[str, Any]:
        tf_len_diff = abs(true_v["length"] - false_v["length"])
        tf_body_diff = true_v["body_hash"] != false_v["body_hash"]
        tf_status_diff = true_v["status"] != false_v["status"]
        suspicious = tf_body_diff and (tf_len_diff > 40 or tf_status_diff)
        if not suspicious:
            return {"suspicious": False, "summary": "no differential change", "severity": "Info"}
        severity = "High" if tf_status_diff and true_v["status"] in (200, 201) and false_v["status"] >= 400 else "Medium"
        return {
            "suspicious": True,
            "summary": f"true={true_v['status']}/{true_v['length']} vs false={false_v['status']}/{false_v['length']}",
            "severity": severity,
            "length_diff": tf_len_diff,
        }


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
        extra = {"urls": ["https://example.com/item?id=10", "https://example.com/search?q=abc"]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = SQLiHunterSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
