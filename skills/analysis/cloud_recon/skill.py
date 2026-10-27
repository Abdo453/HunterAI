"""
Cloud Recon — اكتشاف حاويات سحابة عامة مكشوفة
===============================================
يختبر عناوين شائعة لـ AWS S3 و Azure Blob و GCP Storage للنطاق المستهدف
ويُسجل الحاويات المفتوحة (قابلة للقراءة/الكتابة) كمرشحات takeover أو تسريب بيانات.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class CloudReconSkill(BaseSkill):
    name = "cloud_recon"
    category = "analysis"
    description = "اكتشاف حاويات سحابة عامة مكشوفة (S3، Azure Blob، GCS)"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 60.0
    max_retries = 1

    def _candidate_urls(self, target: str) -> List[str]:
        name = target.replace("https://", "").replace("http://", "").split("/")[0]
        domain = name.split(".")[0]
        urls = [
            f"https://{domain}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain}",
            f"https://{domain}.blob.core.windows.net",
            f"https://{domain}.blob.core.windows.net/$root",
            f"https://storage.googleapis.com/{domain}",
            f"https://{domain}.storage.googleapis.com",
            f"https://{domain}.digitaloceanspaces.com",
        ]
        return urls

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="cloud_recon")
        target = ctx.target
        urls = self._candidate_urls(target)
        candidates: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False, trust_env=False) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                except Exception:
                    continue
                body = resp.text[:1000]
                open_bucket = False
                reason = ""
                if resp.status_code == 200 and ("ListBucketResult" in body or "Container" in body or "<?xml" in body):
                    open_bucket = True
                    reason = "استجابة XML/Open bucket"
                elif resp.status_code in (403, 404):
                    continue
                if open_bucket:
                    candidates.append({
                        "url": url,
                        "status": resp.status_code,
                        "reason": reason,
                        "severity": "High",
                        "evidence": f"حاوية سحابة عامة مفتوحة: {url} (status {resp.status_code})",
                    })

        payload = {
            "target": target,
            "urls_tested": len(urls),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "محاولة الوصول إلى عناوين حاويات سحابية شائعة واكتشاف الحاويات المفتوحة للقراءة.",
        }

        p_out = ctx.workspace.write_file(target, "analysis", "cloud_recon.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"cloud_recon.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Exposed cloud bucket ({c['url']})",
                evidence=c["evidence"],
                severity="High",
                vuln_type="cloud_exposure",
                recommendation="قم بتقييد الوصول إلى الحاوية واستخدم سياسات IAM صارمة.",
                url=c["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[CloudRecon] tested {len(urls)} URLs, {len(candidates)} exposed buckets")
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
        extra = {}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = CloudReconSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
