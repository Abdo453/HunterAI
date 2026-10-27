"""
Takeover Confirm Skill — مهارة "تأكيد الاستحواذ على النطاق الفرعي"
=====================================================================
تجيب عن سؤال: "هل النطاقات الفرعية المعرّضة للاستحواذ (dangling CNAME) قابلة للاستحواذ فعليًا؟"

تقوم بـ:
  1. استلام نطاقات فرعية بها سجل CNAME (من subdomain_enum/dns).
  2. فحص الـ CNAME ضد أنماط الخدمات المعروفة (GitHub Pages, Heroku, AWS S3, Azure, Shopify, etc.).
  3. محاولة الاتصال بالهدف المستضاف والتحقق من استجابة "لا يوجد موقع" الخاصة بالخدمة (دليل على الاستحواذ المحتمل).
  4. تسجيل النطاقات المؤهلة للاستحواذ مع طريقة الإثبات.

مخرجات:
  - takeover_candidates.json : النطاقات المؤهلة للاستحواذ
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


# CNAME pattern -> (service name, fingerprint text indicating dangling service)
TAKEOVER_FINGERPRINTS: List[Dict[str, Any]] = [
    {"pattern": r"github\.io", "service": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here"},
    {"pattern": r"herokuapp\.com", "service": "Heroku", "fingerprint": "No such app"},
    {"pattern": r"s3\.amazonaws\.com|\.s3\.", "service": "AWS S3", "fingerprint": "NoSuchBucket"},
    {"pattern": r"azurewebsites\.net", "service": "Azure Web Apps", "fingerprint": "404"},
    {"pattern": r"cloudfront\.net", "service": "AWS CloudFront", "fingerprint": "Bad request"},
    {"pattern": r"shopify\.com", "service": "Shopify", "fingerprint": "Sorry, this shop is currently unavailable"},
    {"pattern": r"fastly\.net", "service": "Fastly", "fingerprint": "Fastly error: unknown domain"},
    {"pattern": r"wpengine\.com", "service": "WP Engine", "fingerprint": "No such site"},
    {"pattern": r"bitbucket\.io", "service": "Bitbucket Pages", "fingerprint": "Repository not found"},
    {"pattern": r"readme\.io", "service": "Readme.io", "fingerprint": "Project not found"},
]


class TakeoverConfirmSkill(BaseSkill):
    name = "takeover_confirm"
    category = "analysis"
    description = "Confirms subdomain takeover candidates via dangling CNAME fingerprints."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 80.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="takeover_confirm")
        target = ctx.target
        subdomains: List[str] = ctx.extra.get("subdomains", []) or []
        cname_map: Dict[str, str] = ctx.extra.get("cname_map", {}) or {}

        candidates: List[Dict[str, Any]] = []
        t0 = time.time()

        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False, trust_env=False) as client:
            for sub in subdomains[:50]:
                cname = cname_map.get(sub)
                if not cname:
                    # Try to guess CNAME from a prior DNS skill output if stored (skip network DNS here)
                    continue
                matched = [fp for fp in TAKEOVER_FINGERPRINTS if re.search(fp["pattern"], cname, re.I)]
                if not matched:
                    continue

                # Attempt HTTP to confirm dangling state
                for scheme in ("https", "http"):
                    try:
                        resp = await client.get(f"{scheme}://{sub}", timeout=10)
                        body = resp.text[:2000]
                        for fp in matched:
                            if fp["fingerprint"].lower() in body.lower():
                                candidates.append({
                                    "subdomain": sub,
                                    "cname": cname,
                                    "service": fp["service"],
                                    "scheme": scheme,
                                    "status": resp.status_code,
                                    "fingerprint_matched": fp["fingerprint"],
                                    "proof_url": f"{scheme}://{sub}",
                                    "severity": "High",
                                    "evidence": f"CNAME {cname} ({fp['service']}) returns '{fp['fingerprint']}' — subdomain is claimable.",
                                })
                                break
                        else:
                            continue
                        break
                    except Exception:
                        continue

        payload = {
            "target": target,
            "subdomains_checked": len(subdomains),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "Match CNAME to known service fingerprints; confirm with HTTP response containing the service's 'not found' page.",
        }

        p_out = ctx.workspace.write_file(target, "analysis", "takeover_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"takeover_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Subdomain takeover: {c['subdomain']} → {c['service']}",
                evidence=c["evidence"],
                severity="High",
                vuln_type="subdomain_takeover",
                recommendation=f"Reclaim the CNAME or delete the dangling DNS record for {c['subdomain']}.",
                url=c["proof_url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[Takeover] {len(subdomains)} checked, {len(candidates)} claimable candidates")
        return result


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
        extra = {"subdomains": ["old.example.com"], "cname_map": {"old.example.com": "old.github.io"}}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = TakeoverConfirmSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
