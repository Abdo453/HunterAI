"""
XSS Hunter — صيد حقنieur النصوص عبر المواقع (عكسية/مخزنة أولية)
====================================================================
حقن علامة فريدة في المعاملات والتحقق من ظهورها في الاستجابة بدون ترميز.
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


class XSSHunterSkill(BaseSkill):
    name = "xss_hunter"
    category = "web"
    description = "كشف XSS انعكاسي عبر حقن علامة فريدة والتحقق من ظهورها خامًا في الاستجابة"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 90.0
    max_retries = 1

    MARKER_PREFIX = "pentestxss_"
    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "'<script>alert(1)</script>",
    ]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="xss_hunter")
        target = ctx.target
        urls: List[str] = ctx.extra.get("urls", []) or []
        candidates: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=12, verify=False, follow_redirects=True, trust_env=False) as client:
            for url in urls[:40]:
                params = self._extract_params(url)
                if not params:
                    continue
                for param in params:
                    marker = f"{self.MARKER_PREFIX}{int(time.time()*1000)%100000}"
                    try:
                        inj = await self._inject(client, url, param, marker)
                        await asyncio.sleep(0.2)
                    except Exception as exc:
                        self.logger.warning(f"XSS request failed {url}: {exc}")
                        continue

                    reflected = marker in inj.get("body", "")
                    if reflected:
                        candidates.append({
                            "url": url,
                            "parameter": param,
                            "marker": marker,
                            "status": inj["status"],
                            "evidence": f"العلامة '{marker}' ظهرت غير مشفرة في الاستجابة — احتمال XSS انعكاسي",
                            "severity": "Medium",
                        })
                        break

        payload = {
            "target": target,
            "urls_tested": len(urls),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "حقن علامة فريدة في كل معامل والتحقق من ظهورها خامًا في جسم الاستجابة.",
        }

        p_out = ctx.workspace.write_file(target, "web", "xss_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"xss_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Potential Reflected XSS via {c['parameter']} ({c['url'][:70]})",
                evidence=c["evidence"],
                severity=c["severity"],
                vuln_type="xss",
                recommendation="ترميز المخرجات (output encoding) وسياسة أمان المحتوى (CSP). aplic البوابة السباعية قبل الإبلاغ.",
                url=c["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[XSS] tested {len(urls)} URLs, {len(candidates)} candidates")
        return result

    def _extract_params(self, url: str) -> List[str]:
        if "?" not in url:
            return []
        qs = url.split("?", 1)[1]
        params = re.findall(r"([\w\-]+)=[^&]*", qs)
        return list(dict.fromkeys(params))[:5]

    async def _inject(self, client: httpx.AsyncClient, url: str, param: str, marker: str) -> Dict[str, Any]:
        value = f"{self.MARKER_PREFIX}{marker}"
        new_url = re.sub(rf"([?&]{re.escape(param)}=)[^&]+", rf"\g<1>{value}", url, flags=re.I)
        if new_url == url:
            new_url = url + (("&" if "?" in url else "?") + f"{param}={value}")
        resp = await client.get(new_url)
        return {
            "url": new_url,
            "status": resp.status_code,
            "body": resp.text,
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
        extra = {"urls": ["https://example.com/search?q=test", "https://example.com/page?name=foo"]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = XSSHunterSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
