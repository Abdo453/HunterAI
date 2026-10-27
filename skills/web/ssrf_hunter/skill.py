"""
SSRF Hunter Skill — مهارة "صيد طلبات التزوير من الخادم (SSRF)"
=================================================================
تجيب عن سؤال: "هل يمكن إجبار الخادم على طلب موارد داخلية/خارجية نيابة عن المهاجم؟"

تقوم بـ:
  1. استلام عناوين تحتوي على معاملات URL محتملة (url=, callback=, webhook=, return=, next=, redirect=, image=, src=).
  2. إرسال payload آمن (مثلاً http://127.0.0.1 أو عنوان تعاون يُحدده المستخدم) ورصد سلوك الخادم.
  3. تسجيل المرشحين مع staus/stlength differential بين الطلب الطبيعي والطلب المحمل.
  4. آمنة: لا تستهدف أنظمة داخلية حقيقية إلا إذا توفير collaborator domain.

مخرجات:
  - ssrf_candidates.json : معاملات مشبوهة مع أدلة
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


class SSRFHunterSkill(BaseSkill):
    name = "ssrf_hunter"
    category = "web"
    description = "Detects SSRF parameters by comparing normal vs SSRF-payload responses."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 90.0
    max_retries = 1

    SSRF_PARAMS = ["url", "callback", "webhook", "return", "next", "redirect", "uri",
                   "image", "src", "fetch", "load", "page", "file", "document", "domain"]

    SAFE_PAYLOAD = "http://127.0.0.1:1"  # unlikely to open a real service; only detects server-side request

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="ssrf_hunter")
        target = ctx.target
        candidate_urls: List[str] = ctx.extra.get("urls", []) or []
        collaborator = ctx.extra.get("collaborator")  # optional out-of-band domain provided by operator

        if not candidate_urls:
            candidate_urls = self._read_candidate_urls(ctx, target)

        candidates: List[Dict[str, Any]] = []
        t0 = time.time()

        async with httpx.AsyncClient(timeout=12, verify=False, follow_redirects=False, trust_env=False) as client:
            for url in candidate_urls[:40]:
                param = self._find_ssrf_param(url)
                if not param:
                    continue
                try:
                    normal = await self._fetch(client, url, param, "https://example.com")
                    await asyncio.sleep(0.2)
                    payload_url = collaborator if collaborator else self.SAFE_PAYLOAD
                    injected = await self._fetch(client, url, param, payload_url)
                except Exception as exc:
                    self.logger.warning(f"Request failed for {url}: {exc}")
                    continue

                diff = self._compare(normal, injected)
                if diff["suspicious"]:
                    candidates.append({
                        "url": url,
                        "parameter": param,
                        "payload_used": payload_url,
                        "normal": normal,
                        "injected": injected,
                        "diff": diff,
                        "severity": diff["severity"],
                        "evidence": f"SSRF payload '{payload_url}' changed response vs normal: {diff['summary']}",
                    })

        payload = {
            "target": target,
            "urls_tested": len(candidate_urls),
            "collaborator": collaborator,
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "Compare response when url-param points to example.com vs a controlled payload; look for server-side fetch evidence.",
        }

        p_out = ctx.workspace.write_file(target, "web", "ssrf_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"ssrf_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Potential SSRF via {c['parameter']} ({c['url'][:80]})",
                evidence=c["evidence"],
                severity=c["severity"],
                vuln_type="ssrf",
                recommendation="Validate and whitelist URL schemes/hosts; disable internal network access from the fetching service. Apply 7-Question Gate.",
                url=c["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[SSRF] tested {len(candidate_urls)} URLs, {len(candidates)} candidates")
        return result

    def _find_ssrf_param(self, url: str) -> Optional[str]:
        for p in self.SSRF_PARAMS:
            if re.search(rf"[?&]{p}=", url, re.I):
                return p
        return None

    async def _fetch(self, client: httpx.AsyncClient, url: str, param: str, value: str) -> Dict[str, Any]:
        new_url = re.sub(rf"([?&]{re.escape(param)}=)[^&]+", rf"\g<1>{value}", url, flags=re.I)
        if new_url == url:
            new_url = url + (("&" if "?" in url else "?") + f"{param}={value}")
        try:
            resp = await client.get(new_url)
            return {
                "url": new_url,
                "status": resp.status_code,
                "length": len(resp.content),
                "body_hash": self._hash(resp.text),
                "error": None,
            }
        except Exception as exc:
            return {"url": new_url, "status": 0, "length": 0, "body_hash": "", "error": str(exc)}

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]

    def _compare(self, normal: Dict[str, Any], injected: Dict[str, Any]) -> Dict[str, Any]:
        if normal.get("error") or injected.get("error"):
            return {"suspicious": False, "summary": "request error", "severity": "Info"}
        length_diff = abs(injected["length"] - normal["length"])
        status_changed = injected["status"] != normal["status"]
        body_changed = injected["body_hash"] != normal["body_hash"]
        suspicious = body_changed and (length_diff > 30 or status_changed)
        if not suspicious:
            return {"suspicious": False, "summary": "no significant change", "severity": "Info"}
        severity = "High" if injected["status"] in (200, 201, 204) and normal["status"] >= 400 else "Medium"
        return {
            "suspicious": True,
            "summary": f"status {normal['status']}->{injected['status']}, length {normal['length']}->{injected['length']}",
            "severity": severity,
        }

    def _read_candidate_urls(self, ctx: SkillContext, target: str) -> List[str]:
        urls: List[str] = []
        try:
            from pathlib import Path
            ws = ctx.workspace.get_workspace_path(target, ctx.session_id)
            for fname in ("katana_output.txt", "arjun_output.txt", "urls.txt", "ssrf_params.txt"):
                p = ws / fname
                if p.exists():
                    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line and ("?" in line):
                            urls.append(line)
        except Exception:
            pass
        return urls


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, cmd):
            return True

    class FakeWS:
        def get_workspace_path(self, t, s):
            from pathlib import Path
            return Path("/tmp")
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"urls": ["https://example.com/fetch?url=https://example.com/image.png"]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = SSRFHunterSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
