"""
IDOR Tester Skill — مهارة "فحص تجاوز تفويض الكائنات غير المباشر"
=================================================================
تجيب عن سؤال: "هل يمكن للمهاجم الوصول لبيانات غير مباشرة بتغيير رقم المعرف (ID)؟"

تقوم بـ:
  1. استلام عناوين تحتوي على معاملات ID (id=, uid=, user_id=, account=, order=, invoice=).
  2. استبدال القيمة بقيم متتالية (مثلاً 1, 2, 3) ومقارنة الاستجابة (حالة، طول، فرق في المحتوى).
  3. تسجيل المرشحين الذين يظهر استجابة مختلفة (دليل محتمل على IDOR).
  4. آمنة: لا تعدّل بيانات، فقط تقارن响应ات للقراءة.

مخرجات:
  - idor_candidates.json : عناوين مشبوهة مع أدلة المقارنة
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class IDORTesterSkill(BaseSkill):
    name = "idor_tester"
    category = "web"
    description = "Tests sequential ID parameters for IDOR via differential response analysis."
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 90.0
    max_retries = 1

    ID_PARAMS = ["id", "uid", "user_id", "account", "account_id", "order", "order_id",
                 "invoice", "ticket", "document", "file", "pid", "profile_id"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="idor_tester")
        target = ctx.target
        candidate_urls: List[str] = ctx.extra.get("urls", []) or []

        # If no URLs provided, try reading from katana/arjun outputs in workspace
        if not candidate_urls:
            candidate_urls = self._read_candidate_urls(ctx, target)

        candidates: List[Dict[str, Any]] = []
        t0 = time.time()

        async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True, trust_env=False) as client:
            for url in candidate_urls[:40]:  # 5-minute rule cap
                param = self._find_id_param(url)
                if not param:
                    continue
                try:
                    baseline = await self._fetch(client, url, param, "1")
                    await asyncio.sleep(0.2)
                    altered = await self._fetch(client, url, param, "2")
                except Exception as exc:
                    self.logger.warning(f"Request failed for {url}: {exc}")
                    continue

                diff = self._compare(baseline, altered)
                if diff["suspicious"]:
                    candidates.append({
                        "url": url,
                        "parameter": param,
                        "baseline": baseline,
                        "altered": altered,
                        "diff": diff,
                        "severity": diff["severity"],
                        "evidence": f"Changing {param} from 1 to 2 changed response: {diff['summary']}",
                    })

        payload = {
            "target": target,
            "urls_tested": len(candidate_urls),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "Compare HTTP response for ID=1 vs ID=2; record length/status/body differential.",
        }

        p_out = ctx.workspace.write_file(target, "web", "idor_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"idor_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:5]:
            result.add_finding(
                title=f"Potential IDOR on {c['parameter']} ({c['url'][:80]})",
                evidence=c["evidence"],
                severity=c["severity"],
                vuln_type="idor",
                recommendation="Verify authorization server-side for every object access. Apply 7-Question Gate before reporting.",
                url=c["url"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[IDOR] tested {len(candidate_urls)} URLs, {len(candidates)} suspicious candidates")
        return result

    def _find_id_param(self, url: str) -> Optional[str]:
        for p in self.ID_PARAMS:
            if re.search(rf"[?&]{p}=", url, re.I):
                return p
        # generic numeric-looking param at end
        m = re.search(r"[?&](\w+)=\d+", url)
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
            "headers": dict(resp.headers),
            "body_hash": self._hash(resp.text),
        }

    def _hash(self, text: str) -> str:
        import hashlib
        return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]

    def _compare(self, b: Dict[str, Any], a: Dict[str, Any]) -> Dict[str, Any]:
        length_diff = abs(a["length"] - b["length"])
        status_changed = a["status"] != b["status"]
        body_changed = a["body_hash"] != b["body_hash"]
        suspicious = body_changed and (length_diff > 50 or status_changed)
        if not suspicious:
            return {"suspicious": False, "summary": "no significant change", "severity": "Info"}
        if status_changed and a["status"] in (200, 201, 204) and b["status"] in (403, 404):
            severity = "High"
        elif length_diff > 500:
            severity = "Medium"
        else:
            severity = "Low"
        return {
            "suspicious": True,
            "summary": f"status {b['status']}->{a['status']}, length {b['length']}->{a['length']} (diff {length_diff})",
            "severity": severity,
            "length_diff": length_diff,
            "status_changed": status_changed,
        }

    def _read_candidate_urls(self, ctx: SkillContext, target: str) -> List[str]:
        urls: List[str] = []
        try:
            from pathlib import Path
            ws = ctx.workspace.get_workspace_path(target, ctx.session_id)
            for fname in ("katana_output.txt", "arjun_output.txt", "urls.txt"):
                p = ws / fname
                if p.exists():
                    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if line and ("?" in line or "=" in line):
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
        extra = {"urls": ["https://example.com/order?id=123", "https://example.com/profile?uid=5"]}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = IDORTesterSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
