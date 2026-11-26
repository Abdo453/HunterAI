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
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from core.scope_engine import validate_http_url_target
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
        urls: List[str] = list(ctx.extra.get("urls", []) or [])
        if not urls:
            urls = self._read_workspace_urls(ctx, target)
        candidates: List[Dict[str, Any]] = []
        allow_loopback = bool(ctx.extra.get("allow_loopback", False))
        in_scope = ctx.extra.get("in_scope")

        async with httpx.AsyncClient(timeout=12, verify=False, follow_redirects=False, trust_env=False) as client:
            for url in urls[:40]:
                ok_url, _ = validate_http_url_target(
                    url,
                    in_scope=in_scope,
                    allow_loopback=allow_loopback,
                    resolve_dns=False,
                    fail_closed=False,
                )
                if not ok_url:
                    continue
                params = self._extract_params(url)
                if not params:
                    continue
                for param in params:
                    marker = f"{self.MARKER_PREFIX}{int(time.time()*1000)%100000}"
                    try:
                        inj = await self._inject(client, url, param, marker)
                        await asyncio.sleep(0.1)
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
                recommendation="ترميز المخرجات (output encoding) وسياسة أمان المحتوى (CSP). طبّق البوابة السباعية قبل الإبلاغ.",
                url=c["url"],
            )
            if "triage_gate" not in result.next_skills:
                result.next_skills.append("triage_gate")

        self.logger.info(f"[XSS] tested {len(urls)} URLs, {len(candidates)} candidates")
        return result

    def _read_workspace_urls(self, ctx: SkillContext, target: str) -> List[str]:
        found: List[str] = []
        try:
            ws = ctx.workspace.get_workspace_path(target, ctx.session_id)
            for rel in ("web/urls.txt", "urls.txt"):
                p = ws / rel
                if p.is_file():
                    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                        s = line.strip()
                        if s.startswith(("http://", "https://")) and "?" in s:
                            found.append(s)
        except Exception:
            pass
        return found

    def _extract_params(self, url: str) -> List[str]:
        parsed = urlsplit(url)
        if not parsed.query:
            return []
        params = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True) if k]
        return list(dict.fromkeys(params))[:5]

    async def _inject(self, client: httpx.AsyncClient, url: str, param: str, marker: str) -> Dict[str, Any]:
        value = marker if marker.startswith(self.MARKER_PREFIX) else f"{self.MARKER_PREFIX}{marker}"
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        updated = False
        new_pairs: List[tuple[str, str]] = []
        for k, v in pairs:
            if k.lower() == param.lower() and not updated:
                new_pairs.append((k, value))
                updated = True
            else:
                new_pairs.append((k, v))
        if not updated:
            new_pairs.append((param, value))
        new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(new_pairs), parsed.fragment))
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
            return Path(tempfile.gettempdir()) / "xss_candidates.json"

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
