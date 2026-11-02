"""
Secrets Hunter — البحث عن أسرار ومفاتيح مسربة
===============================================
يستخدم trufflehog/gitleaks إن توفّرا، وإلا يجري بحثًا أنماطيًا (regex) على نصوص الاستجابات وملفات JS:
  - AWS keys, Google keys, Stripe, GitHub tokens, Slack, generic API keys, passwords.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult


SECRET_PATTERNS: List[Dict[str, str]] = [
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}"},
    {"name": "AWS Secret Key", "pattern": r"[0-9a-zA-Z/+]{40}"},
    {"name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9]{36,}"},
    {"name": "Slack Token", "pattern": r"xox[baprs]-[0-9a-zA-Z-]{10,}"},
    {"name": "Stripe Key", "pattern": r"(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}"},
    {"name": "Generic API Key", "pattern": r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"},
    {"name": "Private Key", "pattern": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
    {"name": "JWT", "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"},
]


class SecretsHunterSkill(BaseSkill):
    name = "secrets_hunter"
    category = "analysis"
    description = "بحث عن أسرار ومفاتيح مسربة باستخدام أنماط أو trufflehog/gileaks"
    tools_required: List[str] = []
    fallback_tools: List[str] = ["trufflehog", "gitleaks"]
    timeout_seconds = 90.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="secrets_hunter")
        target = ctx.target
        paths: List[str] = ctx.extra.get("paths", []) or []
        contents: Dict[str, str] = ctx.extra.get("contents", {}) or {}
        candidates: List[Dict[str, Any]] = []

        # 1) أداة خارجية إن توفّرت
        tool = self._pick_tool(ctx.tool_manager)
        if tool:
            for p in paths[:20]:
                try:
                    res = await ctx.tool_manager.execute(f"{tool} {p}", timeout=60)
                    out = res.stdout + res.stderr
                    candidates.extend(self._parse_secret_output(out, p, tool))
                except Exception as exc:
                    self.logger.warning(f"{tool} failed for {p}: {exc}")

        # 2) بحث أنماطي على محتويات مقدمة
        for p, text in contents.items():
            candidates.extend(self._scan_text(text, p))

        payload = {
            "target": target,
            "paths_scanned": len(paths) + len(contents),
            "candidates": candidates,
            "generated_at": time.time(),
            "methodology": "أنماط تعبير منظم للمفاتيح والرموز الحساسة؛ يدعم trufflehog/gileaks إن توفّرا.",
        }

        p_out = ctx.workspace.write_file(target, "analysis", "secrets_candidates.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"secrets_candidates.json": str(p_out)}
        result.raw_output = {"candidates": json.dumps(payload, ensure_ascii=False)}

        for c in candidates[:8]:
            result.add_finding(
                title=f"Potential leaked secret: {c['type']} ({c['file'][:60]})",
                evidence=c["evidence"],
                severity="High",
                vuln_type="secret_exposure",
                recommendation="أزل السر من الكود، دوّره فورًا، وتحقق من استخدامه غير المصرح به.",
                url=c["file"],
            )
            result.next_skills.append("validation_gate")

        self.logger.info(f"[Secrets] scanned {payload['paths_scanned']} paths, {len(candidates)} candidates")
        return result

    def _pick_tool(self, tool_manager) -> Optional[str]:
        for t in ("trufflehog", "gitleaks"):
            try:
                if tool_manager and tool_manager.is_available(t):
                    return t
            except Exception:
                pass
        return None

    def _parse_secret_output(self, out: str, file: str, tool: str) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for line in out.splitlines():
            if not line.strip():
                continue
            found.append({
                "type": f"secret ({tool})",
                "file": file,
                "evidence": line[:300],
            })
        return found

    def _scan_text(self, text: str, file: str) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for rule in SECRET_PATTERNS:
            for m in re.finditer(rule["pattern"], text):
                found.append({
                    "type": rule["name"],
                    "file": file,
                    "evidence": m.group(0)[:200],
                })
                break  #一种类型 لكل ملف لتجنب التكرار المفرط
        return found


if __name__ == "__main__":
    import asyncio

    class FakeTM:
        def is_available(self, c):
            return False

    class FakeWS:
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"paths": [], "contents": {"js/main.js": 'const key = "sk_live_abcdefghijklmnopqrstuvwxyz";'}}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = SecretsHunterSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["candidates"][:400])

    asyncio.run(main())
