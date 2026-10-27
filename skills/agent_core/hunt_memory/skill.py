"""
Hunt Memory — ذاكرة الصيد
==========================
تنفّذ أوامر /remember و /memory-gc:
  - remember(target, note): يسجل ملاحظة/ثغرة في ملف JSONL لكل هدف
  - memory-gc:يدوّر ملفات ذاكرة الصيد القديمة ويحتفظ بالأحدث
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class HuntMemorySkill(BaseSkill):
    name = "hunt_memory"
    category = "agent_core"
    description = "يسجل ملاحظات الصيد لكل هدف ويّدوّر ملفات الذاكرة القديمة"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 30.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        action = ctx.extra.get("action", "remember")  # remember | gc | list
        note = ctx.extra.get("note", "")

        memory_dir = ctx.workspace.get_workspace_path(target, ctx.session_id).parent / "memory"
        memory_dir.mkdir(parents=True, exist_ok=True)

        if action == "remember":
            entry = {
                "target": target,
                "note": note,
                "timestamp": time.time(),
                "session_id": ctx.session_id,
            }
            mem_file = memory_dir / f"{target}.jsonl"
            with mem_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            result.add_finding(
                title="Hunt memory recorded",
                evidence=note,
                severity="Info",
                vuln_type="memory",
                recommendation="راجع ملف الذاكرte قبل إعداد التقرير النهائي.",
                url=target,
            )
            result.output_files = {"memory": str(mem_file)}
            result.raw_output = {"action": "remember", "file": str(mem_file), "note": note}

        elif action == "gc":
            kept = self._gc(memory_dir)
            result.raw_output = {"action": "gc", "kept_files": kept, "removed_count": kept.get("removed", 0)}
            result.add_finding(
                title="Memory GC completed",
                evidence=f"أُزيلت {kept.get('removed', 0)} ملفًا قديمًا، يُحتفظ بملفات كل هدف.",
                severity="Info",
                vuln_type="memory",
                recommendation="نفّذ memory-gc دوريًا لمنع نمو الملفات.",
                url=target,
            )

        elif action == "list":
            files = [str(p) for p in memory_dir.glob("*.jsonl")]
            result.raw_output = {"action": "list", "files": files}
        else:
            result.success = False
            result.errors.append(f"unknown action: {action}")

        self.logger.info(f"[HuntMemory] action={action} target={target}")
        return result

    def _gc(self, memory_dir: Path, keep_per_target: int = 1) -> Dict[str, Any]:
        removed = 0
        kept_files: List[str] = []
        by_target: Dict[str, List[Path]] = {}
        for f in memory_dir.glob("*.jsonl"):
            target = f.stem
            by_target.setdefault(target, []).append(f)
        for target, files in by_target.items():
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for f in files[keep_per_target:]:
                try:
                    f.unlink()
                    removed += 1
                except Exception:
                    pass
            kept_files.append(str(files[0]))
        return {"removed": removed, "kept": kept_files}


if __name__ == "__main__":
    import asyncio

    class FakeWS:
        def get_workspace_path(self, t, s):
            from pathlib import Path
            return Path(f"/tmp/ws/{t}/{s}")
        def write_file(self, *a, **k):
            from pathlib import Path
            return Path("/tmp/x")

    class FakeCtx:
        target = "example.com"
        extra = {"action": "remember", "note": "id=5suspect on /order"}
        retry_attempt = 0
        tool_manager = None
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = HuntMemorySkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output)

    asyncio.run(main())
