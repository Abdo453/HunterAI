"""
Token Scan — فحص التوكنات للأنماط المشبوهة (Rug Pull heuristics)
==================================================================
يأخذ كود Solidity أو عنوان عقدة ويبحث عن أنماط خطرة:
  - يمكن Минت غير محدود بدون سقف
  - رسوم تحويل/شراء/بيع عالية (> 50%)
  - يمكن إزالة السيولة أو إيقاف التداول من قبل المالك
  - المالك يحتفظ بمعظم الإمداد
  - لا يمكن التنصل من الملكية (renounceOwnership غير موجود)
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class TokenScanSkill(BaseSkill):
    name = "token_scan"
    category = "web3"
    description = "فحص التوكنات للأنماط المشبوهة (Rug Pull heuristics)"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 40.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="token_scan")
        target = ctx.target
        source = ctx.extra.get("source", "") or ""
        address = ctx.extra.get("address", target)

        flags: List[Dict[str, Any]] = []
        score = 0

        def add(name: str, evidence: str, weight: int):
            flags.append({"name": name, "evidence": evidence, "weight": weight})
            nonlocal score
            score += weight

        # Mint غير محدود
        if re.search(r"function\s+mint\b[^)]*\)\s*public", source, re.I):
            add("Unlimited mint function", "دالة مينت عامة قد تزيد الإمداد بلا سقف", 25)
        # رسوم عالية
        m = re.search(r"(_fee|feeBasisPoints|transferFee)\s*[:=]\s*(\d+)", source, re.I)
        if m:
            try:
                val = int(m.group(2))
                if val > 5000:  # 50% if basis points
                    add("High transfer fee", f"رسوم تحويل مرتفعة: {val}", 20)
            except ValueError:
                pass
        # يمكن إزالة السيولة/إيقاف التداول
        if re.search(r"(removeLiquidity|setTradingEnabled|setSwap|pause)\b", source, re.I):
            add("Liquidity/trading control", "الدالة تسمح بإزالة سيولة أو إيقاف تداول", 20)
        # المالك يحتفظ بمعظم الإمداد
        if re.search(r"_balances\[owner\]\s*[:=]\s*_totalSupply|owner.*\*\s*_totalSupply", source, re.I):
            add("Owner holds most supply", "المالك يحتفظ بمعظم إمداد التوكن", 15)
        # لا يمكن التنصل من الملكية
        if "renounceOwnership" not in source:
            add("Cannot renounce ownership", "لا دالة للتنصل من الملكية، المالك يسيطر إلى الأبد", 10)

        risk = "Critical" if score >= 60 else ("High" if score >= 40 else ("Medium" if score >= 20 else "Low"))

        payload = {
            "target": target,
            "address": address,
            "risk_score": min(score, 100),
            "risk_level": risk,
            "flags": flags,
            "generated_at": time.time(),
        }

        p_out = ctx.workspace.write_file(target, "web3", "token_scan.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"token_scan.json": str(p_out)}
        result.raw_output = {"scan": json.dumps(payload, ensure_ascii=False)}

        if risk in ("Critical", "High"):
            result.add_finding(
                title=f"High-risk token detected ({risk}, score {score})",
                evidence=" | ".join(f["evidence"] for f in flags[:5]),
                severity=risk,
                vuln_type="token_rug_pull",
                recommendation="تجنب التفاعل مع هذا التوكن؛ راجع العقود قبل الاستثمار.",
                url=address,
            )

        self.logger.info(f"[TokenScan] {address}: score={score} risk={risk}")
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
        target = "0x123"
        extra = {"address": "0x123", "source": "function mint(uint256 amount) public { _mint(msg.sender, amount); }"}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = TokenScanSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["scan"][:400])

    asyncio.run(main())
