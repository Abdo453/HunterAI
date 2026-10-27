"""
Web3 Audit — تدقيق أولي للعقود الذكية (Solidity)
=================================================
يكشف أنماط الثغرات الكلاسيكية:
  - Reentrancy (استدعاء خارجي قبل تحديث الحالة)
  - استخدام tx.origin للتحقق من الصلاحية
  - Missing access control على دوال حساسة (owner-only)
  - delegatecall مع معاملات تُتحكم فيها من المستخدم
  - Integer overflow/underflow إشارات
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult


class Web3AuditSkill(BaseSkill):
    name = "web3_audit"
    category = "web3"
    description = "تدقيق أولي للعقود الذكية Solidty للأنماط الخطرة"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 40.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="web3_audit")
        target = ctx.target
        source = ctx.extra.get("source", "") or ""

        issues: List[Dict[str, Any]] = []

        def add(issue: str, evidence: str, severity: str):
            issues.append({"issue": issue, "evidence": evidence[:200], "severity": severity})

        # Reentrancy: call/transfer before state update (heuristic: .call/.transfer then balance change)
        if re.search(r"\.call\s*\{|externalCall|\.transfer\(", source):
            if re.search(r"\+\=|\-=|\balances\s*\[" , source):
                add("Potential reentrancy", "استدعاء خارجي (.call/.transfer) مع تعديل حالة قد يسمح بإعادة الدخول", "High")

        # tx.origin for authorization
        if re.search(r"tx\.origin\s*==", source):
            add("tx.origin authorization", "استخدام tx.origin للتحقق من الهوية يمكن انتحاله عبر contract وسيط", "High")

        # Missing access control on sensitive functions
        sensitive = re.findall(r"function\s+(\w+)\s*\([^)]*\)\s*(public|external)", source)
        for fname, vis in sensitive:
            if any(k in fname.lower() for k in ("owner", "admin", "mint", "burn", "withdraw", "transfer")):
                if "onlyOwner" not in source and "require(msg.sender" not in source:
                    add(f"Missing access control on {fname}", f"دالة حساسة '{fname}' بدون حماية onlyOwner/msg.sender", "Medium")
                    break

        # delegatecall with user-controlled
        if re.search(r"\.delegatecall\(", source):
            add("delegatecall usage", "استخدام delegatecall قد يسمح بتنفيذ كود خبيث إذا كان الهدف يُتحكم فيه من المستخدم", "Medium")

        # Overflow/underflow hints (solidity <0.8 without SafeMath)
        if re.search(r"pragma solidity\s+\^?0\.\d\.", source) and "SafeMath" not in source:
            add("Possible integer overflow", "إصدار Solidty قديم (<0.8) بدون SafeMath قد يسمح بالتجاوز الحسابي", "Low")

        risk = "High" if any(i["severity"] == "High" for i in issues) else ("Medium" if issues else "Low")

        payload = {
            "target": target,
            "issues": issues,
            "risk": risk,
            "generated_at": time.time(),
        }

        p_out = ctx.workspace.write_file(target, "web3", "web3_audit.json", json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {"web3_audit.json": str(p_out)}
        result.raw_output = {"audit": json.dumps(payload, ensure_ascii=False)}

        if issues:
            result.add_finding(
                title=f"Web3 contract risk ({risk})",
                evidence=" | ".join(f"{i['issue']}: {i['evidence']}" for i in issues[:5]),
                severity=risk,
                vuln_type="smart_contract",
                recommendation="تدقيق العقد بواسطة أداة متخصصة (Slither/Mythril) قبل النشر.",
                url=target,
            )

        self.logger.info(f"[Web3Audit] {target}: {len(issues)} issues, risk={risk}")
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
        target = "0xcontract"
        extra = {"source": "function withdraw() public { msg.sender.call{value: address(this).balance}() }"}
        retry_attempt = 0
        tool_manager = FakeTM()
        workspace = FakeWS()
        session_id = "s1"

    async def main():
        skill = Web3AuditSkill()
        res = await skill.run(FakeCtx())
        print(res.raw_output["audit"][:400])

    asyncio.run(main())
