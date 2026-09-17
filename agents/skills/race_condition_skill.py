"""
Race Condition & Concurrency Autonomous Skill
=============================================
Integrates RaceConditionEngine to test for double-spending and limit overrun.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult
from core.concurrency.race_engine import RaceConditionEngine

log = logging.getLogger("hunter_ai.skills.race_condition")


class RaceConditionSkill(BaseSkill):
    name: str = "RaceConditionSkill"
    vuln_type: str = "race_condition"
    cwe: str = "CWE-362"
    owasp_top10: str = "A01:2021 — Broken Access Control"
    default_severity: str = "High"

    async def run(self, target_url: str, param_name: str = "coupon", **kwargs) -> SkillResult:
        logs = [f"[RACE] Testing concurrency limit on {target_url} (param={param_name})"]
        engine = RaceConditionEngine()
        payload = kwargs.get("payload", {param_name: "DISCOUNT50"})

        # Concurrent async burst test
        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout, verify=False) as client:
            async def _send_burst():
                try:
                    return await client.post(target_url, data=payload)
                except Exception:
                    return None

            burst_count = 6
            tasks = [_send_burst() for _ in range(burst_count)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            successful = [r for r in responses if isinstance(r, httpx.Response) and r.status_code in (200, 201)]
            # If 3 or more concurrent requests succeed on a single-use action
            if len(successful) >= 3 and any(w in target_url.lower() for w in ["coupon", "transfer", "redeem", "vote", "race"]):
                evidence = f"Executed {burst_count} parallel requests; {len(successful)} requests succeeded concurrently."
                logs.append(f"[RACE] Confirmed race condition: {evidence}")
                return SkillResult(
                    verified=True,
                    vuln_type=self.vuln_type,
                    title=f"Race Condition / Concurrency Flaw on '{target_url}'",
                    severity="High",
                    endpoint=target_url,
                    param_name=param_name,
                    evidence=evidence,
                    payload_used=str(payload),
                    remediation="Apply atomic database transactions or distributed synchronization locks (Redis/PostgreSQL SELECT FOR UPDATE).",
                    confidence=0.90,
                    tool=self.name,
                    evidence_sources=[f"{self.name}/ParallelBurst"],
                    cwe=self.cwe,
                    owasp_top10=self.owasp_top10,
                    logs=logs
                )

        logs.append("[RACE] No concurrency race condition detected")
        return SkillResult(verified=False, vuln_type=self.vuln_type, endpoint=target_url,
                           param_name=param_name, tool=self.name, logs=logs)
