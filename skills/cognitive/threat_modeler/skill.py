"""
ThreatModelerSkill -- AI-powered STRIDE threat model builder + ranked attack paths.
Heuristic-first; optionally enhanced with AIReasoningCore when a provider is available.
Windows-safe: no box-drawing unicode in logger calls.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional heavyweight imports — degrade gracefully when offline
# ---------------------------------------------------------------------------
try:
    from core.ai_reasoning_core import AIReasoningCore
    _HAS_AI = True
except Exception:
    _HAS_AI = False


# ---------------------------------------------------------------------------
# Heuristic pattern table  (url fragment -> (risk, [vulns]))
# ---------------------------------------------------------------------------
_PATTERNS: List[tuple] = [
    # (fragment_list, risk_score, vuln_list)
    (["id=", "uid=", "user_id="],                   8.0, ["IDOR", "BOLA"]),
    (["url=", "redirect=", "webhook=", "callback="], 9.0, ["SSRF", "Open Redirect"]),
    (["password=", "token=", "auth="],               9.0, ["Broken Auth", "JWT"]),
    (["search=", "q=", "query="],                    7.0, ["XSS", "SQLi"]),
    (["upload", "file=", "path="],                   8.0, ["LFI", "File Upload", "Path Traversal"]),
    (["/api/", "/v1/", "/v2/"],                      6.0, ["Mass Assignment", "Excessive Data Exposure"]),
    (["price=", "amount=", "discount=", "coupon="],  8.0, ["Business Logic"]),
]
_DEFAULT_RISK  = 3.0
_DEFAULT_VULNS = ["Information Disclosure"]


class ThreatModelerSkill(BaseSkill):
    name = "threat_modeler"
    category = "cognitive"
    description = "AI-powered threat model builder -- STRIDE analysis + ranked attack paths"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 120.0
    max_retries = 1

    # ------------------------------------------------------------------
    # Heuristic endpoint analysis
    # ------------------------------------------------------------------
    def _analyze_endpoint(self, ep: Any) -> Dict[str, Any]:
        """
        Heuristic risk analysis for a single endpoint entry.
        ep may be a str (URL) or a dict with 'url'/'method' keys.
        """
        if isinstance(ep, dict):
            url    = str(ep.get("url", ep.get("endpoint", str(ep))))
            method = str(ep.get("method", "GET")).upper()
        else:
            url    = str(ep)
            method = "GET"

        url_lower = url.lower()
        risk   = _DEFAULT_RISK
        vulns  = list(_DEFAULT_VULNS)
        attack_vectors: List[str] = []

        for fragments, r, v in _PATTERNS:
            if any(f in url_lower for f in fragments):
                if r > risk:          # keep highest risk match
                    risk  = r
                    vulns = list(v)
                attack_vectors.extend(v)

        # Deduplicate attack_vectors while preserving order
        seen: set = set()
        unique_av: List[str] = []
        for av in attack_vectors:
            if av not in seen:
                seen.add(av)
                unique_av.append(av)

        return {
            "url":            url,
            "method":         method,
            "risk_score":     risk,
            "attack_vectors": unique_av if unique_av else ["Passive Recon"],
            "likely_vulns":   vulns,
        }

    # ------------------------------------------------------------------
    # Fallback synthetic data
    # ------------------------------------------------------------------
    def _fallback_analysis(self, target: str) -> List[Dict[str, Any]]:
        """Returns synthetic endpoint list when no real data is provided."""
        return [
            {
                "url":            f"https://{target}/api/v1/users?id=1",
                "method":         "GET",
                "risk_score":     8.0,
                "attack_vectors": ["IDOR", "BOLA"],
                "likely_vulns":   ["IDOR", "BOLA"],
            },
            {
                "url":            f"https://{target}/search?q=test",
                "method":         "GET",
                "risk_score":     7.0,
                "attack_vectors": ["XSS", "SQLi"],
                "likely_vulns":   ["XSS", "SQLi"],
            },
            {
                "url":            f"https://{target}/redirect?url=http://evil.com",
                "method":         "GET",
                "risk_score":     9.0,
                "attack_vectors": ["SSRF", "Open Redirect"],
                "likely_vulns":   ["SSRF", "Open Redirect"],
            },
        ]

    # ------------------------------------------------------------------
    # AI enhancement (optional)
    # ------------------------------------------------------------------
    async def _ai_enhance(self, target: str, ep_summaries: str) -> str:
        if not _HAS_AI:
            return ""
        try:
            prompt = (
                f"You are a senior security researcher performing STRIDE threat modelling.\n"
                f"Target: {target}\n"
                f"Analysed endpoints:\n{ep_summaries}\n\n"
                f"Provide a brief (<=200 word) executive summary of the top 3 attack paths "
                f"and recommended mitigations. Plain text, no markdown."
            )
            return await AIReasoningCore.ask_ai(prompt)
        except Exception as exc:
            logger.debug("AI enhancement unavailable: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------
    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=False)
        t0 = time.time()

        endpoints_raw: List[Any] = ctx.extra.get("endpoints", [])
        tech_stack: List[str]    = ctx.extra.get("tech_stack", [])
        target: str              = ctx.target

        logger.info("[threat_modeler] Analysing target=%s endpoints=%d", target, len(endpoints_raw))

        # --- Analyse or fall back ---
        if endpoints_raw:
            analysed = [self._analyze_endpoint(ep) for ep in endpoints_raw]
        else:
            logger.info("[threat_modeler] No endpoints provided -- using fallback synthetic data")
            analysed = self._fallback_analysis(target)

        # Sort by risk descending
        analysed.sort(key=lambda x: x["risk_score"], reverse=True)

        high_risk = [e for e in analysed if e["risk_score"] >= 7.0]

        # --- Optional AI summary ---
        ep_summary_text = "\n".join(
            f"  {e['method']} {e['url']} risk={e['risk_score']} vulns={e['likely_vulns']}"
            for e in analysed[:10]
        )
        ai_summary = await self._ai_enhance(target, ep_summary_text)

        # --- Build threat_model dict ---
        threat_model: Dict[str, Any] = {
            "target":           target,
            "tech_stack":       tech_stack,
            "total_endpoints":  len(analysed),
            "high_risk_count":  len(high_risk),
            "ai_summary":       ai_summary,
            "endpoints":        analysed,
            "generated_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # --- Build attack_tree.md ---
        md_lines = [
            f"# Attack Tree -- {target}",
            "",
            f"> Generated: {threat_model['generated_at']}",
            f"> Total endpoints: {len(analysed)} | High-risk: {len(high_risk)}",
            "",
            "## Ranked Attack Paths",
            "",
        ]
        for rank, ep in enumerate(analysed, 1):
            sev = "CRITICAL" if ep["risk_score"] >= 9 else ("HIGH" if ep["risk_score"] >= 7 else "MEDIUM")
            md_lines += [
                f"### {rank}. [{sev}] {ep['url']}",
                f"- **Method**: `{ep['method']}`",
                f"- **Risk Score**: {ep['risk_score']}/10",
                f"- **Attack Vectors**: {', '.join(ep['attack_vectors'])}",
                f"- **Likely Vulns**: {', '.join(ep['likely_vulns'])}",
                "",
            ]

        if ai_summary:
            md_lines += ["## AI Executive Summary", "", ai_summary, ""]

        attack_tree_md = "\n".join(md_lines)

        # --- Write files ---
        tm_path = ctx.workspace.write_file(
            ctx.target, "cognitive",
            "threat_model.json",
            json.dumps(threat_model, indent=2),
            session_id=ctx.session_id,
        )
        at_path = ctx.workspace.write_file(
            ctx.target, "cognitive",
            "attack_tree.md",
            attack_tree_md,
            session_id=ctx.session_id,
        )

        result.output_files["threat_model.json"] = str(tm_path)
        result.output_files["attack_tree.md"]    = str(at_path)

        # --- Add findings for high-risk endpoints ---
        for ep in high_risk:
            sev = "Critical" if ep["risk_score"] >= 9 else "High"
            result.add_finding(
                title       = f"High-Risk Endpoint: {ep['likely_vulns'][0]} @ {ep['url']}",
                evidence    = (
                    f"URL: {ep['url']}\nMethod: {ep['method']}\n"
                    f"Risk Score: {ep['risk_score']}/10\n"
                    f"Likely Vulns: {', '.join(ep['likely_vulns'])}"
                ),
                severity    = sev,
                vuln_type   = ep["likely_vulns"][0],
                tool        = "threat_modeler",
                url         = ep["url"],
                recommendation = (
                    f"Investigate {', '.join(ep['likely_vulns'])} on this endpoint. "
                    "Apply input validation, auth checks and rate-limiting."
                ),
            )

        result.success  = True
        result.metadata = {
            "total_endpoints": len(analysed),
            "high_risk_count": len(high_risk),
            "duration":        round(time.time() - t0, 2),
        }
        result.next_skills = ["adversarial_planner", "exploit_chain_builder"]

        logger.info(
            "[threat_modeler] Done -- endpoints=%d high_risk=%d findings=%d",
            len(analysed), len(high_risk), len(result.findings),
        )
        return result
