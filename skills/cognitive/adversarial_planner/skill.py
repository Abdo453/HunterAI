"""
AdversarialPlannerSkill -- Red-team adversarial planning.
Builds a 5-step exploitation strategy; LLM-enhanced when available, heuristic otherwise.
Windows-safe: no box-drawing unicode in logger calls.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List

from skills.base_skill import BaseSkill, SkillContext, SkillResult

logger = logging.getLogger(__name__)

try:
    from core.ai_reasoning_core import AIReasoningCore
    _HAS_AI = True
except Exception:
    _HAS_AI = False


# ---------------------------------------------------------------------------
# Heuristic plan templates
# ---------------------------------------------------------------------------
_PLAN_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "IDOR": [
        {"step": 1, "name": "ID Enumeration",    "technique": "Iterate object IDs sequentially/BOLA", "tool": "burp",    "outcome": "Discover accessible foreign records",          "chains_to": "Step 2"},
        {"step": 2, "name": "Privilege Mapping",  "technique": "Map exposed API endpoints per role",   "tool": "ffuf",    "outcome": "Identify admin vs user endpoint delta",        "chains_to": "Step 3"},
        {"step": 3, "name": "Data Extraction",    "technique": "Extract PII/secrets via IDOR",          "tool": "burp",    "outcome": "Retrieve sensitive records for PoC",           "chains_to": "Step 4"},
        {"step": 4, "name": "Account Takeover",   "technique": "Modify account via IDOR write",         "tool": "burp",    "outcome": "Full ATO on victim account",                   "chains_to": "Step 5"},
        {"step": 5, "name": "Impact Report",      "technique": "Bundle PoC screenshots + requests",     "tool": "browser", "outcome": "Submission-ready critical severity report",    "chains_to": "Report"},
    ],
    "XSS": [
        {"step": 1, "name": "XSS Discovery",      "technique": "Reflected/Stored XSS fingerprint",     "tool": "dalfox", "outcome": "Confirmed XSS execution context",              "chains_to": "Step 2"},
        {"step": 2, "name": "Session Theft",      "technique": "Cookie exfiltration via document.cookie", "tool": "browser", "outcome": "Captured victim session token",           "chains_to": "Step 3"},
        {"step": 3, "name": "CSRF Pivot",         "technique": "Forge state-changing requests in XSS", "tool": "burp",   "outcome": "Execute actions as victim",                    "chains_to": "Step 4"},
        {"step": 4, "name": "Stored XSS Persist", "technique": "Inject persistent payload in DB field", "tool": "burp",   "outcome": "All users affected on page load",              "chains_to": "Step 5"},
        {"step": 5, "name": "Privilege Escalate", "technique": "Target admin account via stored XSS",   "tool": "browser","outcome": "Admin-level access compromise",                "chains_to": "Report"},
    ],
    "SQLi": [
        {"step": 1, "name": "SQLi Confirm",       "technique": "Error-based / boolean SQLi probe",     "tool": "sqlmap", "outcome": "Confirmed injectable parameter",               "chains_to": "Step 2"},
        {"step": 2, "name": "Schema Extract",     "technique": "INFORMATION_SCHEMA enumeration",       "tool": "sqlmap", "outcome": "Full DB schema map",                           "chains_to": "Step 3"},
        {"step": 3, "name": "Credential Dump",    "technique": "Dump users/hashes table",              "tool": "sqlmap", "outcome": "Plaintext or hashed credentials",              "chains_to": "Step 4"},
        {"step": 4, "name": "Password Crack",     "technique": "Offline hash cracking (hashcat)",      "tool": "nmap",   "outcome": "Valid admin credentials",                      "chains_to": "Step 5"},
        {"step": 5, "name": "Auth Login",         "technique": "Login with cracked credentials",       "tool": "browser","outcome": "Full admin panel access",                      "chains_to": "Report"},
    ],
    "default": [
        {"step": 1, "name": "Passive Recon",      "technique": "Enumerate subdomains + JS endpoints",  "tool": "ffuf",   "outcome": "Full attack surface map",                      "chains_to": "Step 2"},
        {"step": 2, "name": "Endpoint Discovery", "technique": "Directory brute-force + param fuzz",   "tool": "ffuf",   "outcome": "Hidden endpoints and parameters",              "chains_to": "Step 3"},
        {"step": 3, "name": "Parameter Fuzzing",  "technique": "Inject payloads into every parameter", "tool": "burp",   "outcome": "Error messages / anomalous responses",         "chains_to": "Step 4"},
        {"step": 4, "name": "Vuln Scan",          "technique": "Nuclei + manual verification",         "tool": "nuclei", "outcome": "Confirmed CVEs and misconfigs",                "chains_to": "Step 5"},
        {"step": 5, "name": "Report",             "technique": "Bundle evidence for submission",        "tool": "browser","outcome": "Submission-ready report",                      "chains_to": "Report"},
    ],
}


def _extract_json_from_text(text: str) -> Any:
    """Try to parse JSON from an LLM response that may contain extra prose."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    # Try to find the first {...} block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


class AdversarialPlannerSkill(BaseSkill):
    name = "adversarial_planner"
    category = "cognitive"
    description = "Red team adversarial planning -- builds 5-step exploitation strategy using LLM"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 120.0
    max_retries = 1

    # ------------------------------------------------------------------
    # Heuristic plan based on finding types
    # ------------------------------------------------------------------
    def _heuristic_plan(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Select the best matching template from known finding types."""
        # Collect all vuln type mentions
        all_text = " ".join(
            (f.get("type", "") + " " + f.get("title", "")).upper()
            if isinstance(f, dict) else str(f).upper()
            for f in findings
        )
        for key in ("IDOR", "XSS", "SQLI"):
            if key in all_text or key.replace("I", "i") in all_text:
                return _PLAN_TEMPLATES[key]
        return _PLAN_TEMPLATES["default"]

    # ------------------------------------------------------------------
    # LLM-based plan
    # ------------------------------------------------------------------
    async def _llm_plan(
        self, target: str, findings: List[Any], goal: str
    ) -> List[Dict[str, Any]]:
        if not _HAS_AI:
            return []

        findings_summary = json.dumps(findings[:10], indent=2) if findings else "None yet"
        prompt = (
            "You are an elite red team operator.\n"
            f"Given these security findings:\n{findings_summary}\n\n"
            f"Build a 5-step exploitation plan to maximize impact on {target}.\n"
            "Goal: " + goal + "\n\n"
            "For each step provide:\n"
            "- Step number and name\n"
            "- Attack technique\n"
            "- Tool to use (from: burp, browser, nuclei, sqlmap, dalfox, ffuf, nmap)\n"
            "- Expected outcome\n"
            "- Chain to next step\n\n"
            'Respond ONLY in JSON: {"steps": [{"step": 1, "name": "...", "technique": "...", '
            '"tool": "...", "outcome": "...", "chains_to": "..."}]}'
        )
        try:
            raw = await AIReasoningCore.ask_ai(
                prompt,
                system_prompt="You are an elite red team security researcher. Respond only in JSON.",
            )
            if raw:
                parsed = _extract_json_from_text(raw)
                if parsed and "steps" in parsed:
                    return parsed["steps"]
        except Exception as exc:
            logger.debug("[adversarial_planner] LLM plan error: %s", exc)
        return []

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------
    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=False)
        t0 = time.time()

        findings: List[Any] = ctx.extra.get("findings_so_far", [])
        goal: str           = ctx.extra.get("goal", "Find and validate security vulnerabilities")
        target: str         = ctx.target

        logger.info(
            "[adversarial_planner] Planning for target=%s findings=%d",
            target, len(findings),
        )

        # Attempt LLM first; fall back to heuristic
        steps = await self._llm_plan(target, findings, goal)
        plan_source = "llm"
        if not steps:
            logger.info("[adversarial_planner] LLM unavailable -- using heuristic plan")
            steps = self._heuristic_plan(findings)
            plan_source = "heuristic"

        plan_dict = {"target": target, "goal": goal, "source": plan_source, "steps": steps}

        # --- Build attack_plan.md ---
        md_lines = [
            f"# Red Team Attack Plan -- {target}",
            "",
            f"> Goal: {goal}",
            f"> Plan Source: {plan_source.upper()}",
            f"> Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            "",
            "## Exploitation Steps",
            "",
        ]
        for s in steps:
            md_lines += [
                f"### Step {s.get('step', '?')}: {s.get('name', 'Unknown')}",
                f"- **Technique**: {s.get('technique', 'N/A')}",
                f"- **Tool**: `{s.get('tool', 'N/A')}`",
                f"- **Expected Outcome**: {s.get('outcome', 'N/A')}",
                f"- **Chains To**: {s.get('chains_to', 'N/A')}",
                "",
            ]

        if findings:
            md_lines += [
                "## Prior Findings Summary",
                "",
                f"Total findings provided: {len(findings)}",
                "",
            ]
            for f in findings[:5]:
                if isinstance(f, dict):
                    md_lines.append(
                        f"- [{f.get('severity','?')}] {f.get('title', str(f))}"
                    )
                else:
                    md_lines.append(f"- {f}")
            md_lines.append("")

        attack_plan_md = "\n".join(md_lines)

        # --- Write files ---
        ap_path = ctx.workspace.write_file(
            ctx.target, "cognitive",
            "attack_plan.md",
            attack_plan_md,
            session_id=ctx.session_id,
        )
        na_path = ctx.workspace.write_file(
            ctx.target, "cognitive",
            "next_actions.json",
            json.dumps(plan_dict, indent=2),
            session_id=ctx.session_id,
        )

        result.output_files["attack_plan.md"]    = str(ap_path)
        result.output_files["next_actions.json"] = str(na_path)

        # --- Single summary finding ---
        result.add_finding(
            title    = f"Adversarial Plan Generated for {target}",
            evidence = f"5-step plan ({plan_source}) created with {len(steps)} steps.",
            severity = "Info",
            vuln_type = "Red Team Plan",
            tool     = "adversarial_planner",
            url      = target,
        )

        result.success  = True
        result.metadata = {
            "plan_source":  plan_source,
            "steps_count":  len(steps),
            "findings_in":  len(findings),
            "duration":     round(time.time() - t0, 2),
        }
        result.next_skills = ["full_pipeline_orchestrator"]

        logger.info(
            "[adversarial_planner] Done -- steps=%d source=%s duration=%.1fs",
            len(steps), plan_source, time.time() - t0,
        )
        return result
