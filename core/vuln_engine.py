"""
Comprehensive Vulnerability Engine (v2.0)
=========================================
Centralized multi-vector assessment engine that systematically tests discovered
endpoints and parameters against all major vulnerability classes:
- SQL Injection (SQLiSkill + sqlmap fallback)
- Cross-Site Scripting (XSSSkill + dalfox fallback)
- Local File Inclusion & Path Traversal (LFISkill)
- OS Command Injection (CmdInjectionSkill)
- Server-Side Request Forgery (SSRFSkill)
- Insecure Direct Object References (IDORSkill)

Features:
- Never relies on a single speculative LLM guess to blind the scan.
- Heuristic priority scoring per parameter (e.g., 'category' -> SQLi & XSS, 'file' -> LFI).
- Automatic fallback to specialized industry tools (e.g., sqlmap) when built-ins fail.
- Rich diagnostic evidence tracking (evidence_sources, fallback_used, raw responses).
"""
import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urljoin

from agents.skills.base_skill import BaseSkill, SkillResult
from agents.skills.sqli_skill import SQLiSkill, run_sqli_skill
from agents.skills.xss_skill import XSSSkill
from agents.skills.lfi_skill import LFISkill
from agents.skills.cmd_injection_skill import CmdInjectionSkill
from agents.skills.ssrf_skill import SSRFSkill
from agents.skills.idor_skill import IDORSkill

log = logging.getLogger("vuln_engine")


class VulnerabilityEngine:
    """
    المنسق المركزي لجميع الـ Autonomous Skills.
    يضمن فحص كل باراميتر ورابط لاحتمال وجود ثغرات متعددة مع الفحص التفاضلي والـfallback.
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        progress_cb: Optional[Any] = None,
        timeout: float = 15.0,
        max_concurrent: int = 8,
    ):
        self.proxy = proxy
        self.cb = progress_cb
        self.timeout = timeout
        self.max_concurrent = max_concurrent

        # Initialize skill instances
        self.skills: Dict[str, Any] = {
            "sqli": SQLiSkill(proxy=proxy),
            "xss": XSSSkill(proxy=proxy),
            "lfi": LFISkill(proxy=proxy, timeout=timeout),
            "cmd_injection": CmdInjectionSkill(proxy=proxy, timeout=timeout),
            "ssrf": SSRFSkill(proxy=proxy),
            "idor": IDORSkill(proxy=proxy),
        }

    async def _log(self, msg: str):
        log.info(msg)
        if self.cb:
            try:
                if asyncio.iscoroutinefunction(self.cb):
                    await self.cb({"event": "log", "message": msg})
                else:
                    self.cb({"event": "log", "message": msg})
            except Exception:
                pass

    def prioritize_skills_for_param(
        self, param_name: str, url: str = "", primary_focus: Optional[str] = None
    ) -> List[Tuple[str, float]]:
        """
        حساب أولوية الفحص لكل ثغرة بناءً على اسم الباراميتر ومسار الرابط
        مع ضمان عدم استبعاد أي ثغرة مهمة.
        """
        scores: List[Tuple[str, float]] = []
        p_lower = param_name.lower()

        for skill_key, skill in self.skills.items():
            base_score = 0.5
            if hasattr(skill, "can_handle"):
                base_score = skill.can_handle(param_name, url=url)
            else:
                # Fallback heuristics for older skills
                if skill_key == "sqli":
                    if any(k in p_lower for k in ("id", "cat", "search", "q", "query", "filter", "item", "user", "order", "sort", "num")):
                        base_score = 0.95
                    else:
                        base_score = 0.70
                elif skill_key == "xss":
                    if any(k in p_lower for k in ("q", "query", "search", "name", "msg", "title", "text", "comment", "filter")):
                        base_score = 0.90
                    else:
                        base_score = 0.65
                elif skill_key == "ssrf":
                    if any(k in p_lower for k in ("url", "uri", "target", "dest", "redirect", "src", "feed", "link", "host")):
                        base_score = 0.95
                    else:
                        base_score = 0.30
                elif skill_key == "idor":
                    if any(k in p_lower for k in ("id", "user_id", "account", "doc", "order_id", "no", "uid", "profile")):
                        base_score = 0.90
                    else:
                        base_score = 0.30

            # Boost if aligns with primary_focus
            if primary_focus and primary_focus.lower() in skill_key:
                base_score += 0.20

            scores.append((skill_key, base_score))

        # Sort descending by priority score
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    async def assess_target(
        self,
        target_url: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        discovered_params: Optional[List[str]] = None,
        primary_focus: Optional[str] = None,
        mode: str = "web",
    ) -> List[Dict[str, Any]]:
        """
        فحص شامل ودقيق للمستهدف عبر جميع الـ Skills المتاحة.
        """
        all_targets: List[Tuple[str, str]] = []
        seen = set()

        # 1. Target URL params
        parsed_target = urlparse(target_url)
        target_qs = parse_qs(parsed_target.query)
        for p in target_qs.keys():
            key = (target_url.split("?")[0], p)
            if key not in seen:
                seen.add(key)
                all_targets.append((target_url, p))

        # 2. Discovered endpoints
        if endpoints:
            for ep in endpoints:
                ep_url = ep.get("url") if isinstance(ep, dict) else str(ep)
                param = ep.get("param") if isinstance(ep, dict) else None
                if not param and "?" in ep_url:
                    ep_qs = parse_qs(urlparse(ep_url).query)
                    for p in ep_qs.keys():
                        key = (ep_url.split("?")[0], p)
                        if key not in seen:
                            seen.add(key)
                            all_targets.append((ep_url, p))
                elif param:
                    key = (ep_url.split("?")[0], param)
                    if key not in seen:
                        seen.add(key)
                        all_targets.append((ep_url, param))

        # 3. Discovered params fallback
        if discovered_params:
            for p in discovered_params:
                key = (target_url.split("?")[0], p)
                if key not in seen:
                    seen.add(key)
                    all_targets.append((target_url, p))

        # Fallback candidate endpoints if nothing found
        if not all_targets:
            candidate_paths = [
                ("/filter?category=Gifts", "category"),
                ("/product?productId=1", "productId"),
                ("/search?q=test", "q"),
                ("/?id=1", "id"),
            ]
            for c_path, c_param in candidate_paths:
                full_cand = urljoin(target_url, c_path)
                all_targets.append((full_cand, c_param))

        await self._log(f"[VULN_ENGINE] Starting multi-vector assessment across {len(all_targets)} parameter targets...")
        findings: List[Dict[str, Any]] = []

        for probe_url, param_name in all_targets[:12]:
            ordered_skills = self.prioritize_skills_for_param(param_name, probe_url, primary_focus)
            await self._log(f"[VULN_ENGINE] Target: {probe_url} | param={param_name!r} | Priority order: {[s[0] for s in ordered_skills[:3]]}")

            for skill_key, score in ordered_skills:
                # If score is too low and we are in focused mode, skip
                if score < 0.35 and primary_focus and primary_focus.lower() not in skill_key:
                    continue

                skill = self.skills.get(skill_key)
                if not skill:
                    continue

                await self._log(f"[VULN_ENGINE] Running {skill_key.upper()} probe on {param_name!r} (priority={score:.2f})...")
                try:
                    res_dict = None
                    if skill_key == "sqli":
                        # Run SQLi Skill
                        async with asyncio.Semaphore(self.max_concurrent):
                            res_raw = await run_sqli_skill(probe_url, param_name, proxy=self.proxy)
                        for lg in res_raw.get("logs", []):
                            await self._log(f"   {lg}")

                        if res_raw.get("state") == "COMPLETE" or res_raw.get("extracted_data") or res_raw.get("objective_met"):
                            dbms_str = res_raw.get("dbms", "unknown").upper()
                            ext = res_raw.get("extracted_data", "")
                            technique = res_raw.get("technique", "union")
                            fallback_used = res_raw.get("fallback_used", False)
                            fallback_engine = res_raw.get("fallback_engine", None)
                            
                            title = f"SQL Injection ({dbms_str}) in parameter {param_name!r}"
                            if fallback_used:
                                title += f" [Fallback: {fallback_engine}]"

                            res_dict = {
                                "type": "sqli",
                                "vuln_type": "sqli",
                                "param_name": param_name,
                                "endpoint": probe_url,
                                "title": title,
                                "severity": "Critical",
                                "evidence": ext or res_raw.get("union_payload") or "SQLi Confirmed",
                                "payload_used": res_raw.get("union_payload", "N/A"),
                                "remediation": "Use Prepared Statements with Parameterized Queries.",
                                "cwe": "CWE-89",
                                "owasp_top10": "A03:2021 — Injection",
                                "confidence": 0.98,
                                "tool": f"SQLiSkill{('/' + fallback_engine) if fallback_used else ''}",
                                "evidence_sources": [f"SQLiSkill/{'sqlmap_fallback' if fallback_used else 'StateMachine'}"],
                                "fallback_used": fallback_used,
                                "fallback_engine": fallback_engine,
                                "fallback_details": res_raw.get("fallback_details"),
                                "dbms": res_raw.get("dbms"),
                                "extracted_data": ext,
                                "objective_met": res_raw.get("objective_met", False),
                            }

                    elif skill_key in ("lfi", "cmd_injection"):
                        skill_res: SkillResult = await skill.run(probe_url, param_name)
                        for lg in skill_res.logs:
                            await self._log(f"   {lg}")
                        if skill_res.verified:
                            res_dict = skill_res.to_dict()

                    elif skill_key == "xss":
                        xss_res = await skill.run(probe_url, param_name)
                        for lg in xss_res.get("logs", []):
                            await self._log(f"   {lg}")
                        if xss_res.get("state") == "COMPLETE":
                            res_dict = {
                                "type": "xss",
                                "vuln_type": "xss",
                                "param_name": param_name,
                                "endpoint": probe_url,
                                "title": f"Cross-Site Scripting (XSS) in {param_name!r} ({xss_res.get('context', 'html')})",
                                "severity": "Medium" if xss_res.get("csp_bypassable") else "Low",
                                "evidence": xss_res.get("evidence_snippet", "Reflection confirmed"),
                                "payload_used": xss_res.get("vulnerable_payload", "?"),
                                "remediation": "Context-aware output encoding and CSP.",
                                "cwe": "CWE-79",
                                "owasp_top10": "A03:2021 — Injection",
                                "confidence": xss_res.get("confidence", 0.90),
                                "tool": "XSSSkill",
                                "evidence_sources": ["XSSSkill/ContextEvaluator"],
                            }

                    elif skill_key == "ssrf":
                        ssrf_res = await skill.run(probe_url, param_name)
                        for lg in ssrf_res.get("logs", []):
                            await self._log(f"   {lg}")
                        if ssrf_res.get("state") == "COMPLETE":
                            res_dict = {
                                "type": "ssrf",
                                "vuln_type": "ssrf",
                                "param_name": param_name,
                                "endpoint": probe_url,
                                "title": f"SSRF — Server-Side Request Forgery ({ssrf_res.get('impact', 'Internal Access')})",
                                "severity": "High" if "metadata" in ssrf_res.get("impact", "").lower() else "Medium",
                                "evidence": ssrf_res.get("evidence_snippet", "SSRF access verified"),
                                "payload_used": ssrf_res.get("vulnerable_payload", "?"),
                                "remediation": "Enforce strict allowlist on URLs and block internal IPs (169.254.169.254, 127.0.0.1).",
                                "cwe": "CWE-918",
                                "owasp_top10": "A10:2021 — Server-Side Request Forgery",
                                "confidence": 0.95,
                                "tool": "SSRFSkill",
                                "evidence_sources": ["SSRFSkill/StateMachine"],
                            }

                    elif skill_key == "idor":
                        idor_res = await skill.run(probe_url, param_name)
                        for lg in idor_res.get("logs", []):
                            await self._log(f"   {lg}")
                        if idor_res.get("state") == "COMPLETE":
                            res_dict = {
                                "type": "idor",
                                "vuln_type": "idor",
                                "param_name": param_name,
                                "endpoint": probe_url,
                                "title": f"IDOR/BOLA in parameter {param_name!r}",
                                "severity": "High",
                                "evidence": idor_res.get("evidence_snippet", "Cross-object access confirmed"),
                                "payload_used": f"ID mutation to {idor_res.get('vulnerable_id')}",
                                "remediation": "Implement robust server-side object-level access control (RBAC/ABAC).",
                                "cwe": "CWE-639",
                                "owasp_top10": "A01:2021 — Broken Access Control",
                                "confidence": idor_res.get("confidence", 0.90),
                                "tool": "IDORSkill",
                                "evidence_sources": ["IDORSkill/MatrixChecker"],
                            }

                    if res_dict:
                        findings.append(res_dict)
                        await self._log(f"[VULN_ENGINE] 🔥 VULNERABILITY CONFIRMED: {res_dict.get('title')}")
                        if self.cb:
                            try:
                                if asyncio.iscoroutinefunction(self.cb):
                                    await self.cb({"event": "finding", **res_dict})
                                else:
                                    self.cb({"event": "finding", **res_dict})
                            except Exception:
                                pass
                        # If a critical vulnerability like SQLi or RCE is confirmed on this parameter, move to next parameter
                        if res_dict.get("severity") in ("Critical",):
                            break

                except Exception as e:
                    log.exception(f"Error evaluating {skill_key} on {param_name}")
                    await self._log(f"[VULN_ENGINE] Warning: error evaluating {skill_key}: {e}")

        await self._log(f"[VULN_ENGINE] Assessment complete. Total confirmed findings: {len(findings)}")
        return findings
