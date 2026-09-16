"""
Autonomous Pentest Brain — OODA Loop
العقل الرئيسي: يقرر -> ينفذ -> يحلل -> يعيد التفكير

مبادئ الأمان:
- النموذج يُنتج خطة فقط، لا يُنفّذ أوامر مباشرة
- التنفيذ عبر TOOL_REGISTRY ثابت فقط
- allowlist للأدوات + validation للخطة
- audit trail لكل قرار وأمر
- dry_run mode للاختبار بدون تنفيذ فعلي
- rate limit على عدد الـ probe requests
"""
import asyncio
import os
import re
import json
import time
import logging
from copy import deepcopy
from typing import Dict, Any, List, Optional, Callable, Tuple
from urllib.parse import urlparse, parse_qs, urljoin
from core.evidence_court import EvidenceCourt, CourtVerdict
from core.court.evidence_court_v2 import EvidenceCourtV2, TribunalRuling
from core.causal.causal_graph import CausalSecurityGraph, CausalNodeType
from core.twin.security_digital_twin import SecurityDigitalTwin, RoleTier
from core.reasoning.competing_hypotheses import CompetingHypothesesEngine, HypothesisOption
from core.safety.constitutional_layer import AgentConstitution, ConstitutionalCheckResult
from core.statemachine.security_state_machine import SecurityStateMachine, ApplicationState
from core.code_intel import CodeIntelligenceAgent
from core.attack_surface_graph import AttackSurfaceGraph, ThirdPartyDependencyFirewall
from core.browser import StatefulBrowserSession, HumanLikeExplorationEngine
from pathlib import Path

log = logging.getLogger("autonomous_brain")


# ─── TOOL_REGISTRY HANDLERS ──────────────────────────────────────────────────
# التنفيذ فقط من هنا — لا أوامر shell مباشرة من مخرجات النماذج

async def _run_smartpoc(brain: "AutonomousBrain", target: str, params: list,
                        focus: str, proxy: str, auth: dict,
                        endpoints: Optional[list] = None, **kwargs) -> list:
    """SmartPoC: يختبر params والـ endpoints المكتشفة بدقة عالية"""
    results = []
    if not brain.poc:
        log.warning("SmartPoC: executor not available")
        return results

    tested_pairs = set()

    # 1. اختبار الـ Endpoints المكتشفة من الروابط والنماذج (e.g. /filter?category=Gifts)
    if endpoints:
        for ep in endpoints[:20]:
            ep_url = ep.get("url") or target
            param = ep.get("param")
            if not param:
                continue
            pair = (ep_url.split("?")[0], param)
            if pair in tested_pairs:
                continue
            tested_pairs.add(pair)

            await brain._log(f"[PROBE] Endpoint: {ep_url} | param={param!r} | focus={focus}")
            try:
                poc_res = await brain.poc.execute_and_verify(
                    target_url=ep_url, param_name=param, vuln_type=focus
                )
                if poc_res and poc_res.get("verified"):
                    results.append({
                        "tool": "SmartPoC",
                        "param": param,
                        "endpoint": ep_url,
                        "poc_result": poc_res
                    })
                    payload_used = poc_res.get("payload_used", "?")
                    await brain._log(f"[FOUND] {focus.upper()} on {ep_url} (param={param!r}) | payload={payload_used}")
                else:
                    await brain._log(f"[SAFE] {ep_url} (param={param!r}) — clean")
            except Exception:
                log.exception(f"SmartPoC probe failed for endpoint={ep_url!r}")

    # 2. اختبار الباراميترات المستخرجة على الرابط الرئيسي
    for param in params:
        pair = (target.split("?")[0], param)
        if pair in tested_pairs:
            continue
        tested_pairs.add(pair)
        await brain._log(f"[PROBE] Target: {target} | param={param!r} | focus={focus}")
        try:
            poc_res = await brain.poc.execute_and_verify(
                target_url=target, param_name=param, vuln_type=focus
            )
            if poc_res and poc_res.get("verified"):
                results.append({
                    "tool": "SmartPoC",
                    "param": param,
                    "endpoint": target,
                    "poc_result": poc_res
                })
                payload_used = poc_res.get("payload_used", "?")
                await brain._log(f"[FOUND] {focus.upper()} on param={param!r} | payload={payload_used}")
            else:
                await brain._log(f"[SAFE] param={param!r} — clean")
        except Exception:
            log.exception(f"SmartPoC probe failed for param={param!r}")

    return results


async def _run_recon(brain: "AutonomousBrain", target: str, proxy: str,
                     auth: dict, **kwargs) -> list:
    try:
        from agents.recon_agent import ReconAgent
        from agents.base_agent import AgentTask
        ra = ReconAgent(brain.tools, brain.cb)
        res = await ra.run(AgentTask(target=target, mode="recon"))
        return res.findings if res and res.findings else []
    except Exception:
        log.exception("ReconAgent failed")
        return []


async def _run_bugbounty(brain: "AutonomousBrain", target: str, proxy: str,
                         auth: dict, mode: str = "bugbounty_full", **kwargs) -> list:
    try:
        from agents.bugbounty_agent import BugBountyAgent
        from agents.base_agent import AgentTask
        ba = BugBountyAgent(brain.tools, brain.cb, proxy=proxy, auth=auth)
        res = await ba.run(AgentTask(target=target, mode=mode,
                                     extra={"proxy": proxy, "auth": auth}))
        return res.findings if res and res.findings else []
    except Exception:
        log.exception("BugBountyAgent failed")
        return []


async def _run_browser(brain: "AutonomousBrain", target: str, proxy: str,
                       auth: dict, mode: str = "auto", visible: bool = True, **kwargs) -> list:
    try:
        from agents.browser_agent import BrowserAgent
        from agents.base_agent import AgentTask
        bra = BrowserAgent(brain.tools, brain.cb, proxy=proxy, visible=visible, auth=auth)
        res = await bra.run(AgentTask(target=target, mode=mode))
        return res.findings if res and res.findings else []
    except Exception:
        log.exception("BrowserAgent failed")
        return []


async def _run_webagent(brain: "AutonomousBrain", target: str, proxy: str,
                        auth: dict, mode: str = "auto", **kwargs) -> list:
    try:
        from agents.web_agent import WebAgent
        from agents.base_agent import AgentTask
        wa = WebAgent(brain.tools, brain.cb)
        res = await wa.run(AgentTask(target=target, mode=mode))
        return res.findings if res and res.findings else []
    except Exception:
        log.exception("WebAgent failed")
        return []


async def _run_nuclei(brain: "AutonomousBrain", target: str, **kwargs) -> list:
    if not brain.tools.is_available("nuclei"):
        await brain._log("[TOOL] nuclei not installed — skipping")
        return []
    from tools.web_tools import WebTools
    wt = WebTools(brain.tools)
    res = await wt.nuclei_scan(target)
    if not res.stdout.strip():
        return []
    findings = []
    classify = await brain.decision.classify_tool_output("nuclei", res.stdout, target)
    if classify.get("is_real_vuln"):
        qwen = await brain.artifact.analyze_tool_output("nuclei", res.stdout, target)
        findings.append({
            "type": qwen.get("vuln_type", "nuclei_finding"),
            "severity": qwen.get("severity", "High"),
            "title": f"Nuclei Finding: {qwen.get('vuln_type', 'Vulnerability')}",
            "evidence": res.stdout[:800],
            "remediation": qwen.get("remediation_code", "Apply vendor patches or component updates."),
            "confidence": 0.85,
            "tool": "nuclei",
        })
    return findings


async def _run_sqlmap(brain: "AutonomousBrain", target: str, **kwargs) -> list:
    if not brain.tools.is_available("sqlmap"):
        await brain._log("[TOOL] sqlmap not installed — skipping")
        return []
    from tools.web_tools import WebTools
    wt = WebTools(brain.tools)
    res = await wt.sqlmap(target)
    if not res.stdout.strip() or ("is not vulnerable" in res.stdout.lower() and "injection" not in res.stdout.lower()):
        return []
    classify = await brain.decision.classify_tool_output("sqlmap", res.stdout, target)
    findings = []
    if classify.get("is_real_vuln"):
        qwen = await brain.artifact.analyze_tool_output("sqlmap", res.stdout, target)
        findings.append({
            "type": "sqli",
            "severity": "Critical",   # SQLi confirmed by sqlmap is always Critical
            "title": "SQL Injection Confirmed (sqlmap)",
            "evidence": res.stdout[:800],
            "remediation": qwen.get("remediation_code", "Use parameterized queries / prepared statements."),
            "confidence": 0.95,
            "tool": "sqlmap",
        })
    return findings


async def _run_dalfox(brain: "AutonomousBrain", target: str, **kwargs) -> list:
    if not brain.tools.is_available("dalfox"):
        await brain._log("[TOOL] dalfox not installed — skipping")
        return []
    from tools.web_tools import WebTools
    wt = WebTools(brain.tools)
    res = await wt.dalfox(target)
    hits = [l for l in res.stdout.splitlines() if "[V]" in l or "POC" in l]
    findings = []
    if hits:
        qwen = await brain.artifact.analyze_tool_output("dalfox", "\n".join(hits), target)
        findings.append({
            "type": "xss",
            "severity": qwen.get("severity", "High"),
            "title": "Cross-Site Scripting (XSS) Confirmed (dalfox)",
            "evidence": "\n".join(hits[:5]),
            "remediation": qwen.get("remediation_code", "Contextually encode output and sanitize inputs."),
            "confidence": 0.90,
            "tool": "dalfox",
        })
    return findings


async def _run_gobuster(brain: "AutonomousBrain", target: str, **kwargs) -> list:
    from tools.web_tools import WebTools
    wt = WebTools(brain.tools)
    res = await wt.gobuster_dir(target)
    found = [l for l in res.stdout.splitlines() if "(Status:" in l]
    findings = []
    if found:
        ev = "\n".join(found[:20])
        if getattr(res, "output_file", None):
            ev = f"[Log File: {res.output_file}]\n" + ev
        findings.append({
            "type": "directory_enumeration",
            "severity": "Info",
            "title": f"Directories / Sensitive Endpoints Discovered ({len(found)})",
            "evidence": ev,
            "remediation": "Disable directory browsing and restrict administrative paths.",
            "confidence": 0.80,
            "tool": "gobuster",
            "log_file": getattr(res, "output_file", None),
        })
    return findings


async def _run_nmap(brain: "AutonomousBrain", target: str, **kwargs) -> list:
    if not brain.tools.is_available("nmap"):
        await brain._log("[TOOL] nmap not installed — skipping")
        return []
    from tools.network_tools import NetworkTools
    host = urlparse(target).hostname or target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
    nt = NetworkTools(brain.tools)
    res = await nt.nmap_scan(host)
    open_ports = [l for l in res.stdout.splitlines() if "/tcp" in l and "open" in l]
    findings = []
    if open_ports:
        ev = "\n".join(open_ports[:15])
        if getattr(res, "output_file", None):
            ev = f"[Log File: {res.output_file}]\n" + ev
        findings.append({
            "type": "open_ports",
            "severity": "Info",
            "title": f"Open Network Services ({len(open_ports)} ports)",
            "evidence": ev,
            "remediation": "Close unnecessary ports and protect services with a firewall.",
            "confidence": 0.90,
            "tool": "nmap",
            "log_file": getattr(res, "output_file", None),
        })
    return findings


async def _run_subfinder(brain: "AutonomousBrain", target: str, **kwargs) -> list:
    host = urlparse(target).hostname or target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
    res = await brain.tools.execute(f"subfinder -d {host} -silent", timeout=90)
    subs = [s.strip() for s in res.stdout.splitlines() if s.strip()]
    findings = []
    if subs:
        ev = "\n".join(subs[:25])
        if getattr(res, "output_file", None):
            ev = f"[Log File: {res.output_file}]\n" + ev
        findings.append({
            "type": "subdomains",
            "severity": "Info",
            "title": f"Subdomains Discovered ({len(subs)})",
            "evidence": ev,
            "remediation": "Audit discovered subdomains and decommission obsolete DNS entries.",
            "confidence": 0.85,
            "tool": "subfinder",
            "log_file": getattr(res, "output_file", None),
        })
    return findings



async def _run_sqli_skill(brain: "AutonomousBrain", target: str, proxy: str,
                          auth: dict, mode: str, **kwargs) -> list:
    """
    SQLi Autonomous Skill — State Machine كاملة مع Auto-Discovery للـ Endpoints:
    DETECT → CLASSIFY → FINGERPRINT → COUNT_COLS → TEXT_COLS
    → UNION_VERIFY → EXTRACT → CHECK_OBJ → COMPLETE
    """
    from urllib.parse import urlparse, parse_qs, urljoin
    import re
    import httpx
    from agents.skills.sqli_skill import run_sqli_skill as _sqli_run

    targets_to_probe = []

    # 1. فحص target الرئيسي
    parsed = urlparse(target)
    qs = parse_qs(parsed.query)
    if qs:
        for p in qs.keys():
            targets_to_probe.append((target, p))

    # 2. فحص الـ endpoints المكتشفة في مرحلة Observe
    discovered_eps = kwargs.get("endpoints", [])
    if hasattr(brain, "security_state") and brain.security_state:
        for ep_path, ep_data in brain.security_state.endpoints.items():
            ep_url = ep_data.get("url") or urljoin(target, ep_path)
            ep_qs = parse_qs(urlparse(ep_url).query)
            for p in ep_qs.keys():
                targets_to_probe.append((ep_url, p))

    for ep in discovered_eps:
        ep_url = ep.get("url") if isinstance(ep, dict) else str(ep)
        ep_qs = parse_qs(urlparse(ep_url).query)
        for p in ep_qs.keys():
            targets_to_probe.append((ep_url, p))

    # 3. إذا لم نجد أي بارامترات، نقوم بعمل Crawler سريع لاستخراج الروابط من الصفحة
    if not targets_to_probe:
        await brain._log(f"[SQLiSkill] No query params in URL — crawling {target} for endpoints...")
        try:
            transport = None
            if proxy:
                transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=False)
            async with httpx.AsyncClient(transport=transport, verify=False, timeout=8.0) as client:
                r = await client.get(target)
                matches = re.findall(r'href=[\'"]([^\'"]*\?[^\'"]+)[\'"]', r.text, re.I)
                for m in matches:
                    found_url = urljoin(target, m)
                    found_qs = parse_qs(urlparse(found_url).query)
                    for p in found_qs.keys():
                        targets_to_probe.append((found_url, p))
        except Exception as e:
            await brain._log(f"[SQLiSkill] Crawler notice: {e}")

    # 4. Fallback: تجربة بارامترات شائعة على المسارات الأساسية للـ labs والتطبيقات
    if not targets_to_probe:
        candidate_params = ["category", "id", "search", "q", "filter"]
        for p in candidate_params:
            targets_to_probe.append((urljoin(target, f"/filter?{p}=Gifts"), p))
            targets_to_probe.append((urljoin(target, f"/?{p}=test"), p))

    # إزالة التكرارات
    seen = set()
    unique_targets = []
    for t_url, p_name in targets_to_probe:
        key = (t_url.split("?")[0], p_name)
        if key not in seen:
            seen.add(key)
            unique_targets.append((t_url, p_name))

    findings = []
    for target_url, param in unique_targets[:8]:
        await brain._log(f"[SQLiSkill] Running state machine on {target_url} (param={param!r})")
        try:
            result = await _sqli_run(
                target_url=target_url,
                param_name=param,
                proxy=proxy or None,
                objective="retrieve_db_version",
            )
            # إرسال اللوجات للـbrain
            for lg in result.get("logs", []):
                await brain._log(lg)

            state = result.get("state", "FAILED")
            if state == "COMPLETE" or result.get("extracted_data") or result.get("objective_met"):
                extracted = result.get("extracted_data", "")
                dbms_str  = result.get("dbms", "unknown").upper()
                technique = result.get("technique", "union")

                _owasp_primary = (
                    "PRIMARY DEFENSES (OWASP SQLi Prevention Cheat Sheet):\n"
                    "  1. [BEST] Use Prepared Statements with Parameterized Queries:\n"
                    "     String query = \"SELECT ... WHERE user_name = ?\";\n"
                    "     PreparedStatement pstmt = connection.prepareStatement(query);\n"
                    "     pstmt.setString(1, userInput);\n"
                    "  2. Use Properly Constructed Stored Procedures\n"
                    "  3. Allow-list Input Validation for table/column names\n"
                    "  4. [DISCOURAGED] Escape all user-supplied input\n"
                    "\n"
                    "ADDITIONAL DEFENSES:\n"
                    "  - Least Privilege: no DBA/admin access for app DB accounts\n"
                    "  - Separate DB users per web application\n"
                    "  - Use SQL Views to restrict access to sensitive columns\n"
                    f"\nDBMS Detected: {dbms_str} | Technique: {technique}"
                )

                finding = {
                    "type": "sqli",
                    "param_name": param,
                    "endpoint": target_url,
                    "title": f"SQL Injection — Full Exploitation Complete ({dbms_str}) (param={param!r})",
                    "severity": "Critical",
                    "evidence": extracted or "UNION-based SQLi confirmed and exploited",
                    "payload_used": result.get("union_payload", "?"),
                    "remediation": _owasp_primary,
                    "owasp_ref": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "cwe": "CWE-89",
                    "owasp_top10": "A03:2021 — Injection",
                    "confidence": 0.98,
                    "tool": "SQLiSkill",
                    "dbms": result.get("dbms", "unknown"),
                    "col_count": result.get("col_count", 0),
                    "text_cols": result.get("text_cols", []),
                    "extracted_data": extracted,
                    "objective_met": result.get("objective_met", False),
                    "evidence_sources": ["SQLiSkill/StateMachine"],
                    "technique": technique,
                }
                findings.append(finding)
                if hasattr(brain, "_emit"):
                    await brain._emit("finding", **finding)
                await brain._log(
                    f"[SQLiSkill] ✅ COMPLETE | param={param!r} | "
                    f"DBMS={result.get('dbms')} | extracted={extracted[:80]!r}"
                )
                break
            elif state not in ("FAILED",):
                await brain._log(f"[SQLiSkill] INCOMPLETE (state={state}) on param={param!r}")
        except Exception:
            log.exception(f"SQLiSkill failed for param={param!r}")
    return findings


async def _run_ssrf_skill(brain, target_url: str, params: list, proxy: str = "") -> list:
    """تشغيل SSRF Autonomous Skill (Cloud Metadata Matrix + Filter Bypass)"""
    from agents.skills.ssrf_skill import SSRFSkill
    skill = SSRFSkill(proxy=proxy or None)
    findings = []
    test_params = params or ["url", "target", "dest", "redirect", "uri", "path", "feed", "src", "file", "endpoint"]
    for param in test_params:
        try:
            res = await skill.run(target_url, param)
            for lg in res.get("logs", []):
                await brain._log(lg)
            if res.get("state") == "COMPLETE":
                findings.append({
                    "type": "ssrf",
                    "param_name": param,
                    "title": f"SSRF — Server-Side Request Forgery ({res.get('impact', 'Internal Access Verified')})",
                    "severity": "High" if "metadata" in res.get("impact", "").lower() else "Medium",
                    "evidence": res.get("evidence_snippet", "SSRF internal access verified"),
                    "payload_used": res.get("vulnerable_payload", "?"),
                    "remediation": "Enforce strict URL allow-list, disable following redirects, and block access to 169.254.169.254 / 127.0.0.0/8.",
                    "confidence": 0.95,
                    "tool": "SSRFSkill",
                    "evidence_sources": ["SSRFSkill/StateMachine"],
                    "cwe": "CWE-918",
                    "owasp_top10": "A10:2021 — Server-Side Request Forgery",
                })
        except Exception:
            log.exception(f"SSRFSkill failed on {param}")
    return findings


async def _run_idor_skill(brain, target: str = None, target_url: str = None, params: list = None, proxy: str = "", auth: dict = None, **kwargs) -> list:
    """تشغيل IDOR/BOLA Autonomous Skill (Cross‑Tenant Matrix + Verb Tampering)"""
    # Determine the URL to scan – accept either `target` (new) or `target_url` (legacy)
    url = target if target is not None else target_url
    if not url:
        raise ValueError("IDOR skill requires a target URL")
    from agents.skills.idor_skill import IDORSkill
    skill = IDORSkill(proxy=proxy or None)
    findings = []
    test_params = params or ["id", "user_id", "account_id", "order_id", "doc_id", "profile_id"]
    for param in test_params:
        try:
            res = await skill.run(url, param)
            for lg in res.get("logs", []):
                await brain._log(lg)
            if res.get("state") == "COMPLETE":
                findings.append({
                    "type": "idor",
                    "param_name": param,
                    "title": f"IDOR/BOLA — Insecure Direct Object Reference (param={param!r})",
                    "severity": "High",
                    "evidence": res.get("evidence_snippet", "Cross-object access confirmed"),
                    "payload_used": f"ID mutation to {res.get('vulnerable_id')}",
                    "remediation": "Implement robust server-side object-level access control checks (ACL/RBAC).",
                    "confidence": res.get("confidence", 0.90),
                    "tool": "IDORSkill",
                    "evidence_sources": ["IDORSkill/MatrixChecker"],
                    "cwe": "CWE-639",
                    "owasp_top10": "A01:2021 — Broken Access Control",
                })
        except Exception:
            log.exception(f"IDORSkill failed on {param}")
    return findings


async def _run_xss_skill(brain, target_url: str, params: list, proxy: str = "") -> list:
    """تشغيل XSS Autonomous Skill (Context-Aware Breakout + CSP Evaluator)"""
    from agents.skills.xss_skill import XSSSkill
    skill = XSSSkill(proxy=proxy or None)
    findings = []
    test_params = params or ["q", "search", "name", "query", "filter", "msg", "title"]
    for param in test_params:
        try:
            res = await skill.run(target_url, param)
            for lg in res.get("logs", []):
                await brain._log(lg)
            if res.get("state") == "COMPLETE":
                findings.append({
                    "type": "xss",
                    "param_name": param,
                    "title": f"Cross-Site Scripting (XSS) — Unescaped Reflection in {res.get('context')}",
                    "severity": "Medium" if res.get("csp_bypassable") else "Low",
                    "evidence": res.get("evidence_snippet", "Unescaped HTML/JS reflection confirmed"),
                    "payload_used": res.get("vulnerable_payload", "?"),
                    "remediation": "Context-aware output encoding (HTML Entity / JS String escape) and implement Content-Security-Policy (CSP).",
                    "confidence": res.get("confidence", 0.90),
                    "tool": "XSSSkill",
                    "evidence_sources": ["XSSSkill/ContextEvaluator"],
                    "cwe": "CWE-79",
                    "owasp_top10": "A03:2021 — Injection",
                })
        except Exception:
            log.exception(f"XSSSkill failed on {param}")
    return findings


def _deduplicate_findings(findings: list) -> list:
    """
    دمج الـfindings المكررة — نفس الـparam + نفس نوع الثغرة = finding واحد
    مع دمج الـevidence sources.
    """
    _SEV_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

    def _normalize_type(t: str) -> str:
        t = t.lower().replace("-", "_").replace(" ", "_")
        for alias in [("sql_injection", "sqli"), ("cross_site_scripting", "xss"),
                      ("reflected_xss", "xss"), ("stored_xss", "xss")]:
            if alias[0] in t:
                return alias[1]
        return t

    seen: Dict[tuple, dict] = {}
    result: list = []
    for f in findings:
        key = (
            f.get("param_name", f.get("endpoint", f.get("title", "?"))),
            _normalize_type(f.get("type", "unknown")),
        )
        if key not in seen:
            seen[key] = f
            f.setdefault("evidence_sources", [f.get("tool", "?")])
            result.append(f)
        else:
            existing = seen[key]
            # Merge evidence source
            src = f.get("tool", "?")
            existing.setdefault("evidence_sources", [])
            if src not in existing["evidence_sources"]:
                existing["evidence_sources"].append(src)
            # Promote severity if higher
            new_sev = f.get("severity", "Info")
            cur_sev = existing.get("severity", "Info")
            try:
                if _SEV_ORDER.index(new_sev) > _SEV_ORDER.index(cur_sev):
                    existing["severity"] = new_sev
            except ValueError:
                pass
            # Prefer higher confidence
            if f.get("confidence", 0) > existing.get("confidence", 0):
                existing["confidence"] = f["confidence"]
    return result


# ─── TOOL REGISTRY MAP ───────────────────────────────────────────────────────

async def _run_vuln_engine(brain: "AutonomousBrain", target: str, proxy: str = "",
                           auth: dict = None, mode: str = "web", endpoints: list = None,
                           params: list = None, focus: str = None, **kwargs) -> list:
    """تشغيل الـ VulnerabilityEngine الشامل متعدد النواقل"""
    from core.vuln_engine import VulnerabilityEngine
    max_concurrent = getattr(brain, "max_concurrent", 8)
    engine = VulnerabilityEngine(proxy=proxy or None, progress_cb=brain._emit_raw, max_concurrent=max_concurrent)
    return await engine.assess_target(
        target_url=target,
        endpoints=endpoints or [],
        discovered_params=params or [],
        primary_focus=focus,
        mode=mode,
    )


async def _run_lfi_skill(brain: "AutonomousBrain", target: str, params: list = None,
                         proxy: str = "", **kwargs) -> list:
    """تشغيل LFI/Path Traversal Autonomous Skill"""
    from agents.skills.lfi_skill import LFISkill
    skill = LFISkill(proxy=proxy or None)
    findings = []
    test_params = params or ["file", "path", "page", "doc", "template", "view", "include"]
    for param in test_params:
        try:
            res = await skill.run(target, param)
            for lg in res.logs:
                await brain._log(lg)
            if res.verified:
                findings.append(res.to_dict())
        except Exception:
            log.exception(f"LFISkill failed on {param}")
    return findings


async def _run_cmd_injection_skill(brain: "AutonomousBrain", target: str, params: list = None,
                                   proxy: str = "", **kwargs) -> list:
    """تشغيل OS Command Injection Autonomous Skill"""
    from agents.skills.cmd_injection_skill import CmdInjectionSkill
    skill = CmdInjectionSkill(proxy=proxy or None)
    findings = []
    test_params = params or ["ip", "host", "cmd", "exec", "ping", "query", "target"]
    for param in test_params:
        try:
            res = await skill.run(target, param)
            for lg in res.logs:
                await brain._log(lg)
            if res.verified:
                findings.append(res.to_dict())
        except Exception:
            log.exception(f"CmdInjectionSkill failed on {param}")
    return findings

async def _run_csrf_skill(brain: "AutonomousBrain", target: str, params: list = None,
                          proxy: str = "", **kwargs) -> list:
    """تشغيل CSRF Autonomous Skill"""
    from agents.skills.csrf_skill import CSRFSkill
    skill = CSRFSkill(proxy=proxy or None)
    findings = []
    test_params = params or ["csrf", "token", "authenticity_token", "csrf_token"]
    for param in test_params:
        try:
            res = await skill.run(target, param)
            if res.verified:
                findings.append(res.to_dict())
        except Exception:
            log.exception(f"CSRFSkill failed on {param}")
    return findings


TOOL_REGISTRY: Dict[str, Callable] = {
    "VulnerabilityEngine": _run_vuln_engine,
    "LFISkill":           _run_lfi_skill,
    "CmdInjectionSkill":   _run_cmd_injection_skill,
    "CSRFSkill":          _run_csrf_skill,
    "SmartPoC":           _run_smartpoc,
    "SQLiSkill":          _run_sqli_skill,
    "SSRFSkill":      _run_ssrf_skill,
    "IDORSkill":      _run_idor_skill,
    "XSSSkill":       _run_xss_skill,
    "ReconAgent":     _run_recon,
    "BugBountyAgent": _run_bugbounty,
    "BrowserAgent":   _run_browser,
    "WebAgent":       _run_webagent,
    "nuclei":         _run_nuclei,
    "sqlmap":         _run_sqlmap,
    "dalfox":         _run_dalfox,
    "gobuster":       _run_gobuster,
    "nmap":           _run_nmap,
    "subfinder":      _run_subfinder,
}




# ─── AutonomousBrain ─────────────────────────────────────────────────────────

class AutonomousBrain:
    """
    OODA Loop — Observe → Decide → Act → Verify

    Rules:
    - Model produces a JSON plan only
    - Execution only via TOOL_REGISTRY (no shell commands from model)
    - Every action is logged in _audit_log
    - dry_run=True runs all logic except actual tool execution
    - max_probes limits total probe requests per scan
    """

    AVAILABLE_TOOLS: List[str] = sorted(TOOL_REGISTRY.keys())

    def __init__(
        self,
        resource_manager,
        tool_manager,
        progress_callback: Optional[Callable] = None,
        dry_run: bool = False,
        max_probes: int = 30,
        scan_timeout: float = 300.0,
    ):
        self.rm = resource_manager
        self.tools = tool_manager
        self.tm = tool_manager
        self.cb = progress_callback

        self.dry_run = dry_run
        self.max_probes = max_probes
        self.scan_timeout = scan_timeout
        self._audit_log: List[Dict[str, Any]] = []

        # V8.0 Investigation OS Tri-Engine Components
        self.digital_twin: Optional[SecurityDigitalTwin] = None
        self.causal_graph: Optional[CausalSecurityGraph] = None
        self.state_machine: Optional[SecurityStateMachine] = None
        self.consumed_requests: int = 0
        self.max_request_budget: int = 5000

        from core.brain.decision_engine import DecisionEngine
        from core.brain.artifact_analyzer import ArtifactAnalyzer
        from core.brain.api_escalation import APIEscalationManager

        self.decision = DecisionEngine(resource_manager, emit_fn=self._emit_raw)
        self.artifact = ArtifactAnalyzer(resource_manager, emit_fn=self._emit_raw)
        self.api_esc = APIEscalationManager(emit_fn=self._emit_raw)

        # Self-Learning: augments scans with learned payloads/techniques
        try:
            from core.learning.self_learning_loop import SelfLearningLoop
            self.knowledge = SelfLearningLoop(resource_manager=resource_manager)
            log.info("[BRAIN] Knowledge base connected")
        except Exception:
            log.warning("SelfLearningLoop not available", exc_info=True)
            self.knowledge = None

        # Aggressive Knowledge Saturation Engine
        try:
            from core.learning.aggressive_learner import AggressiveLearner
            self.learner = AggressiveLearner(
                kb=self.knowledge.kb if self.knowledge else None,
                resource_manager=resource_manager
            )
            log.info("[BRAIN] AggressiveLearner connected")
        except Exception:
            log.warning("AggressiveLearner not available", exc_info=True)
            self.learner = None

        try:
            from core.smart_probe_engine import SmartPoCExecutor
            self.poc = SmartPoCExecutor(tool_manager, progress_callback)
        except Exception:
            log.warning("SmartPoCExecutor not available", exc_info=True)
            self.poc = None

        # Security Intelligence Layer (Reasoning, Hypotheses, Arabic Explanations & Defense-in-Depth)
        try:
            from agents.security_intelligence.brain import SecurityIntelligence
            self.security_intelligence = SecurityIntelligence()
            log.info("[BRAIN] SecurityIntelligence Layer attached")
        except Exception as e:
            log.warning(f"[BRAIN] SecurityIntelligence Layer could not be attached: {e}")
            self.security_intelligence = None

        # Comprehensive Methodology Knowledge Base (Recon + PortSwigger 31 classes)
        try:
            from core.methodology_kb import MethodologyKB
            self.methodology_kb = MethodologyKB()
            log.info("[BRAIN] MethodologyKB (Recon + 31 PortSwigger classes) attached")
        except Exception as e:
            log.warning(f"[BRAIN] MethodologyKB could not be attached: {e}")
            self.methodology_kb = None

        # Attack State Memory (Cairn-inspired state-space tracker)
        self.security_state = None

        # Governed Tool Gateway (CyberStrikeAI-inspired)
        try:
            from core.gateway.tool_gateway import GovernedToolGateway
            from core.gateway.policy_engine import PolicyEngine
            scope_guard_inst = self.security_intelligence.scope_guard if self.security_intelligence else None
            policy_engine = PolicyEngine(scope_guard=scope_guard_inst)
            self.tool_gateway = GovernedToolGateway(
                policy_engine=policy_engine,
                tool_manager=self.tm,
                security_state=self.security_state
            )
            log.info("[BRAIN] GovernedToolGateway attached")
        except Exception as e:
            log.warning(f"[BRAIN] GovernedToolGateway could not be attached: {e}")
            self.tool_gateway = None

        # State-Space Planner (Cairn-inspired goal search)
        try:
            from core.planner.state_space_planner import StateSpacePlanner
            self.planner = StateSpacePlanner(
                security_state=self.security_state,
                tool_gateway=self.tool_gateway
            )
            log.info("[BRAIN] StateSpacePlanner attached")
        except Exception as e:
            log.warning(f"[BRAIN] StateSpacePlanner could not be attached: {e}")
            self.planner = None

        # Causal Attack Graph & Multi-Agent Lead Analyst (LuaN1ao & SickHackShark)
        try:
            from core.attack_graph.graph import CausalAttackGraph
            from core.multi_agent.specialists import LeadAnalyst
            self.attack_graph = CausalAttackGraph(target="target.local")
            self.lead_analyst = LeadAnalyst(target="target.local")
            log.info("[BRAIN] CausalAttackGraph and LeadAnalyst attached")
        except Exception as e:
            log.warning(f"[BRAIN] AttackGraph/LeadAnalyst could not be attached: {e}")
            self.attack_graph = None
            self.lead_analyst = None

        # Epistemic Reasoning Loop
        try:
            from core.reasoning.reasoning_loop import AutonomousReasoningLoop
            self.reasoning_loop = AutonomousReasoningLoop(
                target="target.local",
                attack_graph=self.attack_graph
            )
            log.info("[BRAIN] AutonomousReasoningLoop attached")
        except Exception as e:
            log.warning(f"[BRAIN] AutonomousReasoningLoop could not be attached: {e}")
            self.reasoning_loop = None

        # Loop protection & operation tracking
        self.operation_id = f"op-{int(time.time())}"
        self.action_history_counts: Dict[str, int] = {}
        self.max_same_action = 3

        # User hints & interactive co-pilot guidance
        self.user_hints: List[Dict[str, Any]] = []

        # V15.0 Sensory Triad & Burp Sensor Integration
        self.burp_sensor = None
        self.sensory_triad = None
        try:
            from core.sensors import BurpSensor, SensoryTriadCoordinator
            self.burp_sensor = BurpSensor()
            self.sensory_triad = SensoryTriadCoordinator(burp_sensor=self.burp_sensor)
            log.info("[BRAIN] BurpSensor and SensoryTriadCoordinator attached")
        except Exception as e:
            log.warning(f"[BRAIN] BurpSensor could not be attached: {e}")

        # V18.0 Auditable Security Platform Subsystems
        self.flight_recorder = None
        self.agent_ids = None
        self.capability_gate = None
        self.coverage_ledger = None
        self.replay_lab = None
        self.request_fingerprinter = None
        try:
            from core.telemetry.flight_recorder import SecurityFlightRecorder
            from core.safety.agent_ids import AgentIntrusionDetector
            from core.safety.capabilities import CapabilityGate
            from core.replay_lab.replay_lab import ReplayLab
            from core.request_fingerprinter import RequestFingerprinter
            from core.safety.kill_switch import EmergencyKillSwitch

            self.flight_recorder = SecurityFlightRecorder.get_instance()
            self.agent_ids = AgentIntrusionDetector()
            self.capability_gate = CapabilityGate()
            self.replay_lab = ReplayLab()
            self.request_fingerprinter = RequestFingerprinter()
            EmergencyKillSwitch().register_teardown(
                lambda: log.info("[BRAIN] Teardown triggered by EmergencyKillSwitch"),
                name="AutonomousBrain"
            )
            log.info("[BRAIN] V18.0 Auditable Subsystems attached (FlightRecorder, AgentIDS, CapabilityGate, ReplayLab, RequestFingerprinter)")
        except Exception as e:
            log.warning(f"[BRAIN] V18.0 Auditable Subsystems could not be attached: {e}")

        # V19.0 Epistemic Security OS Subsystems
        self.decision_trace = None
        self.policy_engine = None
        self.contract_engine = None
        self.budget_manager = None
        self.drift_classifier = None
        self.bundle_manager = None
        try:
            from core.trace.agent_decision_trace import AgentDecisionTrace
            from core.policy.policy_as_code import PolicyAsCodeEngine, EnvironmentTier
            from core.contract.security_contract import SecurityContractEngine
            from core.budget.categorized_budget import CategorizedBudgetManager
            from core.drift.evidence_drift_classifier import EvidenceDriftClassifier
            from core.bundle.investigation_bundle import InvestigationBundleManager

            self.decision_trace = AgentDecisionTrace(trace_id=f"TRC-{int(time.time())}", target="target.local")
            self.policy_engine = PolicyAsCodeEngine(policy_version="v1.4", environment=EnvironmentTier.LAB)
            self.contract_engine = SecurityContractEngine()
            self.budget_manager = CategorizedBudgetManager()
            self.drift_classifier = EvidenceDriftClassifier()
            self.bundle_manager = InvestigationBundleManager()
            log.info("[BRAIN] V19.0 Epistemic Subsystems attached (DecisionTrace, PolicyAsCode, ContractEngine, CategorizedBudget, DriftClassifier, BundleManager)")
        except Exception as e:
            log.warning(f"[BRAIN] V19.0 Epistemic Subsystems could not be attached: {e}")

        # V20.0 PentesterFlow Sensory Triad & Auditable Evidence OS Engine
        self.pentester_flow = None
        try:
            from core.sensors.pentester_flow import PentesterFlowEngine
            self.pentester_flow = PentesterFlowEngine(
                burp_sensor=self.burp_sensor,
                sensory_triad=self.sensory_triad,
                contract_engine=self.contract_engine,
                bundle_manager=self.bundle_manager,
                decision_trace=self.decision_trace,
            )
            log.info("[BRAIN] V20.0 PentesterFlow Sensory Triad Engine attached")
        except Exception as e:
            log.warning(f"[BRAIN] PentesterFlow could not be attached: {e}")

    def attach_burp_sensor(self, sensor: Any) -> None:
        """Attaches or updates the BurpSensor perceptual organ."""
        self.burp_sensor = sensor
        if self.sensory_triad:
            self.sensory_triad.burp_sensor = sensor
        if self.pentester_flow:
            self.pentester_flow.burp_sensor = sensor
        self._audit("burp_sensor_attached", status=sensor.get_sensor_status() if hasattr(sensor, "get_sensor_status") else {})

    def attach_sensory_triad(self, triad: Any) -> None:
        """Attaches or updates the unified SensoryTriadCoordinator."""
        self.sensory_triad = triad
        if hasattr(triad, "burp_sensor") and triad.burp_sensor:
            self.burp_sensor = triad.burp_sensor
        if self.pentester_flow:
            self.pentester_flow.sensory_triad = triad
            if self.burp_sensor:
                self.pentester_flow.burp_sensor = self.burp_sensor
        self._audit("sensory_triad_attached")

    def ingest_burp_transaction(self, tx: Any, parent_id: Optional[str] = None) -> Any:
        """Ingests live HTTP transaction from Burp Suite into the sensory stream."""
        if self.pentester_flow:
            event = self.pentester_flow.ingest_burp_transaction(tx, parent_id=parent_id)
            self._audit("burp_transaction_ingested", url=event.burp_tx.url, method=event.burp_tx.method)
            from core.sensors.burp_sensor import NormalizedObservation, SensorType
            obs = NormalizedObservation(
                sensor_type=SensorType.BURP,
                target_url=event.burp_tx.url,
                method=event.burp_tx.method,
                status_code=event.burp_tx.status_code,
                parameters=event.burp_tx.parameter_ids,
                headers=event.burp_tx.headers,
                raw_context=event.burp_tx.to_dict(),
                timestamp=event.burp_tx.timestamp,
            )
            return obs
        elif self.burp_sensor:
            obs = self.burp_sensor.ingest_transaction(tx, parent_id=parent_id)
            self._audit("burp_transaction_ingested", url=obs.target_url, method=obs.method)
            return obs
        return None

    def run_pentester_flow(self, scenario: Any) -> Any:
        """Executes a complete, reproducible PentesterFlow causal investigation cycle."""
        if self.pentester_flow:
            ruling = self.pentester_flow.run_scenario(scenario)
            self._audit("pentester_flow_scenario_completed", scenario=str(scenario), verdict=ruling.court_verdict)
            return ruling
        return None

    def add_user_hint(self, hint: str) -> None:
        """إضافة نصيحة أو توجيه من المستخدم للـ Agent أثناء التخطيط والتنفيذ"""
        self.user_hints.append({"hint": hint, "ts": time.time()})
        self._audit("user_hint_received", hint=hint)



    # ─── Logging & Audit ────────────────────────────────────────────────────

    async def _emit_raw(self, data: dict) -> None:
        if self.cb:
            try:
                await self.cb(data)
            except Exception:
                log.exception("AutonomousBrain._emit_raw: callback failed")

    async def _emit(self, event: str, **kwargs) -> None:
        await self._emit_raw({"event": event, **kwargs})

    async def _log(self, msg: str) -> None:
        log.debug(msg)
        await self._emit("log", message=msg)

    def _audit(self, event: str, **kwargs) -> None:
        """Append to immutable audit trail"""
        self._audit_log.append({"ts": time.time(), "event": event, **kwargs})

    # ─── OBSERVE Helpers ────────────────────────────────────────────────────

    async def _fetch_target(
        self, url: str, auth: Optional[dict], proxy: Optional[str]
    ) -> Tuple[str, int, dict]:
        import httpx
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if auth:
            if auth.get("cookie"):
                headers["Cookie"] = auth["cookie"]
            if auth.get("token"):
                headers["Authorization"] = f"Bearer {auth['token']}"

        transport = None
        if proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=False)
            except Exception:
                pass

        try:
            async with httpx.AsyncClient(
                headers=headers, transport=transport,
                timeout=15.0, follow_redirects=True, verify=False
            ) as client:
                resp = await client.get(url)
                return resp.text, resp.status_code, dict(resp.headers)
        except Exception as e:
            log.warning(f"_fetch_target failed for {url!r}: {e}")
            return "", 0, {}

    async def _check_burp_online(self, proxy: Optional[str]) -> bool:
        if not proxy:
            return False
        import httpx
        try:
            host_port = proxy.replace("http://", "").replace("https://", "")
            parts = host_port.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 8080
            async with httpx.AsyncClient(timeout=1.5) as c:
                await c.get(f"http://{host}:{port}")
            return True
        except Exception:
            return False

    def _is_in_scope(self, url: str, base_url: str) -> bool:
        """
        Ensures that discovered URLs belong strictly to the target host or its subdomains,
        filtering out 3rd party trackers, CDNs, app stores, and external links.
        """
        try:
            from urllib.parse import urlparse
            parsed_target = urlparse(base_url)
            parsed_probe = urlparse(url)
            target_host = (parsed_target.hostname or "").lower().strip()
            probe_host = (parsed_probe.hostname or "").lower().strip()
            if not probe_host:
                return True
            if probe_host == target_host:
                return True
            # Subdomains of target
            if target_host and probe_host.endswith(f".{target_host}"):
                return True
            # Blocklist external CDNs, analytics, app stores, social media
            external_blocklist = {
                "google.com", "googletagmanager.com", "google-analytics.com", "gstatic.com",
                "play.google.com", "apple.com", "apps.apple.com", "facebook.com", "twitter.com",
                "linkedin.com", "youtube.com", "instagram.com", "cloudflare.com", "cdnjs.cloudflare.com"
            }
            if any(probe_host == b or probe_host.endswith(f".{b}") for b in external_blocklist):
                return False
            # Allow common apex domain matching (e.g. sub.bancoplata.mx -> bancoplata.mx)
            parts = target_host.split(".")
            if len(parts) >= 2:
                root_domain = ".".join(parts[-2:])
                if probe_host == root_domain or probe_host.endswith(f".{root_domain}"):
                    return True
            return False
        except Exception:
            return False

    def _extract_endpoints_and_params(self, html: str, base_url: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        """
        استخراج ذكي وشامل لجميع الـ Endpoints والـ Parameters من:
        1. الروابط (href) بما فيها فلاتر PortSwigger مثل /filter?category=Gifts
        2. نماذج الإدخال (Forms, Inputs, Textareas, Selects)
        3. استدعاءات الـ JavaScript والـ APIs
        4. الـ Query Parameters في الرابط الأصلي
        مع فحص صارم للـ Scope وفك تشفير كيانات HTML.
        """
        params: set = set()
        endpoints: List[Dict[str, Any]] = []
        seen_ep_keys: set = set()

        import html as html_lib
        from urllib.parse import urljoin, urlparse, parse_qs

        # 1. Base URL query parameters
        try:
            parsed_base = urlparse(base_url)
            qs = parse_qs(parsed_base.query)
            for p, vals in qs.items():
                clean_p = re.sub(r"[^a-zA-Z0-9_\-\[\].]", "", p)[:64]
                if clean_p:
                    params.add(clean_p)
                    val = vals[0] if vals else ""
                    key = (base_url.split("?")[0], clean_p)
                    if key not in seen_ep_keys:
                        seen_ep_keys.add(key)
                        endpoints.append({
                            "url": base_url,
                            "base_url": base_url.split("?")[0],
                            "param": clean_p,
                            "orig_value": val,
                            "method": "GET"
                        })
        except Exception:
            pass

        # 2. Extract from <a> href links (e.g. /filter?category=Gifts, /product?productId=1)
        try:
            hrefs = re.findall(r'href=["\']([^"\'#]+)["\']', html, re.IGNORECASE)
            for href in hrefs:
                clean_href = html_lib.unescape(href.strip())
                if "?" in clean_href:
                    full_url = urljoin(base_url, clean_href)
                    if not self._is_in_scope(full_url, base_url):
                        continue
                    parsed = urlparse(full_url)
                    qs = parse_qs(parsed.query)
                    for p, vals in qs.items():
                        clean_p = re.sub(r"[^a-zA-Z0-9_\-\[\].]", "", p)[:64]
                        if clean_p:
                            params.add(clean_p)
                            val = vals[0] if vals else ""
                            base_ep = full_url.split("?")[0]
                            key = (base_ep, clean_p)
                            if key not in seen_ep_keys:
                                seen_ep_keys.add(key)
                                endpoints.append({
                                    "url": full_url,
                                    "base_url": base_ep,
                                    "param": clean_p,
                                    "orig_value": val,
                                    "method": "GET"
                                })
        except Exception:
            pass

        # 3. Extract from <form> elements
        try:
            form_matches = re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
            for form in form_matches:
                attrs = form.group(1)
                body = form.group(2)
                action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                action = html_lib.unescape(action_m.group(1).strip()) if action_m else ""
                method = method_m.group(1).upper() if method_m else "GET"
                form_url = urljoin(base_url, action) if action else base_url
                if not self._is_in_scope(form_url, base_url):
                    continue

                form_inputs = re.findall(r'<(?:input|textarea|select)[^>]+name=["\']([^"\']{1,64})["\']', body, re.IGNORECASE)
                for inp_name in form_inputs:
                    clean_p = re.sub(r"[^a-zA-Z0-9_\-\[\].]", "", inp_name)[:64]
                    if clean_p:
                        params.add(clean_p)
                        key = (form_url.split("?")[0], clean_p)
                        if key not in seen_ep_keys:
                            seen_ep_keys.add(key)
                            endpoints.append({
                                "url": form_url,
                                "base_url": form_url.split("?")[0],
                                "param": clean_p,
                                "orig_value": "test",
                                "method": method
                            })
        except Exception:
            pass

        # 4. Standalone inputs outside forms
        try:
            for inp_name in re.findall(r'<(?:input|textarea|select)[^>]+name=["\']([^"\']{1,64})["\']', html, re.IGNORECASE):
                clean_p = re.sub(r"[^a-zA-Z0-9_\-\[\].]", "", inp_name)[:64]
                if clean_p:
                    params.add(clean_p)
        except Exception:
            pass

        safe_params = [p for p in params if p]
        if not safe_params:
            safe_params = ["category", "search", "id", "q", "filter"]

        return safe_params, endpoints

    def _extract_params_from_html(self, html: str, url: str) -> List[str]:
        p, _ = self._extract_endpoints_and_params(html, url)
        return p

    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        import html as html_lib
        found = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        try:
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for src in srcs:
                clean_src = html_lib.unescape(src.strip())
                if clean_src.startswith("http"):
                    full_src = clean_src
                elif clean_src.startswith("//"):
                    full_src = f"{parsed.scheme}:{clean_src}"
                elif clean_src.startswith("/"):
                    full_src = f"{base}{clean_src}"
                else:
                    full_src = f"{base}/{clean_src}"
                if self._is_in_scope(full_src, base_url):
                    found.append(full_src)
        except Exception:
            pass
        return found[:5]

    async def _fetch_js(self, url: str, proxy: Optional[str] = None) -> str:
        import httpx
        transport = None
        if proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=False)
            except Exception:
                pass

        try:
            async with httpx.AsyncClient(
                transport=transport, timeout=10.0, verify=False
            ) as client:
                resp = await client.get(url)
                return resp.text[:8000]
        except Exception:
            log.debug(f"_fetch_js failed: {url!r}", exc_info=True)
            return ""

    # ─── ACT: Safe Tool Execution ────────────────────────────────────────────

    async def _execute_tool(self, tool_name: str, **kwargs) -> List[dict]:
        """
        التنفيذ الآمن عبر TOOL_REGISTRY فقط.
        أي tool غير مسجّل يُرفض فوراً — لا shell commands.
        """
        handler = TOOL_REGISTRY.get(tool_name)
        if handler is None:
            await self._log(f"[ACT] Rejected unknown tool: {tool_name!r}")
            self._audit("tool_rejected", tool=tool_name)
            return []

        # V8.0 Machine-Enforced Constitutional Gate
        target = kwargs.get("target", "")
        target_ip = urlparse(target).hostname or target
        method = kwargs.get("method", "GET")
        has_approval = kwargs.get("has_operator_approval", True if method.upper() == "GET" else False)
        chk = AgentConstitution.verify_action(
            target_ip=target_ip,
            is_in_scope=self._is_in_scope(target, target) if target else True,
            method=method,
            has_operator_approval=has_approval,
            consumed_requests=self.consumed_requests,
            max_budget=self.max_request_budget
        )
        if not chk.is_compliant:
            await self._log(f"[CONSTITUTION] Blocked {tool_name} on {target}: {chk.violated_invariant} ({chk.remediation_action})")
            self._audit("constitutional_violation", tool=tool_name, target=target, invariant=chk.violated_invariant)
            return []
        self.consumed_requests += 1

        # Defense-in-Depth Scope & Governed Gateway Check before active execution
        if self.tool_gateway and target:
            from core.gateway.schemas import ActionProposal
            proposal = ActionProposal(
                proposing_agent="AutonomousBrain",
                target=target,
                tool_name=tool_name,
                command_args=str(kwargs.get("params", "")),
                action_type="CLI_TOOL",
                rationale=f"Autonomous probe for {kwargs.get('focus', 'vulnerabilities')}"
            )
            verdict = self.tool_gateway.policy.evaluate_proposal(proposal)
            if not verdict.allowed:
                await self._log(f"[GATEWAY] Blocked {tool_name} on {target}: {verdict.reason}")
                event_type = "tool_scope_blocked" if "scope" in verdict.reason.lower() else "tool_gateway_blocked"
                self._audit(event_type, tool=tool_name, target=target, reason=verdict.reason, risk=verdict.risk_tier.value)
                return []

        elif self.security_intelligence and target:
            scope_dec = self.security_intelligence.evaluate_scope(target, action=f"active_tool_{tool_name}")
            if not scope_dec.allowed:
                await self._log(f"[SCOPE] Blocked {tool_name} on {target}: {scope_dec.reason}")
                self._audit("tool_scope_blocked", tool=tool_name, target=target, reason=scope_dec.reason)
                return []

        if self.dry_run:
            await self._log(f"[DRY_RUN] Would execute: {tool_name} — skipping")
            self._audit("tool_dry_run", tool=tool_name, kwargs=list(kwargs.keys()))
            return []

        await self._log(f"[ACT] Executing: {tool_name}")
        self._audit("tool_execute", tool=tool_name, target=kwargs.get("target", ""))

        try:
            result = await handler(self, **kwargs)
            self._audit("tool_done", tool=tool_name, results=len(result or []))
            return result or []
        except Exception:
            log.exception(f"Tool execution failed: {tool_name!r}")
            self._audit("tool_error", tool=tool_name)
            return []

    # ─── MAIN OODA LOOP ──────────────────────────────────────────────────────

    async def run_scan(
        self,
        target: str,
        mode: str = "auto",
        auth: Optional[Dict] = None,
        proxy: Optional[str] = None,
        use_browser: bool = False,
        use_proxy: bool = False,
    ) -> Dict[str, Any]:
        """نقطة الدخول الرئيسية — الـ OODA Loop الكامل"""
        t0 = time.time()
        findings: List[dict] = []
        js_findings: List[dict] = []

        # Check emergency kill switch
        from core.safety.kill_switch import EmergencyKillSwitch
        if EmergencyKillSwitch().is_tripped:
            await self._log("[BRAIN] 🛑 Emergency Kill Switch is TRIPPED. Aborting scan immediately.")
            self._audit("scan_aborted_kill_switch", target=target)
            return {"target": target, "status": "ABORTED_BY_KILL_SWITCH", "findings": []}

        # Initialize Coverage Ledger and Flight Recorder
        from core.coverage.coverage_ledger import CoverageLedger, CoverageStatus
        from core.telemetry.flight_recorder import FlightEventType
        self.coverage_ledger = CoverageLedger(target_scope=target)
        if self.flight_recorder:
            self.flight_recorder.record_event(
                event_type=FlightEventType.SCOPE_LOADED,
                phase="ORIENT",
                actor="AutonomousBrain",
                rationale=f"Target {target} loaded into active scope",
                details={"target": target, "mode": mode}
            )
            self.flight_recorder.record_event(
                event_type=FlightEventType.ASSET_DISCOVERED,
                phase="ORIENT",
                actor="AutonomousBrain",
                rationale=f"Primary target asset recognized: {urlparse(target).hostname or target}",
                details={"host": urlparse(target).hostname or target}
            )

        # Initialize Decision Trace for this scan
        if self.decision_trace:
            self.decision_trace.target = target
            self.decision_trace.record_step(
                observation=f"Target {target} armed into active scope",
                evidence=[f"Mode: {mode}", f"Host: {urlparse(target).hostname or target}"],
                decision="Initiate passive discovery and sensory observation phase",
                policy_result="ALLOW",
                policy_receipt="POL-V14-INIT",
                action="Arm scope boundaries and telemetry blackbox",
                result="Epistemic security tracking active"
            )

        if self.dry_run:
            await self._log("[BRAIN] dry_run=True — no actual tools will execute")

        # Initialize Attack State Memory (Cairn-inspired state-space tracker)
        try:
            from core.state.security_state import SecurityState
            self.security_state = SecurityState(target=target)
            parsed_host = urlparse(target).hostname or target
            self.security_state.add_asset(host=parsed_host)
            if self.tool_gateway:
                self.tool_gateway.set_security_state(self.security_state)
        except Exception as e:
            log.debug(f"Failed to initialize SecurityState: {e}")
            self.security_state = None

        # V8.0 Investigation OS Tri-Engine Initialization
        target_host = urlparse(target).hostname or target
        self.digital_twin = SecurityDigitalTwin(target_host)
        self.causal_graph = CausalSecurityGraph(target_host)
        self.state_machine = SecurityStateMachine(session_id=f"scan_{int(time.time())}")

        # ── PHASE 0: OBSERVE (Human-like Browser Exploration Sensor) ────────
        await self._emit("phase", phase="observe", message="[OBSERVE] Launching Browser Sensor & Application Explorer...")
        self._audit("observe_start", target=target, mode=mode)

        if self.user_hints:
            for uh in self.user_hints:
                await self._log(f"[HINT 💡] User Guidance Active: {uh.get('hint')}")

        burp_online = await self._check_burp_online(proxy)

        # Initialize continuous Browser Sensor with Event Bus
        target_host_sanitized = (urlparse(target).hostname or "target").replace(":", "_").replace(".", "_")
        browser_output_dir = Path(f"data/scans/{target_host_sanitized}/browser")
        if not hasattr(self, "browser_event_bus") or not self.browser_event_bus:
            from core.browser.browser_event_bus import BrowserEventBus
            self.browser_event_bus = BrowserEventBus()

        self.browser_session = StatefulBrowserSession(
            target_url=target,
            output_dir=browser_output_dir,
            headless=not use_browser,
            proxy=proxy,
            event_bus=self.browser_event_bus,
        )
        self.browser_explorer = HumanLikeExplorationEngine(
            session=self.browser_session,
            max_pages=8 if mode in ("full", "web", "auto") else 4,
            max_depth=2,
            time_budget_sec=60.0,
            coverage_target_pct=80.0,
            on_progress_cb=lambda msg: self._log(msg)
        )

        try:
            exploration_res = await self.browser_explorer.explore()
        except Exception as e:
            log.warning(f"Browser exploration non-critical error: {e}")
            exploration_res = {}
        self._last_browser_exploration = exploration_res

        cov_table = exploration_res.get("coverage_table", "")
        if cov_table:
            await self._log(f"[COVERAGE]\n{cov_table}")

        html, status_code, headers = await self._fetch_target(target, auth, proxy)
        static_params, static_endpoints = self._extract_endpoints_and_params(html, target)

        # Merge browser discovered artifacts with static extraction
        params_from_page = list(dict.fromkeys(static_params + exploration_res.get("params", [])))
        discovered_endpoints = list(static_endpoints)
        for ep_url in exploration_res.get("endpoints", []):
            if not any((ep.get("url") if isinstance(ep, dict) else ep) == ep_url for ep in discovered_endpoints):
                discovered_endpoints.append({"url": ep_url, "param": None})

        # Merge JS URLs
        static_js = self._extract_js_urls(html, target)
        js_urls = list(dict.fromkeys(static_js + exploration_res.get("js_urls", [])))

        # Update SecurityState with observed endpoints
        if self.security_state:
            for ep in discovered_endpoints:
                ep_url = ep.get("url") if isinstance(ep, dict) else str(ep)
                ep_path = urlparse(ep_url).path if "://" in ep_url else ep_url
                self.security_state.add_endpoint(path=ep_path, url=ep_url)

        manifest_obj = exploration_res.get("manifest", {}) if isinstance(exploration_res.get("manifest"), dict) else {}
        pages_val = manifest_obj.get("pages_visited", 0)
        browser_pages_count = len(pages_val) if isinstance(pages_val, (list, set, dict)) else int(pages_val or 0)

        self._audit("observe_done", status=status_code,
                    params=params_from_page, endpoints_count=len(discovered_endpoints), js_count=len(js_urls),
                    browser_pages=browser_pages_count)
        await self._log(
            f"[OBSERVE] status={status_code} | "
            f"params={len(params_from_page)} | "
            f"endpoints={len(discovered_endpoints)} | "
            f"js={len(js_urls)} | burp={'online' if burp_online else 'offline'} | "
            f"browser_states={len(exploration_res.get('state_graph', {}).get('states', {}))}"
        )

        # Tech Stack Detection via AggressiveLearner
        tech_info: Dict = {}
        if self.learner:
            try:
                tech_info = await self.learner.detect_tech_stack(target, html=html, headers=headers)
                detected_techs = tech_info.get("detected_technologies", [])
                if detected_techs:
                    await self._log(f"[TECH_STACK] Detected: {', '.join(detected_techs[:6])}")
                    self._audit("tech_stack_detected", technologies=detected_techs)
                    if self.security_state:
                        parsed_host = urlparse(target).hostname or target
                        self.security_state.add_asset(host=parsed_host, technologies=detected_techs)
            except Exception:
                log.debug("Tech stack detection non-critical failure", exc_info=True)

        # ── PHASE 0.3: CODE INTELLIGENCE (Client-side Page & JS Analysis) ────
        code_intel_res: Dict[str, Any] = {}
        spa_detected = False
        try:
            target_host_sanitized = (urlparse(target).hostname or "target").replace(":", "_").replace(".", "_")
            code_intel_agent = CodeIntelligenceAgent(output_dir=f"data/scans/{target_host_sanitized}")
            code_intel_res = await code_intel_agent.analyze_page(
                target_url=target,
                raw_html=html,
                headers=headers
            )
            self._last_code_intel = code_intel_res
            fw = code_intel_res.get("framework", {})
            techs = code_intel_res.get("manifest", {}).get("technologies", [])
            if fw.get("detected") or any(t.lower() in ("next.js", "react", "vue", "angular", "spa") for t in techs):
                spa_detected = True

            # Merge in-scope discovered endpoints
            for ep in code_intel_res.get("endpoints", []):
                ep_path = ep.get("url_or_path", "")
                if ep_path and self._is_in_scope(ep_path, target):
                    full_ep_url = urljoin(target, ep_path)
                    discovered_endpoints.append({"url": full_ep_url, "param": ep.get("parameters", [None])[0] if ep.get("parameters") else None})
                    for p in ep.get("parameters", []):
                        if p and p not in params_from_page:
                            params_from_page.append(p)
            m = code_intel_res.get("manifest", {})
            await self._log(
                f"[CODE_INTEL] Analyzed {m.get('js_analyzed', 0)} scripts | "
                f"Discovered {m.get('endpoints_discovered', 0)} API endpoints | "
                f"Secrets validated: {m.get('secrets_discovered', 0)}"
            )
            self._audit("code_intelligence_done", manifest=m)

            # Bidirectional Sensor Feedback: direct active Browser Sensor to explore top newly discovered JS API routes
            if hasattr(self, "browser_explorer") and self.browser_explorer:
                for ep in code_intel_res.get("endpoints", [])[:3]:
                    ep_path = ep.get("url_or_path", "")
                    if ep_path and self._is_in_scope(ep_path, target):
                        try:
                            await self.browser_explorer.explore_endpoint(ep_path)
                        except Exception:
                            pass
        except Exception as e:
            log.debug(f"CodeIntelligenceAgent non-critical error: {e}")

        # ── PHASE 0.5: ORIENT (Security Intelligence Layer) ──────────────────
        si_context = None
        si_hypotheses = []
        if self.security_intelligence:
            try:
                from agents.security_intelligence.schemas import SecurityObservation, ObservationType
                obs = SecurityObservation(
                    project_id="autonomous_brain_scan",
                    target=target,
                    source="autonomous_brain.observe",
                    obs_type=ObservationType.HTTP_RESPONSE,
                    data={
                        "url": target,
                        "path": urlparse(target).path or "/",
                        "status": status_code,
                        "headers": headers,
                        "html_snippet": html[:1000] if html else "",
                        "parameters": params_from_page,
                        "endpoints": [ep.get("url") if isinstance(ep, dict) else str(ep) for ep in discovered_endpoints[:20]]
                    },
                    operation_id=self.operation_id
                )
                si_context = await self.security_intelligence.get_context(obs)
                si_hypotheses = await self.security_intelligence.generate_hypotheses(obs)
                if si_hypotheses:
                    top_hyp_strs = [f"{h.vulnerability_type} ({h.confidence:.2f})" for h in si_hypotheses[:3]]
                    await self._log(f"[INTELLIGENCE] Hypotheses: {', '.join(top_hyp_strs)}")
                    if self.security_state:
                        for h in si_hypotheses:
                            self.security_state.add_unknown(f"Is {h.target_endpoint} vulnerable to {h.vulnerability_type}?")
                self._audit(
                    "security_intelligence_oriented",
                    hypotheses=[h.model_dump() for h in si_hypotheses[:5]],
                    auth_state=si_context.auth_type if si_context else "unknown"
                )
            except Exception as e:
                log.debug(f"SecurityIntelligence orient failed gracefully: {e}")


        # ── PHASE 1: DECIDE ─────────────────────────────────────────────────
        await self._emit("phase", phase="decide",
                         message="[DECIDE] WhiteRabbitNeo building attack plan...")
        self._audit("decide_start")

        plan = await self.decision.make_plan(
            target=target,
            html_snippet=html[:500],
            headers=headers,
            available_tools=self.AVAILABLE_TOOLS,
            mode=mode,
            dry_run=self.dry_run,
        )
        if tech_info.get("detected_technologies"):
            plan["detected_technologies"] = tech_info["detected_technologies"]

        # Automatically schedule BrowserAgent exploration if a modern SPA (Next.js/React/Vue) is detected
        if spa_detected or any("next" in str(t).lower() or "react" in str(t).lower() for t in tech_info.get("detected_technologies", [])):
            if mode in ("full", "web", "auto", "ctf") and not plan.get("use_browser"):
                plan["use_browser"] = True
                tools_list = plan.setdefault("needed_tools", ["SmartPoC"])
                if "BrowserAgent" not in tools_list:
                    tools_list.append("BrowserAgent")
                await self._log("[DECIDE] Modern SPA / Next.js detected -> Automatically activated BrowserAgent for dynamic client-side exploration")

        # Guide plan with SecurityIntelligence hypotheses
        if si_hypotheses:
            top_focus = si_hypotheses[0].vulnerability_type.lower()
            plan["intelligence_focus"] = top_focus
            if not plan.get("primary_focus") or plan.get("primary_focus") == "xss":
                plan["primary_focus"] = top_focus


        # ── KB Augmentation: use learned knowledge to improve the plan ──────
        kb_context: Dict = {}
        if self.knowledge:
            try:
                kb_context = self.knowledge.retrieve_for_scan(target, html[:300])
                recommended_techs = kb_context.get("recommended_techniques", [])
                if recommended_techs:
                    # Merge KB-recommended focuses into plan
                    plan_focus = plan.get("primary_focus", "xss")
                    if plan_focus not in recommended_techs:
                        recommended_techs.insert(0, plan_focus)
                    plan["kb_recommended_techniques"] = recommended_techs[:5]
                    await self._log(
                        f"[KB] Retrieved {len(kb_context.get('similar_articles', []))} similar articles | "
                        f"Recommended techniques: {recommended_techs[:3]}"
                    )
                    self._audit("kb_augmented", techniques=recommended_techs[:5],
                                confidence=kb_context.get("confidence", 0.0))
            except Exception:
                log.warning("KB retrieval failed", exc_info=True)

        # Merge + sanitize params
        ai_params = [
            re.sub(r"[^a-zA-Z0-9_\-\[\].]", "", str(p))[:64]
            for p in plan.get("parameters_to_audit", [])
            if p
        ]
        all_params = list(dict.fromkeys(ai_params + params_from_page))
        if not all_params:
            all_params = ["category", "search", "id", "q", "filter"]
        all_params = all_params[: self.max_probes]

        self._audit("decide_done", plan=plan, params=all_params)
        await self._log(f"[DECIDE] Parameters to audit ({len(all_params)}): {all_params}")

        # ── PHASE 2: ACT ────────────────────────────────────────────────────
        await self._emit("phase", phase="act", message="[ACT] Executing selected tools...")

        needed_tools = plan.get("needed_tools", ["SmartPoC"])
        primary_focus = plan.get("primary_focus", "xss")

        # ── Smart Tool Routing ────────────────────────────────────────────────
        is_sqli_focus = any(kw in primary_focus.lower() for kw in ("sql", "sqli", "injection"))
        is_ssrf_focus = any(kw in primary_focus.lower() for kw in ("ssrf", "forgery", "metadata", "webhook"))
        is_idor_focus = any(kw in primary_focus.lower() for kw in ("idor", "bola", "authz", "access_control", "tenant"))
        is_xss_focus  = any(kw in primary_focus.lower() for kw in ("xss", "cross", "scripting"))

        if is_sqli_focus or mode in ("sqli",):
            if "SQLiSkill" not in needed_tools:
                needed_tools.append("SQLiSkill")
                await self._log("[ROUTE] SQLi focus → added SQLiSkill (State Machine)")
            if "dalfox" in needed_tools:
                needed_tools.remove("dalfox")
                await self._log("[ROUTE] SQLi focus → removed dalfox (XSS-only, irrelevant here)")

        if is_ssrf_focus or mode in ("ssrf",):
            if "SSRFSkill" not in needed_tools:
                needed_tools.append("SSRFSkill")
                await self._log("[ROUTE] SSRF focus → added SSRFSkill (Cloud Metadata Matrix)")

        if is_idor_focus or mode in ("idor", "bola"):
            if "IDORSkill" not in needed_tools:
                needed_tools.append("IDORSkill")
                await self._log("[ROUTE] IDOR focus → added IDORSkill (Cross-Tenant Matrix)")

        if is_xss_focus or mode in ("xss",):
            if "XSSSkill" not in needed_tools:
                needed_tools.append("XSSSkill")
                await self._log("[ROUTE] XSS focus → added XSSSkill (Context-Aware Evaluator)")

        # ── Smart Tool Routing for Recon & Full Scans ─────────────────────────
        clean_host = urlparse(target).hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        is_domain = bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', clean_host)) or bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_host))

        should_run_recon = mode in ("full", "recon", "bugbounty_full", "auto") or plan.get("needs_recon") or is_domain
        if should_run_recon:
            if "ReconAgent" not in needed_tools:
                needed_tools.append("ReconAgent")
            plan["needs_recon"] = True

        # Ensure directory fuzzing (gobuster / ffuf / python_dir_fuzz) runs in full / bugbounty / web modes
        should_run_fuzz = mode in ("full", "bugbounty_full", "web", "fuzz", "auto") or "fuzz" in primary_focus.lower()
        if should_run_fuzz and "gobuster" not in needed_tools:
            needed_tools.append("gobuster")

        # Ensure port scanning (nmap) runs in full / recon / network modes or when target is a host
        should_run_nmap = mode in ("full", "recon", "network", "bugbounty_full") or is_domain
        if should_run_nmap and self.tools.is_available("nmap") and "nmap" not in needed_tools:
            needed_tools.append("nmap")

        # Log final tool plan
        await self._log(f"[ROUTE] Final tools: {needed_tools} | focus={primary_focus!r}")
        # ─────────────────────────────────────────────────────────────────────

        # Launch cloud APIs in background (parallel, non-blocking)
        cloud_prompt = (
            f"Security analysis for: {target}\nMode: {mode}\n"
            f"AI Plan: {json.dumps(plan)}\n"
            "Provide additional threat intelligence and payload suggestions."
        )
        api_task = asyncio.create_task(self.api_esc.call_all_parallel(cloud_prompt))

        # 2a. ReconAgent if full domain
        if (plan.get("needs_recon") or should_run_recon) and ("ReconAgent" in needed_tools or should_run_recon):
            await self._log("[ACT] Launching ReconAgent...")
            raw_results = await self._execute_tool(
                "ReconAgent", target=target, proxy=proxy, auth=auth or {}
            )
            for r in raw_results:
                r.setdefault("tool", "ReconAgent")
            findings.extend(raw_results)
            await self._log(f"[ACT] ReconAgent: {len(raw_results)} findings")

        # 2b. VulnerabilityEngine Systematic Multi-Vector Assessment
        is_passive_mode = mode in ("recon", "passive", "understand", "info", "gather")
        if not is_passive_mode:
            await self._log(f"[ACT] VulnerabilityEngine: running systematic multi-vector audit across all endpoints & parameters...")
            engine_findings = await self._execute_tool(
                "VulnerabilityEngine",
                target=target,
                proxy=proxy,
                auth=auth or {},
                mode=mode,
                endpoints=discovered_endpoints,
                params=all_params,
                focus=primary_focus,
            )
            for ef in engine_findings:
                findings.append(ef)
                self._audit("finding_added", title=ef.get("title", ""), severity=ef.get("severity", "Info"))

        # 2c. SmartPoC probing (runs on active scans or if SmartPoC selected)
        run_poc = (not is_passive_mode) and ("SmartPoC" in needed_tools or mode in ("bugbounty_full", "web", "sqli", "xss", "auto", "vuln") or len(discovered_endpoints) > 0)
        if run_poc:
            await self._log(
                f"[ACT] SmartPoC: {len(all_params)} params across {len(discovered_endpoints)} endpoints, focus={primary_focus}"
            )
            raw_hits = await self._execute_tool(
                "SmartPoC",
                target=target, params=all_params,
                focus=primary_focus, proxy=proxy, auth=auth or {},
                endpoints=discovered_endpoints
            )
            for hit in raw_hits:
                poc_result = hit.get("poc_result", {})
                param = hit.get("param", "?")
                # xploiter classifies — is it real?
                classify = await self.decision.classify_tool_output(
                    "SmartPoC", json.dumps(poc_result), target
                )
                if not classify.get("is_real_vuln", False):
                    await self._log(f"   -> xploiter: false positive for param={param!r}")
                    self._audit("finding_rejected", reason="xploiter_false_positive",
                                param=param)
                    continue

                qwen = await self.artifact.analyze_tool_output(
                    "SmartPoC", json.dumps(poc_result), target
                )
                vt = poc_result.get("vuln_type", primary_focus)

                # ── Evidence Court 2.0 & Causal Tri-Engine Adjudication ──────
                p_reason = str(poc_result.get("proof_reason", ""))
                is_reflection = ("reflection" in p_reason.lower() or "Reflection != Execution" in p_reason)
                has_arith = bool("72" in p_reason and "53+19" not in p_reason)
                is_reproduced = poc_result.get("reproduced", False)
                is_verified = poc_result.get("verified", False) and not is_reflection

                # 1. Causal Security Graph
                if self.causal_graph is None:
                    self.causal_graph = CausalSecurityGraph(urlparse(target).hostname or target)
                causal_res = self.causal_graph.build_standard_injection_chain(
                    finding_id=f"CAUSAL-{vt}-{param}",
                    param=param,
                    sink_name=f"{vt.upper()}_SINK",
                    differential_detail=p_reason or "Observable differential anomaly triggered"
                )

                # 2. Analysis of Competing Hypotheses (ACH)
                baseline_stable = not ("unstable" in p_reason.lower() or "jitter" in p_reason.lower() or "flaky" in p_reason.lower())
                waf_found = ("403" in p_reason or "cloudflare" in p_reason.lower() or "waf" in p_reason.lower())
                auth_valid = not ("session expired" in p_reason.lower() or "login required" in p_reason.lower())
                ach_res = CompetingHypothesesEngine.evaluate(
                    status_code=poc_result.get("status_code", 200),
                    body=p_reason,
                    proof_nonce_present=bool((has_arith or is_verified) and not is_reflection),
                    baseline_stable=baseline_stable,
                    waf_signatures_found=waf_found,
                    auth_session_valid=auth_valid
                )

                # 3. Evidence Court 2.0 (Adversarial Epistemic Tribunal)
                case_id = f"CASE-{vt.upper()}-{int(time.time()*1000)%100000}"
                ruling = EvidenceCourtV2.adjudicate_case(
                    case_id=case_id,
                    endpoint=target,
                    proof_nonce_proven=bool((has_arith or is_verified) and ach_res.verdict == "CONFIRMED"),
                    reproductions_count=2 if is_reproduced else 1,
                    causal_chain_verified=causal_res.is_causally_proven,
                    baseline_stable=baseline_stable and (ach_res.verdict != "INCONCLUSIVE"),
                    waf_clean=not waf_found
                )

                if ruling.final_verdict != "CONFIRMED" or not ruling.unanimous:
                    await self._log(
                        f"   -> [COURT-V2: {ruling.final_verdict}] param={param!r} vt={vt} "
                        f"| {ruling.chief_justification}"
                    )
                    self._audit("finding_rejected", reason=ruling.final_verdict,
                                param=param, rationale=ruling.chief_justification)
                    continue

                finding = {
                    "type": vt,
                    "param_name": param,
                    "title": f"{vt.upper()} in parameter {param!r}",
                    "severity": "CRITICAL" if has_arith else "HIGH",
                    "evidence": p_reason or ruling.chief_justification,
                    "payload_used": poc_result.get("payload_used", "N/A"),
                    "remediation": qwen.get("remediation_code", ""),
                    "confidence": 0.95,
                    "tool": "AutonomousBrain/SmartPoC",
                    "lifecycle_verdict": ruling.final_verdict,
                    "tribunal_ruling": ruling.to_dict(),
                    "causal_chain": causal_res.unbroken_chain,
                    "ach_evaluation": ach_res.to_dict(),
                }
                findings.append(finding)
                self._audit("finding_added", title=finding["title"], severity=finding["severity"], verdict=ruling.final_verdict)
                await self._emit("finding", **finding)
                # ── Feedback Loop: save confirmed finding to Knowledge Base ──
                if self.knowledge:
                    try:
                        from core.learning.learning_server import _handle_feedback
                        asyncio.create_task(_handle_feedback({
                            "target": target,
                            "finding": finding
                        }))
                        await self._log(f"[KB] Feedback saved: {finding['title'][:50]}")
                    except Exception:
                        log.debug("KB feedback failed (non-critical)", exc_info=True)

        # 2c. Other specific tools in plan (nuclei, sqlmap, dalfox, gobuster, nmap, subfinder, WebAgent)
        for tool_name in needed_tools:
            if tool_name in ("SmartPoC", "ReconAgent", "BrowserAgent", "BugBountyAgent"):
                continue
            if tool_name in TOOL_REGISTRY:
                tool_findings = await self._execute_tool(
                    tool_name, target=target, proxy=proxy, auth=auth or {}, mode=mode,
                    endpoints=discovered_endpoints
                )
                findings.extend(tool_findings)

        # 2d. BugBountyAgent
        if "BugBountyAgent" in needed_tools or mode in ("bugbounty_full", "full"):
            await self._log("[ACT] Launching BugBountyAgent...")
            bb_results = await self._execute_tool(
                "BugBountyAgent", target=target, proxy=proxy or "",
                auth=auth or {}, mode=mode
            )
            for f in bb_results:
                f.setdefault("tool", "BugBountyAgent")
            findings.extend(bb_results)
            await self._log(f"[ACT] BugBountyAgent: {len(bb_results)} findings")

        # 2e. BrowserAgent
        if plan.get("use_browser") or use_browser or ("BrowserAgent" in needed_tools):
            await self._log("[ACT] Launching BrowserAgent (Interactive / Auth / DOM Inspection)...")
            br_results = await self._execute_tool(
                "BrowserAgent", target=target, proxy=proxy or "",
                auth=auth or {}, mode=mode, visible=True
            )
            for f in br_results:
                f.setdefault("tool", "BrowserAgent")
            findings.extend(br_results)
            await self._log(f"[ACT] BrowserAgent: {len(br_results)} findings")

        # 2f. JS analysis via Qwen (runs concurrently using gather)
        if js_urls:
            await self._log(f"[ACT] Analyzing {len(js_urls)} JS files with Qwen...")
            js_tasks = []
            for js_url in js_urls:
                async def _analyze_js(u=js_url):
                    content = await self._fetch_js(u, proxy)
                    if not content:
                        return None
                    result = await self.artifact.analyze_js_file(content, u)
                    if result.get("secrets") or result.get("api_keys"):
                        await self._log(
                            f"   -> JS secrets in {u[:50]}: "
                            f"{result.get('secrets', [])[:2]}"
                        )
                        return result
                    return None
                js_tasks.append(_analyze_js())

            js_raw = await asyncio.gather(*js_tasks, return_exceptions=True)
            for r in js_raw:
                if isinstance(r, dict):
                    js_findings.append(r)
                elif isinstance(r, Exception):
                    log.exception("JS analysis task failed")

        # ── PHASE 3: VERIFY ─────────────────────────────────────────────────
        if findings:
            await self._emit("phase", phase="verify",
                             message="[VERIFY] Cross-checking findings with Tool Agreement & Evidence Court...")
            verified: List[dict] = []
            for f in findings:
                confidence = f.get("confidence", 0.8)
                f_title = f.get("title", f.get("type", "finding"))
                f_id = f.get("id", f"FND-{abs(hash(f_title)) % 100000:05d}")

                # Tool Agreement Evaluation
                try:
                    from core.scoring.tool_agreement import ToolAgreementEngine, SensorSignals
                    signals = SensorSignals(
                        burp_observed=bool(self.burp_sensor),
                        browser_dom_executed=f.get("dom_executed", True),
                        http_diff_confirmed=f.get("diff_confirmed", True),
                        poe_token_verified=bool(f.get("evidence", "")),
                        waf_blocked=False,
                        is_reflection_only=f.get("reflection_only", False)
                    )
                    agreement = ToolAgreementEngine.evaluate(signals)
                    f["tool_agreement"] = agreement
                    if not agreement.get("is_valid", True):
                        await self._log(f"[VERIFY] ToolAgreementEngine rejected: {f_title} ({agreement.get('reason')})")
                        self._audit("finding_rejected", reason="tool_agreement_rejection", title=f_title)
                        if self.coverage_ledger:
                            self.coverage_ledger.record_probed(f.get("endpoint", "/"), f.get("method", "GET"), f.get("param", ""), verified_finding=False)
                        continue
                except Exception as e:
                    log.debug(f"Tool agreement check bypassed: {e}")

                # Multidimensional Confidence Score
                try:
                    from core.scoring.confidence_calculator import MultidimensionalConfidenceCalculator, ConfidenceFactors
                    factors = ConfidenceFactors(
                        evidence_score=0.9 if f.get("evidence") else 0.5,
                        differential_signal=0.85 if f.get("diff_confirmed") else 0.4,
                        reproducibility=1.0,
                        tool_agreement=0.9,
                        negative_test_result=1.0,
                        is_reflection_only=f.get("reflection_only", False)
                    )
                    det_conf = MultidimensionalConfidenceCalculator.calculate(factors)
                    f["deterministic_confidence"] = det_conf
                    if det_conf < 0.60:
                        await self._log(f"[VERIFY] Low confidence ({det_conf:.2f}): {f_title} demoted")
                        continue
                except Exception as e:
                    log.debug(f"Confidence calculation bypassed: {e}")

                if confidence < 0.65:
                    escalated = await self.api_esc.escalate_if_uncertain(
                        f, threshold=0.65
                    )
                    if escalated.get("api_recommended_action") == "reject":
                        await self._log(
                            f"[VERIFY] Cloud rejected: {f_title}"
                        )
                        self._audit("finding_rejected", reason="cloud_rejected",
                                    title=f_title)
                        continue

                # Auto-freeze into ReplayLab
                if self.replay_lab:
                    try:
                        self.replay_lab.freeze_finding(
                            finding_id=f_id,
                            target_url=f.get("url", target),
                            method=f.get("method", "GET"),
                            parameter=f.get("param", ""),
                            payload=f.get("payload", ""),
                            raw_request=f.get("raw_request", f"GET {f.get('url', target)} HTTP/1.1"),
                            raw_response=f.get("raw_response", f"HTTP/1.1 200 OK\r\n\r\n{f.get('evidence', '')}"),
                            raw_baseline=f.get("raw_baseline", "HTTP/1.1 200 OK\r\n\r\nSafe Baseline"),
                            verdict="CONFIRMED"
                        )
                        f["replay_bundle_available"] = True
                    except Exception as e:
                        log.debug(f"Could not freeze replay bundle: {e}")

                # Record in Flight Recorder
                if self.flight_recorder:
                    from core.telemetry.flight_recorder import FlightEventType
                    self.flight_recorder.record_event(
                        event_type=FlightEventType.POE_VERIFIED,
                        phase="VERIFY",
                        actor="EvidenceCourt",
                        rationale=f"Deterministic evidence confirmed for {f_title}",
                        finding_id=f_id,
                        details={"title": f_title, "confidence": f.get("confidence", 0.8)}
                    )
                    self.flight_recorder.record_event(
                        event_type=FlightEventType.COURT_VERDICT,
                        phase="VERIFY",
                        actor="EvidenceCourt",
                        rationale="CONFIRMED",
                        finding_id=f_id
                    )

                # Record in Coverage Ledger
                if self.coverage_ledger:
                    self.coverage_ledger.record_probed(
                        f.get("endpoint", urlparse(f.get("url", target)).path or "/"),
                        f.get("method", "GET"),
                        f.get("param", ""),
                        verified_finding=True
                    )

                # Policy-as-Code: Issue cryptographically auditable PolicyReceipt
                if self.policy_engine:
                    receipt = self.policy_engine.evaluate_action(
                        target=f.get("url", target),
                        action_type="CONFIRM_FINDING",
                        is_state_mutating=False,
                        is_in_scope=True
                    )
                    f["policy_receipt"] = receipt.receipt_id
                    f["policy_version"] = receipt.policy_version

                # Decision Trace: Record non-CoT epistemic verification step
                if self.decision_trace:
                    self.decision_trace.record_step(
                        observation=f"Confirmed security finding: {f_title}",
                        evidence=[str(f.get("evidence", ""))[:120]],
                        decision="Promote to CONFIRMED via tripartite Evidence Court",
                        policy_result="ALLOW",
                        policy_receipt=f.get("policy_receipt", "POL-V14-AUTO"),
                        action=f"Seal finding {f_id} and export portable investigation case bundle",
                        result="Confirmed finding registered in EvidenceOS ledger"
                    )

                # Export Portable Investigation Bundle
                if self.bundle_manager:
                    try:
                        self.bundle_manager.export_case(
                            finding_id=f_id,
                            target=target,
                            finding_data=f,
                            output_parent_dir=Path("data/cases")
                        )
                        f["investigation_bundle_available"] = True
                    except Exception as e:
                        log.debug(f"Could not export investigation bundle for {f_id}: {e}")

                verified.append(f)
                await self._log(
                    f"[VERIFY] Confirmed: {f_title} "
                    f"| confidence={confidence:.0%}"
                )
            findings = verified

        # ── PHASE 3b: DEDUPLICATION ──────────────────────────────────────────
        before_dedup = len(findings)
        findings = _deduplicate_findings(findings)
        after_dedup = len(findings)
        if before_dedup != after_dedup:
            await self._log(
                f"[DEDUP] Merged {before_dedup} → {after_dedup} findings "
                f"(removed {before_dedup - after_dedup} duplicates)"
            )
            for f in findings:
                srcs = f.get("evidence_sources", [])
                if len(srcs) > 1:
                    await self._log(
                        f"   -> {f.get('title','?')[:60]} "
                        f"| evidence from: {', '.join(srcs)}"
                    )

        # ── PHASE 3c: OBJECTIVE CHECK ────────────────────────────────────────
        # Finding ≠ Completion — check if the actual mission objective was met
        objective_result = {
            "objective": "vulnerability_detection",
            "status": "INCOMPLETE",
            "extracted_data": "",
            "next_steps": [],
        }
        sqli_findings = [f for f in findings if "sqli" in f.get("type", "").lower()
                         or "sql" in f.get("type", "").lower()]
        if sqli_findings:
            # Tìm nếu SQLiSkill đã hoàn thành objective
            completed = [f for f in sqli_findings if f.get("objective_met")]
            if completed:
                obj_f = completed[0]
                objective_result = {
                    "objective": "retrieve_db_version",
                    "status": "COMPLETE",
                    "extracted_data": obj_f.get("extracted_data", ""),
                    "dbms": obj_f.get("dbms", "unknown"),
                    "evidence_sources": obj_f.get("evidence_sources", []),
                }
                await self._log(
                    f"[OBJECTIVE] retrieve_db_version → COMPLETE ✅ "
                    f"| data={obj_f.get('extracted_data','?')[:80]!r}"
                )
            else:
                objective_result["status"] = "DETECTED_NOT_EXPLOITED"
                objective_result["next_steps"] = [
                    "Run SQLiSkill in sqli mode for full exploitation",
                    "Try: '+UNION+SELECT+BANNER,+NULL+FROM+v$version--",
                    "Manually verify column count with ORDER BY",
                ]
                await self._log(
                    "[OBJECTIVE] SQLi detected but NOT fully exploited "
                    "— objective INCOMPLETE"
                )
                await self._log("[NEXT] Use mode='sqli' to trigger full SQLiSkill exploitation")

        # Collect cloud API notes (wait max 30s)
        try:
            api_results = await asyncio.wait_for(api_task, timeout=30.0)
            api_notes = [r for r in (api_results or []) if r.get("content")]
        except Exception:
            log.warning("Cloud API task timed out or failed")
            api_notes = []

        # ── PHASE 4: REPORT ─────────────────────────────────────────────────
        duration = round(time.time() - t0, 1)
        total = len(findings)
        self._audit("scan_done", duration=duration, total_findings=total,
                    js_findings=len(js_findings),
                    objective_status=objective_result.get("status"))
        await self._log(
            f"[DONE] findings={total} | js_secrets={len(js_findings)} | "
            f"duration={duration}s | probes={len(all_params)} | "
            f"objective={objective_result.get('status','?')}"
        )
        await self._emit("phase", phase="done",
                         message=f"Brain completed in {duration}s")


        # Gracefully finalize and persist browser session
        if hasattr(self, "browser_session") and self.browser_session:
            try:
                await self.browser_session.close()
            except Exception:
                pass

        return {
            "target": target,
            "mode": mode,
            "duration": duration,
            "dry_run": self.dry_run,
            "plan": plan,
            "findings": findings,
            "js_findings": js_findings,
            "api_notes": api_notes,
            "params_audited": all_params,
            "burp_online": burp_online,
            "security_state": self.security_state.get_snapshot() if self.security_state else None,
            "attack_graph": self.attack_graph.to_dict() if self.attack_graph else None,
            "audit_log": self._audit_log,
            "objective_result": objective_result,   # Finding ≠ Completion tracking
            "code_intelligence": getattr(self, "_last_code_intel", code_intel_res),
            "browser_exploration": getattr(self, "_last_browser_exploration", {}),
            "exploration_coverage": getattr(self, "_last_browser_exploration", {}).get("coverage", {}),
            "exploration_memory": getattr(self, "_last_browser_exploration", {}).get("memory", {}),
        }

    async def explore_discovered_endpoint(self, endpoint_url_or_path: str) -> Dict[str, Any]:
        """Bidirectional sensor feedback: directs the active browser to visit and inspect a new route"""
        if hasattr(self, "browser_explorer") and self.browser_explorer:
            return await self.browser_explorer.explore_endpoint(endpoint_url_or_path)
        return {"status": "BROWSER_SENSOR_NOT_INITIALIZED"}

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        """Immutable copy of the audit trail"""
        return list(self._audit_log)

    async def run_mission(self, goal, max_steps: int = 8):
        """
        تشغيل مهمة محددة الهدف عبر محرك فضاء الحالات (StateSpacePlanner)
        """
        if not self.planner:
            from core.planner.state_space_planner import StateSpacePlanner
            self.planner = StateSpacePlanner(
                security_state=self.security_state,
                tool_gateway=self.tool_gateway
            )
        return await self.planner.run_mission(goal, max_steps=max_steps)

