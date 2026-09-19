"""
HunterAI Investigation Controller — Autonomous OODA Loop
Replaces linear skill execution with a prioritized, multi-iteration hypothesis testing loop.

Architecture:
    RECON / Attack Surface Graph
                 ↓
      HypothesisPriorityQueue
                 ↓
      while budget_remaining:
          hyp = queue.pop()
          strategy = AI.strategize(hyp)          # WhiteRabbitNeo / Ollama
          result   = skill.execute(hyp)          # SQLi / XSS / IDOR / LFI / SSRF / SSTI / CmdInjection
          verdict  = observe(result)
          if verdict == INSUFFICIENT:
              followups = generate_followup(hyp)
              queue.push_all(followups)
          elif verdict == CONFIRMED:
              evidence_court.promote(hyp, result) # Evidence Court & Gate
          trace.record(all_events)
                 ↓
      InvestigationSummary -> printed to terminal + saved in artifacts
"""
from __future__ import annotations

import asyncio
import heapq
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from hunter_ai.pipeline.parameter_intelligence import ParameterRole, inject_url_parameter

logger = logging.getLogger("hunter_ai.investigation_controller")


# ---------------------------------------------------------------------------
# Hypothesis Dataclass with Full Provenance
# ---------------------------------------------------------------------------
@dataclass
class Hypothesis:
    id: str
    vuln_type: str
    target_url: str
    param: str
    rationale: str
    priority: float
    source: str
    parent_id: Optional[str] = None
    followup_depth: int = 0
    status: str = "QUEUED"
    test_count: int = 0
    created_at: float = field(default_factory=time.time)
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other: "Hypothesis") -> bool:
        return self.priority > other.priority  # higher priority pops first


# ---------------------------------------------------------------------------
# InvestigationTrace (Terminal & Artifact Logger)
# ---------------------------------------------------------------------------
class InvestigationTrace:
    def __init__(self, emit_cb: Optional[Callable] = None):
        self._emit = emit_cb
        self._obs_n = 0
        self._hyp_n = 0
        self._test_n = 0
        self._ai_n = 0
        self._conf_n = 0
        self._rej_n = 0
        self._fu_n = 0
        self._lines: List[str] = []

    def _log(self, line: str) -> None:
        logger.info(line)
        self._lines.append(line)
        if self._emit:
            try:
                res = self._emit("investigation_trace", message=line)
                if asyncio.iscoroutine(res):
                    asyncio.ensure_future(res)
            except Exception:
                pass

    def observation(self, msg: str) -> str:
        self._obs_n += 1
        oid = f"O-{self._obs_n:03d}"
        self._log(f"[AGENT] Observation {oid}: {msg}")
        return oid

    def hypothesis_created(self, hyp: Hypothesis) -> None:
        self._hyp_n += 1
        self._log(
            f"[AGENT] Hypothesis {hyp.id} created -- {hyp.vuln_type} on "
            f"{hyp.target_url}?{hyp.param}  priority={hyp.priority:.2f}  source={hyp.source}"
        )
        if hyp.rationale:
            self._log(f"[AGENT]   Reason: {hyp.rationale}")

    def test_start(self, hyp_id: str, n: int, tool: str, url: str) -> None:
        self._test_n += 1
        self._log(f"[AGENT] {hyp_id} Test #{n}: {tool} -> {url}")

    def result(self, hyp_id: str, verdict: str, detail: str = "") -> None:
        self._log(f"[AGENT] {hyp_id} Result: {verdict}" + (f" -- {detail}" if detail else ""))

    def followup(self, parent_id: str, new_id: str, vuln_type: str, reason: str) -> None:
        self._fu_n += 1
        self._log(
            f"[AGENT] Evidence insufficient -> spawning follow-up {new_id} "
            f"(from {parent_id}, {vuln_type}, reason: {reason})"
        )

    def confirmed(self, hyp_id: str, detail: str) -> None:
        self._conf_n += 1
        self._log(f"[AGENT] [CONFIRMED] {hyp_id} -> Evidence Court: {detail}")

    def rejected(self, hyp_id: str, reason: str) -> None:
        self._rej_n += 1
        self._log(f"[AGENT] [REJECTED] {hyp_id} -- {reason}")

    def ai_call(self, model: str, task: str) -> None:
        self._ai_n += 1
        self._log(f"[AGENT] AI {model}: {task}")

    def browser_recovery(self, reason: str, action: str) -> None:
        self._log(f"[AGENT] [BROWSER RECOVERY] {reason} -> {action}")

    def budget_exhausted(self, elapsed: float, cap: float) -> None:
        self._log(f"[AGENT] Investigation budget exhausted ({elapsed:.0f}s / {cap:.0f}s cap)")

    def summary(self) -> str:
        sep = "=" * 60
        return (
            f"\n{sep}\n         INVESTIGATION SUMMARY\n{sep}\n"
            f"  Observations  :  {self._obs_n}\n"
            f"  Hypotheses    :  {self._hyp_n}\n"
            f"  Tests executed:  {self._test_n}\n"
            f"  Follow-ups    :  {self._fu_n}\n"
            f"  AI calls      :  {self._ai_n}\n"
            f"  Confirmed     :  {self._conf_n}\n"
            f"  Rejected      :  {self._rej_n}\n"
            f"{sep}\n"
        )

    @property
    def observation_count(self) -> int: return self._obs_n
    @property
    def hypothesis_count(self) -> int: return self._hyp_n
    @property
    def test_count(self) -> int: return self._test_n
    @property
    def ai_call_count(self) -> int: return self._ai_n
    @property
    def confirmed_count(self) -> int: return self._conf_n
    @property
    def rejected_count(self) -> int: return self._rej_n


# ---------------------------------------------------------------------------
# Priority Queue
# ---------------------------------------------------------------------------
class HypothesisPriorityQueue:
    def __init__(self) -> None:
        self._heap: List[Hypothesis] = []
        self._seen: set = set()

    def push(self, hyp: Hypothesis) -> bool:
        key = f"{hyp.vuln_type}::{hyp.target_url}::{hyp.param}"
        if key in self._seen:
            return False
        self._seen.add(key)
        heapq.heappush(self._heap, hyp)
        return True

    def pop(self) -> Optional[Hypothesis]:
        return heapq.heappop(self._heap) if self._heap else None

    def __len__(self) -> int:
        return len(self._heap)


# ---------------------------------------------------------------------------
# Investigation Summary
# ---------------------------------------------------------------------------
@dataclass
class InvestigationSummary:
    duration_sec: float
    observations: int
    hypotheses_seeded: int
    hypotheses_total: int
    tests_executed: int
    followups_spawned: int
    ai_calls: int
    confirmed: int
    rejected: int
    confirmed_findings: List[Any] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Vulnerability Mappings & Defaults
# ---------------------------------------------------------------------------
_VULN_PRIORITY = {
    "SQLi": 0.98,
    "CmdInjection": 0.96,
    "SSTI": 0.94,
    "TemplateInjection": 0.94,
    "LFI": 0.92,
    "PathTraversal": 0.90,
    "FileInclusion": 0.90,
    "SSRF": 0.88,
    "OpenRedirect": 0.72,
    "IDOR": 0.87,
    "BOLA": 0.87,
    "BFLA": 0.80,
    "XSS": 0.82,
    "Reflected_XSS": 0.80,
    "GeneralFuzz": 0.50,
}

_VULN_SKILL_MAP = {
    "SQLi": ["sqli_skill"],
    "CmdInjection": ["cmd_injection_skill"],
    "SSTI": ["ssti_skill"],
    "TemplateInjection": ["ssti_skill"],
    "LFI": ["lfi_skill"],
    "PathTraversal": ["lfi_skill"],
    "FileInclusion": ["lfi_skill"],
    "SSRF": ["ssrf_skill"],
    "OpenRedirect": ["ssrf_skill"],
    "IDOR": ["idor_skill"],
    "BOLA": ["idor_skill"],
    "BFLA": ["idor_skill"],
    "XSS": ["xss_skill"],
    "Reflected_XSS": ["xss_skill"],
}

_CVSS_DEFAULTS = {
    "SQLi": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"),
    "CmdInjection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Critical"),
    "SSTI": (9.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical"),
    "TemplateInjection": (9.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Critical"),
    "LFI": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Critical"),
    "PathTraversal": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Critical"),
    "SSRF": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "High"),
    "IDOR": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "High"),
    "BOLA": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "High"),
    "XSS": (7.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "High"),
}

_REMEDIATIONS = {
    "SQLi": "Use parameterized queries. Never interpolate user input into SQL strings.",
    "CmdInjection": "Use subprocess with execve arg arrays. Never pass user input to shell.",
    "SSTI": "Never render user input in template strings. Use sandboxed environments.",
    "LFI": "Use allowlist for file paths. Strip traversal sequences. Apply os.path.basename().",
    "SSRF": "Allowlist permitted outbound URLs. Block RFC1918 at network egress.",
    "IDOR": "Implement server-side ownership checks. Never trust client-supplied IDs alone.",
    "XSS": "Use context-aware output encoding. Implement strict Content-Security-Policy.",
}


# ---------------------------------------------------------------------------
# InvestigationController
# ---------------------------------------------------------------------------
class InvestigationController:
    """
    Autonomous OODA investigation loop.
    Controls the lifecycle:
    Hypothesis Selection -> AI Strategizing -> Targeted Testing -> Evidence Observation -> Follow-up / Confirmation.
    """
    MAX_HYPOTHESES = 300
    MAX_FOLLOWUP_DEPTH = 2
    MAX_TESTS_PER_HYP = 2
    BUDGET_CAP_SEC = 1800.0

    def __init__(self, orchestrator: Any) -> None:
        self.orc = orchestrator
        self.trace = InvestigationTrace(emit_cb=orchestrator._emit)
        self.queue = HypothesisPriorityQueue()
        self._hyp_serial = 0
        self._confirmed_findings: List[Any] = []
        self._start_time = 0.0

    def _next_id(self) -> str:
        self._hyp_serial += 1
        return f"H-{self._hyp_serial:03d}"

    def _elapsed(self) -> float:
        return time.time() - self._start_time

    def _budget_ok(self, cap: float) -> bool:
        return self._elapsed() < cap

    async def _emit(self, event: str, **kw) -> None:
        try:
            res = self.orc._emit(event, **kw)
            if asyncio.iscoroutine(res):
                await res
        except Exception:
            pass

    # -- Seeding Hypotheses --
    _STATIC_EXTS = {
        ".webp", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".tiff",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".css", ".map", ".js"
    }
    _MEDIA_PARAMS = {"q", "w", "h", "f", "fit", "quality", "width", "height", "format", "v", "ver", "version"}

    def _seed_from_parameters(self) -> int:
        seeded = 0
        from urllib.parse import urlparse as _up
        for p in self.orc.parameters:
            ctx = getattr(p, "context", None) or {}
            is_active = ctx.get("is_active_candidate", True)
            role = ctx.get("role", "GENERIC_INPUT")

            # Gating check: Skip non-active candidates (media transformation, tracking noise)
            if not is_active or role in (ParameterRole.IMAGE_TRANSFORMATION.value, ParameterRole.TRACKING_METRIC.value):
                self.trace.observation(
                    f"Parameter '{p.parameter}' classified as {role} (noise) -- gated from active testing"
                )
                continue

            # Filter out non-injectable media parameters on static asset paths as defense in depth
            parsed_path = _up(p.endpoint).path.lower()
            if any(parsed_path.endswith(ext) for ext in self._STATIC_EXTS) and p.parameter.lower() in self._MEDIA_PARAMS:
                continue

            for vtype in (p.potential_classes or []):
                if vtype not in _VULN_SKILL_MAP:
                    continue
                hyp = Hypothesis(
                    id=self._next_id(),
                    vuln_type=vtype,
                    target_url=p.endpoint,
                    param=p.parameter,
                    rationale=f"Parameter '{p.parameter}' ({role}) mapped to {vtype} candidate",
                    priority=_VULN_PRIORITY.get(vtype, 0.50),
                    source="Seed",
                    provenance={
                        "source": p.source,
                        "method": p.method,
                        "sample_value": p.sample_value,
                        "role": role,
                        "family_pattern": ctx.get("family_pattern", ""),
                        "first_seen": datetime.utcnow().isoformat() + "Z",
                    },
                )
                if self.queue.push(hyp):
                    self.trace.observation(
                        f"Parameter '{p.parameter}' -> {vtype} candidate (source={p.source}, role={role}, endpoint={p.endpoint})"
                    )
                    self.trace.hypothesis_created(hyp)
                    seeded += 1
                    if seeded >= self.MAX_HYPOTHESES:
                        return seeded
        return seeded

    def _seed_from_decision_core(self) -> int:
        seeded = 0
        try:
            ep_urls = [e.url for e in self.orc.endpoints[:60]]
            params = [p.parameter for p in self.orc.parameters[:60]]
            techs: List[str] = []
            for la in self.orc.live_assets:
                techs.extend(la.technologies)
            recs = self.orc.decision_core.evaluate_signals(
                target_host=self.orc.domain,
                endpoints=ep_urls,
                parameters=params,
                technologies=list(set(techs)),
                raw_observations=[f"profile={self.orc.profile}"],
            )
            self.trace.observation(f"DecisionCore generated {len(recs)} track recommendations")
            _tv = {
                "wordpress": "SQLi",
                "graphql": "SQLi",
                "openapi_swagger": "IDOR",
                "file_upload": "LFI",
                "jwt_auth": "IDOR",
                "redirect_ssrf": "SSRF",
                "idor_access_control": "IDOR",
                "standard_recon": "XSS",
            }
            for rec in recs:
                vtype = _tv.get(rec.track.value, "XSS")
                pname = rec.trigger_signal.split("'")[1] if "'" in rec.trigger_signal else "general"
                hyp = Hypothesis(
                    id=self._next_id(),
                    vuln_type=vtype,
                    target_url=rec.target_url,
                    param=pname,
                    rationale=rec.suggested_hypothesis,
                    priority=min(0.99, rec.confidence_in_signal + 0.05),
                    source="DecisionCore",
                    provenance={"track": rec.track.value, "test_plan": rec.test_plan},
                )
                if self.queue.push(hyp):
                    self.trace.hypothesis_created(hyp)
                    seeded += 1
        except Exception as e:
            logger.debug(f"[InvestigationController] DecisionCore seed error: {e}")
        return seeded

    # -- Browser Sensor Recovery --
    async def _browser_recovery(self) -> None:
        if len(self.orc.endpoints) > 0:
            return
        self.trace.browser_recovery("Playwright captured 0 endpoints", "Probing base URL with httpx to diagnose")
        try:
            import httpx
            from urllib.parse import urlparse as _up
            from hunter_ai.pipeline.schemas import EndpointRecord

            async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
                resp = await client.head(self.orc.base_url)
                s = resp.status_code
                if s in (301, 302, 307, 308):
                    loc = resp.headers.get("location", "")
                    self.trace.browser_recovery(f"HTTP {s} redirect -> {loc}", "Adding redirect target as endpoint")
                    _p = _up(loc)
                    self.orc.endpoints.append(
                        EndpointRecord(
                            url=loc or self.orc.base_url,
                            path=_p.path or "/",
                            method="GET",
                            source="browser_recovery_redirect",
                        )
                    )
                elif s == 200:
                    self.trace.browser_recovery(
                        "HTTP 200 OK but 0 endpoints captured (SPA suspected)",
                        "Retrying Playwright with wait_until=load",
                    )
                    try:
                        from core.browser.playwright_controller import PlaywrightBrowserController
                        import pathlib

                        bc = PlaywrightBrowserController(
                            output_dir=str(pathlib.Path(self.orc.artifact_root) / "15_browser"),
                            proxy=self.orc.proxy,
                        )
                        browser_target = getattr(self.orc, "browser_type", "firefox")
                        if await bc.launch(browser_type=browser_target):
                            ok, _ = await bc.goto(self.orc.base_url, wait_until="load", timeout=30_000)
                            if ok:
                                links_raw = await bc.evaluate_js(
                                    "[...document.querySelectorAll('a[href]')].map(a=>a.href)"
                                )
                                for lnk in (links_raw or [])[:80]:
                                    if isinstance(lnk, str) and self.orc.domain in lnk:
                                        _pp = _up(lnk)
                                        self.orc.endpoints.append(
                                            EndpointRecord(
                                                url=lnk,
                                                path=_pp.path or "/",
                                                method="GET",
                                                source="browser_recovery_retry",
                                            )
                                        )
                                self.trace.browser_recovery(
                                    f"Playwright retry: {len(links_raw or [])} links captured",
                                    "Injected into endpoint list",
                                )
                            await bc.close()
                    except Exception as e2:
                        logger.debug(f"[BrowserRecovery] Playwright retry failed: {e2}")
                else:
                    self.trace.browser_recovery(f"HTTP {s}", "Continuing with available data")
        except Exception as e:
            logger.debug(f"[InvestigationController] Browser recovery failed: {e}")

    # -- AI Strategy Formulation --
    async def _ai_strategize(self, hyp: Hypothesis) -> Optional[str]:
        try:
            from hunter_ai.brain.local_triad_agent import LocalTriadAgent

            self.trace.ai_call("WhiteRabbitNeo", f"Formulating {hyp.vuln_type} strategy for param '{hyp.param}'")
            result = await asyncio.wait_for(
                LocalTriadAgent().formulate_offensive_strategy(
                    target_url=hyp.target_url,
                    param_name=hyp.param,
                    vuln_type=hyp.vuln_type,
                    context=hyp.rationale,
                ),
                timeout=30.0,
            )
            return result.get("analysis", "")
        except Exception as e:
            logger.debug(f"[AI] Strategy skipped: {e}")
            return None

    # -- Skill Execution --
    async def _execute_skill(self, hyp: Hypothesis, ai_context: Optional[str] = None) -> Tuple[bool, Any]:
        vtype = hyp.vuln_type
        proxy = self.orc.proxy
        timeout = self.orc.timeout_multiplier * 12.0
        url = hyp.target_url
        param = hyp.param
        hyp.test_count += 1
        hyp.status = "TESTING"
        skill_name = (_VULN_SKILL_MAP.get(vtype) or ["unknown"])[0]
        self.trace.test_start(hyp.id, hyp.test_count, skill_name, url)

        try:
            if vtype in ("XSS", "Reflected_XSS"):
                from agents.skills.xss_skill import XSSSkill

                res = await XSSSkill(proxy=proxy, timeout=timeout).run(url, param)
                return bool(res.get("objective_met") or res.get("state") == "COMPLETE"), res

            elif vtype in ("IDOR", "BOLA", "BFLA"):
                from agents.skills.idor_skill import IDORSkill

                res = await IDORSkill(proxy=proxy, timeout=timeout).run(url, param)
                return res.verified, res

            elif vtype in ("LFI", "PathTraversal", "FileInclusion"):
                from agents.skills.lfi_skill import LFISkill

                res = await LFISkill(proxy=proxy, timeout=timeout).run(url, param)
                return res.verified, res

            elif vtype in ("SSRF", "OpenRedirect"):
                from agents.skills.ssrf_skill import SSRFSkill

                res = await SSRFSkill(proxy=proxy, timeout=timeout).run(url, param)
                return res.verified, res

            elif vtype in ("SSTI", "TemplateInjection"):
                from agents.skills.ssti_skill import SSTISkill

                res = await SSTISkill(proxy=proxy, timeout=timeout).run(url, param)
                return res.verified, res

            elif vtype == "SQLi":
                from agents.skills.sqli_skill import run_sqli_skill

                res = await run_sqli_skill(url, param, proxy=proxy)
                return bool(res.get("objective_met") or res.get("extracted_data")), res

            elif vtype == "CmdInjection":
                from agents.skills.cmd_injection_skill import CmdInjectionSkill

                res = await CmdInjectionSkill(proxy=proxy, timeout=timeout).run(url, param)
                return res.get("objective_met", False), res

            else:
                return False, None
        except Exception as e:
            logger.debug(f"[InvestigationController] Skill error ({vtype}): {e}")
            return False, None

    # -- Dynamic Follow-up Generation --
    def _generate_followup(self, hyp: Hypothesis, reason: str) -> List[Hypothesis]:
        if hyp.followup_depth >= self.MAX_FOLLOWUP_DEPTH:
            return []
        _fm = {
            "XSS": "SSTI",
            "Reflected_XSS": "SSTI",
            "SSTI": "CmdInjection",
            "TemplateInjection": "CmdInjection",
            "IDOR": "BOLA",
            "LFI": "SSRF",
            "SSRF": "OpenRedirect",
            "PathTraversal": "LFI",
        }
        nt = _fm.get(hyp.vuln_type)
        if not nt or nt not in _VULN_SKILL_MAP:
            return []
        new_id = self._next_id()
        fu = Hypothesis(
            id=new_id,
            vuln_type=nt,
            target_url=hyp.target_url,
            param=hyp.param,
            rationale=f"Follow-up from {hyp.id}: {reason}",
            priority=hyp.priority * 0.90,
            source="Followup",
            parent_id=hyp.id,
            followup_depth=hyp.followup_depth + 1,
            provenance=hyp.provenance.copy(),
        )
        self.trace.followup(hyp.id, new_id, nt, reason)
        self.trace.hypothesis_created(fu)
        return [fu]

    # -- Evidence Court Promotion --
    async def _promote_to_evidence_court(self, hyp: Hypothesis, raw_result: Any) -> Optional[Any]:
        try:
            import hashlib
            from datetime import datetime as _dt
            from hunter_ai.pipeline.schemas import (
                HunterFinding,
                FindingStatus,
                FindingTier,
                VerificationEvidence,
                ReproductionArtifact,
            )

            if hasattr(raw_result, "verified"):
                payload = getattr(raw_result, "payload_used", "")
                ev_str = str(getattr(raw_result, "evidence", ""))[:300]
                conf = getattr(raw_result, "confidence", 0.90)
                cwe = getattr(raw_result, "cwe", "CWE-20")
                owasp = getattr(raw_result, "owasp_top10", "A03:2021")
            elif isinstance(raw_result, dict):
                payload = raw_result.get("vulnerable_payload") or raw_result.get("payload_used", "")
                ev_str = str(raw_result.get("evidence_snippet") or raw_result.get("extracted_data", ""))[:300]
                conf = raw_result.get("confidence", 0.90)
                cwe = raw_result.get("cwe", "CWE-20")
                owasp = raw_result.get("owasp_top10", "A03:2021")
            else:
                payload = ev_str = ""
                conf = 0.85
                cwe = "CWE-20"
                owasp = "A03:2021"

            clean_test_url = inject_url_parameter(hyp.target_url, hyp.param, str(payload))
            req_h = hashlib.sha256(f"GET {clean_test_url}".encode("utf-8", "ignore")).hexdigest()
            resp_h = hashlib.sha256(ev_str.encode("utf-8", "ignore")).hexdigest()
            cvss_score, cvss_vector, severity = _CVSS_DEFAULTS.get(
                hyp.vuln_type, (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Medium")
            )
            remediation = _REMEDIATIONS.get(hyp.vuln_type, "Validate and sanitize all user input.")
            skill_name = (_VULN_SKILL_MAP.get(hyp.vuln_type) or ["HunterAI"])[0]

            finding = HunterFinding(
                finding=f"{hyp.vuln_type} Confirmed on '{hyp.param}' [Investigation Loop {hyp.id}]",
                asset=self.orc.domain,
                endpoint=hyp.target_url,
                parameter=hyp.param,
                vuln_type=hyp.vuln_type,
                status=FindingStatus.CONFIRMED,
                tier=FindingTier.VERIFIED_FINDING,
                severity=severity,
                confidence=conf,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe=cwe,
                owasp_top10=owasp,
                request_hash=req_h,
                response_hash=resp_h,
                reproducible=True,
                execution_timestamp_utc=_dt.utcnow().isoformat() + "Z",
                evidence=[
                    VerificationEvidence(
                        type="skill_confirmed",
                        description=f"{skill_name} confirmed {hyp.vuln_type} (OODA depth={hyp.followup_depth})",
                        proof_snippet=ev_str,
                        verified=True,
                        request_hash=req_h,
                        response_hash=resp_h,
                    )
                ],
                reproduction=ReproductionArtifact(
                    curl_command=f"curl -s '{clean_test_url}'",
                    payload_used=payload,
                ),
                false_positive_checks={"investigation_loop": True, "skill_confirmed": True},
                remediation=remediation,
                tool=skill_name,
            )
            self.orc.findings.append(finding)
            self._confirmed_findings.append(finding)
            self.trace.confirmed(hyp.id, f"{hyp.vuln_type} on {hyp.target_url}?{hyp.param}")
            try:
                self.orc.engagement_mgr.record_lineage(
                    asset_id=f"vuln:{hyp.vuln_type}:{hyp.param}:{hyp.id}",
                    asset_value=f"{hyp.vuln_type} on {hyp.param} (InvestigationLoop)",
                    asset_type="vulnerability",
                    tool=skill_name,
                    stage="12_vulnerabilities",
                    parent_id=f"{hyp.target_url}?{hyp.param}",
                )
            except Exception:
                pass
            return finding
        except Exception as e:
            logger.warning(f"[InvestigationController] Evidence court error: {e}")
            return None

    # -- Main Execution Loop --
    async def run(self, budget_seconds: float = 1800.0) -> InvestigationSummary:
        """Main entry point. Runs OODA loop until budget exhausted or queue empty."""
        cap = min(float(budget_seconds), self.BUDGET_CAP_SEC)
        self._start_time = time.time()
        await self._emit(
            "investigation_start",
            message=f"Investigation Controller starting -- budget={cap:.0f}s profile={self.orc.profile}",
        )
        logger.info(f"[InvestigationController] Starting -- budget cap={cap:.0f}s")

        # Phase 0: Browser Recovery
        await self._browser_recovery()

        # Phase 1: Seed Hypothesis Queue
        seeded_params = self._seed_from_parameters()
        seeded_dc = self._seed_from_decision_core() if self.orc.profile in ("full", "hunter", "deep") else 0
        total_seeded = seeded_params + seeded_dc
        await self._emit(
            "investigation_seeded",
            count=total_seeded,
            queue_size=len(self.queue),
            message=f"Hypothesis queue: {total_seeded} hypotheses ({seeded_params} from params, {seeded_dc} from DecisionCore)",
        )
        logger.info(f"[InvestigationController] Queue seeded: {total_seeded} hypotheses")

        # Phase 2: Main Autonomous OODA Loop
        while len(self.queue) > 0 and self._budget_ok(cap):
            hyp = self.queue.pop()
            if hyp is None:
                break
            if hyp.test_count >= self.MAX_TESTS_PER_HYP:
                self.trace.rejected(hyp.id, "Max test attempts reached")
                continue

            self.trace.observation(
                f"Testing {hyp.vuln_type} on {hyp.target_url}?{hyp.param} "
                f"[priority={hyp.priority:.2f}, depth={hyp.followup_depth}]"
            )

            # THINK: AI Strategy formulation for top hypotheses
            ai_ctx = None
            if hyp.priority >= 0.85 and hyp.test_count == 0 and self.orc.profile in ("full", "hunter", "deep"):
                ai_ctx = await self._ai_strategize(hyp)

            # ACT: Skill Execution
            confirmed, raw_result = await self._execute_skill(hyp, ai_context=ai_ctx)

            # DECIDE & OBSERVE
            if confirmed:
                self.trace.result(hyp.id, "CONFIRMED", f"skill verified {hyp.vuln_type}")
                hyp.status = "CONFIRMED"
                await self._promote_to_evidence_court(hyp, raw_result)
            else:
                self.trace.result(hyp.id, "inconclusive", "proof threshold not met")
                if hyp.test_count < self.MAX_TESTS_PER_HYP:
                    hyp.priority *= 0.80
                    self.queue.push(hyp)
                else:
                    hyp.status = "REJECTED"
                    self.trace.rejected(hyp.id, f"max tests ({hyp.test_count}), evidence insufficient")
                    for fu in self._generate_followup(
                        hyp, f"{hyp.vuln_type} inconclusive after {hyp.test_count} tests"
                    ):
                        self.queue.push(fu)

            await asyncio.sleep(0)  # yield control to event loop

        if not self._budget_ok(cap):
            self.trace.budget_exhausted(self._elapsed(), cap)

        # Phase 3: Investigation Summary & Artifact Persistence
        summary_text = self.trace.summary()
        logger.info(summary_text)
        summary = InvestigationSummary(
            duration_sec=round(self._elapsed(), 2),
            observations=self.trace.observation_count,
            hypotheses_seeded=total_seeded,
            hypotheses_total=self._hyp_serial,
            tests_executed=self.trace.test_count,
            followups_spawned=self.trace._fu_n,
            ai_calls=self.trace.ai_call_count,
            confirmed=self.trace.confirmed_count,
            rejected=self.trace.rejected_count,
            confirmed_findings=self._confirmed_findings,
        )

        try:
            self.orc._save_stage_artifact(
                "12_vulnerabilities",
                "investigation_trace.json",
                {
                    "summary": {k: v for k, v in summary.__dict__.items() if k != "confirmed_findings"},
                    "trace_lines": self.trace._lines,
                },
            )
        except Exception as e:
            logger.debug(f"[InvestigationController] Failed to save trace: {e}")

        await self._emit(
            "investigation_done",
            confirmed=summary.confirmed,
            rejected=summary.rejected,
            tests=summary.tests_executed,
            ai_calls=summary.ai_calls,
            duration=summary.duration_sec,
            message=summary_text,
        )
        return summary
