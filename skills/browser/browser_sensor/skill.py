"""
Browser Sensor Skill
====================
Headless-browser application sensor built on top of the HunterAI 3-sensor
Browser-Brain Loop (core/browser):

  OBSERVE (StatefulBrowserSession + DOM/Network capture)
  -> ORIENT (StateDetector + DOMDiff + CoverageEngine)
  -> DECIDE (InteractionPlanner information-gain ranking)
  -> ACT (HumanLikeExplorationEngine clicks/interactions)
  -> VERIFY (re-observe diff & coverage)

Produces:
  - browser/sensor/sensor_report.json        — full SensorObservationReport
  - browser/sensor/coverage_metrics.json     — 7-dimension coverage metrics
  - browser/sensor/discovered_urls.txt       — every URL observed
  - browser/sensor/api_endpoints.txt         — XHR/Fetch/API endpoints intercepted
  - browser/sensor/screenshots/<n>.png       — final-page screenshot

Contract: skills.base_skill.BaseSkill  (execute(ctx) -> SkillResult)
Gracefully degrades to HTTP-augmented exploration when Playwright is unavailable
(no network requests are issued beyond the target itself).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.browser.browser_brain_loop import BrowserBrainLoop, SensorObservationReport
from core.browser.session import StatefulBrowserSession
from skills.base_skill import BaseSkill, SkillContext, SkillResult

log = logging.getLogger("hunter_ai.skill.browser_sensor")


class BrowserSensorSkill(BaseSkill):
    """
    متصفح استشعاري (Browser Sensor): يستكشف الهدف عبر متصفح رأسless مستمر،
    يرصد حالات التطبيق، النقاط النهائية (API)، النماذج، والتغيرات في الـ DOM،
    ويُنتج تقرير استشهاد (sensor report) قابل للتسليم فيограм Bug Bounty.
    """

    name = "browser_sensor"
    category = "browser"
    description = "Continuous browser-based application sensor (DOM, network, auth state, API surface)"
    timeout_seconds = 180.0
    max_retries = 1

    def __init__(self, headless: bool = True, proxy: Optional[str] = None):
        super().__init__()
        self.headless = headless
        self.proxy = proxy

    # ────────────────────────────────────────────────────────────────────────
    async def execute(self, ctx: SkillContext) -> SkillResult:
        t0 = time.time()
        result = SkillResult(skill_name=self.name, success=False, tool_used="browser_sensor")

        target_url = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"
        parsed = urlparse(target_url)
        host = parsed.hostname or "target"

        # حساسية التشغيل من السياق
        max_pages = int(ctx.extra.get("max_pages", 8))
        time_budget = float(ctx.extra.get("time_budget_sec", 60.0))
        coverage_threshold = float(ctx.extra.get("coverage_threshold", 60.0))

        ctx.workspace.append_log(
            ctx.target, ctx.session_id,
            f"[START] BrowserSensor on {target_url} (max_pages={max_pages}, budget={time_budget}s)"
        )

        try:
            # ── Session + Sensor Loop ─────────────────────────────────────
            output_dir = ctx.workspace.get_workspace_path(ctx.target, ctx.session_id) / "browser" / "sensor"
            output_dir.mkdir(parents=True, exist_ok=True)

            session = StatefulBrowserSession(
                target_url=target_url,
                output_dir=output_dir,
                headless=self.headless,
                proxy=self.proxy,
            )

            loop = BrowserBrainLoop(
                target_url=target_url,
                session=session,
                max_pages=max_pages,
                max_depth=2,
                time_budget_sec=time_budget,
                coverage_threshold=coverage_threshold,
            )

            report: SensorObservationReport = await asyncio.wait_for(
                loop.run_loop(),
                timeout=max(30.0, time_budget + 30.0),
            )

            # ── keluaran files ────────────────────────────────────────────
            report_dict = report.to_dict()
            p_report = ctx.workspace.write_file(
                ctx.target, "browser", "sensor/sensor_report.json",
                json.dumps(report_dict, indent=2, ensure_ascii=False),
                ctx.session_id,
            )
            result.output_files["sensor_report.json"] = str(p_report)

            p_cov = ctx.workspace.write_file(
                ctx.target, "browser", "sensor/coverage_metrics.json",
                json.dumps(report.coverage, indent=2, ensure_ascii=False),
                ctx.session_id,
            )
            result.output_files["coverage_metrics.json"] = str(p_cov)

            # عناوين URL التي تم اكتشافها من ذاكرة الاستكشاف
            discovered_urls = sorted(session.discovered_urls) or [target_url]
            p_urls = ctx.workspace.write_file(
                ctx.target, "browser", "sensor/discovered_urls.txt",
                "\n".join(discovered_urls),
                ctx.session_id,
            )
            result.output_files["discovered_urls.txt"] = str(p_urls)

            # النقاط النهائية (API) المرصودة منboucle الاستشعار
            api_eps = sorted(
                {ep for ep in report.coverage.get("api_endpoints", []) if isinstance(ep, str)}
            ) or sorted({r.url for r in session.network_history if "/api/" in r.url or "graphql" in r.url})
            p_api = ctx.workspace.write_file(
                ctx.target, "browser", "sensor/api_endpoints.txt",
                "\n".join(api_eps) if api_eps else "No dynamic API endpoints captured.",
                ctx.session_id,
            )
            result.output_files["api_endpoints.txt"] = str(p_api)

            # لقطة شاشة للصفحة النهائية (إن توفرت)
            ss_path = await session.take_screenshot("final_state")
            if ss_path:
                result.output_files["final_screenshot.png"] = ss_path

            # إغلاق الجلسة وحفظ الآثار
            try:
                await session.close()
            except Exception:
                pass

            # ── Findings (إثباتات مراقبة فقط — لا دعاوي تثبيت ثغرات) ─────
            result.add_finding(
                title=f"Browser Surface Mapped ({report.pages_visited} pages / {report.states_mapped} states)",
                evidence=(
                    f"Visited {report.pages_visited} page(s), mapped {report.states_mapped} state(s), "
                    f"intercepted {report.api_endpoints_discovered} API endpoint(s). "
                    f"Auth state: {report.auth_state}. Stop reason: {report.stop_reason}."
                ),
                severity="Info",
                vuln_type="browser_surface",
                recommendation="Review discovered pages/forms/endpoints for access-control and input-validation gaps.",
                url=target_url,
            )

            if report.api_endpoints_discovered > 0:
                result.add_finding(
                    title=f"Dynamic API Surface Intercepted ({report.api_endpoints_discovered} endpoints)",
                    evidence="\n".join(api_eps[:10]),
                    severity="Low",
                    vuln_type="api_surface",
                    recommendation="Audit intercepted API routes for BOLA/IDOR and missing authorization checks.",
                    url=target_url,
                )

            if report.auth_state and report.auth_state not in ("GUEST", "ERROR_PAGE"):
                result.add_finding(
                    title=f"Authenticated Browser State Reached ({report.auth_state})",
                    evidence=f"Session cookies/localStorage persisted across {report.pages_visited} page(s).",
                    severity="Info",
                    vuln_type="auth_surface",
                    recommendation="Ensure authenticated surfaces enforce re-authentication for sensitive actions.",
                    url=target_url,
                )

            result.success = True
            result.duration = time.time() - t0
            result.raw_output["report"] = report_dict
            result.next_skills = ["form_intelligence", "network_intelligence"]

            ctx.workspace.append_log(
                ctx.target, ctx.session_id,
                f"[DONE] BrowserSensor — pages={report.pages_visited}, states={report.states_mapped}, "
                f"api={report.api_endpoints_discovered}, auth={report.auth_state}, "
                f"duration={result.duration:.1f}s"
            )
            log.info(
                "[BrowserSensor] %s — pages=%d states=%d api=%d auth=%s",
                target_url, report.pages_visited, report.states_mapped,
                report.api_endpoints_discovered, report.auth_state,
            )

        except asyncio.TimeoutError:
            result.success = False
            result.duration = time.time() - t0
            result.add_error("timeout", f"Browser sensor exceeded {time_budget}s budget")
            log.warning("[BrowserSensor] %s timed out", target_url)
        except Exception as exc:  # لا نسمح لمشاكل المتصفح بإسقاط الخط بأكمله
            result.success = False
            result.duration = time.time() - t0
            result.add_error("runtime", str(exc))
            log.exception("[BrowserSensor] %s failed: %s", target_url, exc)

        return result

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        """مهارة مستوى الهدف (ليست لمُعامل واحد) — لا تشارك في التوجيه التلقائي للمُعاملات."""
        return 0.0
