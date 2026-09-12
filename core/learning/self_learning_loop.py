"""
Self-Learning Loop — Phase 4: Orchestration of the Full Learning Pipeline
حلقة التعلم الذاتي الكاملة:
  Fetch → Analyze → Store → Index → Feedback
يعمل كـ background task أو يُشغَّل يدوياً
"""
import asyncio
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.learning.fetcher import IntelligenceFetcher
from core.learning.analyzer import DeepAnalyzer
from core.learning.knowledge_base import KnowledgeBase

log = logging.getLogger("learning.loop")

STATE_FILE = Path("data/knowledge_base/learning_state.json")

# ─── Learning State ───────────────────────────────────────────────────────────

def _load_state() -> Dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "last_run": {},
        "total_articles_learned": 0,
        "total_cves_indexed": 0,
        "total_payloads_saved": 0,
        "last_full_run": None,
        "learning_cycles": 0,
    }


def _save_state(state: Dict):
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


# ─── SelfLearningLoop ────────────────────────────────────────────────────────

class SelfLearningLoop:
    """
    العقل المتعلم ذاتياً — يُنسّق بين:
    - Fetcher (جلب البيانات)
    - Analyzer (تحليل وفهم)
    - KnowledgeBase (تخزين ومؤشرة)
    - Feedback loop (تحسين مستمر)
    """

    def __init__(self, resource_manager=None):
        self.rm = resource_manager
        self.fetcher = IntelligenceFetcher()
        self.analyzer = DeepAnalyzer(resource_manager=resource_manager)
        self.kb = KnowledgeBase()
        self._state = _load_state()
        self._running = False

    async def _emit(self, msg: str, data: Dict = None):
        """يُصدر log events — يمكن توصيله بـ WebSocket لاحقاً"""
        entry = {"ts": datetime.utcnow().isoformat(), "message": msg, **(data or {})}
        log.info(f"[LEARN] {msg}")
        return entry

    # ── Learning Cycles ───────────────────────────────────────────────────────

    async def learn_from_nvd(self, keyword: str = "web application", limit: int = 30) -> Dict:
        """يتعلم من CVE database (NVD)"""
        await self._emit(f"Fetching NVD CVEs: keyword={keyword!r}, limit={limit}")
        cves = await self.fetcher.fetch_nvd_cves(keyword=keyword)
        saved = 0
        for cve_entry in cves[:limit]:
            try:
                analysis = await self.analyzer.analyze_cve_entry(cve_entry)
                if analysis.get("cve_id"):
                    self.kb.save_cve(analysis)
                    # Save payloads extracted
                    raw_payloads = analysis.get("payloads", [])
                    raw_techs = analysis.get("techniques", [])
                    tech_names = [t.get("technique") if isinstance(t, dict) else str(t) for t in raw_techs] or ["unknown"]

                    for payload in raw_payloads:
                        p_text = payload.get("payload") if isinstance(payload, dict) else str(payload)
                        p_cat = payload.get("category") if isinstance(payload, dict) else None
                        if len(p_text) > 5:
                            for tech in tech_names:
                                self.kb.save_payload(
                                    payload_text=p_text,
                                    payload_type=p_cat or tech,
                                    technologies=analysis.get("affected_technologies", []),
                                    source_url=analysis.get("source_url", ""),
                                    severity=analysis.get("severity", "Medium"),
                                )
                    self.kb.log_learning(
                        source_url=f"nvd:{analysis['cve_id']}",
                        source_type="cve",
                        analysis=analysis
                    )
                    saved += 1
            except Exception as e:
                log.warning(f"CVE processing error: {e}")
        self._state["total_cves_indexed"] = self._state.get("total_cves_indexed", 0) + saved
        await self._emit(f"NVD learning done: {saved} CVEs saved")
        return {"saved": saved, "source": "nvd"}

    async def learn_from_cisa_kev(self) -> Dict:
        """يتعلم من CISA Known Exploited Vulnerabilities"""
        await self._emit("Fetching CISA KEV...")
        kev_list = await self.fetcher.fetch_cisa_kev()
        saved = 0
        for entry in kev_list[:50]:
            try:
                cve_id = entry.get("cveID", "")
                desc = entry.get("shortDescription", "") + " " + entry.get("notes", "")
                analysis = await self.analyzer.analyze(
                    desc,
                    source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    use_ai=False
                )
                analysis["cve_id"] = cve_id
                analysis["published"] = entry.get("dateAdded", "")
                analysis["cvss_score"] = 8.0  # KEV is always high-severity
                analysis["severity"] = "High"
                self.kb.save_cve(analysis)
                self.kb.log_learning(
                    source_url=f"cisa:{cve_id}",
                    source_type="cisa_kev",
                    analysis=analysis
                )
                saved += 1
            except Exception as e:
                log.warning(f"CISA KEV error: {e}")
        await self._emit(f"CISA KEV done: {saved} vulns saved")
        return {"saved": saved, "source": "cisa_kev"}

    async def learn_from_medium(self, tags: List[str] = None, limit: int = 15) -> Dict:
        """يتعلم من مقالات Medium"""
        if tags is None:
            tags = ["bug-bounty", "cybersecurity", "penetration-testing", "web-security"]
        total_saved = 0
        for tag in tags:
            await self._emit(f"Fetching Medium articles: tag={tag!r}")
            articles = await self.fetcher.fetch_medium_rss(tag=tag, limit=limit)
            for art in articles:
                try:
                    text = art.get("text", "")
                    if len(text) < 200:
                        continue
                    analysis = await self.analyzer.analyze(
                        text,
                        source_url=art.get("url", ""),
                        use_ai=True
                    )
                    analysis["title"] = art.get("title", "")
                    analysis["source_type"] = "article"
                    # Save payloads
                    raw_payloads = analysis.get("payloads", [])
                    raw_techs = analysis.get("techniques", [])
                    tech_names = [t.get("technique") if isinstance(t, dict) else str(t) for t in raw_techs] or ["unknown"]

                    for payload in raw_payloads:
                        p_text = payload.get("payload") if isinstance(payload, dict) else str(payload)
                        p_cat = payload.get("category") if isinstance(payload, dict) else None
                        if len(p_text) > 5:
                            for tech in tech_names:
                                self.kb.save_payload(
                                    payload_text=p_text,
                                    payload_type=p_cat or tech,
                                    technologies=analysis.get("affected_technologies", []),
                                    source_url=analysis.get("source_url", ""),
                                    severity=analysis.get("severity", "Medium"),
                                )

                    # Save techniques
                    tools_list = [t.get("tool") if isinstance(t, dict) else str(t) for t in analysis.get("tools", analysis.get("related_tools", []))]
                    bypasses_list = [b.get("bypass") if isinstance(b, dict) else str(b) for b in analysis.get("bypass_methods", analysis.get("bypass_techniques", []))]
                    payload_samples = [p.get("payload") if isinstance(p, dict) else str(p) for p in raw_payloads][:5]

                    for tech in raw_techs:
                        tech_name = tech.get("technique") if isinstance(tech, dict) else str(tech)
                        if tech_name:
                            self.kb.save_technique(
                                technique_name=tech_name,
                                category="web_exploitation",
                                description=analysis.get("summary", ""),
                                tools=tools_list,
                                payloads=payload_samples,
                                bypass_methods=bypasses_list,
                                affected_tech=analysis.get("affected_technologies", []),
                            )
                    self.kb.save_article(analysis)
                    self.kb.log_learning(
                        source_url=art.get("url", ""),
                        source_type="article",
                        analysis=analysis
                    )
                    total_saved += 1
                    # Rate limit
                    await asyncio.sleep(0.5)
                except Exception as e:
                    log.warning(f"Medium article error: {e}")
        self._state["total_articles_learned"] = self._state.get("total_articles_learned", 0) + total_saved
        await self._emit(f"Medium learning done: {total_saved} articles saved")
        return {"saved": total_saved, "source": "medium"}

    async def learn_from_portswigger(self) -> Dict:
        """يتعلم من PortSwigger Web Security Academy"""
        await self._emit("Fetching PortSwigger labs...")
        labs = await self.fetcher.fetch_portswigger_labs()
        saved = 0
        for lab in labs:
            try:
                title = lab.get("title", "")
                url = lab.get("url", "")
                if not title:
                    continue
                analysis = await self.analyzer.analyze(
                    title,
                    source_url=url,
                    use_ai=False
                )
                analysis["title"] = title
                analysis["source_type"] = "lab"
                for tech_name in analysis.get("techniques", []):
                    self.kb.save_technique(
                        technique_name=tech_name,
                        category="web_lab",
                        description=f"PortSwigger Lab: {title}",
                        tools=[],
                        affected_tech=analysis.get("affected_technologies", []),
                    )
                self.kb.save_article(analysis)
                saved += 1
            except Exception as e:
                log.warning(f"PortSwigger lab error: {e}")
        await self._emit(f"PortSwigger done: {saved} labs indexed")
        return {"saved": saved, "source": "portswigger"}

    async def learn_payloads_from_github(self) -> Dict:
        """يجلب payloads من PayloadsAllTheThings"""
        categories = [
            "XSS Injection", "SQL Injection", "Server Side Template Injection",
            "SSRF injection", "XML External Entity",
            "Open Redirect", "CSRF Injection"
        ]
        total_saved = 0
        for cat in categories:
            await self._emit(f"Fetching payloads: {cat}")
            content = await self.fetcher.fetch_payloads_all_things(cat)
            if not content:
                continue
            # Extract code blocks from markdown
            code_blocks = [b.strip() for b in content.split("```") if b.strip() and len(b.strip()) > 3]
            tech_name = cat.lower().replace(" ", "_").replace("-", "_")
            for block in code_blocks[:30]:
                # Filter: only keep lines that look like payloads
                lines = [l.strip() for l in block.splitlines() if l.strip() and len(l.strip()) > 5]
                for line in lines[:10]:
                    if any(c in line for c in ["<", "'", "\"", ";", "--", "%", "{{", "${", "\\", "0x"]):
                        self.kb.save_payload(
                            payload_text=line[:500],
                            payload_type=tech_name.split("_")[0],
                            source_url=f"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/{cat}",
                            severity="High",
                        )
                        total_saved += 1
        self._state["total_payloads_saved"] = self._state.get("total_payloads_saved", 0) + total_saved
        await self._emit(f"Payload learning done: {total_saved} payloads saved")
        return {"saved": total_saved, "source": "payloads_all_things"}

    async def learn_from_exploit_db(self, keyword: str = "web") -> Dict:
        """يتعلم من Exploit-DB"""
        await self._emit(f"Fetching Exploit-DB: keyword={keyword!r}")
        exploits = await self.fetcher.fetch_exploit_db_search(keyword, limit=20)
        saved = 0
        for exp in exploits:
            try:
                text = f"{exp.get('title','')} {exp.get('type','')} {exp.get('platform','')}"
                analysis = await self.analyzer.analyze(text, source_url=exp.get("url",""), use_ai=False)
                analysis["title"] = exp.get("title", "")
                analysis["source_type"] = "exploit"
                self.kb.save_article(analysis)
                saved += 1
            except Exception as e:
                log.warning(f"Exploit-DB entry error: {e}")
        await self._emit(f"Exploit-DB done: {saved} entries saved")
        return {"saved": saved, "source": "exploit_db"}

    # ── Full Learning Cycle ───────────────────────────────────────────────────

    async def run_full_cycle(
        self,
        sources: Optional[List[str]] = None,
        use_ai: bool = True,
        emit_fn=None
    ) -> Dict[str, Any]:
        """
        دورة تعلم كاملة — تُشغَّل يومياً أو عند الطلب.
        sources: قائمة بالمصادر المطلوبة — None = الكل
        """
        self._running = True
        cycle_start = time.time()
        results = {}

        if emit_fn:
            self.emit_fn = emit_fn

        all_sources = sources or [
            "cisa_kev", "nvd", "medium", "portswigger",
            "payloads", "exploit_db"
        ]

        await self._emit("=== Self-Learning Cycle Started ===")

        for source in all_sources:
            if not self._running:
                break
            try:
                if source == "nvd":
                    r = await self.learn_from_nvd(keyword="web application", limit=30)
                elif source == "cisa_kev":
                    r = await self.learn_from_cisa_kev()
                elif source == "medium":
                    r = await self.learn_from_medium(use_ai=use_ai) if hasattr(self, '_medium_with_ai') else await self.learn_from_medium()
                elif source == "portswigger":
                    r = await self.learn_from_portswigger()
                elif source == "payloads":
                    r = await self.learn_payloads_from_github()
                elif source == "exploit_db":
                    r = await self.learn_from_exploit_db()
                else:
                    r = {}
                results[source] = r
                self._state["last_run"][source] = datetime.utcnow().isoformat()
                _save_state(self._state)
                await asyncio.sleep(2)  # rate limit between sources
            except Exception as e:
                log.exception(f"Learning cycle error: source={source}")
                results[source] = {"error": str(e)}

        # Finalize
        self.kb.flush_vectors()
        duration = round(time.time() - cycle_start, 1)
        self._state["last_full_run"] = datetime.utcnow().isoformat()
        self._state["learning_cycles"] = self._state.get("learning_cycles", 0) + 1
        _save_state(self._state)

        stats = self.kb.stats()
        await self._emit(
            f"=== Cycle Complete in {duration}s ===",
            {"stats": stats, "results": results}
        )
        self._running = False
        return {
            "duration": duration,
            "results": results,
            "kb_stats": stats,
            "state": self._state,
        }

    async def learn_topic(self, topic: str) -> Dict:
        """تعلم موضوع محدد (XSS, SQLi, SSRF...)"""
        await self._emit(f"Learning topic: {topic!r}")
        results = {}
        results["nvd"] = await self.learn_from_nvd(keyword=topic, limit=20)
        results["medium"] = await self.learn_from_medium(tags=[topic, f"{topic}-vulnerability"], limit=10)
        results["payloads"] = await self.learn_payloads_from_github()
        self.kb.flush_vectors()
        return {
            "topic": topic,
            "results": results,
            "kb_stats": self.kb.stats(),
        }

    def retrieve_for_scan(self, target_url: str, html_snippet: str = "") -> Dict:
        """
        يُعيد معرفة مرتبطة بهدف فحص — يُستدعى من AutonomousBrain
        """
        return self.kb.find_relevant_for_scan(target_url, html_snippet)

    def get_payloads(self, vuln_type: str, limit: int = 20) -> List[str]:
        """يُعيد payloads من قاعدة المعرفة المتعلَّمة"""
        return self.kb.get_payloads_by_type(vuln_type, limit=limit)

    def get_stats(self) -> Dict:
        return {**self.kb.stats(), "state": self._state}

    def stop(self):
        self._running = False
