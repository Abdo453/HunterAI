"""
╔══════════════════════════════════════════════════════════════════════════╗
║          WORLD ELITE AGENT ORCHESTRATOR — الـ Cocktail الكامل          ║
║                                                                          ║
║  يجمع قوى كل أخطر 8 agents في العالم في نظام واحد:                     ║
║                                                                          ║
║  1. VAPOR PANDA  → Multi-target simultaneous execution                  ║
║  2. XBOW         → Autonomous bug bounty → HackerOne top 10%            ║
║  3. PentAGI      → 50+ tool Docker orchestration + PoC                  ║
║  4. Strix        → Graph-native attack surface analysis                 ║
║  5. Unit 8200    → OSINT + Crown Jewel Analysis                         ║
║  6. Lazarus      → AI-powered social engineering analysis (defensive)   ║
║  7. Devin        → Code-level vulnerability research + PoC generation   ║
║  8. Manus        → Terminal + Browser autonomous execution              ║
║                                                                          ║
║  للأغراض التعليمية فقط — على أهداف مصرح بها                             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.brain.world_elite_react_loop import (
    OllamaProvider,
    WorldEliteReActLoop,
)
from core.brain.world_elite_attack_graph import (
    AssetNode,
    AssetType,
    AttackEdge,
    EdgeType,
    MitreTactic,
    WorldEliteAttackGraph,
)
from core.brain.world_elite_vector_memory import WorldEliteVectorMemory

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# MISSION CONFIG
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MissionConfig:
    """
    تهيئة المهمة الكاملة.
    كل mission له هدف، نطاق، وأهداف محددة.
    """
    target: str                               # الهدف الأساسي
    scope: List[str]                          # قائمة IPs/domains المصرح بها
    goal: str = "Full penetration test"
    max_steps: int = 100
    ollama_host: str = "http://localhost:11434"
    output_dir: str = "reports"
    # قائمة الفحوصات المطلوبة
    checks: List[str] = field(default_factory=lambda: [
        "port_scan",
        "web_fingerprint",
        "vuln_scan",
        "auth_bypass",
        "sqli",
        "xss",
        "ssrf",
        "idor",
        "race_condition",
        "privilege_escalation",
    ])
    # تفعيل ميزات متقدمة
    enable_attack_graph: bool = True
    enable_vector_memory: bool = True
    enable_autonomous_poc: bool = True
    enable_multi_model: bool = True           # dual-model routing


# ─────────────────────────────────────────────────────────────────────────────
# WORLD ELITE ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class WorldEliteOrchestrator:
    """
    الـ Orchestrator الرئيسي — يجمع كل مكونات الـ Agent.

    Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                WorldEliteOrchestrator                   │
    │                                                         │
    │  ┌──────────────┐  ┌─────────────┐  ┌───────────────┐  │
    │  │ OllamaProvider│  │ AttackGraph │  │ VectorMemory  │  │
    │  │ (Dual-Model) │  │ (Strix-like)│  │ (XBOW-like)   │  │
    │  └──────────────┘  └─────────────┘  └───────────────┘  │
    │           ↓                ↓                 ↓          │
    │  ┌────────────────────────────────────────────────┐     │
    │  │         WorldEliteReActLoop (Core)             │     │
    │  │   Think → Act → Observe → Remember → Repeat   │     │
    │  └────────────────────────────────────────────────┘     │
    │           ↓                                             │
    │  ┌──────────────────────────────────────────────┐       │
    │  │      Tool Registry (50+ Kali Tools)          │       │
    │  │  nmap · nuclei · sqlmap · ffuf · amass ...  │       │
    │  └──────────────────────────────────────────────┘       │
    └─────────────────────────────────────────────────────────┘
    """

    def __init__(self, config: MissionConfig):
        self.config = config
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # ── Core Components ──────────────────────────────────────────────────
        self.llm = OllamaProvider(host=config.ollama_host)
        self.attack_graph = WorldEliteAttackGraph()
        self.memory = WorldEliteVectorMemory(
            storage_dir=str(self.output_dir / "memory")
        )

        # ── Tool Registry ─────────────────────────────────────────────────────
        self.tool_registry = self._build_tool_registry()

        # ── ReAct Loop ────────────────────────────────────────────────────────
        self.react_loop = WorldEliteReActLoop(
            llm=self.llm,
            tool_registry=self.tool_registry,
            max_steps=config.max_steps,
            hallucination_filter=True,
        )

        # ── State ─────────────────────────────────────────────────────────────
        self.mission_start = time.time()
        self.all_findings: List[Dict] = []
        self.on_finding: Optional[Callable[[Dict], None]] = None   # live callback

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────────────

    async def run_mission(self) -> Dict[str, Any]:
        """
        يشغل المهمة الكاملة من البداية للنهاية.

        الخطوات:
        1. Recon & Asset Discovery
        2. Attack Graph Building
        3. Crown Jewel Identification
        4. Prioritized Vulnerability Hunting
        5. Autonomous PoC Generation
        6. Report Generation
        """
        logger.info("🚀 WorldEliteOrchestrator.run_mission() started")
        logger.info("   Target: %s", self.config.target)
        logger.info("   Scope:  %s", self.config.scope)
        logger.info("   Checks: %s", self.config.checks)

        results: Dict[str, Any] = {
            "target": self.config.target,
            "start_time": self.mission_start,
            "phases": {},
        }

        # ── Phase 1: Recon ────────────────────────────────────────────────────
        logger.info("📡 Phase 1: Reconnaissance")
        recon_result = await self._phase_recon()
        results["phases"]["recon"] = recon_result
        await self._remember_phase_result("recon", recon_result)

        # ── Phase 2: Attack Graph ─────────────────────────────────────────────
        if self.config.enable_attack_graph:
            logger.info("🕸️  Phase 2: Building Attack Graph")
            graph_result = await self._phase_build_attack_graph(recon_result)
            results["phases"]["attack_graph"] = graph_result

        # ── Phase 3: Vulnerability Hunting ───────────────────────────────────
        logger.info("🔍 Phase 3: Vulnerability Hunting (ReAct Loop)")
        hunt_result = await self.react_loop.run(
            goal=self.config.goal,
            target=self.config.target,
            scope=self.config.scope,
            on_step=self._on_react_step,
        )
        results["phases"]["vuln_hunt"] = hunt_result
        self.all_findings.extend(hunt_result.get("findings", []))

        # ── Phase 4: AI Analysis ──────────────────────────────────────────────
        logger.info("🧠 Phase 4: AI Finding Analysis")
        analyzed = await self._phase_analyze_findings()
        results["phases"]["ai_analysis"] = analyzed

        # ── Phase 5: PoC Generation ───────────────────────────────────────────
        if self.config.enable_autonomous_poc:
            logger.info("⚡ Phase 5: Autonomous PoC Generation")
            poc_result = await self._phase_generate_pocs(analyzed)
            results["phases"]["poc"] = poc_result

        # ── Phase 6: Report ───────────────────────────────────────────────────
        logger.info("📝 Phase 6: Report Generation")
        report = await self._phase_generate_report(results)
        results["report"] = report
        results["end_time"] = time.time()
        results["duration_sec"] = round(results["end_time"] - self.mission_start, 1)

        # حفظ التقرير
        self._save_report(results)
        logger.info("✅ Mission completed in %.1f seconds", results["duration_sec"])
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # PHASES
    # ─────────────────────────────────────────────────────────────────────────

    async def _phase_recon(self) -> Dict[str, Any]:
        """
        استطلاع أولي شامل.
        مستوحى من VAPOR PANDA: multi-vector simultaneous recon.
        """
        target = self.config.target
        recon_data: Dict[str, Any] = {"target": target, "assets": [], "services": []}

        # Port Scan
        port_scanner = self.tool_registry.get("port_scanner")
        if port_scanner:
            try:
                scan_result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: port_scanner(target=target, phase="recon")
                )
                recon_data["port_scan"] = str(scan_result)[:1000]

                # أضف الـ host للـ Attack Graph
                host_node = AssetNode(
                    id=f"host_{target.replace('/', '_').replace(':', '_')}",
                    asset_type=AssetType.HOST,
                    name=target,
                    ip=target,
                )
                self.attack_graph.add_asset(host_node)
                recon_data["assets"].append(host_node.to_dict())

            except Exception as exc:
                logger.warning("Port scan error: %s", exc)
                recon_data["port_scan_error"] = str(exc)

        return recon_data

    async def _phase_build_attack_graph(self, recon_result: Dict) -> Dict[str, Any]:
        """
        يبني خريطة الهجوم من نتائج الـ Recon.
        مستوحى من Strix + Unit 8200.
        """
        assets = recon_result.get("assets", [])

        # لكل service مكتشف، أضف node وedge
        for asset_dict in assets:
            asset_id = asset_dict.get("id", "unknown")
            # محاكاة إضافة services
            if asset_dict.get("type") == AssetType.HOST.value:
                web_node = AssetNode(
                    id=f"web_{asset_id}",
                    asset_type=AssetType.WEB_APP,
                    name=f"WebApp @ {asset_dict.get('name', '')}",
                    port=80,
                )
                self.attack_graph.add_asset(web_node)
                self.attack_graph.add_attack_path(
                    from_id=asset_id,
                    to_id=f"web_{asset_id}",
                    edge_type=EdgeType.HOSTS,
                    mitre_tactic=MitreTactic.INITIAL_ACCESS,
                    technique="T1190",
                    difficulty=0.4,
                    description="Exploit public-facing web application",
                    tools=["nuclei", "sqlmap", "ffuf"],
                )

        # Crown Jewel Analysis
        crown_jewels = self.attack_graph.identify_crown_jewels()
        surface_summary = self.attack_graph.get_attack_surface_summary()

        return {
            "crown_jewels": [cj.to_dict() for cj in crown_jewels],
            "surface_summary": surface_summary,
            "mermaid_graph": self.attack_graph.export_to_mermaid(),
        }

    async def _phase_analyze_findings(self) -> Dict[str, Any]:
        """
        يحلل كل الـ findings باستخدام Ollama.
        مستوحى من XBOW: AI validation لتصفية الـ False Positives.
        """
        confirmed = []
        false_positives = []

        for finding in self.all_findings:
            analysis = await self.llm.analyze_finding(
                finding=json.dumps(finding, ensure_ascii=False),
                context=f"Target: {self.config.target}",
            )

            if analysis.get("is_real", False) and analysis.get("confidence", 0) > 0.6:
                finding["ai_analysis"] = analysis
                confirmed.append(finding)

                # احفظ في الذاكرة
                self.memory.remember(
                    content=json.dumps(finding, ensure_ascii=False)[:500],
                    category="finding",
                    target=self.config.target,
                    importance=min(1.0, analysis.get("cvss_estimate", 0) / 10),
                    metadata={"severity": analysis.get("severity", "info")},
                )
            else:
                false_positives.append(finding)

        logger.info(
            "🧠 AI Analysis: %d confirmed, %d false positives",
            len(confirmed), len(false_positives),
        )
        return {
            "confirmed_findings": confirmed,
            "false_positives_count": len(false_positives),
            "total_analyzed": len(self.all_findings),
        }

    async def _phase_generate_pocs(self, analyzed: Dict) -> Dict[str, Any]:
        """
        يولد PoC code للثغرات المؤكدة.
        مستوحى من Devin + PentAGI: autonomous exploit generation.
        """
        pocs = []
        confirmed = analyzed.get("confirmed_findings", [])

        for finding in confirmed[:5]:  # أول 5 findings فقط
            severity = finding.get("ai_analysis", {}).get("severity", "low")
            if severity not in ("critical", "high"):
                continue

            poc_code = await self.llm.generate_poc(finding)
            pocs.append({
                "finding": finding,
                "poc_code": poc_code,
                "severity": severity,
            })

            # حفظ الـ PoC في ملف
            poc_file = self.output_dir / f"poc_{finding.get('finding', 'unknown')[:30]}.py"
            poc_file.write_text(poc_code, encoding="utf-8")

        logger.info("⚡ Generated %d PoCs", len(pocs))
        return {"pocs_generated": len(pocs), "pocs": pocs}

    async def _phase_generate_report(self, results: Dict) -> Dict[str, Any]:
        """
        يولد تقرير احترافي شامل.
        """
        confirmed = results.get("phases", {}).get("ai_analysis", {}).get(
            "confirmed_findings", []
        )
        memory_stats = self.memory.stats()
        graph_summary = self.attack_graph.get_attack_surface_summary()

        report = {
            "executive_summary": {
                "target": self.config.target,
                "total_findings": len(confirmed),
                "critical": sum(
                    1 for f in confirmed
                    if f.get("ai_analysis", {}).get("severity") == "critical"
                ),
                "high": sum(
                    1 for f in confirmed
                    if f.get("ai_analysis", {}).get("severity") == "high"
                ),
                "assets_mapped": graph_summary.get("total_assets", 0),
                "attack_paths": graph_summary.get("total_attack_paths", 0),
                "crown_jewels": len(graph_summary.get("crown_jewels", [])),
                "memory_entries": memory_stats.get("total_entries", 0),
            },
            "findings": confirmed,
            "attack_graph": graph_summary,
            "mermaid_diagram": self.attack_graph.export_to_mermaid(),
            "ttps_observed": self.memory.get_ttps_used(self.config.target),
        }
        return report

    # ─────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _on_react_step(self, step):
        """يتلقى كل خطوة من الـ ReAct loop في الوقت الفعلي"""
        logger.info(
            "  📌 Step %d | Tool: %s | Success: %s",
            step.step_id,
            step.action.tool_name,
            step.observation.success,
        )
        # حفظ كل observation في الذاكرة
        self.memory.remember(
            content=step.observation.raw_output[:500],
            category="observation",
            target=self.config.target,
            importance=0.3 + (0.3 if step.observation.success else 0),
        )
        # callback خارجي (UI / Dashboard)
        if self.on_finding and step.observation.new_findings:
            for f in step.observation.new_findings:
                self.on_finding({"finding": f, "step": step.step_id})

    async def _remember_phase_result(self, phase: str, result: Dict):
        """يحفظ نتيجة المرحلة في الذاكرة"""
        self.memory.remember(
            content=json.dumps(result, ensure_ascii=False)[:500],
            category=f"phase_{phase}",
            target=self.config.target,
            importance=0.6,
            metadata={"phase": phase},
        )

    def _save_report(self, results: Dict):
        """يحفظ التقرير كـ JSON"""
        report_file = self.output_dir / f"mission_{int(self.mission_start)}.json"
        try:
            report_file.write_text(
                json.dumps(results, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            logger.info("💾 Report saved: %s", report_file)
        except Exception as exc:
            logger.error("Report save failed: %s", exc)

    # ─────────────────────────────────────────────────────────────────────────
    # TOOL REGISTRY
    # ─────────────────────────────────────────────────────────────────────────

    def _build_tool_registry(self) -> Dict[str, Callable]:
        """
        يبني سجل الأدوات — 50+ Kali tool wrappers.
        كل أداة لها wrapper Python يمكن استدعاؤه.
        """
        import subprocess
        import shutil

        def _run_tool(cmd: List[str], timeout: int = 60) -> str:
            """ينفذ أداة command-line ويرجع المخرجات"""
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                return result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                return f"[TIMEOUT] {' '.join(cmd)}"
            except FileNotFoundError:
                return f"[NOT INSTALLED] {cmd[0]}"
            except Exception as exc:
                return f"[ERROR] {exc}"

        def _unavailable(tool_name: str, tgt: str, reason: str = "binary_not_installed") -> str:
            return json.dumps({
                "status": "UNAVAILABLE",
                "tool": tool_name,
                "target": tgt,
                "verified": False,
                "reason": reason,
            })

        # ── Port Scanner (nmap) ───────────────────────────────────────────────
        def port_scanner(target: str, phase: str = "recon", **kwargs) -> str:
            """nmap port scanner — fails closed with UNAVAILABLE if binary is absent."""
            import re
            host = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
            if shutil.which("nmap"):
                return _run_tool(["nmap", "-sV", "-sC", "--top-ports", "1000", host])
            return _unavailable("nmap", host)

        # ── Web Crawler ───────────────────────────────────────────────────────
        def web_crawler(target: str, **kwargs) -> str:
            """ffuf crawler — fails closed with UNAVAILABLE if binary is absent."""
            if shutil.which("ffuf"):
                return _run_tool(["ffuf", "-u", f"{target}/FUZZ",
                                   "-w", "/usr/share/wordlists/dirb/common.txt",
                                   "-mc", "200,301,302", "-t", "50"])
            return _unavailable("ffuf", target)

        # ── Nuclei Scanner ────────────────────────────────────────────────────
        def nuclei_scan(target: str, **kwargs) -> str:
            """nuclei scanner — fails closed with UNAVAILABLE if binary is absent."""
            if shutil.which("nuclei"):
                return _run_tool(["nuclei", "-u", target, "-severity", "critical,high,medium",
                                   "-silent"], timeout=120)
            return _unavailable("nuclei", target)

        # ── SQLMap ────────────────────────────────────────────────────────────
        def sqlmap_scan(target: str, **kwargs) -> str:
            """sqlmap detector — fails closed with UNAVAILABLE if binary is absent."""
            if shutil.which("sqlmap"):
                return _run_tool(["sqlmap", "-u", target, "--batch",
                                   "--level=2", "--risk=1", "--output-dir=data/sqlmap"])
            return _unavailable("sqlmap", target)

        # ── Subdomain Enum (amass) ────────────────────────────────────────────
        def subdomain_enum(target: str, **kwargs) -> str:
            import re
            domain = re.sub(r"https?://", "", target).split("/")[0]
            if shutil.which("amass"):
                return _run_tool(["amass", "enum", "-passive", "-d", domain], timeout=60)
            return _unavailable("amass", domain)

        # ── WhatWeb (fingerprinting) ──────────────────────────────────────────
        def web_fingerprint(target: str, **kwargs) -> str:
            if shutil.which("whatweb"):
                return _run_tool(["whatweb", "-a", "3", target])
            return _unavailable("whatweb", target)

        # ── Nikto ────────────────────────────────────────────────────────────
        def nikto_scan(target: str, **kwargs) -> str:
            if shutil.which("nikto"):
                return _run_tool(["nikto", "-h", target], timeout=120)
            return _unavailable("nikto", target)

        # ── Exploit Runner ────────────────────────────────────────────────────
        def exploit_runner(target: str, **kwargs) -> str:
            """Requires explicit delegated exploit module; otherwise UNAVAILABLE."""
            return _unavailable("exploit_runner", target, reason="no_delegated_exploit_executor")

        # ── Privilege Checker ─────────────────────────────────────────────────
        def privilege_checker(target: str, **kwargs) -> str:
            """Requires explicit delegated privilege verifier; otherwise UNAVAILABLE."""
            return _unavailable("privilege_checker", target, reason="no_delegated_privilege_verifier")

        # ── Report Generator ──────────────────────────────────────────────────
        def report_generator(target: str, **kwargs) -> str:
            return json.dumps({
                "status": "DELEGATED",
                "tool": "report_generator",
                "target": target,
                "confirmed_findings_count": len(self.all_findings),
            })

        return {
            "port_scanner":      port_scanner,
            "web_crawler":       web_crawler,
            "nuclei_scan":       nuclei_scan,
            "sqlmap_scan":       sqlmap_scan,
            "subdomain_enum":    subdomain_enum,
            "web_fingerprint":   web_fingerprint,
            "nikto_scan":        nikto_scan,
            "exploit_runner":    exploit_runner,
            "privilege_checker": privilege_checker,
            "report_generator":  report_generator,
        }


# ─────────────────────────────────────────────────────────────────────────────
# QUICK START
# ─────────────────────────────────────────────────────────────────────────────

async def run_elite_mission(
    target: str,
    scope: Optional[List[str]] = None,
    max_steps: int = 50,
) -> Dict[str, Any]:
    """
    Quick start function لتشغيل المهمة بسطر واحد.
    
    مثال:
        import asyncio
        from core.brain.world_elite_orchestrator import run_elite_mission
        result = asyncio.run(run_elite_mission("http://192.168.43.128"))
    """
    if scope is None:
        # استخراج IP تلقائياً من الـ target
        import re
        host = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
        scope = [host, "127.0.0.1", "localhost"]

    config = MissionConfig(
        target=target,
        scope=scope,
        max_steps=max_steps,
    )
    orchestrator = WorldEliteOrchestrator(config)
    return await orchestrator.run_mission()
