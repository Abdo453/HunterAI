"""
Enhanced Web Control Center API — Master Router for all HunterAI Capabilities.

Exposes comprehensive control endpoints for:
  1. Master One-Command-For-Everything Autonomous Assessments (all/run/hunt)
  2. Professional Burp Suite Log Inspector (XML, JSON, HAR, live proxy)
  3. Active AI Browser & DOM XSS Studio (Playwright Chromium)
  4. Dynamic AI Command Synthesizer for 62 Kali Tools
  5. 149 Skills Matrix & 6 Elite Exploit Probers
  6. Generated Master Dossiers & Checkpoint Snapshots
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from core.arsenal.ai_command_synthesizer import (
    AIToolCommandSynthesizer,
    TargetContext,
    is_root_privileged,
    resolve_kali_params_wordlist,
    resolve_kali_wordlist,
)
from core.browser.ai_browser_operator import run_ai_browser_session_sync
from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine
from core.skills.skill_matrix_viewer import SkillMatrixViewer
from core.workspace_manager import WorkspaceManager
from skills.base_skill import SkillContext
from skills.burp.burp_log_inspector.skill import BurpLogInspectorSkill
from tools.tool_manager import ToolManager

logger = logging.getLogger("hunter_ai.enhanced_control_api")

router = APIRouter(prefix="/api/enhanced", tags=["enhanced_control"])

_ACTIVE_MASTER_MISSIONS: Dict[str, Dict[str, Any]] = {}


# ── Pydantic Request Models ───────────────────────────────────────────────────

class MasterLaunchRequest(BaseModel):
    target: str = Field(..., description="Target host, domain, comma list, or targets.txt")
    platform: str = Field(default="hackerone", description="hackerone, bugcrowd, intigriti, immunefi")
    proxy: Optional[str] = Field(default=None, description="Upstream Burp proxy URL (e.g. http://127.0.0.1:8080)")
    burp_file: Optional[str] = Field(default=None, description="Path to exported Burp XML/JSON/HAR file")
    resume: Optional[str] = Field(default=None, description="Engagement checkpoint ID to resume from")
    coverage: float = Field(default=0.85, ge=0.0, le=1.0)
    max_cycles: int = Field(default=10, ge=1, le=50)
    force_fallback: bool = Field(default=False)
    self_operate: bool = Field(default=True)
    output_dir: str = Field(default="data/reports")


class BurpInspectRequest(BaseModel):
    source: str = Field(default="live", description="File path, URL, or 'live'")
    content_text: Optional[str] = Field(default=None, description="Raw Burp XML or JSON text pasted directly")
    target: Optional[str] = Field(default=None, description="Target domain or URL")
    port: int = Field(default=8085, description="Burp Gateway port")
    min_risk: float = Field(default=6.0, description="Minimum risk score threshold")


class BrowserExploreRequest(BaseModel):
    target_url: str = Field(..., description="URL to explore with Playwright AI browser")
    proxy: Optional[str] = Field(default=None, description="HTTP proxy (e.g. http://127.0.0.1:8080)")
    headless: bool = Field(default=True, description="Run headless or with GUI window")
    max_pages: int = Field(default=5, ge=1, le=25)


class CommandSynthesizeRequest(BaseModel):
    tool_name: str = Field(..., description="Name of Kali tool (e.g. nuclei, ffuf, sqlmap, nmap, dalfox)")
    target: str = Field(..., description="Target host or URL")
    waf_name: Optional[str] = Field(default=None, description="Known WAF (e.g. Cloudflare, Akamai)")
    ports: List[int] = Field(default_factory=lambda: [80, 443])
    tech_stack: List[str] = Field(default_factory=lambda: ["generic"])
    proxy: Optional[str] = Field(default=None, description="Upstream proxy")
    is_root: Optional[bool] = Field(default=None, description="Privilege level override")


class EliteSkillRequest(BaseModel):
    skill_name: str = Field(..., description="http_smuggling, cache_poisoning, oauth2_abuse, prototype_pollution, path_traversal, jwt_advanced")
    target_url: str = Field(..., description="Target URL to test")
    param_name: str = Field(default="", description="Parameter name (optional)")


# ── 1. Master One-Command-For-Everything Controller ───────────────────────────

@router.post("/omni/launch-all")
async def launch_master_assessment(req: MasterLaunchRequest):
    """
    Launches Unified One-Command-For-Everything assessment across single or multiple targets.
    Coordinates all 11 engines, 149 skills, AI browser, Burp integration, and dossier generation.
    """
    raw_targets = req.target.strip()
    target_list: List[str] = []

    target_path = Path(raw_targets)
    if target_path.is_file() or raw_targets.endswith(".txt") or raw_targets.endswith(".lst"):
        if target_path.is_file():
            for line in target_path.read_text(encoding="utf-8").splitlines():
                cln = line.strip()
                if cln and not cln.startswith("#"):
                    target_list.append(cln)
        else:
            raise HTTPException(400, f"Target file '{raw_targets}' not found.")
    elif "," in raw_targets:
        target_list = [t.strip() for t in raw_targets.split(",") if t.strip()]
    else:
        target_list = [raw_targets]

    if not target_list:
        raise HTTPException(400, "No valid targets supplied.")

    master_mission_id = f"MISSION-{int(time.time())}"
    _ACTIVE_MASTER_MISSIONS[master_mission_id] = {
        "mission_id": master_mission_id,
        "targets": target_list,
        "current_target_index": 0,
        "current_target": target_list[0],
        "status": "RUNNING",
        "current_phase": "INIT",
        "coverage_pct": 0.0,
        "confirmed_findings": [],
        "dossiers": [],
        "start_time": time.time(),
        "elapsed_secs": 0.0,
        "error": None,
    }

    async def _execute_mission():
        mission_state = _ACTIVE_MASTER_MISSIONS[master_mission_id]
        out_dir = Path(req.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        all_results = []

        try:
            for idx, tgt in enumerate(target_list):
                mission_state["current_target_index"] = idx
                mission_state["current_target"] = tgt
                clean_domain = tgt.replace("https://", "").replace("http://", "").split("/")[0]

                config = AssessmentConfig(
                    target_url=tgt if tgt.startswith("http") else f"https://{tgt}",
                    scope_domains=[clean_domain],
                    authorized_by="Master Web Control Center Operator",
                    coverage_threshold=req.coverage,
                    max_cycles=req.max_cycles,
                    enable_thinking=True,
                    enable_browser=True,
                    enable_burp=True,
                    enable_elite_skills=True,
                    enable_oob=True,
                    generate_poc_bundles=True,
                    force_tool_fallback=req.force_fallback,
                    self_operate=req.self_operate,
                    proxy=req.proxy,
                    resume_engagement_id=req.resume,
                    burp_log_file=req.burp_file,
                )

                engine = OmniHunterEngine(config)
                # Run autonomous assessment loop
                res = await asyncio.to_thread(engine.run)
                all_results.append(res)

                mission_state["confirmed_findings"].extend(res.confirmed_findings)
                mission_state["coverage_pct"] = res.coverage_pct
                mission_state["current_phase"] = res.phase_reached.value

                # Write single target dossier
                ts = time.strftime("%Y%m%d_%H%M%S")
                dossier_name = f"MASTER_DOSSIER_{clean_domain}_{ts}.md"
                dossier_path = out_dir / dossier_name
                with open(dossier_path, "w", encoding="utf-8") as df:
                    df.write(f"# Comprehensive Security Assessment Dossier: {clean_domain}\n\n")
                    df.write(f"- **Target URL:** {res.target}\n")
                    df.write(f"- **Engagement ID:** `{res.engagement_id}`\n")
                    df.write(f"- **Coverage:** {res.coverage_pct:.1f}%\n")
                    df.write(f"- **Confirmed Findings:** {len(res.confirmed_findings)}\n\n")
                    for f in res.confirmed_findings:
                        df.write(f"### [{f.get('vuln_class')}] {f.get('title')}\n")
                        df.write(f"Target: `{f.get('target')}`\n\nEvidence:\n```\n{f.get('evidence')}\n```\n\n")
                mission_state["dossiers"].append(str(dossier_path))

            # If multi-target, write master multi-target dossier
            if len(target_list) > 1:
                ts = time.strftime("%Y%m%d_%H%M%S")
                multi_dossier_path = out_dir / f"MASTER_MULTI_TARGET_DOSSIER_{ts}.md"
                with open(multi_dossier_path, "w", encoding="utf-8") as mdf:
                    mdf.write(f"# Multi-Target Master Assessment Dossier\n\n")
                    mdf.write(f"- **Targets Assessed:** {len(target_list)}\n")
                    mdf.write(f"- **Total Findings:** {len(mission_state['confirmed_findings'])}\n\n")
                    for r in all_results:
                        mdf.write(f"## Target: {r.target} (ID: `{r.engagement_id}`)\n")
                        mdf.write(f"- Coverage: {r.coverage_pct:.1f}%\n")
                        mdf.write(f"- Confirmed Findings: {len(r.confirmed_findings)}\n\n")
                mission_state["dossiers"].append(str(multi_dossier_path))

            mission_state["status"] = "COMPLETED"
        except Exception as err:
            logger.error("Master mission %s failed: %s", master_mission_id, err)
            mission_state["status"] = "FAILED"
            mission_state["error"] = str(err)
        finally:
            mission_state["elapsed_secs"] = round(time.time() - mission_state["start_time"], 1)

    asyncio.create_task(_execute_mission())
    return {
        "status": "LAUNCHED",
        "mission_id": master_mission_id,
        "targets_count": len(target_list),
        "targets": target_list,
    }


@router.get("/omni/status/{mission_id}")
async def get_master_mission_status(mission_id: str):
    """Returns live status, active phase, findings count, and dossiers for a master mission."""
    mission = _ACTIVE_MASTER_MISSIONS.get(mission_id)
    if not mission:
        raise HTTPException(404, f"Mission '{mission_id}' not found.")
    elapsed = round(time.time() - mission["start_time"], 1) if mission["status"] == "RUNNING" else mission["elapsed_secs"]
    return {
        "mission_id": mission_id,
        "status": mission["status"],
        "current_target": mission["current_target"],
        "target_progress": f"{mission['current_target_index'] + 1}/{len(mission['targets'])}",
        "current_phase": mission["current_phase"],
        "coverage_pct": round(mission["coverage_pct"], 1),
        "confirmed_findings_count": len(mission["confirmed_findings"]),
        "confirmed_findings": mission["confirmed_findings"],
        "dossiers": mission["dossiers"],
        "elapsed_secs": elapsed,
        "error": mission["error"],
    }


# ── 2. Professional Burp Suite Log Inspector ──────────────────────────────────

@router.post("/burp/inspect")
async def inspect_burp_logs(req: BurpInspectRequest):
    """
    Ingests and deeply analyzes Burp Suite logs (XML, JSON, HAR, live proxy).
    Extracts cloud credentials, database error traces, IDOR/SSRF parameters, and BOLA anomalies.
    """
    target = req.target or "https://burp-target.local"
    log_file_path = None

    if req.content_text:
        upload_dir = Path("data/burp_uploads")
        upload_dir.mkdir(parents=True, exist_ok=True)
        temp_file = upload_dir / f"burp_input_{int(time.time())}.xml"
        temp_file.write_text(req.content_text, encoding="utf-8")
        log_file_path = str(temp_file)
    elif req.source and Path(req.source).is_file():
        log_file_path = req.source

    output_dir = "data/reports"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    session_id = f"BURP-WEB-{int(time.time())}"

    ctx = SkillContext(
        target=target,
        session_id=session_id,
        workspace=WorkspaceManager(output_dir),
        tool_manager=ToolManager(),
        extra={
            "log_file": log_file_path,
            "burp_port": req.port,
            "min_risk_score": req.min_risk,
        },
    )

    skill = BurpLogInspectorSkill()
    res = await skill.execute(ctx)

    if not res.success:
        raise HTTPException(500, f"Burp inspection failed: {res.errors}")

    return {
        "success": True,
        "target": target,
        "total_interactions": res.metadata.get("total_interactions", 0),
        "total_findings": len(res.findings),
        "findings": res.findings,
        "discovered_endpoints": res.metadata.get("discovered_endpoints", []),
        "discovered_apis": res.metadata.get("discovered_apis", []),
        "output_files": res.output_files,
    }


# ── 3. Active AI Browser & DOM XSS Studio ─────────────────────────────────────

@router.post("/browser/explore")
async def explore_with_ai_browser(req: BrowserExploreRequest):
    """
    Launches headless Playwright Chromium to interact with SPAs, click DOM buttons,
    inject canary probes for DOM XSS, and intercept background Fetch/XHR APIs.
    """
    try:
        report = await asyncio.to_thread(
            run_ai_browser_session_sync,
            target_url=req.target_url,
            proxy=req.proxy,
            headless=req.headless,
        )
        return {
            "success": report.success if report else False,
            "target": req.target_url,
            "pages_visited": report.pages_visited if report else [],
            "actions_performed": report.actions_performed if report else [],
            "intercepted_api_endpoints": report.intercepted_api_endpoints if report else [],
            "dom_xss_signals": getattr(report, "dom_xss_candidates", []) or getattr(report, "dom_xss_signals", []),
            "state_graph_summary": getattr(report, "state_graph_summary", None),
            "intercepted_websockets": getattr(report, "intercepted_websockets", []),
            "dual_session_idor_candidates": getattr(report, "dual_session_idor_candidates", []),
        }
    except Exception as e:
        logger.error("AI Browser execution error: %s", e)
        raise HTTPException(500, f"AI Browser session error: {str(e)}")


# ── 4. Dynamic AI Command Synthesizer ─────────────────────────────────────────

@router.post("/arsenal/synthesize")
async def synthesize_kali_command(req: CommandSynthesizeRequest):
    """
    Dynamically synthesizes command-line flags for any Kali tool tailored to
    perimeter WAF, ports, tech stack, privilege status, and upstream Burp proxy.
    """
    from core.arsenal.kali_catalog import get_tool_definition
    tool_def = get_tool_definition(req.tool_name)
    if not tool_def:
        raise HTTPException(404, f"Tool '{req.tool_name}' not found in Kali catalog.")

    ctx = TargetContext(
        target=req.target if req.target.startswith("http") else f"https://{req.target}",
        waf_name=req.waf_name,
        open_ports=req.ports,
        tech_stack=req.tech_stack,
        proxy=req.proxy,
    )
    result = AIToolCommandSynthesizer.synthesize_sync(tool_def, ctx)

    # Wordlist resolver metadata
    wordlist_used = None
    if req.tool_name.lower() in ("ffuf", "gobuster", "feroxbuster", "dirsearch"):
        wordlist_used = resolve_kali_wordlist()
    elif req.tool_name.lower() == "x8":
        wordlist_used = resolve_kali_params_wordlist()

    is_root = is_root_privileged() if req.is_root is None else req.is_root

    return {
        "tool_name": req.tool_name,
        "target": req.target,
        "synthesized_command": result.command_line,
        "rationale": result.ai_reasoning,
        "ai_reasoning": result.ai_reasoning,
        "risk_profile": result.risk_level,
        "recommended_flags": result.args,
        "waf_evasion_applied": bool(ctx.waf_name),
        "wordlist_resolved": wordlist_used,
        "privilege_status": "root (-sS mode)" if is_root else "non-root (-sT unprivileged mode)",
        "proxy_injected": req.proxy,
    }


# ── 5. 149 Skills Matrix & Elite Exploit Engines ──────────────────────────────

@router.get("/skills/catalog")
async def get_skills_catalog(category: Optional[str] = None, layer: Optional[str] = None):
    """Returns the unified catalog across all 4 skill layers (149 curated skills)."""
    skills = SkillMatrixViewer.list_all_skills(category=category, layer=layer)
    stats = SkillMatrixViewer.get_summary_stats()
    return {
        "stats": stats,
        "total": len(skills),
        "skills": skills,
    }


@router.post("/skills/elite-run")
async def execute_elite_skill(req: EliteSkillRequest):
    """Directly triggers one of the 6 Elite Exploit Engines against a target."""
    sk_map = {
        "http_smuggling": "HTTPSmugglingSkill",
        "cache_poisoning": "CachePoisoningSkill",
        "oauth2_abuse": "OAuth2AbuseSkill",
        "prototype_pollution": "PrototypePollutionSkill",
        "path_traversal": "PathTraversalSkill",
        "jwt_advanced": "JWTAdvancedSkill",
    }
    if req.skill_name.lower() not in sk_map:
        raise HTTPException(400, f"Unknown elite skill '{req.skill_name}'. Supported: {list(sk_map.keys())}")

    try:
        if req.skill_name.lower() == "http_smuggling":
            from agents.skills.http_smuggling_skill import HTTPSmugglingSkill
            sk = HTTPSmugglingSkill()
        elif req.skill_name.lower() == "cache_poisoning":
            from agents.skills.cache_poisoning_skill import CachePoisoningSkill
            sk = CachePoisoningSkill()
        elif req.skill_name.lower() == "oauth2_abuse":
            from agents.skills.oauth2_abuse_skill import OAuth2AbuseSkill
            sk = OAuth2AbuseSkill()
        elif req.skill_name.lower() == "prototype_pollution":
            from agents.skills.prototype_pollution_skill import PrototypePollutionSkill
            sk = PrototypePollutionSkill()
        elif req.skill_name.lower() == "path_traversal":
            from agents.skills.path_traversal_skill import PathTraversalSkill
            sk = PathTraversalSkill()
        else:
            from agents.skills.jwt_advanced_skill import JWTAdvancedSkill
            sk = JWTAdvancedSkill()

        res = await sk.run(req.target_url, param_name=req.param_name)
        return {
            "skill_name": req.skill_name,
            "target": req.target_url,
            "verified": res.verified,
            "vuln_type": res.vuln_type,
            "confidence": res.confidence,
            "title": res.title,
            "evidence": res.evidence,
            "payload_used": res.payload_used,
            "cwe": res.cwe,
        }
    except Exception as e:
        logger.error("Elite skill %s execution error: %s", req.skill_name, e)
        raise HTTPException(500, f"Elite skill error: {str(e)}")


# ── 6. Reports & Snapshots Management ─────────────────────────────────────────

@router.get("/reports")
async def list_reports():
    """Lists all generated assessment dossiers and Burp reports."""
    rep_dir = Path("data/reports")
    if not rep_dir.exists():
        return {"reports": []}

    items = []
    for p in sorted(rep_dir.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
        items.append({
            "filename": p.name,
            "path": str(p),
            "size_bytes": p.stat().st_size,
            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)),
            "is_master_dossier": "MASTER_DOSSIER" in p.name or "MASTER_MULTI_TARGET" in p.name,
        })
    return {"reports": items}


@router.get("/reports/{filename}")
async def get_report_content(filename: str):
    """Returns markdown text content of a requested report file."""
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(400, "Invalid filename")
    p = Path("data/reports") / filename
    if not p.is_file():
        raise HTTPException(404, f"Report '{filename}' not found.")
    return PlainTextResponse(p.read_text(encoding="utf-8", errors="replace"))


@router.get("/snapshots")
async def list_snapshots():
    """Lists saved engagement snapshots for checkpoint resumption."""
    snap_dir = Path("snapshots")
    if not snap_dir.exists():
        return {"snapshots": []}

    items = []
    for p in sorted(snap_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            items.append({
                "filename": p.name,
                "snapshot_id": data.get("snapshot_id", p.stem),
                "target": data.get("target", "unknown"),
                "phase": data.get("phase", "UNKNOWN"),
                "coverage_pct": data.get("coverage_pct", 0.0),
                "findings_count": len(data.get("confirmed_findings", [])),
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime)),
            })
        except Exception:
            continue
    return {"snapshots": items}
