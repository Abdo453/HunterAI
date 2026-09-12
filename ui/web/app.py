"""
Web UI — FastAPI + WebSocket (Updated for SmartOrchestrator)
يدعم: Chat Mode + Scan Mode + GPU Status + Self-Learning Brain
"""
import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path


from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles


@asynccontextmanager
async def lifespan(app: FastAPI):
    """تشغيل الـ Auto-Scheduler عند بدء التطبيق"""
    import logging
    log = logging.getLogger("app.lifespan")
    scheduler_task = None
    try:
        from core.learning.learning_server import get_scheduler
        scheduler = get_scheduler()
        scheduler_task = asyncio.create_task(
            scheduler.run_forever(check_interval_minutes=30),
            name="learning_scheduler"
        )
        log.info("[APP] LearningScheduler started (30-min interval)")
    except Exception as e:
        log.warning(f"[APP] LearningScheduler not started: {e}")

    # Start Unified BurpAgent & SecurityIntelligence Background Workers
    try:
        burp = get_burp_agent()
        if hasattr(burp, "start_background_workers"):
            await burp.start_background_workers()
            log.info("[APP] BurpAgent (Port 8085) & SecurityIntelligence EventBus connected.")
    except Exception as e:
        log.warning(f"[APP] Could not start BurpAgent workers: {e}")

    yield


    # Shutdown
    if scheduler_task and not scheduler_task.done():
        scheduler_task.cancel()
        try:
            await scheduler_task
        except asyncio.CancelledError:
            pass
    log.info("[APP] Shutdown complete")


app = FastAPI(title="PentestAI Unified", lifespan=lifespan)
BASE = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
_HTML_PATH = BASE / "templates" / "index.html"


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=_HTML_PATH.read_text(encoding="utf-8"))


@app.get("/api/status")
async def get_status():
    """حالة الـ GPU + الموديلات"""
    import httpx
    from models.ollama_manager import normalize_ollama_host
    ollama_host = normalize_ollama_host(os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))
    local_models = []
    loaded_models = []

    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{ollama_host}/api/tags")
            if r.status_code == 200:
                local_models = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass

    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{ollama_host}/api/ps")
            if r.status_code == 200:
                loaded_models = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass

    api_keys = {
        "gemini": bool(os.getenv("GEMINI_API_KEY")),
        "openrouter": bool(os.getenv("OPENROUTER_API_KEY")),
        "taskade": bool(os.getenv("TASKADE_API_KEY")),
        "groq": bool(os.getenv("GROQ_API_KEY")),
        "openai": bool(os.getenv("OPENAI_API_KEY")),
        "anthropic": bool(os.getenv("ANTHROPIC_API_KEY")),
        "deepseek": bool(os.getenv("DEEPSEEK_API_KEY")),
    }

    return {
        "local_models": local_models,
        "loaded_models": loaded_models,
        "api_keys": api_keys,
        "ollama_host": ollama_host,
    }


@app.get("/api/ai/diagnostics")
async def get_ai_diagnostics():
    """تقرير تشخيصي حي لحالة الموديلات المحلية والسحابية"""
    from core.ai_diagnostics import run_full_ai_diagnostics
    return await run_full_ai_diagnostics(verbose=False)


# ── Global Static Reasoning Engine Instance ──
_GLOBAL_STATIC_REASONING_ENGINE = None

def get_static_reasoning_engine():
    global _GLOBAL_STATIC_REASONING_ENGINE
    if _GLOBAL_STATIC_REASONING_ENGINE is None:
        from core.static_reasoning_engine import StaticSecurityReasoningEngine
        _GLOBAL_STATIC_REASONING_ENGINE = StaticSecurityReasoningEngine()
    return _GLOBAL_STATIC_REASONING_ENGINE


@app.post("/api/static/audit")
async def audit_source_code(req: Request):
    """تحليل أمني استنتاجي للكود المصدر عبر منهجية 8-Phases Reasoning"""
    data = await req.json()
    source_code = data.get("source_code", "")
    target_name = data.get("target_name", "Component")
    context = data.get("context", "")
    if not source_code.strip():
        return JSONResponse(status_code=400, content={"error": "source_code is required"})
    engine = get_static_reasoning_engine()
    result = await engine.analyze_source(source_code, target_name=target_name, additional_context=context)
    return result


@app.get("/api/static/memory")
async def get_static_reasoning_memory():
    """سجل الذاكرة الاستنتاجية للأنماط الأمنية المكتشفة"""
    engine = get_static_reasoning_engine()
    return {"reasoning_memory": engine.reasoning_memory}


@app.get("/api/diagnostics/preflight")


async def check_preflight():
    """فحص جاهزية النظام والبروكسي والأدوات قبل بدء الفحص"""
    import socket
    import shutil
    import httpx
    
    # 1. Burp Suite Proxy Check
    burp_host = "127.0.0.1"
    burp_port = 8080
    burp_online = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.6)
        res = sock.connect_ex((burp_host, burp_port))
        if res == 0:
            burp_online = True
        sock.close()
    except Exception:
        burp_online = False

    # 2. Ollama Local Server Check
    ollama_host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    ollama_online = False
    try:
        async with httpx.AsyncClient(timeout=2, trust_env=False) as c:
            r = await c.get(f"{ollama_host}/api/tags")
            if r.status_code == 200:
                ollama_online = True
    except Exception:
        ollama_online = False

    # 3. Security Tools Available in PATH
    tools = ["httpx", "nuclei", "katana", "sqlmap", "ffuf", "wafw00f", "nmap"]
    tools_status = {}
    for t in tools:
        tools_status[t] = shutil.which(t) is not None or shutil.which(f"{t}.exe") is not None

    # 4. APIs
    api_ready = bool(os.getenv("GEMINI_API_KEY") or os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY"))

    return {
        "burp": {
            "host": burp_host,
            "port": burp_port,
            "online": burp_online,
            "message": "Burp Suite Proxy is running (127.0.0.1:8080)" if burp_online else "Burp Suite is NOT running on 127.0.0.1:8080"
        },
        "ollama": {
            "online": ollama_online,
            "host": ollama_host
        },
        "tools": tools_status,
        "tools_ready_count": sum(1 for v in tools_status.values() if v),
        "total_tools": len(tools),
        "api_ready": api_ready
    }


@app.get("/api/sessions")
async def list_sessions():
    from core.session_manager import SessionManager
    return SessionManager().list_all()


@app.get("/api/session/{sid}")
async def get_session(sid: str):
    from core.session_manager import SessionManager
    s = SessionManager().load(sid)
    if not s:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return {
        "id": s.id, "target": s.target, "mode": s.mode, "status": s.status,
        "created_at": s.created_at, "findings_count": len(s.findings),
        "findings": [
            {"title": f.title, "severity": f.severity, "cvss": f.cvss_score,
             "tool": f.tool, "evidence": f.evidence[:200]}
            for f in s.findings
        ],
        "strategy": s.strategy
    }


@app.get("/api/report/{sid}/{fmt}")
async def get_report(sid: str, fmt: str):
    from core.session_manager import SessionManager
    from core.bugbounty_reporter import BugBountyReporter
    
    # Check custom reports first
    if fmt == "hackerone":
        p = Path("data/reports") / f"{sid}_hackerone.md"
        if not p.exists():
            s = SessionManager().load(sid)
            if s:
                s_dict = {"id": s.id, "target": s.target, "findings": [{"title": f.title, "severity": f.severity, "cvss_score": f.cvss_score, "tool": f.tool, "evidence": f.evidence, "recommendation": f.recommendation} for f in s.findings]}
                BugBountyReporter().generate_hackerone_report(s_dict)
        if p.exists():
            return FileResponse(str(p), media_type="text/markdown", filename=f"{sid}_hackerone.md")

    elif fmt == "executive":
        p = Path("data/reports") / f"{sid}_executive.html"
        if not p.exists():
            s = SessionManager().load(sid)
            if s:
                s_dict = {"id": s.id, "target": s.target, "findings": [{"title": f.title, "severity": f.severity, "cvss_score": f.cvss_score, "tool": f.tool, "evidence": f.evidence, "recommendation": f.recommendation} for f in s.findings]}
                BugBountyReporter().generate_executive_html(s_dict)
        if p.exists():
            return FileResponse(str(p), media_type="text/html")

    p = Path("data/reports") / f"{sid}_report.{fmt}"
    if not p.exists():
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return FileResponse(str(p))


# ── Tool Outputs API Endpoints ───────────────────────────────

@app.get("/api/tool_outputs")
async def list_tool_outputs():
    """قائمة بكافة ملفات المخرجات النصية للأدوات"""
    from tools.tool_manager import ToolManager
    tm_inst = ToolManager()
    files = tm_inst.list_output_files()
    return {"status": "success", "count": len(files), "files": files}


@app.get("/api/tool_outputs/{filename}")
async def get_tool_output(filename: str):
    """عرض أو تحميل مخرجات أداة نصية محددة"""
    from tools.tool_manager import ToolManager
    from fastapi.responses import PlainTextResponse
    tm_inst = ToolManager()
    content = tm_inst.get_output_content(filename)
    if content is None:
        return JSONResponse(status_code=404, content={"error": "File not found"})
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


# ── VRAM-Conscious Sequential Pipeline Endpoints ──

@app.post("/api/pipeline/vram/execute")
async def execute_vram_pipeline_endpoint(req: Request):
    """
    تشغيل خط الأنابيب التسلسلي خماسي المراحل مع تفريغ VRAM تلقائياً:
    Stage 1: Recon & Ingestion (0 AI Tokens, SQLite Hash Diffing)
    Stage 2: Qwen 2.5 Coder 14B (Decompiler & Param Extractor)
    Stage 3: WhiteRabbitNeo 8B (Offensive Hypothesis Engine)
    Stage 4: ScopeGuard & Rate-Limited Execution (0 AI Tokens)
    Stage 5: xploiter / Cloud Triage (8-Question Gate & Enterprise Report)
    """
    from core.pipeline.vram_sequential_pipeline import vram_pipeline
    data = await req.json()
    target_url = data.get("target_url", "").strip()
    in_scope = data.get("in_scope", [target_url] if target_url else [])
    out_of_scope = data.get("out_of_scope", [])
    rate_limit_rps = float(data.get("rate_limit_rps", 2.0))

    if not target_url:
        return JSONResponse(status_code=400, content={"error": "target_url is required"})

    try:
        result = await vram_pipeline.execute_pipeline(
            target_url=target_url,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rate_limit_rps=rate_limit_rps
        )
        return {
            "status": "completed",
            "target": result.target,
            "scan_id": result.scan_id,
            "duration_seconds": result.duration_seconds,
            "findings_count": result.findings_count,
            "findings": [
                {
                    "id": f.finding_id,
                    "title": f.title,
                    "type": f.vulnerability_type,
                    "severity": f.severity,
                    "cvss": f.cvss_score,
                    "cwe": f.cwe_id,
                    "summary": f.summary,
                    "poc": f.proof_of_concept,
                    "remediation": f.remediation
                }
                for f in result.findings
            ],
            "reports": {
                "json": result.report_json_path,
                "html": result.report_html_path
            },
            "vram_unloaded": result.vram_unloaded_successfully
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Pipeline failed: {str(e)}"})


@app.get("/api/pipeline/vram/status")
async def get_vram_pipeline_status():
    """الحصول على حالة النماذج والـ VRAM في خط الأنابيب التسلسلي"""
    from core.pipeline.vram_sequential_pipeline import vram_pipeline
    from core.ai_bridge.agent_ai_cognitive_bridge import cognitive_bridge
    health = await cognitive_bridge.refresh_model_health()
    return {
        "active_model_in_vram": vram_pipeline.vram_mgr.currently_loaded_model or "None (VRAM Freed)",
        "models_health": health,
        "pipeline_stages": [
            {"stage": 1, "name": "Mechanical Recon & Hash Diffing", "engine": "Deterministic (0 AI)"},
            {"stage": 2, "name": "Decompiler & Param Extractor", "engine": "Qwen 2.5 Coder (14B)"},
            {"stage": 3, "name": "Offensive Security Logic", "engine": "WhiteRabbitNeo (8B)"},
            {"stage": 4, "name": "Scope & Rate-Limited Execution", "engine": "Pure Async Python (0 AI)"},
            {"stage": 5, "name": "8-Question Gate Triage & Report", "engine": "xploiter / Llama 70B"}
        ]
    }


# ── Hunter Agent Protocol v1 & Blackboard Memory Endpoints ──

_GLOBAL_HUNTER_MANAGER = None

def get_hunter_agent_manager():
    global _GLOBAL_HUNTER_MANAGER
    if _GLOBAL_HUNTER_MANAGER is None:
        from hunter_ai.brain.agent_manager import HunterAgentManager
        from hunter_ai.agents.recon_contract_agent import ReconContractAgent
        from hunter_ai.agents.web_contract_agent import WebContractAgent
        from hunter_ai.agents.report_contract_agent import ReportContractAgent

        mgr = HunterAgentManager()
        mgr.register_agent(ReconContractAgent())
        mgr.register_agent(WebContractAgent())
        mgr.register_agent(ReportContractAgent())
        _GLOBAL_HUNTER_MANAGER = mgr
    return _GLOBAL_HUNTER_MANAGER


@app.get("/api/hunter/contracts")
async def list_hunter_contracts():
    """عرض عقود كافة الوكلاء المسجلين في Hunter Agent Protocol v1"""
    mgr = get_hunter_agent_manager()
    return {
        "protocol": "Hunter Agent Protocol v1",
        "registered_agents_count": len(mgr.list_contracts()),
        "contracts": mgr.list_contracts()
    }


@app.post("/api/hunter/mission/execute")
async def execute_hunter_mission_endpoint(req: Request):
    """
    تشغيل مهمة أمنية متعددة الوكلاء (Multi-Agent Mission) عبر نظام الذاكرة المشتركة (Blackboard) والتسليم (Handoffs):
    ReconAgent -> Handoff -> WebAgent -> Handoff -> ReportAgent
    """
    data = await req.json()
    target_url = data.get("target_url", "").strip()
    initial_agent = data.get("initial_agent", "ReconAgent")

    if not target_url:
        return JSONResponse(status_code=400, content={"error": "target_url is required"})

    mgr = get_hunter_agent_manager()
    try:
        mission_res = await mgr.execute_mission(
            target_url=target_url,
            initial_agent_name=initial_agent
        )
        return {
            "status": "completed",
            "protocol": "Hunter Agent Protocol v1",
            "mission": mission_res
        }
    except Exception as ex:
        return JSONResponse(status_code=500, content={"error": f"Mission failed: {str(ex)}"})


@app.get("/api/hunter/blackboard/{job_id}")
async def get_blackboard_state(job_id: str):
    """استعراض حالة الذاكرة المشتركة (Blackboard Level 1 Summary & Level 2 Evidence)"""
    mgr = get_hunter_agent_manager()
    summary = mgr.blackboard.get_summary_dict(job_id)
    if not summary:
        return JSONResponse(status_code=404, content={"error": "Job not found in Blackboard"})

    evidences = [
        {
            "id": ev.evidence_id,
            "url": ev.url,
            "parameter": ev.parameter,
            "type": ev.vulnerability_type,
            "notes": ev.differential_notes
        }
        for ev in mgr.blackboard.list_evidence_for_job(job_id)
    ]

    return {
        "job_id": job_id,
        "level1_summary": summary,
        "level2_evidence_count": len(evidences),
        "level2_evidence": evidences
    }


@app.get("/api/hunter/memory/agent/{agent_name}")
async def get_agent_memory(agent_name: str):
    """استرجاع ذاكرة التعلم التراكمية لوكيل معين"""
    mgr = get_hunter_agent_manager()
    lessons = mgr.memory.get_agent_lessons(agent_name)
    return {
        "agent_name": agent_name,
        "lessons_count": len(lessons),
        "lessons": lessons
    }


@app.post("/api/browser/browse")
async def browser_browse(req: Request):
    """فتح وتحكم في المتصفح تلقائياً (Firefox, Chrome, Chromium, Edge) وفحص الـ DOM وتوجيه الترافيك لـ Burp Suite"""
    data = await req.json()
    url = data.get("url", "").strip()
    visible = data.get("visible", True)
    browser_pref = data.get("browser", "auto")
    proxy = data.get("proxy", "127.0.0.1:8080" if data.get("use_proxy", False) else None)

    if not url:
        return JSONResponse(status_code=400, content={"error": "URL required"})
    if not url.startswith("http"):
        url = f"http://{url}"

    from tools.browser_tools import BrowserController
    bc = BrowserController(headless=not visible, proxy=proxy)
    started = bc.start(visible=visible, preferred_browser=browser_pref)
    if not started:
        avail = bc.detect_available_browsers()
        return JSONResponse(status_code=500, content={
            "error": "لم يتم العثور على أي متصفح مدعوم (Firefox, Chrome, Chromium, Edge). يرجى التأكد من تثبيت المتصفح والـ driver.",
            "detected_browsers": avail
        })

    try:
        bc.navigate(url)
        title = bc.get_title()
        curr_url = bc.get_current_url()
        elements = bc.find_interactive_elements()
        cookies = bc.get_cookies()
        screenshot_path = bc.screenshot()
        
        # Execute actions if provided
        action_results = []
        for act in data.get("actions", []):
            atype = act.get("type")
            if atype == "click" and act.get("selector"):
                from selenium.webdriver.common.by import By
                ok = bc.click_element(By.CSS_SELECTOR, act["selector"])
                action_results.append({"action": "click", "selector": act["selector"], "success": ok})
            elif atype == "fill" and act.get("selector"):
                ok = bc.fill_input(act["selector"], act.get("text", ""))
                action_results.append({"action": "fill", "selector": act["selector"], "success": ok})

        return {
            "status": "success",
            "active_browser": bc.active_browser or "Browser",
            "url": curr_url,
            "title": title,
            "interactive_elements": elements,
            "cookies_count": len(cookies),
            "screenshot": screenshot_path,
            "actions_executed": action_results,
            "proxy_active": proxy is not None
        }
    finally:
        if visible:
            await asyncio.sleep(2)
        bc.stop()


@app.post("/api/waf-check")
async def check_waf(req: Request):
    """فحص WAF الهدف وتحديد بروفايل الفحص"""
    data = await req.json()
    target = data.get("target", "").strip()
    if not target:
        return JSONResponse(status_code=400, content={"error": "Target required"})
    from tools.waf_evasion import WAFEvasionEngine
    profile = await WAFEvasionEngine().detect_waf(target)
    return {
        "target": profile.target,
        "waf_detected": profile.waf_detected,
        "waf_names": profile.waf_names,
        "rate_limit_detected": profile.rate_limit_detected,
        "recommended_mode": profile.recommended_mode,
        "delay_range": profile.delay_range,
        "confidence": profile.confidence
    }


@app.get("/api/methodology")
async def get_methodology(q: Optional[str] = None):
    """استرجاع المنهجية وقواعد الأوامر والبحث فيها"""
    from core.methodology_kb import MethodologyKB
    kb = MethodologyKB()
    if q:
        return {"query": q, "results": kb.search(q)}
    return {
        "steps": kb.get_all_steps(),
        "target_selection_guide": kb.get_target_selection_guide(),
        "portswigger_matrix": kb.get_portswigger_matrix()
    }


@app.post("/api/run-tool")
async def run_tool(req: Request):
    """تنفيذ أداة أمنية معتمدة بأمان"""
    data = await req.json()
    tool = data.get("tool", "").strip()
    target = data.get("target", "").strip()
    args = data.get("args", "")

    if not tool or not target:
        return JSONResponse(status_code=400, content={"error": "Tool and Target required"})

    from tools.tool_manager import ToolManager
    tm = ToolManager()
    
    # Run tool via ToolManager
    result = await tm.execute_tool(tool, f"{target} {args}".strip())
    return {
        "tool": tool,
        "target": target,
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "duration": round(result.duration, 2),
        "cached": result.cached
    }


# ── Pipeline & Graph State ───────────────────────────────────
_active_pipelines: dict = {}
_latest_graph_data: dict = {"nodes": [], "edges": []}


@app.post("/api/pipeline/start")
async def start_recon_pipeline(req: Request):
    """بدء سلسلة الاستطلاع التلقائية الكاملة"""
    data = await req.json()
    target = data.get("target", "").strip()
    in_scope = data.get("in_scope", [])
    out_of_scope = data.get("out_of_scope", [])

    if not target:
        return JSONResponse(status_code=400, content={"error": "Target required"})

    from core.scope_guard import ScopeGuard
    from core.pipeline_runner import ReconPipelineRunner

    guard = ScopeGuard(in_scope=in_scope or [target], out_of_scope=out_of_scope)
    session_id = f"pipe_{int(time.time())}"

    async def pipeline_cb(ev):
        # Update latest graph data cache
        if ev.get("event") == "graph_update":
            _latest_graph_data["nodes"] = ev.get("nodes", [])
            _latest_graph_data["edges"] = ev.get("edges", [])

    runner = ReconPipelineRunner(target, scope_guard=guard, progress_cb=pipeline_cb, session_id=session_id)
    _active_pipelines[session_id] = runner

    # Launch in background
    asyncio.create_task(runner.run())

    return {
        "status": "started",
        "session_id": session_id,
        "target": target
    }


@app.get("/api/pipeline/graph")
async def get_pipeline_graph():
    """الحصول على بيانات الرسم البياني الشبكي الحالية أو بناء خريطة من آخر جلسة فحص"""
    if not _latest_graph_data.get("nodes"):
        try:
            from core.session_manager import SessionManager
            sm = SessionManager()
            sessions = sm.list_all()
            if sessions:
                latest = sessions[0]
                s_data = sm.load(latest["id"])
                target = s_data.target or "Target"
                nodes = [
                    {"id": "root", "label": f"🎯 {target}\n(Root Target)", "group": "target"}
                ]
                edges = []
                for i, f in enumerate(s_data.findings[:15]):
                    fid = f"find_{i}"
                    nodes.append({
                        "id": fid,
                        "label": f"[{f.severity}] {f.title[:28]}",
                        "group": "vuln" if f.severity in ["Critical", "High"] else "endpoint"
                    })
                    edges.append({"from": "root", "to": fid, "label": f.tool or "detected"})
                return {"nodes": nodes, "edges": edges}
        except Exception:
            pass
    return _latest_graph_data


@app.post("/api/hunter/start")
async def start_autonomous_hunter(req: Request):
    """بدء عملية الصيد الذاتية الكاملة (Autonomous AI Hunter)"""
    data = await req.json()
    target = data.get("target", "").strip()
    in_scope = data.get("in_scope", [])
    out_of_scope = data.get("out_of_scope", [])
    burp_proxy = data.get("burp_proxy", "127.0.0.1:8080")
    use_burp = data.get("use_burp", True)

    if not target:
        return JSONResponse(status_code=400, content={"error": "Target required"})

    from core.scope_guard import ScopeGuard
    from core.autonomous_hunter import AutonomousHunter

    guard = ScopeGuard(in_scope=in_scope or [target], out_of_scope=out_of_scope)
    session_id = f"hunt_{int(time.time())}"

    hunter = AutonomousHunter(
        target=target,
        scope_guard=guard,
        session_id=session_id,
        burp_proxy=burp_proxy,
        use_burp=use_burp
    )

    # تشغيل في الخلفية
    asyncio.create_task(hunter.start())

    return {
        "status": "started",
        "session_id": session_id,
        "target": target,
        "burp_proxy": burp_proxy
    }


# ── Threat Intelligence & CVE Feed ───────────────────────────
@app.get("/api/cve/latest")
async def get_latest_cve_feed():
    """جلب أحدث ثغرات الـ CVE المنشورة حديثاً عالمياً"""
    from core.cve_feed_learner import CVEFeedLearner
    learner = CVEFeedLearner()
    cves = await learner.fetch_recent_cves(limit=15)
    return {"count": len(cves), "cves": cves}


@app.get("/api/cve/search")
async def search_cves(q: str):
    """البحث عن ثغرة CVE أو منتج معين"""
    from core.cve_feed_learner import CVEFeedLearner
    learner = CVEFeedLearner()
    results = learner.search_cve(q)
    return {"query": q, "results": results}


@app.post("/api/cve/explain")
async def explain_cve(req: Request):
    """شرح وتحليل الثغرة تقنياً بواسطة الذكاء الاصطناعي"""
    data = await req.json()
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return JSONResponse(status_code=400, content={"error": "cve_id required"})

    from core.cve_feed_learner import CVEFeedLearner
    from orchestrator.resource_manager import ResourceManager

    learner = CVEFeedLearner()
    prompt = learner.format_cve_explanation_prompt(cve_id)
    if not prompt:
        # Try fetching it directly or format basic query
        prompt = f"Please provide an in-depth technical analysis, root cause, detection methods, and remediation for {cve_id}."

    rm = ResourceManager()
    explanation = await rm.run_local_model(
        model_name="xploiter/pentester:latest",
        messages=[
            {"role": "system", "content": "You are a senior security researcher and vulnerability analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )

    return {
        "cve_id": cve_id,
        "technical_explanation": explanation
    }


@app.post("/api/analyze-http")
@app.post("/api/http/analyze")
async def analyze_http_traffic(req: Request):
    """تحليل حركة مرور وطلبات HTTP / Burp Suite"""
    data = await req.json()
    raw_req = data.get("raw_request", "").strip()
    raw_resp = data.get("raw_response", "").strip()

    if not raw_req:
        return JSONResponse(status_code=400, content={"error": "Raw HTTP request required"})

    from core.http_analyzer import HTTPTrafficAnalyzer
    analyzer = HTTPTrafficAnalyzer()
    analysis_result = analyzer.analyze(raw_req, raw_resp if raw_resp else None)

    return analysis_result


# ── Dynamic Skill Memory & Triage API ────────────────────────
@app.get("/api/skills")
async def list_skills():
    """عرض كافة المهارات والتقنيات المحفوظة في ذاكرة الـ AI"""
    from core.skill_memory_engine import SkillLearnerEngine
    engine = SkillLearnerEngine()
    return {"skills": engine.list_skills()}


@app.post("/api/skills/train")
async def train_skill(req: Request):
    """تدريب الـ AI على تقرير ثغرة أو مهارة جديدة"""
    from core.skill_memory_engine import SkillLearnerEngine
    data = await req.json()
    category = data.get("category", "").strip()
    writeup = data.get("writeup", "").strip()
    if not category or not writeup:
        return JSONResponse(status_code=400, content={"error": "Category and writeup content required"})
    engine = SkillLearnerEngine()
    ok = engine.train_skill(category, writeup)
    return {"status": "trained" if ok else "failed", "category": category}


@app.post("/api/skills/analyze")
async def run_skill_triage(req: Request):
    """تشغيل الفحص الذكي (Crawler -> Router -> Analyzer -> Triage)"""
    from core.skill_memory_engine import SkillLearnerEngine
    data = await req.json()
    target_url = data.get("url", "").strip()
    cookie_str = data.get("cookie", "").strip()
    if not target_url:
        return JSONResponse(status_code=400, content={"error": "URL required"})
    engine = SkillLearnerEngine()
    result = await engine.run_pipeline(target_url, cookie_str=cookie_str)
    return result


@app.delete("/api/skills/{category}")
async def delete_skill(category: str):
    """حذف مهارة من الذاكرة"""
    from core.skill_memory_engine import SkillLearnerEngine
    engine = SkillLearnerEngine()
    ok = engine.delete_skill(category)
    return {"status": "deleted" if ok else "not_found"}


# ── Self-Learning & Curriculum API ──────────────────────────
@app.get("/api/learning/topics")
async def get_learning_topics():
    """عرض كافة مواضيع لابات PortSwigger والتعلم الذاتي المتاحة"""
    from core.self_learning_engine import SelfLearningEngine
    engine = SelfLearningEngine()
    return {"topics": engine.get_topics()}


@app.get("/api/learning/history")
async def get_learning_history():
    """عرض سجل الدورات التعليمية السابقة"""
    from core.self_learning_engine import SelfLearningEngine
    engine = SelfLearningEngine()
    return {"history": engine.get_learning_history()}


@app.post("/api/learning/start")
async def start_self_learning(req: Request):
    """بدء دورة التعلم الذاتي للموديلات"""
    data = await req.json()
    topic_id = data.get("topic_id", "all").strip()
    from core.self_learning_engine import SelfLearningEngine
    engine = SelfLearningEngine()
    if topic_id == "all":
        res = await engine.learn_all_topics()
    else:
        res = await engine.learn_topic(topic_id)
    return res


@app.post("/api/learning/scrape")
async def scrape_and_learn_source(req: Request):
    """سحب وتعلم تقارير مباشرة من HackerOne أو GitHub أو Medium أو OWASP"""
    data = await req.json()
    source = data.get("source", "owasp").strip()
    url = data.get("url", "").strip()
    limit = int(data.get("limit", 10))
    query = data.get("query", "bug bounty writeup").strip()

    from core.auto_scraper_learner import AutoScraperLearner
    learner = AutoScraperLearner()
    result = await learner.train_from_source(source=source, url=url, limit=limit, query=query)
    return result


@app.post("/api/learning/vector-match")
async def vector_match_skills(req: Request):
    """البحث المتجه بالـ Cosine Similarity عن المهارات المطابقة للمدخلات"""
    data = await req.json()
    target_data = data.get("target_data", "").strip()
    top_k = int(data.get("top_k", 5))

    from core.auto_scraper_learner import VectorSkillStorage
    storage = VectorSkillStorage()
    matches = storage.find_relevant_skills(target_data, top_k=top_k)
    return {"matches_count": len(matches), "matches": matches}


@app.post("/api/probe/verify")
async def verify_vulnerability_live(req: Request):
    """تنفيذ فحص الـ PoC التفاضلي وفلترة الـ False Positives وحساب الـ CVSS"""
    data = await req.json()
    target_url = data.get("target_url", "").strip()
    param_name = data.get("param_name", "").strip()
    vuln_type = data.get("vuln_type", "sqli").strip()
    payload = data.get("payload", "").strip()

    if not target_url or not param_name:
        return JSONResponse(status_code=400, content={"error": "Target URL and parameter name required"})

    from core.smart_probe_engine import SmartPoCExecutor
    executor = SmartPoCExecutor()
    result = await executor.execute_and_verify(target_url, param_name, vuln_type, payload if payload else None)
    return result


@app.post("/api/scope/check")
async def check_scope(req: Request):
    """التحقق من الهدف وفق قواعد الـ Scope"""
    data = await req.json()
    target = data.get("target", "").strip()
    in_scope = data.get("in_scope", [])
    out_of_scope = data.get("out_of_scope", [])

    from core.scope_guard import ScopeGuard
    guard = ScopeGuard(in_scope=in_scope, out_of_scope=out_of_scope)
    allowed, reason = guard.is_in_scope(target)

    return {
        "target": target,
        "allowed": allowed,
        "reason": reason
    }


# ── Self-Learning Brain APIs ──────────────────────────────────
@app.get("/api/brain/kb/stats")
async def get_kb_stats():
    """إحصائيات قاعدة المعرفة المتعلَّمة"""
    from core.learning.knowledge_base import KnowledgeBase
    kb = KnowledgeBase()
    return kb.stats()


@app.post("/api/brain/learn")
async def trigger_learning(req: Request):
    """
    يُطلق دورة تعلم ذاتي.
    Body: { "sources": ["nvd","cisa_kev","medium","portswigger","payloads","exploit_db"], "topic": "xss" }
    """
    data = await req.json()
    sources = data.get("sources", None)  # None = all
    topic = data.get("topic", "").strip()

    from core.learning.self_learning_loop import SelfLearningLoop
    loop = SelfLearningLoop()

    async def _run():
        if topic:
            return await loop.learn_topic(topic)
        return await loop.run_full_cycle(sources=sources, use_ai=True)

    # Run in background task so the HTTP response returns immediately
    task = asyncio.create_task(_run())
    return {"status": "learning_started", "topic": topic or "all", "sources": sources or "all"}


@app.get("/api/brain/kb/search")
async def kb_semantic_search(q: str, top_k: int = 5, source_type: str = ""):
    """بحث دلالي في قاعدة المعرفة المتعلَّمة"""
    from core.learning.knowledge_base import KnowledgeBase
    kb = KnowledgeBase()
    results = kb.semantic_search(
        q, top_k=top_k,
        source_type=source_type if source_type else None
    )
    return {"query": q, "results": results}


@app.get("/api/brain/kb/payloads/{vuln_type}")
async def get_learned_payloads(vuln_type: str, limit: int = 20):
    """يُعيد payloads متعلَّمة من KB بحسب نوع الثغرة"""
    from core.learning.knowledge_base import KnowledgeBase
    kb = KnowledgeBase()
    payloads = kb.get_payloads_by_type(vuln_type, limit=limit)
    return {"vuln_type": vuln_type, "payloads": payloads, "count": len(payloads)}


@app.get("/api/brain/kb/cve/{cve_id}")
async def get_cve_details(cve_id: str):
    """يُعيد تفاصيل CVE من KB المحلي"""
    from core.learning.knowledge_base import KnowledgeBase
    kb = KnowledgeBase()
    details = kb.get_cve_details(cve_id.upper())
    if not details:
        return JSONResponse(status_code=404, content={"error": f"{cve_id} not found in local KB"})
    return details


@app.post("/api/brain/retrieve")
async def retrieve_for_scan(req: Request):
    """
    يسترجع معرفة مرتبطة بهدف فحص — يُستخدم قبل بدء الفحص
    Body: { "target_url": "https://...", "html_snippet": "..." }
    """
    data = await req.json()
    target_url = data.get("target_url", "").strip()
    html_snippet = data.get("html_snippet", "")
    if not target_url:
        return JSONResponse(status_code=400, content={"error": "target_url required"})
    from core.learning.self_learning_loop import SelfLearningLoop
    loop = SelfLearningLoop()
    return loop.retrieve_for_scan(target_url, html_snippet)


@app.post("/api/brain/tech-stack")
async def detect_tech_stack_api(req: Request):
    """
    كشف التكنولوجيات المستخدمة في الهدف (Framework, CMS, DB, Server, Frontend, Auth)
    Body: { "target_url": "https://...", "html": "...", "headers": {...} }
    """
    data = await req.json()
    target_url = data.get("target_url", "").strip()
    if not target_url:
        return JSONResponse(status_code=400, content={"error": "target_url required"})
    html = data.get("html", "")
    headers = data.get("headers", {})

    from core.learning.aggressive_learner import AggressiveLearner
    learner = AggressiveLearner()
    result = await learner.detect_tech_stack(target_url, html=html, headers=headers)
    return result


@app.post("/api/brain/saturate")
async def aggressive_saturation_api(req: Request):
    """
    دورة الإشباع المعرفي الكاملة (Aggressive Pre-Scan Saturation)
    يمتص المعرفة الأمنية والـ CVEs والـ Payloads والـ Exploit Chains الخاصة بالهدف
    Body: { "target_url": "https://...", "html": "...", "headers": {...} }
    """
    data = await req.json()
    target_url = data.get("target_url", "").strip()
    if not target_url:
        return JSONResponse(status_code=400, content={"error": "target_url required"})
    html = data.get("html", "")
    headers = data.get("headers", {})

    from core.learning.aggressive_learner import AggressiveLearner
    learner = AggressiveLearner()
    report = await learner.aggressive_prescan_saturation(target_url, html=html, headers=headers)
    return report


@app.post("/api/brain/feedback")
async def learning_feedback(req: Request):
    """
    Feedback Loop — يُحفظ الـ confirmed finding في قاعدة المعرفة.
    يُستدعى تلقائياً من AutonomousBrain عند تأكيد الثغرة، أو يدوياً.
    Body: {
        "target": "https://...",
        "finding": { "type": "xss", "param_name": "q", "payload_used": "<script>...", "confidence": 0.9, ... }
    }
    """
    data = await req.json()
    if not data.get("finding"):
        return JSONResponse(status_code=400, content={"error": "finding required"})
    from core.learning.learning_server import _handle_feedback
    doc_id = await _handle_feedback(data)
    return {"status": "learned", "doc_id": doc_id}


@app.get("/api/brain/scheduler/status")
async def scheduler_status():
    """حالة الـ Auto-Scheduler"""
    from core.learning.learning_server import get_scheduler
    sched = get_scheduler()
    due = [s for s in sched.SCHEDULE if sched._is_due(s)]
    return {
        "schedule": sched.SCHEDULE,
        "state": sched._state,
        "due_now": due,
    }


@app.post("/api/brain/scheduler/run-now")
async def run_scheduler_now(req: Request):
    """يُشغّل الـ scheduler فوراً بغض النظر عن الـ frequency"""
    data = await req.json()
    sources = data.get("sources", None)
    from core.learning.self_learning_loop import SelfLearningLoop
    loop = SelfLearningLoop()

    async def _run():
        return await loop.run_full_cycle(sources=sources, use_ai=False)

    asyncio.create_task(_run())
    return {"status": "scheduled", "sources": sources or "all"}


# ── WebSocket: LEARN (Real-time Learning Stream) ──────────────────────────────
@app.websocket("/ws/learn")
async def ws_learn(ws: WebSocket):
    """
    WebSocket لمتابعة دورة التعلم الذاتي في الوقت الحقيقي.
    يرسل: { "sources": [...], "topic": "...", "use_ai": false }
    يستقبل: stream من events { event, message, source, saved, stats }
    """
    await ws.accept()
    try:
        data = json.loads(await ws.receive_text())
        sources = data.get("sources", None)
        topic = data.get("topic", "").strip()
        use_ai = data.get("use_ai", False)

        async def stream(event: str, msg: str, **kwargs):
            try:
                await ws.send_text(json.dumps({
                    "event": event, "message": msg,
                    "ts": time.time(), **kwargs
                }, default=str))
            except Exception:
                pass

        await stream("start", f"Learning cycle started | sources={sources or 'all'} | topic={topic or 'all'}")

        from core.learning.self_learning_loop import SelfLearningLoop
        loop = SelfLearningLoop()

        # Patch the loop's _emit to stream over WebSocket
        original_emit = loop._emit
        async def ws_emit(msg: str, data: dict = None):
            await stream("log", msg, **(data or {}))
            return await original_emit(msg, data)
        loop._emit = ws_emit

        if topic:
            result = await loop.learn_topic(topic)
        else:
            result = await loop.run_full_cycle(sources=sources, use_ai=use_ai)

        await stream("done", "Learning cycle complete",
                     kb_stats=result.get("kb_stats", {}),
                     results=result.get("results", {}),
                     duration=result.get("duration", 0))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await ws.send_text(json.dumps({"event": "error", "message": str(e)}))
        except Exception:
            pass


# ── WebSocket: CHAT ──────────────────────────────────────────
@app.websocket("/ws/chat")
async def ws_chat(ws: WebSocket):
    """Chat mode — يصنف المهمة ويوجهها للموديل الصح"""
    await ws.accept()
    try:
        from core.smart_orchestrator import SmartOrchestrator

        async def cb(ev):
            try:
                await ws.send_text(json.dumps(ev, default=str))
            except Exception:
                pass

        orchestrator = SmartOrchestrator(progress_callback=cb)

        while True:
            try:
                data = json.loads(await ws.receive_text())
                if data.get("action") == "clear_memory":
                    orchestrator.memory.clear_conversation()
                    continue

                user_input = data.get("message", "").strip()
                selected_model = data.get("model", "auto")
                if not user_input:
                    continue

                result = await orchestrator.chat(user_input, selected_model=selected_model)
                await ws.send_text(json.dumps({
                    "event": "chat_response",
                    "answer": result["answer"],
                    "route": result["route"],
                    "duration": result["duration"],
                    "gpu_status": result["gpu_status"],
                    "model_used": result.get("selected_model", selected_model),
                }, default=str))

            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await ws.send_text(json.dumps({"event": "error", "message": str(e)}))
        except Exception:
            pass


# ── Enterprise Assessment & Defense Endpoints ─────────────────

@app.post("/api/session-auth/audit")
async def audit_session_auth(req: Request):
    """تدقيق أمان الجلسات والكوكيز ورموز الـ JWT وفق OWASP A07"""
    data = await req.json()
    target = data.get("target", "").strip()
    if not target:
        return JSONResponse(status_code=400, content={"error": "target URL required"})
    from core.session_auth import AdvancedSessionManager
    sm = AdvancedSessionManager()
    result = await sm.analyze_session_security(target)
    return result


@app.post("/api/proxy/analyze-traffic")
async def analyze_proxy_traffic(req: Request):
    """تحليل حركة المرور المسجلة واستخراج الـ APIs وفحص الـ CORS والتفاضل"""
    data = await req.json()
    traffic = data.get("traffic", [])
    if not isinstance(traffic, list):
        return JSONResponse(status_code=400, content={"error": "traffic list required"})
    from core.integration import ProxyMonitoringEngine
    pme = ProxyMonitoringEngine()
    result = pme.analyze_traffic_stream(traffic)
    return result


@app.post("/api/cvss/calculate")
async def calculate_cvss_score(req: Request):
    """حساب درجة خطورة CVSS v3.1 المعتمدة لثغرة أمنية"""
    data = await req.json()
    from core.reporting import CVSSv31Calculator
    score_data = CVSSv31Calculator.calculate_base_score(
        av=data.get("av", "N"),
        ac=data.get("ac", "L"),
        pr=data.get("pr", "N"),
        ui=data.get("ui", "N"),
        s=data.get("s", "U"),
        c=data.get("c", "H"),
        i=data.get("i", "N"),
        a=data.get("a", "N")
    )
    return score_data


@app.post("/api/remediation/lookup")
async def get_remediation_guide(req: Request):
    """توليد كود الترقيع والإصلاح الأمني المباشر للمطورين"""
    data = await req.json()
    vuln_type = data.get("vuln_type", "sqli")
    from core.remediation import RemediationGenerator
    return RemediationGenerator.get_remediation_for_vuln(vuln_type)


# Global scheduler instance for app
_GLOBAL_SCHEDULER = None

def get_scheduler():
    global _GLOBAL_SCHEDULER
    if _GLOBAL_SCHEDULER is None:
        from core.scheduling import AdvancedScheduler
        _GLOBAL_SCHEDULER = AdvancedScheduler(max_concurrent_targets=3)
    return _GLOBAL_SCHEDULER


@app.post("/api/scheduler/enqueue")
async def enqueue_target_scan(req: Request):
    """إضافة هدف إلى طابور الفحص المتعدد الذكي"""
    data = await req.json()
    target = data.get("target", "").strip()
    if not target:
        return JSONResponse(status_code=400, content={"error": "target required"})
    mode = data.get("mode", "standard")
    priority = int(data.get("priority", 5))
    sched = get_scheduler()
    task_id = sched.enqueue_target(target, mode=mode, priority=priority)
    return {"status": "queued", "task_id": task_id, "target": target}


# ── HunterAI BurpAgent Subsystem ──────────────────────────────
_GLOBAL_BURP_AGENT = None
_GLOBAL_SECURITY_INTELLIGENCE = None

def get_burp_agent():
    global _GLOBAL_BURP_AGENT
    if _GLOBAL_BURP_AGENT is None:
        from agents.burp_agent import BurpAgent
        _GLOBAL_BURP_AGENT = BurpAgent()
    return _GLOBAL_BURP_AGENT

def get_security_intelligence():
    global _GLOBAL_SECURITY_INTELLIGENCE
    if _GLOBAL_SECURITY_INTELLIGENCE is None:
        burp = get_burp_agent()
        if hasattr(burp, "security_intelligence") and burp.security_intelligence:
            _GLOBAL_SECURITY_INTELLIGENCE = burp.security_intelligence
        else:
            from agents.security_intelligence import SecurityIntelligence
            _GLOBAL_SECURITY_INTELLIGENCE = SecurityIntelligence()
    return _GLOBAL_SECURITY_INTELLIGENCE

from agents.burp_agent.integrations.api import create_burp_api_router
app.include_router(create_burp_api_router(get_burp_agent()))


# ── HunterAI Security Intelligence & Scope Control Endpoints ─
@app.get("/api/intelligence/status")
async def get_intelligence_status():
    """الحالة الشاملة للذكاء الأمني والنطاق والمرور الحي"""
    si = get_security_intelligence()
    burp = get_burp_agent()
    stats = burp.get_stats() if hasattr(burp, "get_stats") else {}
    rule = si.scope_guard.rule
    profile = si.learning_profile.get_profile().model_dump() if hasattr(si, "learning_profile") else {}
    return {
        "status": "online",
        "scope": {
            "target": rule.target,
            "allowed_domains": rule.allowed_domains,
            "excluded_paths": rule.excluded_paths,
            "allow_active_tests": rule.allow_active_tests
        },
        "traffic_stats": stats,
        "learning_profile": profile,
        "subsystems": {
            "autonomous_brain": "connected",
            "burp_agent": "listening_8085",
            "security_intelligence": "active",
            "scope_guard": "defense_in_depth_enforced",
            "event_bus": "bridged"
        }
    }


@app.post("/api/intelligence/scope")
async def update_intelligence_scope(req: Request):
    """تحديث سياسة النطاق وحظر المسارات الحساسة والتصريح"""
    data = await req.json()
    from agents.security_intelligence.schemas import ScopeRule
    target = data.get("target", "*").strip()
    allowed = data.get("allowed_domains", [])
    excluded = data.get("excluded_paths", ["/admin/delete", "/system/reset", "/logout"])
    allow_active = bool(data.get("allow_active_tests", False))

    rule = ScopeRule(
        target=target,
        allowed_domains=allowed,
        excluded_paths=excluded,
        allow_active_tests=allow_active
    )
    si = get_security_intelligence()
    si.set_scope(rule)
    return {
        "status": "updated",
        "target": target,
        "mode": "ACTIVE" if allow_active else "PASSIVE",
        "allowed_domains": allowed,
        "excluded_paths": excluded
    }


@app.post("/api/intelligence/explain")
async def explain_security_concept(req: Request):
    """توليد شرح تعليمي تفاعلي عبر المستويات الأربعة"""
    data = await req.json()
    subject = data.get("subject", "").strip()
    lang = data.get("language", "ar")
    if not subject:
        return JSONResponse(status_code=400, content={"error": "Subject required"})
    si = get_security_intelligence()
    explanations = await si.explain(subject, language=lang)
    return {"subject": subject, "explanations": explanations}


@app.post("/api/intelligence/quiz/start")
async def start_security_quiz(req: Request):
    """بدء اختبار سيناريو أمني تفاعلي لموضوع معين"""
    data = await req.json()
    topic = data.get("topic", "bola").strip()
    si = get_security_intelligence()
    quiz = await si.start_quiz(topic)
    return quiz.model_dump()


@app.post("/api/intelligence/quiz/evaluate")
async def evaluate_security_quiz(req: Request):
    """تقييم إجابة المستخدم في الاختبار وتحديث ملف التعلم الشخصي"""
    data = await req.json()
    quiz_data = data.get("quiz")
    choice_idx = int(data.get("choice_idx", 0))
    if not quiz_data:
        return JSONResponse(status_code=400, content={"error": "Quiz object required"})
    from agents.security_intelligence.schemas import QuizQuestion
    quiz = QuizQuestion(**quiz_data)
    si = get_security_intelligence()
    evaluation = await si.evaluate_quiz_answer(quiz, choice_idx)
    return evaluation.model_dump()


@app.post("/api/intelligence/research")
async def research_threat(req: Request):
    """البحث الأمني في قواعد بيانات CVE و OWASP مع التخزين المؤقت الذكي"""
    data = await req.json()
    topic = data.get("topic", "").strip()
    if not topic:
        return JSONResponse(status_code=400, content={"error": "Topic or CVE required"})
    si = get_security_intelligence()
    report = await si.research(topic)
    return report.model_dump()


@app.get("/api/intelligence/profile")
async def get_user_learning_profile():
    """الحصول على ملف التعلم الشخصي ومستوى المستخدم الحالي"""
    si = get_security_intelligence()
    return si.learning_profile.get_profile().model_dump()


@app.get("/api/intelligence/state")
async def get_live_security_state():
    """الحصول على لقطة حية لذاكرة حالة الهجوم والأمن (SecurityState Snapshot)"""
    si = get_security_intelligence()
    brain = getattr(app.state, "active_brain", None)
    if brain and getattr(brain, "security_state", None):
        return brain.security_state.get_snapshot()

    from core.state.security_state import SecurityState
    default_state = getattr(app.state, "default_security_state", None)
    if not default_state:
        target_rule = si.scope_guard.rule.target or "target.local"
        default_state = SecurityState(target=target_rule)
        default_state.add_asset(host=target_rule)
        app.state.default_security_state = default_state
    return default_state.get_snapshot()


@app.post("/api/gateway/execute")
async def execute_governed_action(req: Request):
    """تنفيذ مقترح أمني عبر بوابة الأدوات المحكومة (Governed Tool Gateway)"""
    data = await req.json()
    from core.gateway.schemas import ActionProposal
    proposal = ActionProposal(**data)

    brain = getattr(app.state, "active_brain", None)
    if brain and getattr(brain, "tool_gateway", None):
        gateway = brain.tool_gateway
    else:
        from core.gateway.tool_gateway import GovernedToolGateway
        from core.gateway.policy_engine import PolicyEngine
        si = get_security_intelligence()
        policy = PolicyEngine(scope_guard=si.scope_guard)
        gateway = GovernedToolGateway(policy_engine=policy)

    result = await gateway.execute_proposal(proposal)
    return result.model_dump()


@app.post("/api/planner/mission")
async def execute_planner_mission(req: Request):
    """إطلاق مهمة أمنية موجهة بالهدف عبر محرك فضاء الحالات (State-Space Planner)"""
    data = await req.json()
    from core.planner.schemas import SecurityGoal, GoalType
    goal = SecurityGoal(**data)

    max_steps = data.get("max_steps", 8)
    brain = getattr(app.state, "active_brain", None)
    if brain and getattr(brain, "planner", None):
        report = await brain.run_mission(goal, max_steps=max_steps)
    else:
        from core.planner.state_space_planner import StateSpacePlanner
        from core.state.security_state import SecurityState
        from core.gateway.tool_gateway import GovernedToolGateway
        from core.gateway.policy_engine import PolicyEngine
        si = get_security_intelligence()
        state = SecurityState(target=goal.target)
        policy = PolicyEngine(scope_guard=si.scope_guard)
        gateway = GovernedToolGateway(policy_engine=policy, security_state=state)
        planner = StateSpacePlanner(security_state=state, tool_gateway=gateway)
        report = await planner.run_mission(goal, max_steps=max_steps)

    return report.model_dump()


@app.get("/api/attack_graph/snapshot")
async def get_attack_graph_snapshot():
    """الحصول على لقطة حية للرسم البياني السببي للهجوم ونصف قطر الانفجار"""
    brain = getattr(app.state, "active_brain", None)
    if brain and getattr(brain, "attack_graph", None):
        return brain.attack_graph.to_dict()

    from core.attack_graph.graph import CausalAttackGraph
    default_graph = getattr(app.state, "default_attack_graph", None)
    if not default_graph:
        default_graph = CausalAttackGraph(target="target.local")
        app.state.default_attack_graph = default_graph
    return default_graph.to_dict()


@app.post("/api/multi_agent/analyze")
async def execute_multi_agent_investigation(req: Request):
    """تنسيق فحص واستدلال أمني متقدم عبر فريق الوكلاء المتخصصين"""
    data = await req.json()
    target = data.get("target", "target.local")
    brain = getattr(app.state, "active_brain", None)
    if brain and getattr(brain, "lead_analyst", None):
        return await brain.lead_analyst.coordinate_investigation(target=target)

    from core.multi_agent.specialists import LeadAnalyst
    analyst = LeadAnalyst(target=target)
    return await analyst.coordinate_investigation(target=target)


@app.post("/api/reasoning/investigate")
async def run_epistemic_investigation(req: Request):
    """تشغيل حلقة الاستدلال المعرفي المغلقة على هدف مع فحص EIG وتحديث المعتقدات"""
    data = await req.json()
    target = data.get("target", "target.local")
    from core.reasoning.reasoning_loop import AutonomousReasoningLoop
    from core.reasoning.belief_state import BeliefState
    from core.reasoning.action_model import ActionDescriptor, ActionKind

    belief = BeliefState()
    loop = AutonomousReasoningLoop(target=target, belief_state=belief)

    # Sample candidate actions for investigation
    candidates = [
        ActionDescriptor(
            action_kind=ActionKind.DISCOVERY,
            tool_name="httpx",
            target=target,
            rationale="Discover attack surface"
        )
    ]
    step_res = loop.step(candidates=candidates, executor_callback=lambda a: ("generic_200", None))
    return {
        "investigation_id": belief.investigation_id,
        "version": belief.version,
        "step_result": step_res,
        "latest_snapshot": belief.get_latest_snapshot().to_dict()
    }


@app.get("/api/evaluation/benchmark")
async def run_reasoning_benchmark():
    """تشغيل إطار التقييم المعياري وإرجاع بطاقة أداء العقل الاستدلالي (Scorecard)"""
    from evaluation.benchmark_runner import BenchmarkRunner
    runner = BenchmarkRunner()
    scorecards = runner.run_all_benchmarks()
    return {
        "scorecards": [card.model_dump() for card in scorecards],
        "summary": {
            "total_scenarios": len(scorecards),
            "mean_score": round(sum(c.overall_reasoning_score for c in scorecards) / len(scorecards), 1),
            "zero_false_positives": all(c.false_positive_rate_pct == 0.0 for c in scorecards)
        }
    }


# ── Learning Subsystem Endpoints ─────────────────────────────
@app.get("/api/learning/curriculum")
async def get_curriculum():
    """عرض المستويات الـ 10 للمنهج الأمني وموضوعاتها"""
    from core.learning.curriculum import SecurityCurriculum
    curriculum = SecurityCurriculum()
    return {
        "levels": [lvl.model_dump() for lvl in curriculum.get_all_levels()],
        "total_levels": len(curriculum.levels)
    }


@app.post("/api/learning/teach")
async def teach_level(req: Request):
    """طرح تحدي تعليمي أو تقييم استدلال الـ Agent لمستوى معين"""
    data = await req.json()
    level_num = data.get("level", 3)
    actions = data.get("actions", [])
    hyps = data.get("hypotheses", {})
    evids = data.get("evidence", [])

    from core.learning.teacher_agent import TeacherAgent
    teacher = TeacherAgent()

    if actions or hyps or evids:
        eval_res = teacher.evaluate_reasoning_trace(level_num, actions, hyps, evids)
        return {"evaluation": eval_res.model_dump()}

    challenge = teacher.present_challenge(level_num)
    return {"challenge": challenge}


@app.get("/api/learning/experiences")
async def get_experiences():
    """عرض الخبرات السابقة والدروس المستفادة من التحقيقات المكتملة"""
    from core.learning.experience_store import ExperienceStore
    store = ExperienceStore()
    episodes = store.get_recent_episodes(limit=20)
    return {
        "episodes": [ep.model_dump() for ep in episodes],
        "count": len(episodes)
    }


@app.post("/api/learning/rag_query")
async def query_learning_rag(req: Request):
    """استعلام محرك RAG لاسترجاع المعرفة والتجارب المناسبة لترافيك أو إشارات معينة"""
    data = await req.json()
    signals = data.get("signals", [])
    topic = data.get("topic")

    from core.learning.retrieval import LearningRetrievalEngine
    rag = LearningRetrievalEngine()
    result = rag.retrieve_context(signals=signals, topic=topic)
    return result


@app.get("/api/learning/sync")
async def sync_learning_knowledge():
    """مزامنة واكتشاف السيناريوهات والـ CVEs الجديدة تلقائياً بدون تعديل كود"""
    from core.learning.scenario_loader import DynamicScenarioLoader
    loader = DynamicScenarioLoader()
    report = loader.sync_all()
    return {"sync_report": report}


@app.get("/api/learning/sqli/curriculum")
async def get_sqli_curriculum():
    """عرض سيناريوهات تدريب SQLi الـ 10 مع إخفاء الحل عن المتدرب"""
    from core.learning.scenario_loader import DynamicScenarioLoader
    loader = DynamicScenarioLoader()
    scenarios = []
    for s in loader.loaded_scenarios.values():
        if "sqli" in s.get("scenario_id", "").lower():
            # Strip hidden_truth for student view
            safe_copy = {k: v for k, v in s.items() if k != "hidden_truth"}
            scenarios.append(safe_copy)
    return {
        "sqli_scenarios": sorted(scenarios, key=lambda x: x.get("difficulty", 0)),
        "total": len(scenarios)
    }


@app.post("/api/learning/sqli/evaluate")
async def evaluate_sqli_readiness(req: Request):
    """تقييم إتقان الـ Agent لمنهج SQL Injection وإصدار بطاقة التخرج"""
    data = await req.json()
    attempts = data.get("attempts", [])

    from core.learning.sqli_evaluator import SQLiGraduationEvaluator
    evaluator = SQLiGraduationEvaluator()
    scorecard = evaluator.evaluate_full_curriculum(attempts)
    return {
        "scorecard": scorecard.model_dump(),
        "terminal_report": scorecard.format_terminal_scorecard()
    }


@app.get("/api/learning/skill_graph")
async def get_skill_graph():
    """عرض هيكل المهارات الدقيقة ونقاط الضعف المحددة للـ Agent"""
    from core.learning.skill_graph import SkillGraph
    sg = SkillGraph()
    skills = sg.get_all_skills()
    weakest = sg.diagnose_weakest_skills(limit=3)
    recommended = sg.recommend_next_scenario_skill()
    return {
        "skills": [s.model_dump() for s in skills],
        "diagnosed_weak_points": [w.model_dump() for w in weakest],
        "recommended_next_training_skill": recommended.model_dump() if recommended else None,
        "total_skills": len(skills)
    }


@app.post("/api/learning/scenarios/generate_novel")
async def generate_novel_scenario(req: Request):
    """توليد سيناريو تدريبي إجرائي جديد تماماً وغير محفوظ لأي مهارة"""
    data = await req.json()
    skill_id = data.get("skill_id", "sqli_boolean_differential")
    is_vulnerable = data.get("is_vulnerable")

    from core.learning.scenario_generator import ProceduralScenarioGenerator
    scenario = ProceduralScenarioGenerator.generate_scenario(
        skill_id=skill_id,
        is_vulnerable=is_vulnerable
    )
    # Strip hidden_truth for student view if requested
    safe_view = {k: v for k, v in scenario.items() if k != "hidden_truth"}
    return {
        "scenario": safe_view,
        "scenario_id": scenario["scenario_id"]
    }


@app.post("/api/learning/exam/evaluate_run")
async def evaluate_exam_run(req: Request):
    """تقييم مستقل في وضع الامتحان وحساب نسبة الخطأ في المعايرة (ECE)"""
    data = await req.json()
    scenario = data.get("scenario", {})
    submission = data.get("submission", {})

    from core.learning.independent_evaluator import IndependentEvaluator
    evaluator = IndependentEvaluator()
    result = evaluator.evaluate_solution(scenario, submission)
    return {
        "evaluation": result.model_dump(),
        "expected_calibration_error": evaluator.get_calibration_error()
    }


# ── Burp Sensor & Evidence Endpoints ──────────────────────────────
_burp_sensor_bridge = None

def get_burp_sensor_bridge():
    global _burp_sensor_bridge
    if _burp_sensor_bridge is None:
        from agents.burp_agent.extension.burp_extension_bridge import BurpExtensionBridge
        _burp_sensor_bridge = BurpExtensionBridge()
    return _burp_sensor_bridge


@app.post("/api/burp/ingest")
async def ingest_burp_traffic(req: Request):
    """استقبال الترافيك المباشر من إضافة Burp وتطبيعه واستخراج الأدلة والأرتيفاكت"""
    data = await req.json()
    bridge = get_burp_sensor_bridge()
    receipt = await bridge.ingest_transaction(
        method=data.get("method", "GET"),
        url=data.get("url", "http://localhost"),
        request_headers=data.get("request_headers", {}),
        request_body=data.get("request_body", ""),
        response_status=data.get("response_status", 200),
        response_headers=data.get("response_headers", {}),
        response_body=data.get("response_body", ""),
        tool=data.get("tool", "proxy")
    )
    return {"receipt": receipt.model_dump()}


@app.get("/api/burp/artifacts")
async def list_burp_artifacts():
    """عرض كافة الملفات والأرتيفاكت الملتقطة من الرفع والتنزيل"""
    bridge = get_burp_sensor_bridge()
    artifacts = bridge.artifacts.get_all_artifacts(limit=50)
    return {"artifacts": [a.model_dump() for a in artifacts], "total": len(artifacts)}


@app.get("/api/burp/evidence")
async def list_unified_evidence():
    """عرض سجل الأدلة الجنائية الموحدة المشفرة بالـ SHA256"""
    bridge = get_burp_sensor_bridge()
    evidence_list = bridge.evidence_store.get_all_evidence(limit=50)
    return {"evidence": [e.model_dump() for e in evidence_list], "total": len(evidence_list)}


@app.get("/api/burp/sensory_events")
async def get_sensory_events():
    """عرض آخر الأحداث الحسية المبثوثة على الـ SensoryEventBus"""
    bridge = get_burp_sensor_bridge()
    events = bridge.bus.get_recent_events(limit=50)
    return {"events": [ev.model_dump() for ev in events], "total": len(events)}


# ── Tool Orchestration & Repeater Endpoints ──────────────────────────────
_tool_orchestrator = None

def get_tool_orchestrator():
    global _tool_orchestrator
    if _tool_orchestrator is None:
        from core.orchestration.tool_orchestrator import ToolOrchestrator
        _tool_orchestrator = ToolOrchestrator()
    return _tool_orchestrator


@app.get("/api/orchestration/tools")
async def list_orchestrated_tools():
    """استعراض كافة الأدوات المسجلة في الـ ToolRegistry"""
    orch = get_tool_orchestrator()
    tools = orch.registry.list_tools()
    return {"tools": [t.model_dump() for t in tools], "total": len(tools)}


@app.post("/api/orchestration/execute")
async def execute_orchestrated_intent(req: Request):
    """تنفيذ نية تحقيقية مركبة للـ Brain عبر الأدوات المناسبة"""
    data = await req.json()
    intent = data.get("intent", "EXPLORE")
    params = data.get("params", {})
    orch = get_tool_orchestrator()
    result = await orch.execute_investigative_intent(intent=intent, params=params)
    return {"orchestration_result": result.model_dump()}


@app.post("/api/repeater/experiment")
async def create_and_run_repeater_experiment(req: Request):
    """إنشاء وتشغيل تجربة علمية مقننة داخل مساحة عمل الـ Repeater"""
    data = await req.json()
    orch = get_tool_orchestrator()
    exp = orch.burp.create_repeater_experiment(
        base_tx_id=data.get("base_tx_id", "tx_001"),
        hypothesis=data.get("hypothesis", "SQL_INJECTION"),
        mutation_description=data.get("mutation_description", "Probe mutation"),
        mutated_request=data.get("mutated_request", {"method": "GET", "url": "http://localhost"})
    )
    executed = await orch.burp.execute_experiment(exp.experiment_id)
    return {"experiment": executed.model_dump()}


@app.post("/api/analyzer/diff")
async def compare_responses_diff(req: Request):
    """مقارنة تفاضلية سلوكية دقيقة بين استجابة الأساس واستجابة الاختبار"""
    data = await req.json()
    orch = get_tool_orchestrator()
    diff = orch.analyzer.compare_responses(
        baseline_status=data.get("baseline_status", 200),
        baseline_body=data.get("baseline_body", ""),
        test_status=data.get("test_status", 200),
        test_body=data.get("test_body", ""),
        transaction_id=data.get("transaction_id", "tx_diff_api")
    )
    return {"differential": diff.model_dump()}


@app.post("/api/orchestration/run_investigation")
async def run_full_investigation(req: Request):
    """تشغيل حلقة التحقيق الأمني الذاتي المستقلة بالكامل على هدف محدد"""
    data = await req.json()
    target_url = data.get("target_url", "https://target.local")
    hypothesis = data.get("hypothesis", "SQL_INJECTION")
    skill = data.get("skill", "sqli_boolean_differential")

    from core.orchestration.investigation_loop import AutonomousInvestigationEngine
    engine = AutonomousInvestigationEngine()
    report = await engine.run_investigation_cycle(
        target_url=target_url,
        hypothesis_name=hypothesis,
        skill_to_train=skill
    )
    return {
        "report": report.model_dump(),
        "terminal_summary": report.format_terminal_summary()
    }













# ── Agent Co-Pilot & Interactive Advice State ─────────────────
class AgentCoPilotState:
    def __init__(self):
        self.active_hints: List[Dict[str, Any]] = []
        self.pending_questions: List[Dict[str, Any]] = []
        self.answered_questions: List[Dict[str, Any]] = []

    def add_hint(self, hint: str, category: str = "general") -> Dict[str, Any]:
        record = {
            "id": f"hint_{int(time.time()*1000)}",
            "hint": hint,
            "category": category,
            "timestamp": time.time(),
            "formatted_time": time.strftime("%H:%M:%S")
        }
        self.active_hints.append(record)
        return record

    def add_question(self, question: str, options: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        q = {
            "id": f"q_{int(time.time()*1000)}",
            "question": question,
            "options": options or ["نعم، وافق وتابع", "تخطى هذا المسار", "توجيه مخصص"],
            "context": context or {},
            "timestamp": time.time(),
            "status": "pending"
        }
        self.pending_questions.append(q)
        return q

    def answer_question(self, q_id: str, answer: str) -> Optional[Dict[str, Any]]:
        for q in self.pending_questions:
            if q["id"] == q_id:
                q["answer"] = answer
                q["status"] = "answered"
                self.pending_questions.remove(q)
                self.answered_questions.append(q)
                return q
        return None

copilot_state = AgentCoPilotState()


@app.post("/api/agent/hint")
async def post_agent_hint(req: Request):
    """إرسال نصيحة أو توجيه مباشر من المستخدم للـ Agent أثناء التفكير والتنفيذ"""
    data = await req.json()
    hint_text = data.get("hint", "").strip()
    category = data.get("category", "general").strip()
    if not hint_text:
        return JSONResponse(status_code=400, content={"error": "Hint text is required"})

    rec = copilot_state.add_hint(hint_text, category)
    return {"status": "accepted", "hint": rec, "message": "تم إرسال توجيهك إلى عقل الـ Agent فوراً!"}


@app.get("/api/agent/hints")
async def get_agent_hints():
    """استرجاع كافة النصائح والتوجيهات النشطة المسجلة للـ Agent"""
    return {"hints": copilot_state.active_hints, "total": len(copilot_state.active_hints)}


@app.get("/api/agent/questions")
async def get_agent_questions():
    """استرجاع أي استفسارات أو أسئلة موجهة من الـ Agent للمستخدم (Human-in-the-loop)"""
    return {
        "pending_questions": copilot_state.pending_questions,
        "answered_questions": copilot_state.answered_questions[-5:]
    }


@app.post("/api/agent/answer")
async def answer_agent_question(req: Request):
    """إرسال إجابة المستخدم على استشارة الـ Agent"""
    data = await req.json()
    q_id = data.get("question_id", "").strip()
    answer = data.get("answer", "").strip()
    if not q_id or not answer:
        return JSONResponse(status_code=400, content={"error": "question_id and answer are required"})

    res = copilot_state.answer_question(q_id, answer)
    if not res:
        return JSONResponse(status_code=404, content={"error": "Question not found or already answered"})

    # Record answer as a hint for the agent
    copilot_state.add_hint(f"إجابة على السؤال: {answer}", category="user_decision")
    return {"status": "answered", "question": res}

@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    """Scan mode — pentest كامل على هدف"""
    await ws.accept()
    try:
        data = json.loads(await ws.receive_text())
        target = data.get("target", "")
        if not target:
            await ws.send_text(json.dumps({"event": "error", "message": "No target"}))
            return

        async def cb(ev):
            try:
                await ws.send_text(json.dumps(ev, default=str))
            except Exception:
                pass

        use_proxy = data.get("use_proxy", False)
        burp_proxy = data.get("burp_proxy", "127.0.0.1:8080")
        auth_data = data.get("auth", {})

        from core.smart_orchestrator import SmartOrchestrator
        result = await SmartOrchestrator(progress_callback=cb).run_scan(
            target=target,
            mode=data.get("mode", "bugbounty_full"),
            use_browser=data.get("use_browser", False),
            use_proxy=use_proxy,
            burp_proxy=burp_proxy,
            auth=auth_data
        )
        await ws.send_text(json.dumps({"event": "done", **result}, default=str))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await ws.send_text(json.dumps({"event": "error", "message": str(e)}))
        except Exception:
            pass


# ── Autonomous Mission Agent API Endpoints ───────────────────
_active_mission_tasks: dict = {}


@app.post("/api/mission/start")
async def start_autonomous_mission(req: Request):
    """بدء مهمة فحص أمني مستقلة باستخدام AutonomousMissionAgent والـ Skills المكتشفة"""
    data = await req.json()
    target = data.get("target", "").strip()
    mode = data.get("mode", "full")
    session_id = data.get("session_id") or f"msn_{int(time.time())}"

    if not target:
        return JSONResponse(status_code=400, content={"error": "Target parameter is required"})

    from agents.autonomous_mission_agent import AutonomousMissionAgent
    from agents.base_agent import AgentTask

    agent = AutonomousMissionAgent(tool_manager=tm)
    task = AgentTask(target=target, mode=mode, session_id=session_id, extra=data.get("extra", {}))

    # Background async task execution
    async_task = asyncio.create_task(agent.run(task))
    _active_mission_tasks[session_id] = {
        "target": target,
        "mode": mode,
        "agent": agent,
        "async_task": async_task,
        "started_at": time.time()
    }

    return {
        "status": "started",
        "session_id": session_id,
        "target": target,
        "mode": mode,
        "workspace": str(agent.workspace.get_workspace_path(target, session_id))
    }


@app.websocket("/ws/mission/{session_id}")
async def ws_mission_progress(ws: WebSocket, session_id: str):
    """بث أحداث وتقدم المهمة الحية لحظة بلحظة عبر WebSocket للمتصفح"""
    await ws.accept()
    from agents.autonomous_mission_agent import register_mission_listener, unregister_mission_listener

    async def on_event(event_data: dict):
        try:
            await ws.send_text(json.dumps(event_data, default=str))
        except Exception:
            pass

    register_mission_listener(session_id, on_event)
    try:
        # Keep connection open and handle incoming ping/cancel signals
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text(json.dumps({"event": "pong"}))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        unregister_mission_listener(session_id, on_event)



@app.get("/api/mission/skills")
async def list_mission_skills():
    """استعراض جميع المهارات المكتشفة في مجلد skills/"""
    from core.skill_registry import SkillRegistry
    registry = SkillRegistry()
    registry.discover()
    return registry.registry_summary()


@app.get("/api/mission/{session_id}/status")
async def get_mission_status(session_id: str, target: str = ""):
    """الحصول على حالة المهمة الحالية ومحتوى الـ State JSON"""
    from core.workspace_manager import WorkspaceManager
    from core.mission_state import MissionState
    from pathlib import Path

    ws = WorkspaceManager()
    # If target is not provided in query, search matching session folders
    state_file = None
    if target:
        sf = ws.get_state_file(target, session_id)
        if sf.exists():
            state_file = sf
    else:
        # Search for session_id in workspace
        for p in ws.root.rglob("mission_state.json"):
            if session_id in str(p.parent):
                state_file = p
                break

    if not state_file or not state_file.exists():
        return JSONResponse(status_code=404, content={"error": f"Mission session {session_id} not found"})

    state = MissionState.load(state_file)
    return state.summary()


@app.get("/api/mission/{session_id}/report")
async def get_mission_report(session_id: str, target: str = ""):
    """استرجاع التقرير النهائي للمهمة بصيغة Markdown"""
    from core.workspace_manager import WorkspaceManager
    from pathlib import Path

    ws = WorkspaceManager()
    report_file = None
    if target:
        rf = ws.get_report_path(target, session_id)
        if rf.exists():
            report_file = rf
    else:
        for p in ws.root.rglob("final_report.md"):
            if session_id in str(p.parent.parent):
                report_file = p
                break

    if not report_file or not report_file.exists():
        return JSONResponse(status_code=404, content={"error": f"Report for session {session_id} not found or not yet generated"})

    content = report_file.read_text(encoding="utf-8")
    return {"session_id": session_id, "report_markdown": content}


# ── Bug Bounty Skills & Checklists API Endpoints ─────────────

@app.get("/api/checklists")
async def list_security_checklists():
    """استعراض جميع القوائم المرجعية الأمنية المتاحة (Web, API, Cloud, Source, AI)"""
    from core.security_checklists import SecurityChecklistEngine
    return {
        "categories": SecurityChecklistEngine.list_all_categories(),
        "summary_markdown": SecurityChecklistEngine.export_markdown_summary()
    }


@app.get("/api/checklists/{category}")
async def get_security_checklist(category: str):
    """استرجاع بنود قائمة مرجعية معينة"""
    from core.security_checklists import SecurityChecklistEngine
    cl = SecurityChecklistEngine.get_checklist(category)
    if not cl:
        return JSONResponse(status_code=404, content={"error": f"Checklist category '{category}' not found"})
    return {
        "category": cl.category,
        "description": cl.description,
        "items": [
            {
                "id": it.item_id,
                "title": it.title,
                "phase": it.phase,
                "description": it.description,
                "verification_method": it.verification_method,
                "risk_if_missing": it.risk_if_missing
            }
            for it in cl.items
        ]
    }


@app.get("/api/ai/modes")
async def list_ai_prompts_and_modes():
    """استعراض أنماط التفكير المتخصصة للذكاء الاصطناعي (Recon, API, Cloud, Source, AI)"""
    from core.master_prompts import MasterPromptOrchestrator
    return MasterPromptOrchestrator.list_available_modes()


@app.get("/api/cloud/matrix")
async def list_cloud_metadata_matrix():
    """استعراض مصفوفة تأمين الخدمات السحابية ونقاط الـ Metadata (AWS, GCP, Azure, etc.)"""
    from core.cloud_metadata_matrix import CloudMetadataMatrix
    profiles = CloudMetadataMatrix.list_all_profiles()
    return [
        {
            "cloud_provider": p.cloud_provider,
            "imds_version": p.imds_version,
            "endpoint_url": p.endpoint_url,
            "required_headers": p.required_headers,
            "sensitive_paths": p.sensitive_paths,
            "remediation": p.remediation
        }
        for p in profiles
    ]


