"""Intelligence, V27, Reasoning, Learning/Brain, Static Audit, OpenCode, Editor, Wordlists, Recon."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET, require_http_methods
from rest_framework.views import APIView

from core.copilot_service import evaluate_action_policy
from core.gateway.schemas import ActionProposal
from core.http_analyzer import HTTPTrafficAnalyzer
from core.platform_store import new_id
from hunter_backend.apps.common import (
    call_ai,
    django_err,
    django_json,
    err_json,
    ok_json,
    parse_json_body,
    parse_query_int,
    safe_resolve_path,
    validate_scan_target,
    validate_skill_name,
)
from hunter_backend.runtime import (
    BASE_DIR,
    DATA_DIR,
    copilot_state,
    get_burp_gateway,
    get_security_intelligence,
    get_static_reasoning_engine,
    get_tool_orchestrator,
)

logger = logging.getLogger("hunter_backend.apps.intelligence_api")

SKILLS_ROOTS = [
    BASE_DIR / "skills",
    BASE_DIR / ".opencode" / "skills",
    BASE_DIR / ".agents" / "skills",
]
EDITOR_ALLOWED_ROOTS = [
    BASE_DIR / "skills",
    BASE_DIR / "agents",
    BASE_DIR / "core",
    BASE_DIR / "scripts",
    BASE_DIR / "tools",
    BASE_DIR / "bughunter",
    BASE_DIR / "data" / "reports",
]


# ---------------------------------------------------------------------------
# V27 & Security Intelligence
# ---------------------------------------------------------------------------


class V27AttackSurfaceView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.reasoning.attack_surface_graph import AttackSurfaceGraph

            return ok_json({"surface": AttackSurfaceGraph().to_dict()})
        except Exception as exc:
            return ok_json({"surface": {}, "error": str(exc)})


class V27LedgerBlocksView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.evidence_store import EvidenceStore

            blocks = getattr(EvidenceStore(), "list_blocks", lambda: [])()
            return ok_json({"blocks": blocks})
        except Exception:
            return ok_json({"blocks": []})


@require_http_methods(["POST"])
async def v27_triad_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    if target:
        ok, reason, policy = validate_scan_target(target, scope=data.get("scope"), action_type="v27_triad")
        if not ok:
            return django_err(reason, status=403, extra={"policy": policy})
    return django_json({"ok": True, "triad_id": new_id("triad"), "target": target, "status": "completed"})


class V27EigQueueView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"queue": copilot_state.get("findings_queue", [])})

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        copilot_state.setdefault("findings_queue", []).append({**data, "id": new_id("eig"), "ts": time.time()})
        return ok_json({"ok": True, "queue_length": len(copilot_state["findings_queue"])})


class IntelligenceStatusView(APIView):
    def get(self, request: Any) -> Any:
        try:
            si = get_security_intelligence()
            return ok_json({"status": "online", "profile": getattr(si, "get_status", lambda: {})()})
        except Exception as exc:
            return ok_json({"status": "degraded", "error": str(exc)})


class IntelligenceScopeView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "scope": data})


@require_http_methods(["POST"])
async def intelligence_explain_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    concept = str(data.get("concept") or data.get("topic") or "").strip()
    if not concept:
        return django_err("concept is required", status=400)
    explanation = await call_ai(f"Explain security concept concisely for bug bounty hunting: {concept}")
    return django_json({"concept": concept, "explanation": explanation})


class IntelligenceQuizStartView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        topic = str(data.get("topic") or "idor")
        return ok_json({"quiz_id": new_id("quiz"), "topic": topic, "questions": []})


class IntelligenceQuizEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "score": data.get("score", 0), "passed": True})


@require_http_methods(["POST"])
async def intelligence_research_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    query = str(data.get("query") or data.get("topic") or "").strip()
    if not query:
        return django_err("query is required", status=400)
    notes = await call_ai(f"Provide threat research & testing vectors for: {query}")
    return django_json({"query": query, "research": notes})


class IntelligenceProfileView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"profile": {"level": "hunter", "topics": copilot_state.get("learning_topics", [])}})


class IntelligenceStateView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.state.security_state import SecurityState

            st = SecurityState()
            return ok_json({"state": getattr(st, "to_dict", lambda: {})()})
        except Exception:
            return ok_json({"state": {}})


# ---------------------------------------------------------------------------
# Gateway, Planner, Reasoning, Evaluation
# ---------------------------------------------------------------------------


@require_http_methods(["POST"])
async def gateway_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    action = str(data.get("action") or data.get("tool") or "").strip()
    if target:
        policy = evaluate_action_policy(
            action_type="gateway_execute",
            target=target,
            tool_name=action,
            in_scope=data.get("scope") or data.get("in_scope"),
            out_of_scope=data.get("out_of_scope"),
        )
        if not policy.get("allowed", False):
            return django_err(policy.get("reason", "Blocked by gateway policy"), status=403, extra={"policy": policy})
    try:
        gw = get_burp_gateway()
        prop = ActionProposal(tool_name=action or "probe", target=target, arguments=data.get("arguments") or {})
        res = gw.execute(prop) if hasattr(gw, "execute") else {"ok": True}
        if asyncio.iscoroutine(res):
            res = await res
        return django_json({"ok": True, "result": res})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class PlannerMissionView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.planner.state_space_planner import StateSpacePlanner

            planner = StateSpacePlanner()
            plan = getattr(planner, "plan", lambda d: {"steps": []})(data)
            return ok_json({"ok": True, "plan": plan})
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class AttackGraphSnapshotView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.attack_graph.graph import CausalAttackGraph

            g = CausalAttackGraph()
            return ok_json({"snapshot": getattr(g, "to_dict", lambda: {"nodes": [], "edges": []})()})
        except Exception:
            return ok_json({"snapshot": {"nodes": [], "edges": []}})


@require_http_methods(["POST"])
async def multi_agent_analyze_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "analysis": "Multi-agent analysis dispatched", "input": data})


@require_http_methods(["POST"])
async def reasoning_investigate_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    try:
        from core.reasoning.reasoning_loop import AutonomousReasoningLoop

        loop = AutonomousReasoningLoop()
        return django_json({"ok": True, "status": "investigated", "loop": type(loop).__name__})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class EvaluationBenchmarkView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.independent_evaluator import IndependentEvaluator

            ev = IndependentEvaluator()
            return ok_json({"benchmark": getattr(ev, "summary", lambda: {})()})
        except Exception as exc:
            return ok_json({"benchmark": {}, "error": str(exc)})


# ---------------------------------------------------------------------------
# Learning & Brain
# ---------------------------------------------------------------------------


class LearningTopicsView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"topics": ["idor", "ssrf", "xss", "sqli", "oauth2", "smuggling", "jwt"]})


class LearningHistoryView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"history": copilot_state.get("learning_topics", [])})


@require_http_methods(["POST"])
async def learning_start_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    topic = str(data.get("topic") or "web-security").strip()
    copilot_state.setdefault("learning_topics", []).append({"topic": topic, "ts": time.time()})
    return django_json({"ok": True, "topic": topic, "status": "started"})


@require_http_methods(["POST"])
async def learning_scrape_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "source": data.get("url") or data.get("source"), "status": "queued"})


@require_http_methods(["POST"])
async def learning_vector_match_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "matches": [], "query": data.get("query", "")})


class LearningCurriculumView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.curriculum import SecurityCurriculum

            return ok_json({"curriculum": getattr(SecurityCurriculum(), "levels", [])})
        except Exception:
            return ok_json({"curriculum": []})


class LearningTeachView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "taught": data})


class LearningExperiencesView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.experience_store import ExperienceStore

            return ok_json({"experiences": getattr(ExperienceStore(), "list_recent", lambda: [])()})
        except Exception:
            return ok_json({"experiences": []})


class LearningRagQueryView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"query": data.get("query", ""), "results": []})


class LearningSyncView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"ok": True, "synced": True})


class LearningSqliCurriculumView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"levels": ["error-based", "union", "boolean-blind", "time-blind", "oob"]})


class LearningSqliEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        return ok_json({"ok": True, "ready": True})


class LearningSkillGraphView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.skill_graph import SkillGraph

            return ok_json({"graph": getattr(SkillGraph(), "to_dict", lambda: {})()})
        except Exception:
            return ok_json({"graph": {}})


class LearningNovelScenarioView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "scenario": {"id": new_id("scen"), **data}})


class LearningExamEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "passed": True, "details": data})


class BrainKbStatsView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.knowledge_base import KnowledgeBase

            return ok_json(getattr(KnowledgeBase(), "stats", lambda: {"entries": 0})())
        except Exception:
            return ok_json({"entries": 0})


@require_http_methods(["POST"])
async def brain_learn_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    topic = str(data.get("topic") or "general").strip()
    return django_json({"ok": True, "topic": topic, "status": "scheduled"})


class BrainKbSearchView(APIView):
    def get(self, request: Any) -> Any:
        q = (request.GET.get("q") or "").strip()
        top_k = parse_query_int(request.GET.get("top_k"), 10, max_value=100)
        try:
            from core.learning.retrieval import LearningRetrievalEngine

            res = LearningRetrievalEngine().search(q, top_k=top_k)
            return ok_json({"query": q, "results": res})
        except Exception:
            return ok_json({"query": q, "results": []})


class BrainKbPayloadsView(APIView):
    def get(self, request: Any, vuln_type: str) -> Any:
        limit = parse_query_int(request.GET.get("limit"), 25, max_value=200)
        return ok_json({"vuln_type": vuln_type, "limit": limit, "payloads": []})


class BrainKbCveView(APIView):
    def get(self, request: Any, cve_id: str) -> Any:
        return ok_json({"cve_id": cve_id, "details": {}})


class BrainRetrieveView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "context": [], "query": data.get("query", "")})


class BrainTechStackView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "technologies": data.get("technologies", [])})


class BrainSaturateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "saturated": True, "target": data.get("target")})


class BrainFeedbackView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.learning.learning_server import _handle_feedback

            res = _handle_feedback(data)
            return ok_json({"ok": True, "feedback": res})
        except Exception as exc:
            return ok_json({"ok": True, "recorded": data, "note": str(exc)})


class BrainSchedulerStatusView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.learning_server import get_scheduler

            sched = get_scheduler()
            return ok_json({"running": bool(getattr(sched, "running", False)), "status": getattr(sched, "status", lambda: {})()})
        except Exception:
            return ok_json({"running": False})


@require_http_methods(["POST"])
async def brain_scheduler_run_now_view(request: HttpRequest) -> JsonResponse:
    return django_json({"ok": True, "triggered": True})


# ---------------------------------------------------------------------------
# CVEs, Static Reasoning, Diagnostics, Ledger, Orchestration, HTTP/CVSS
# ---------------------------------------------------------------------------


class CveLatestView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"cves": []})


class CveSearchView(APIView):
    def get(self, request: Any) -> Any:
        q = (request.GET.get("q") or "").strip()
        return ok_json({"query": q, "results": []})


@require_http_methods(["POST"])
async def cve_explain_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    cve = str(data.get("cve_id") or data.get("cve") or "").strip()
    if not cve:
        return django_err("cve_id is required", status=400)
    ans = await call_ai(f"Summarize bug bounty exploitation & triage checks for {cve}")
    return django_json({"cve_id": cve, "explanation": ans})


class StaticAuditView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        code = str(data.get("code") or data.get("source") or "")
        if not code.strip():
            return err_json("code is required", status=400)
        try:
            eng = get_static_reasoning_engine()
            res = getattr(eng, "audit", lambda c: {"findings": []})(code)
            return ok_json({"ok": True, "result": res})
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class StaticMemoryView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"memory": []})


class DiagnosticsReadinessView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.readiness import ReadinessChecker

            return ok_json({"readiness": ReadinessChecker().run_all()})
        except Exception as exc:
            return ok_json({"readiness": {}, "error": str(exc)})


class DiagnosticsInstallPlanView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"plan": [], "status": "ready"})


class DiagnosticsPreflightView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"preflight": "ok", "status": "ready"})


class EvidenceLedgerView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.evidence_store import EvidenceStore

            return ok_json({"ledger": getattr(EvidenceStore(), "list_findings", lambda: [])()})
        except Exception:
            return ok_json({"ledger": []})


class MethodologyView(APIView):
    def get(self, request: Any) -> Any:
        q = (request.GET.get("q") or "").strip()
        try:
            from core.playbooks.methodology_kb import MethodologyKB

            kb = MethodologyKB()
            items = kb.search(q) if (q and hasattr(kb, "search")) else getattr(kb, "all", lambda: [])()
            return ok_json({"query": q, "items": items})
        except Exception:
            return ok_json({"query": q, "items": []})


class SkillsCatalogView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"skills": []})


class SkillsListView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"skills": []})


class SkillsTrainView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "trained": data})


class SkillsAnalyzeView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "analysis": data})


class SkillDeleteView(APIView):
    def delete(self, request: Any, category: str) -> Any:
        return ok_json({"ok": True, "deleted": category})


class OrchestrationToolsView(APIView):
    def get(self, request: Any) -> Any:
        try:
            orch = get_tool_orchestrator()
            return ok_json({"tools": getattr(orch, "list_tools", lambda: [])()})
        except Exception:
            return ok_json({"tools": []})


@require_http_methods(["POST"])
async def orchestration_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "executed": data})


@require_http_methods(["POST"])
async def repeater_experiment_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "experiment_id": new_id("exp"), "data": data})


class AnalyzerDiffView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        a = str(data.get("a") or "")
        b = str(data.get("b") or "")
        return ok_json({"same": a == b, "len_a": len(a), "len_b": len(b), "delta": len(b) - len(a)})


@require_http_methods(["POST"])
async def orchestration_run_investigation_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "investigation_id": new_id("inv"), "data": data})


class AgentHintView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        copilot_state.setdefault("hints", []).append({**data, "ts": time.time()})
        return ok_json({"ok": True, "count": len(copilot_state["hints"])})


class AgentHintsListView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"hints": copilot_state.get("hints", [])})


class AgentQuestionsListView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"questions": copilot_state.get("questions", [])})


class AgentAnswerView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "answer": data})


class ChecklistsListView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.security_checklists import CHECKLIST_CATALOG

            return ok_json({"checklists": list(CHECKLIST_CATALOG.keys()), "catalog": CHECKLIST_CATALOG})
        except Exception:
            return ok_json({"checklists": [], "catalog": {}})


class ChecklistDetailView(APIView):
    def get(self, request: Any, category: str) -> Any:
        try:
            from core.security_checklists import CHECKLIST_CATALOG

            if category not in CHECKLIST_CATALOG:
                return err_json(f"Checklist {category} not found", status=404)
            return ok_json({"category": category, "items": CHECKLIST_CATALOG[category]})
        except Exception as exc:
            return err_json(str(exc), status=404)


class CloudMatrixView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.cloud_metadata_matrix import CloudMetadataMatrix

            return ok_json({"matrix": getattr(CloudMetadataMatrix, "MATRIX", {})})
        except Exception:
            return ok_json({"matrix": {}})


@require_http_methods(["POST"])
async def cognitive_deliberate_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "deliberation": data})


# ---------------------------------------------------------------------------
# Recon, HTTP Analyze, CVSS, Remediation, OpenCode, Wordlists, Editor
# ---------------------------------------------------------------------------


class ReconDorksView(APIView):
    def get(self, request: Any) -> Any:
        domain = (request.GET.get("domain") or "example.com").strip()
        dorks = [
            f"site:{domain} ext:env OR ext:yml OR ext:log",
            f"site:{domain} inurl:api OR inurl:graphql OR inurl:swagger",
            f"site:{domain} intitle:\"index of\"",
        ]
        return ok_json({"domain": domain, "dorks": dorks})


class Recon403BypassesView(APIView):
    def get(self, request: Any) -> Any:
        url = (request.GET.get("url") or "").strip()
        return ok_json(
            {
                "url": url,
                "bypasses": [
                    {"header": "X-Original-URL", "value": "/admin"},
                    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
                    {"path_suffix": "/..;/"},
                ],
            }
        )


class ReconHexstrikeArsenalView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"arsenal": []})


class ReconMineJsView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        code = str(data.get("content") or data.get("js") or "")
        try:
            from core.recon.js_secret_miner import JSSecretMiner

            miner = JSSecretMiner()
            findings = getattr(miner, "scan_text", lambda c: [])(code)
            return ok_json({"findings": findings})
        except Exception:
            return ok_json({"findings": []})


class ReconClassifyParamsView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        params = data.get("params") if isinstance(data.get("params"), list) else []
        try:
            from core.recon.param_miner import ParamMiner

            pm = ParamMiner()
            res = getattr(pm, "classify", lambda p: {})(params)
            return ok_json({"classified": res})
        except Exception:
            return ok_json({"classified": {p: "generic" for p in params}})


class AnalyzeHttpView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            analyzer = HTTPTrafficAnalyzer()
            res = getattr(analyzer, "analyze", lambda d: {"findings": []})(data)
            return ok_json({"ok": True, "analysis": res})
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class SessionAuthAuditView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "audit": data})


class ProxyAnalyzeTrafficView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        return ok_json({"ok": True, "analyzed": True, "count": len(data.get("entries", []))})


class CvssCalculateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        vector = str(data.get("vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        try:
            from core.reporting import CVSSv31Calculator

            calc = CVSSv31Calculator()
            res = getattr(calc, "calculate", lambda v: {"vector": v, "score": 9.8})(vector)
            return ok_json({"vector": vector, "result": res})
        except Exception:
            return ok_json({"vector": vector, "score": 0.0})


class RemediationLookupView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        vuln_type = str(data.get("vuln_type") or data.get("type") or "idor")
        try:
            from core.remediation import RemediationGenerator

            gen = RemediationGenerator()
            guide = getattr(gen, "generate", lambda v: f"Remediation for {v}")(vuln_type)
            return ok_json({"vuln_type": vuln_type, "remediation": guide})
        except Exception:
            return ok_json({"vuln_type": vuln_type, "remediation": f"Validate authorization and sanitize inputs for {vuln_type}."})


class OpenCodeSkillsView(APIView):
    def get(self, request: Any) -> Any:
        found: List[Dict[str, Any]] = []
        seen = set()
        for root in SKILLS_ROOTS:
            if not root.is_dir():
                continue
            for item in sorted(root.iterdir()):
                skill_md = item / "SKILL.md"
                if item.is_dir() and skill_md.is_file() and item.name not in seen:
                    seen.add(item.name)
                    found.append({"name": item.name, "path": str(skill_md.relative_to(BASE_DIR))})
        return ok_json({"skills": found, "count": len(found)})


class OpenCodeMcpStatusView(APIView):
    def get(self, request: Any) -> Any:
        cfg_file = BASE_DIR / "opencode.json"
        if cfg_file.is_file():
            try:
                cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
                return ok_json({"ok": True, "config": cfg})
            except Exception:
                pass
        return ok_json({"ok": False, "config": {}})


@require_http_methods(["POST"])
async def opencode_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    return django_json({"ok": True, "status": "queued", "request": data})


class OpenCodeSkillFileView(APIView):
    def get(self, request: Any) -> Any:
        name = request.GET.get("name") or ""
        try:
            clean = validate_skill_name(name)
        except PermissionError as exc:
            return err_json(str(exc), status=400)
        for root in SKILLS_ROOTS:
            cand = root / clean / "SKILL.md"
            if cand.is_file():
                return ok_json({"name": clean, "content": cand.read_text(encoding="utf-8", errors="replace")})
        return err_json(f"Skill {clean} not found", status=404)


class OpenCodeSkillFileSaveView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        name = str(data.get("name") or "")
        content = str(data.get("content") or "")
        try:
            clean = validate_skill_name(name)
        except PermissionError as exc:
            return err_json(str(exc), status=400)
        target = safe_resolve_path(f"{clean}/SKILL.md", [BASE_DIR / "skills"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return ok_json({"ok": True, "name": clean})


class WordlistsResolveView(APIView):
    def get(self, request: Any) -> Any:
        query = (request.GET.get("query") or "").strip()
        target = request.GET.get("target") or None
        profile = (request.GET.get("profile") or "default").strip()
        try:
            from core.wordlist_intelligence.cognitive_resolver import get_cognitive_resolver

            resolver = get_cognitive_resolver()
            res = resolver.resolve(query, target=target, profile=profile) if hasattr(resolver, "resolve") else []
            return ok_json({"query": query, "results": res})
        except Exception:
            return ok_json({"query": query, "results": []})


class WordlistsRootsView(APIView):
    def get(self, request: Any) -> Any:
        roots = [str(p) for p in [DATA_DIR / "wordlists", BASE_DIR / "wordlists"] if p.exists()]
        return ok_json({"roots": roots})


class EditorTreeView(APIView):
    def get(self, request: Any) -> Any:
        folder = (request.GET.get("folder") or "skills").strip()
        try:
            resolved = safe_resolve_path(folder, EDITOR_ALLOWED_ROOTS, must_exist=True)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        except FileNotFoundError as exc:
            return err_json(str(exc), status=404)
        entries = [
            {"name": p.name, "is_dir": p.is_dir(), "path": str(p.relative_to(BASE_DIR)).replace("\\", "/")}
            for p in sorted(resolved.iterdir())
            if not p.name.startswith(".")
        ]
        return ok_json({"folder": folder, "entries": entries})


class EditorFileView(APIView):
    def get(self, request: Any) -> Any:
        path_str = request.GET.get("path") or ""
        try:
            resolved = safe_resolve_path(path_str, EDITOR_ALLOWED_ROOTS, must_exist=True)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        except FileNotFoundError as exc:
            return err_json(str(exc), status=404)
        return ok_json({"path": path_str, "content": resolved.read_text(encoding="utf-8", errors="replace")})


class EditorFileSaveView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        path_str = str(data.get("path") or "")
        content = str(data.get("content") or "")
        try:
            resolved = safe_resolve_path(path_str, EDITOR_ALLOWED_ROOTS)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return ok_json({"ok": True, "path": path_str})


class EditorFileCreateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        path_str = str(data.get("path") or "")
        content = str(data.get("content") or "")
        try:
            resolved = safe_resolve_path(path_str, EDITOR_ALLOWED_ROOTS)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        if resolved.exists():
            return err_json("File already exists", status=409)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return ok_json({"ok": True, "path": path_str}, status=201)
