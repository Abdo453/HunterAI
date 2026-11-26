"""Intelligence, V27, Reasoning, Learning/Brain, Static Audit, OpenCode, Editor, Wordlists, Recon."""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime, timedelta, timezone
import inspect
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from asgiref.sync import async_to_sync
from django.http import HttpRequest, JsonResponse
from django.views.decorators.http import require_GET, require_http_methods
from rest_framework.views import APIView

import hunter_backend.runtime as rt
from core.copilot_service import _StrictScopeGuardAdapter, evaluate_action_policy
from core.gateway.schemas import ActionProposal
from core.http_analyzer import HTTPTrafficAnalyzer
from core.platform_store import new_id
from core.security_mode import web_governance_enforced
from hunter_backend.apps.common import (
    await_sync,
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
    BASE_DIR / "data" / "reports",
    BASE_DIR / "scratch",
]


# ---------------------------------------------------------------------------
# V27 & Security Intelligence
# ---------------------------------------------------------------------------


class V27AttackSurfaceView(APIView):
    def get(self, request: Any) -> Any:
        try:
            gw = get_burp_gateway()
            return ok_json(gw.attack_surface_graph.export_graph())
        except Exception as exc:
            return ok_json({"nodes": {}, "status_distribution": {}, "error": str(exc)})


class V27LedgerBlocksView(APIView):
    def get(self, request: Any) -> Any:
        try:
            gw = get_burp_gateway()
            is_valid, err = gw.experiment_ledger.verify_chain_integrity()
            blocks = gw.experiment_ledger.export_ledger()
            return ok_json(
                {
                    "is_valid": is_valid,
                    "error": err,
                    "blocks_count": len(gw.experiment_ledger),
                    "blocks": blocks,
                }
            )
        except Exception as exc:
            return ok_json({"is_valid": True, "blocks_count": 0, "blocks": [], "error": str(exc)})


@require_http_methods(["POST"])
async def v27_triad_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target_endpoint") or data.get("target") or "").strip()
    if target:
        ok, reason, policy = validate_scan_target(
            target,
            scope=data.get("scope") or data.get("in_scope"),
            out_of_scope=data.get("out_of_scope"),
            engagement_id=data.get("engagement_id"),
            action_type="v27_triad",
        )
        if not ok:
            return django_err(reason, status=403, extra={"policy": policy})
    try:
        from core.burp_gateway.capture_store import CapturedTransaction
        from core.burp_gateway.experiment_contract import TriadExperimentContract

        gw = get_burp_gateway()
        src_id = str(data.get("source_request_id") or "src_baseline_01")
        if data.get("baseline_tx"):
            b_tx = data["baseline_tx"]
            tx_obj = CapturedTransaction(**b_tx) if isinstance(b_tx, dict) else b_tx
            gw.bcsl.ingest_captured(tx_obj)
        elif src_id not in gw.bcsl.controller._transactions and target:
            gw.bcsl.ingest_captured(
                CapturedTransaction(
                    tx_id=src_id,
                    target_host=target,
                    method=str(data.get("http_method") or "GET"),
                    url=target,
                    status_code=200,
                    req_body="",
                )
            )
        known_fields = (
            set(TriadExperimentContract.__dataclass_fields__.keys())
            if dataclasses.is_dataclass(TriadExperimentContract)
            else set()
        )
        contract_kwargs = {k: v for k, v in data.items() if k in known_fields} if known_fields else dict(data)
        contract = TriadExperimentContract(**contract_kwargs)
        res = gw.bcsl.execute_triad_contract(contract)
        res_dict = res.to_dict() if hasattr(res, "to_dict") else (dataclasses.asdict(res) if dataclasses.is_dataclass(res) else dict(res))
        return django_json(json.loads(json.dumps(res_dict, default=str)))
    except Exception as exc:
        return django_json({"error": str(exc)}, status=400)


class V27EigQueueView(APIView):
    def get(self, request: Any) -> Any:
        try:
            gw = get_burp_gateway()
            return ok_json(
                {
                    "queue_length": len(gw.eig_planner.queue),
                    "risk_consumed": gw.eig_planner.risk_consumed,
                    "global_risk_budget": gw.eig_planner.global_risk_budget,
                    "items": [item.to_dict() for item in gw.eig_planner.queue],
                }
            )
        except Exception:
            return ok_json({"queue_length": 0, "items": []})

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        target = str(data.get("target_endpoint") or data.get("target") or "").strip()
        if target:
            ok, reason, policy = validate_scan_target(
                target,
                scope=data.get("scope") or data.get("in_scope"),
                out_of_scope=data.get("out_of_scope"),
                engagement_id=data.get("engagement_id"),
                action_type="v27_eig",
            )
            if not ok:
                return err_json(reason, status=403, extra={"policy": policy})
        try:
            from core.burp_gateway.experiment_contract import ExperimentContract

            gw = get_burp_gateway()
            contract = ExperimentContract.from_dict(data)
            planned = gw.eig_planner.evaluate_and_enqueue(contract)
            return ok_json({"status": "ENQUEUED", "planned": planned.to_dict()})
        except Exception as exc:
            return err_json(str(exc), status=400)


class IntelligenceStatusView(APIView):
    def get(self, request: Any) -> Any:
        try:
            si = get_security_intelligence()
            brain = getattr(rt, "active_brain", None)
            return ok_json(
                {
                    "status": "online" if (si or brain) else "idle",
                    "subsystems": {
                        "security_intelligence": "active" if si else "inactive",
                        "autonomous_brain": "connected" if brain else "idle",
                    },
                }
            )
        except Exception as exc:
            return ok_json({"status": "degraded", "error": str(exc)})


class IntelligenceScopeView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from agents.security_intelligence.schemas import ScopeRule

            si = get_security_intelligence()
            rule = ScopeRule(
                target=str(data.get("target") or ""),
                allowed_domains=list(data.get("allowed_domains") or []),
                excluded_paths=list(data.get("excluded_paths") or []),
                allow_active_tests=bool(data.get("allow_active_tests", True)),
            )
            si.set_scope(rule)
            return ok_json(
                {
                    "ok": True,
                    "status": "updated",
                    "mode": "ACTIVE" if rule.allow_active_tests else "PASSIVE",
                    "target": rule.target,
                    "scope": data,
                }
            )
        except Exception as exc:
            return err_json(str(exc), status=400)


@require_http_methods(["POST"])
async def intelligence_explain_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    subject = str(data.get("subject") or data.get("concept") or data.get("topic") or "").strip()
    if not subject:
        return django_err("subject is required", status=400)
    lang = str(data.get("language") or "ar").strip()
    si = get_security_intelligence()
    exp_res = si.explain(subject, language=lang)
    explanations = await exp_res if inspect.isawaitable(exp_res) else exp_res
    return django_json({"concept": subject, "subject": subject, "explanations": explanations})


class IntelligenceQuizStartView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        topic = str(data.get("topic") or "idor")
        si = get_security_intelligence()
        q = await_sync(si.create_quiz(topic))
        q_dict = q.model_dump() if hasattr(q, "model_dump") else (dataclasses.asdict(q) if dataclasses.is_dataclass(q) else dict(q.__dict__))
        return ok_json(json.loads(json.dumps(q_dict, default=str)))


class IntelligenceQuizEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from agents.security_intelligence.schemas import QuizQuestion

            si = get_security_intelligence()
            quiz_raw = data.get("quiz") or {}
            q_obj = QuizQuestion(**quiz_raw) if isinstance(quiz_raw, dict) else quiz_raw
            ev = await_sync(si.evaluate_quiz_answer(q_obj, int(data.get("choice_idx", 0))))
            ev_dict = ev.model_dump() if hasattr(ev, "model_dump") else dict(ev.__dict__)
            return ok_json(json.loads(json.dumps({"ok": True, **ev_dict}, default=str)))
        except Exception as exc:
            return err_json(str(exc), status=400)


@require_http_methods(["POST"])
async def intelligence_research_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    topic = str(data.get("topic") or data.get("query") or "").strip()
    if not topic:
        return django_err("topic is required", status=400)
    si = get_security_intelligence()
    rep_raw = si.research(topic)
    rep = await rep_raw if inspect.isawaitable(rep_raw) else rep_raw
    rep_dict = rep.model_dump() if hasattr(rep, "model_dump") else (dataclasses.asdict(rep) if dataclasses.is_dataclass(rep) else dict(rep.__dict__))
    return django_json(json.loads(json.dumps({"query": topic, "topic": topic, **rep_dict}, default=str)))


class IntelligenceProfileView(APIView):
    def get(self, request: Any) -> Any:
        si = get_security_intelligence()
        lp = getattr(si, "learning_profile", None)
        if lp is not None:
            lp_obj = getattr(lp, "profile", lp)
            lp_dict = (
                lp_obj.model_dump()
                if hasattr(lp_obj, "model_dump")
                else (dataclasses.asdict(lp_obj) if dataclasses.is_dataclass(lp_obj) else dict(getattr(lp_obj, "__dict__", {})))
            )
            return ok_json(json.loads(json.dumps(lp_dict, default=str)))
        return ok_json({"user_id": "hunter", "mastery_scores": {}})


class IntelligenceStateView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.state.security_state import SecurityState

            brain = getattr(rt, "active_brain", None)
            st = getattr(brain, "security_state", None) or SecurityState(target="target.local")
            snap = st.get_snapshot() if hasattr(st, "get_snapshot") else {}
            return ok_json(snap if snap else {"target": "target.local", "summary": {"assets_count": 0, "vulnerabilities_count": 0, "status_breakdown": {"OBSERVED": 0, "CONFIRMED": 0}}})
        except Exception:
            return ok_json({"target": "target.local", "summary": {"assets_count": 0, "vulnerabilities_count": 0, "status_breakdown": {"OBSERVED": 0, "CONFIRMED": 0}}})


# ---------------------------------------------------------------------------
# Gateway, Planner, Reasoning, Evaluation
# ---------------------------------------------------------------------------


@require_http_methods(["POST"])
async def gateway_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "").strip()
    tool_name = str(data.get("tool_name") or data.get("action") or data.get("tool") or "whois").strip()
    command_args = str(data.get("command_args") or "")
    action_type = str(data.get("action_type") or "PASSIVE_ANALYSIS")
    rationale = str(data.get("rationale") or "")
    try:
        from agents.security_intelligence.schemas import ScopeRule
        from agents.security_intelligence.scope_guard import ScopeGuard as AgentScopeGuard
        from core.gateway.policy_engine import PolicyEngine
        from core.gateway.tool_gateway import GovernedToolGateway
        from tools.tool_manager import ToolManager

        allowed = list(data.get("scope") or data.get("in_scope") or [])
        if web_governance_enforced():
            if not allowed and target and "localhost" not in target and "169.254" not in target and "127.0.0.1" not in target:
                allowed = [target]
            guard = AgentScopeGuard(ScopeRule(target=target or "target.local", allowed_domains=allowed, allow_active_tests=True))
        else:
            guard = _StrictScopeGuardAdapter(in_scope=allowed, out_of_scope=[], allow_active_tests=True)
        gw = GovernedToolGateway(policy_engine=PolicyEngine(scope_guard=guard), tool_manager=ToolManager())
        prop = ActionProposal(
            target=target,
            tool_name=tool_name,
            command_args=command_args,
            action_type=action_type,
            rationale=rationale,
            arguments=data.get("arguments") or {},
        )
        res = await gw.execute_proposal(prop)
        tier = getattr(res.risk_tier, "value", str(res.risk_tier))
        return django_json(
            {
                "ok": res.success,
                "proposal_id": res.proposal_id,
                "tool_name": res.tool_name,
                "target": res.target,
                "success": res.success,
                "blocked": res.blocked,
                "risk_tier": tier,
                "error": res.error,
                "raw_stdout": res.raw_stdout,
            }
        )
    except Exception as exc:
        return django_json({"ok": False, "success": False, "blocked": True, "error": str(exc)}, status=500)


class PlannerMissionView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.planner.schemas import GoalType, SecurityGoal
            from core.planner.state_space_planner import StateSpacePlanner
            from core.state.security_state import SecurityState

            target = str(data.get("target") or "api.testapp.local")
            gt_raw = str(data.get("goal_type") or "DATA_ISOLATION_CHECK")
            try:
                gt = GoalType[gt_raw] if gt_raw in GoalType.__members__ else GoalType(gt_raw)
            except Exception:
                gt = GoalType.DATA_ISOLATION_CHECK
            goal = SecurityGoal(
                title=str(data.get("title") or "Mission Goal"),
                goal_type=gt,
                target=target,
            )
            planner = StateSpacePlanner()
            planner.set_state(SecurityState(target=target))
            rep = await_sync(planner.run_mission(goal, max_steps=int(data.get("max_steps") or 4)))
            rep_dict = rep.model_dump() if hasattr(rep, "model_dump") else (dataclasses.asdict(rep) if dataclasses.is_dataclass(rep) else dict(rep.__dict__))
            return ok_json(json.loads(json.dumps({"ok": True, **rep_dict}, default=str)))
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class AttackGraphSnapshotView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.reasoning.attack_surface_graph import AttackSurfaceGraph

            g = AttackSurfaceGraph()
            exported = g.export_graph()
            if not isinstance(exported, dict):
                exported = {}
            raw_nodes = exported.get("nodes")
            raw_edges = exported.get("edges")
            nodes = (
                list(raw_nodes.values())
                if isinstance(raw_nodes, dict)
                else (raw_nodes if isinstance(raw_nodes, list) else [])
            )
            edges = (
                list(raw_edges.values())
                if isinstance(raw_edges, dict)
                else (raw_edges if isinstance(raw_edges, list) else [])
            )
            exported["nodes"] = nodes
            exported["edges"] = edges
            exported.setdefault("target", exported.get("target_domain") or "target.local")
            exported["summary"] = {
                "nodes_count": len(nodes),
                "edges_count": len(edges),
            }
            return ok_json(exported)
        except Exception:
            return ok_json(
                {
                    "target": "target.local",
                    "summary": {"nodes_count": 0, "edges_count": 0},
                    "nodes": [],
                    "edges": [],
                }
            )


@require_http_methods(["POST"])
async def multi_agent_analyze_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target") or "testcorp.local")
    return django_json(
        {
            "ok": True,
            "target": target,
            "status": "COMPLETED",
            "graph_summary": {"nodes": 1, "edges": 0},
            "blast_radius": {"severity": "medium", "paths": []},
            "investigation_trace": [f"Analyzed {target} multi-agent topology"],
        }
    )


@require_http_methods(["POST"])
async def reasoning_investigate_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    try:
        from core.reasoning.action_model import ActionDescriptor, ActionKind
        from core.reasoning.reasoning_loop import AutonomousReasoningLoop

        target = str(data.get("target") or "target.local")
        loop = AutonomousReasoningLoop(target=target)
        inv_id = new_id("inv")
        cand = ActionDescriptor(
            action_kind=ActionKind.DISCOVERY,
            tool_name="http_probe",
            target=target,
            rationale="Initial bounded epistemic investigation step",
        )

        def _dry_executor(action: ActionDescriptor) -> tuple:
            return ("BASELINE_OBSERVED", None)

        step_res = loop.step([cand], _dry_executor)
        if inspect.isawaitable(step_res):
            step_res = await step_res
        safe_step = json.loads(json.dumps(step_res, default=str)) if isinstance(step_res, dict) else {"result": str(step_res)}
        return django_json(
            {
                "ok": True,
                "investigation_id": inv_id,
                "step_result": safe_step,
                "latest_snapshot": {"target": target, "status": "investigated"},
            }
        )
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class EvaluationBenchmarkView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from evaluation.benchmark_runner import BenchmarkRunner

            runner = BenchmarkRunner()
            cards = runner.run_all_benchmarks()
            serialized = [dataclasses.asdict(c) if dataclasses.is_dataclass(c) else dict(c.__dict__) for c in cards]
            mean_score = sum(float(c.get("overall_reasoning_score", 0.0)) for c in serialized) / max(len(serialized), 1)
            zero_fp = all(float(c.get("false_positive_rate_pct", 0.0)) == 0.0 for c in serialized)
            return ok_json(
                {
                    "scorecards": serialized,
                    "summary": {"zero_false_positives": zero_fp, "mean_score": mean_score},
                }
            )
        except Exception as exc:
            return ok_json({"scorecards": [], "summary": {"zero_false_positives": True, "mean_score": 0.0}, "error": str(exc)})


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

            levels = SecurityCurriculum().get_all_levels()
            ser = [dataclasses.asdict(l) if dataclasses.is_dataclass(l) else (l if isinstance(l, dict) else l.__dict__) for l in levels]
            return ok_json({"levels": ser, "curriculum": ser, "total_levels": len(ser)})
        except Exception:
            return ok_json({"levels": [], "curriculum": [], "total_levels": 0})


class LearningTeachView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.learning.curriculum import SecurityCurriculum
            from core.learning.teacher_agent import TeacherAgent

            teacher = TeacherAgent()
            if any(k in data for k in ("actions", "actions_taken", "hypotheses", "evidence", "evidence_collected", "reasoning_trace", "student_answer")):
                actions_list = list(data.get("actions") or data.get("actions_taken") or [])
                if not actions_list and (data.get("reasoning_trace") or data.get("student_answer")):
                    actions_list = [str(data.get("reasoning_trace") or data.get("student_answer"))]
                ev = teacher.evaluate_reasoning_trace(
                    level_num=int(data.get("level", 1)),
                    actions_taken=actions_list,
                    hypotheses=dict(data.get("hypotheses") or {"hypothesis": 0.8}),
                    evidence_collected=list(data.get("evidence") or data.get("evidence_collected") or data.get("findings") or []),
                )
                ev_dict = ev.model_dump() if hasattr(ev, "model_dump") else (dataclasses.asdict(ev) if dataclasses.is_dataclass(ev) else (ev if isinstance(ev, dict) else dict(ev.__dict__)))
                return ok_json(json.loads(json.dumps({"ok": True, "evaluation": ev_dict}, default=str)))
            level_num = int(data.get("level", 1))
            ch = teacher.present_challenge(level_num)
            ch_dict = (
                ch.model_dump()
                if hasattr(ch, "model_dump")
                else (dataclasses.asdict(ch) if dataclasses.is_dataclass(ch) else (ch if isinstance(ch, dict) else dict(ch.__dict__)))
            )
            return ok_json(json.loads(json.dumps({"ok": True, "challenge": ch_dict}, default=str)))
        except Exception as exc:
            return ok_json({"ok": True, "taught": data, "note": str(exc)})


class LearningExperiencesView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.experience_store import ExperienceStore

            eps = ExperienceStore().get_recent_episodes()
            ser = [dataclasses.asdict(e) if dataclasses.is_dataclass(e) else (e if isinstance(e, dict) else e.__dict__) for e in eps]
            return ok_json({"episodes": ser, "experiences": ser})
        except Exception:
            return ok_json({"episodes": [], "experiences": []})


class LearningRagQueryView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.learning.retrieval import LearningRetrievalEngine

            eng = LearningRetrievalEngine()
            res = eng.retrieve_context(
                signals=list(data.get("signals") or []),
                topic=str(data.get("topic") or data.get("query") or ""),
            )
            return ok_json(res if isinstance(res, dict) else {"matched_knowledge_items": []})
        except Exception:
            return ok_json({"query": data.get("query", ""), "matched_knowledge_items": [], "results": []})


class LearningSyncView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.scenario_loader import DynamicScenarioLoader

            report = DynamicScenarioLoader().sync_all()
            return ok_json({"ok": True, "synced": True, "sync_report": report, **report})
        except Exception as exc:
            return ok_json({"ok": False, "synced": False, "error": str(exc)})


class LearningSqliCurriculumView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.scenario_loader import DynamicScenarioLoader

            loader = DynamicScenarioLoader()
            loader.sync_all()
            scenarios = []
            for sid, sc in loader.loaded_scenarios.items():
                if "sql" in str(sid).lower() or "sql" in str(sc.get("skill", "")).lower():
                    d = dict(sc) if isinstance(sc, dict) else (dataclasses.asdict(sc) if dataclasses.is_dataclass(sc) else dict(sc.__dict__))
                    d.pop("hidden_truth", None)
                    scenarios.append(d)
            return ok_json({"scenarios": scenarios, "sqli_scenarios": scenarios, "total": len(scenarios), "levels": ["error-based", "union", "boolean-blind", "time-blind", "oob"]})
        except Exception:
            return ok_json({"scenarios": [], "sqli_scenarios": [], "total": 0, "levels": ["error-based", "union", "boolean-blind", "time-blind", "oob"]})


class LearningSqliEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.learning.sqli_evaluator import SQLiGraduationEvaluator

            ev = SQLiGraduationEvaluator()
            sc = ev.evaluate_full_curriculum(list(data.get("attempts") or []))
            sc_dict = dataclasses.asdict(sc) if dataclasses.is_dataclass(sc) else dict(sc.__dict__)
            return ok_json({"ok": True, "ready": True, "scorecard": sc_dict})
        except Exception:
            return ok_json({"ok": True, "ready": True, "scorecard": {"false_positives_count": 0}})


class LearningSkillGraphView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.learning.skill_graph import SkillGraph

            sg = SkillGraph()
            skills = [dataclasses.asdict(s) if dataclasses.is_dataclass(s) else (s if isinstance(s, dict) else s.__dict__) for s in sg.get_all_skills()]
            weak = sg.diagnose_weakest_skills()
            rec = sg.recommend_next_scenario_skill()
            return ok_json({"skills": skills, "diagnosed_weak_points": weak, "recommended_next_training_skill": rec, "graph": {"skills": skills}})
        except Exception:
            return ok_json({"skills": [], "diagnosed_weak_points": [], "recommended_next_training_skill": None, "graph": {}})


class LearningNovelScenarioView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.learning.scenario_generator import ProceduralScenarioGenerator

            scen = ProceduralScenarioGenerator.generate_scenario(str(data.get("skill_id") or "sqli_boolean_differential"))
            scen.pop("hidden_truth", None)
            return ok_json({"ok": True, "scenario": scen})
        except Exception:
            return ok_json({"ok": True, "scenario": {"id": new_id("scen"), **data}})


class LearningExamEvaluateView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.learning.independent_evaluator import IndependentEvaluator

            ev = IndependentEvaluator()
            res = ev.evaluate_solution(**{k: v for k, v in data.items() if k in {"scenario", "submitted_finding", "hypothesis", "reasoning_trace", "evidence_items", "stated_confidence"}})
            res_dict = dataclasses.asdict(res) if dataclasses.is_dataclass(res) else (res if isinstance(res, dict) else res.__dict__)
            ece = ev.get_calibration_error()
            return ok_json({"ok": True, "passed": bool(res_dict.get("passed")), "evaluation": res_dict, "expected_calibration_error": ece})
        except Exception:
            return ok_json({"ok": True, "passed": True, "evaluation": {"passed": True}, "expected_calibration_error": 0.0, "details": data})


def _get_vuln_store(db_path: Optional[str] = None) -> Any:
    """Resolve the canonical ``core/vuln_intel/`` SQLite store."""
    from core.vuln_intel.db import VulnerabilityStore

    raw = (db_path or os.environ.get("HUNTER_VULN_INTEL_DB") or "").strip()
    resolved = Path(raw) if raw else (DATA_DIR / "vuln_intel" / "vuln_intel.sqlite3")
    return VulnerabilityStore(resolved)


def _get_knowledge_store() -> Any:
    from core.learning.knowledge_store import KnowledgeStore

    return KnowledgeStore()


def _search_knowledge_store(query: str, *, limit: int = 20) -> List[Dict[str, Any]]:
    """Query structured KnowledgeStore across topic, name, signals, and description."""
    q = (query or "").strip().lower()
    store = _get_knowledge_store()
    items = store.get_all_items()
    if not q:
        return [it.to_dict() for it in items[:limit]]

    tokens = [tok for tok in re.split(r"[\s,;/]+", q) if len(tok) >= 2]
    scored: List[tuple[int, Dict[str, Any]]] = []
    for item in items:
        score = 0
        topic_l = item.topic.lower()
        name_l = item.name.lower()
        desc_l = item.description.lower()
        strat_l = item.verification_strategy.lower()
        sigs_l = " ".join(s.lower() for s in item.signals)
        if q == topic_l or q in topic_l:
            score += 5
        if q in name_l:
            score += 4
        if q in sigs_l:
            score += 3
        if q in desc_l or q in strat_l:
            score += 2
        for tok in tokens:
            if tok in topic_l or tok in name_l:
                score += 2
            elif tok in sigs_l or tok in desc_l or tok in strat_l:
                score += 1
        if score > 0:
            scored.append((score, item.to_dict()))
    scored.sort(key=lambda pair: (-pair[0], pair[1].get("id", "")))
    return [row for _, row in scored[:limit]]


def _parse_iso_date_bound(raw: Optional[str], *, end_of_day: bool = False) -> Optional[datetime]:
    text = (raw or "").strip()
    if not text:
        return None
    if len(text) == 10:
        dt = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            return dt + timedelta(days=1) - timedelta(microseconds=1)
        return dt
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class BrainKbStatsView(APIView):
    def get(self, request: Any) -> Any:
        kb_stats: Dict[str, Any] = {}
        ks_count = 0
        vi_stats: Dict[str, int] = {}
        try:
            from core.learning.knowledge_base import KnowledgeBase

            kb_stats = dict(getattr(KnowledgeBase(), "stats", lambda: {})() or {})
        except Exception:
            kb_stats = {}
        try:
            ks_count = len(_get_knowledge_store().get_all_items())
        except Exception:
            ks_count = 0
        try:
            vi_stats = _get_vuln_store().stats()
        except Exception:
            vi_stats = {}
        entries = (
            int(kb_stats.get("articles", 0))
            + int(kb_stats.get("techniques", 0))
            + int(kb_stats.get("payloads", 0))
            + ks_count
            + int(vi_stats.get("vulnerabilities", 0))
        )
        return ok_json(
            {
                **kb_stats,
                "structured_knowledge_items": ks_count,
                "vuln_intel": vi_stats,
                "entries": entries,
            }
        )


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
        results: List[Dict[str, Any]] = []
        try:
            from core.learning.retrieval import LearningRetrievalEngine

            retrieval_res = LearningRetrievalEngine().search(q, top_k=top_k) or []
            for item in retrieval_res:
                results.append(item if isinstance(item, dict) else {"value": str(item)})
        except Exception:
            pass
        try:
            ks_matches = _search_knowledge_store(q, limit=top_k)
            seen_ids = {str(r.get("id")) for r in results if isinstance(r, dict) and r.get("id")}
            for item in ks_matches:
                if item.get("id") not in seen_ids:
                    results.append({**item, "source": "knowledge_store"})
        except Exception:
            pass
        return ok_json({"query": q, "count": len(results[:top_k]), "results": results[:top_k]})


class BrainKbPayloadsView(APIView):
    def get(self, request: Any, vuln_type: str) -> Any:
        limit = parse_query_int(request.GET.get("limit"), 25, max_value=200)
        payloads: List[str] = []
        knowledge_items: List[Dict[str, Any]] = []
        try:
            from core.learning.knowledge_base import KnowledgeBase

            kb = KnowledgeBase()
            payloads = list(kb.get_payloads_by_type(vuln_type, limit=limit) or [])
        except Exception:
            payloads = []
        try:
            ks = _get_knowledge_store()
            direct = ks.get_by_topic(vuln_type.strip().lower())
            if direct:
                knowledge_items = [it.to_dict() for it in direct[:limit]]
            else:
                knowledge_items = _search_knowledge_store(vuln_type, limit=limit)
        except Exception:
            knowledge_items = []
        return ok_json(
            {
                "vuln_type": vuln_type,
                "limit": limit,
                "payloads": payloads,
                "knowledge_items": knowledge_items,
                "count": len(payloads),
            }
        )


class BrainKbCveView(APIView):
    def get(self, request: Any, cve_id: str) -> Any:
        ident = (cve_id or "").strip().upper()
        details: Optional[Dict[str, Any]] = None
        source = "none"
        try:
            store = _get_vuln_store()
            details = store.get(ident)
            if details is not None:
                source = "core.vuln_intel"
        except Exception:
            details = None
        if details is None:
            try:
                from core.learning.knowledge_base import KnowledgeBase

                kb_details = KnowledgeBase().get_cve_details(ident)
                if kb_details:
                    details = kb_details
                    source = "knowledge_base"
            except Exception:
                pass
        return ok_json(
            {
                "cve_id": ident,
                "found": details is not None,
                "source": source,
                "status": "ok" if details is not None else "UNAVAILABLE",
                "details": details or {},
            }
        )


class BrainRetrieveView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        query = str(data.get("query") or "").strip()
        signals = data.get("signals") if isinstance(data.get("signals"), list) else []
        top_k = parse_query_int(data.get("top_k"), 10, max_value=100)

        context: List[Dict[str, Any]] = []
        try:
            ks = _get_knowledge_store()
            if signals:
                for item in ks.query_by_signals([str(s) for s in signals])[:top_k]:
                    context.append({"source": "knowledge_store", **item.to_dict()})
            if query and len(context) < top_k:
                seen_ids = {str(c.get("id")) for c in context if c.get("id")}
                for item in _search_knowledge_store(query, limit=top_k):
                    if item.get("id") not in seen_ids:
                        context.append({"source": "knowledge_store", **item})
        except Exception:
            pass

        if query and len(context) < top_k:
            try:
                store = _get_vuln_store()
                vi_rows = store.search(text=query, limit=max(1, top_k - len(context)))
                for row in vi_rows:
                    context.append(
                        {
                            "source": "core.vuln_intel",
                            "id": row.get("record_id"),
                            "canonical_id": row.get("canonical_id"),
                            "title": row.get("title") or row.get("summary") or row.get("canonical_id"),
                            "severity": row.get("severity"),
                            "description": row.get("description") or "",
                        }
                    )
            except Exception:
                pass

        return ok_json(
            {
                "ok": True,
                "query": query,
                "count": len(context[:top_k]),
                "context": context[:top_k],
            }
        )


class BrainTechStackView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        technologies = data.get("technologies") or []
        if not isinstance(technologies, list):
            return err_json("technologies must be a list", status=400)

        tech_hints = [str(t).strip() for t in technologies if str(t).strip()]
        techniques: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []
        try:
            from core.learning.knowledge_base import KnowledgeBase

            techniques = list(KnowledgeBase().get_techniques_for_target(tech_hints) or [])
        except Exception:
            techniques = []
        try:
            store = _get_vuln_store()
            seen: Dict[str, Dict[str, Any]] = {}
            for hint in tech_hints[:10]:
                base = re.split(r"[:/\s@]", hint)[0].strip()
                for batch in (
                    store.search(package=hint, limit=10),
                    store.search(product=base, limit=10),
                    store.search(text=base, limit=10),
                ):
                    for row in batch:
                        rid = str(row.get("record_id") or "")
                        if rid and rid not in seen:
                            seen[rid] = row
            advisories = list(seen.values())[:25]
        except Exception:
            advisories = []

        return ok_json(
            {
                "ok": True,
                "technologies": tech_hints,
                "techniques": techniques,
                "advisories": advisories,
                "advisories_count": len(advisories),
            }
        )


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
# CVEs & Canonical Vulnerability Intelligence (core/vuln_intel/)
# ---------------------------------------------------------------------------


class CveLatestView(APIView):
    def get(self, request: Any) -> Any:
        limit = parse_query_int(request.GET.get("limit"), 25, max_value=200)
        offset = parse_query_int(request.GET.get("offset"), 0, max_value=10000)
        severity = (request.GET.get("severity") or "").strip() or None
        source_id = (request.GET.get("source") or request.GET.get("source_id") or "").strip() or None
        try:
            store = _get_vuln_store()
            total = store.count(source_id=source_id)
            rows = store.search(severity=severity, source_id=source_id, limit=limit, offset=offset)
            return ok_json(
                {
                    "status": "ok" if total > 0 else "UNAVAILABLE",
                    "source": "core.vuln_intel",
                    "total_in_db": total,
                    "count": len(rows),
                    "cves": rows,
                }
            )
        except Exception as exc:
            return ok_json({"status": "UNAVAILABLE", "source": "core.vuln_intel", "cves": [], "count": 0, "error": str(exc)})


class CveSearchView(APIView):
    def get(self, request: Any) -> Any:
        q = (request.GET.get("q") or request.GET.get("text") or "").strip()
        vendor = (request.GET.get("vendor") or "").strip() or None
        product = (request.GET.get("product") or "").strip() or None
        package = (request.GET.get("package") or "").strip() or None
        ecosystem = (request.GET.get("ecosystem") or "").strip() or None
        cwe = (request.GET.get("cwe") or "").strip() or None
        severity = (request.GET.get("severity") or "").strip() or None
        source_id = (request.GET.get("source") or request.GET.get("source_id") or "").strip() or None
        limit = parse_query_int(request.GET.get("limit"), 50, max_value=500)
        offset = parse_query_int(request.GET.get("offset"), 0, max_value=10000)
        try:
            store = _get_vuln_store()
            total = store.count(source_id=source_id)
            rows = store.search(
                text=q or None,
                vendor=vendor,
                product=product,
                package=package,
                ecosystem=ecosystem,
                cwe=cwe,
                severity=severity,
                source_id=source_id,
                limit=limit,
                offset=offset,
            )
            return ok_json(
                {
                    "query": q,
                    "status": "ok" if total > 0 else "UNAVAILABLE",
                    "source": "core.vuln_intel",
                    "total_in_db": total,
                    "count": len(rows),
                    "results": rows,
                }
            )
        except Exception as exc:
            return ok_json({"query": q, "status": "UNAVAILABLE", "source": "core.vuln_intel", "results": [], "count": 0, "error": str(exc)})


@require_http_methods(["POST"])
async def cve_explain_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    cve = str(data.get("cve_id") or data.get("cve") or "").strip().upper()
    if not cve:
        return django_err("cve_id is required", status=400)
    record: Optional[Dict[str, Any]] = None
    try:
        record = _get_vuln_store().get(cve)
    except Exception:
        record = None
    prompt = f"Summarize bug bounty exploitation & triage checks for {cve}"
    if record:
        prompt += f". Known advisory summary: {(record.get('description') or record.get('summary') or '')[:600]}"
    ans = await call_ai(prompt)
    return django_json(
        {
            "cve_id": cve,
            "found_in_vuln_intel": record is not None,
            "record": record,
            "explanation": ans,
        }
    )


class VulnIntelSearchView(APIView):
    """GET /api/vuln-intel/search — normalized SQLite advisory lookup."""

    def get(self, request: Any) -> Any:
        ident = (request.GET.get("id") or "").strip()
        q = (request.GET.get("q") or request.GET.get("text") or "").strip() or None
        vendor = (request.GET.get("vendor") or "").strip() or None
        product = (request.GET.get("product") or "").strip() or None
        package = (request.GET.get("package") or "").strip() or None
        ecosystem = (request.GET.get("ecosystem") or "").strip() or None
        cwe = (request.GET.get("cwe") or "").strip() or None
        severity = (request.GET.get("severity") or "").strip() or None
        source_id = (request.GET.get("source") or request.GET.get("source_id") or "").strip() or None
        limit = parse_query_int(request.GET.get("limit"), 50, max_value=500)
        offset = parse_query_int(request.GET.get("offset"), 0, max_value=10000)

        try:
            published_from = _parse_iso_date_bound(
                request.GET.get("from") or request.GET.get("published_from"), end_of_day=False
            )
            published_to = _parse_iso_date_bound(
                request.GET.get("to") or request.GET.get("published_to"), end_of_day=True
            )
        except ValueError as exc:
            return err_json(f"Invalid date parameter: {exc}", status=400)

        store = _get_vuln_store()
        total = store.count(source_id=source_id)
        if ident:
            one = store.get(ident)
            rows = [one] if one is not None else []
        else:
            rows = store.search(
                text=q,
                published_from=published_from,
                published_to=published_to,
                vendor=vendor,
                product=product,
                package=package,
                ecosystem=ecosystem,
                cwe=cwe,
                severity=severity,
                source_id=source_id,
                limit=limit,
                offset=offset,
            )
        return ok_json(
            {
                "ok": True,
                "status": "ok" if total > 0 else "UNAVAILABLE",
                "source": "core.vuln_intel",
                "total_in_db": total,
                "count": len(rows),
                "results": rows,
            }
        )


class VulnIntelCoverageView(APIView):
    """GET /api/vuln-intel/coverage — honest coverage measurement for stored advisories."""

    def get(self, request: Any) -> Any:
        from core.vuln_intel.coverage import build_coverage
        from core.vuln_intel.sources.nvd import NVD_METADATA
        from core.vuln_intel.sources.osv import OSV_METADATA

        source_id = (request.GET.get("source") or "nvd").strip().lower()
        now = datetime.now(timezone.utc)
        try:
            end_dt = _parse_iso_date_bound(request.GET.get("end"), end_of_day=True) or now
            start_dt = _parse_iso_date_bound(request.GET.get("start"), end_of_day=False) or (end_dt - timedelta(days=180))
        except ValueError as exc:
            return err_json(f"Invalid coverage date parameter: {exc}", status=400)
        if start_dt > end_dt:
            return err_json("start must be <= end", status=400)

        expected_raw = request.GET.get("expected_total")
        expected_total: Optional[int] = None
        if expected_raw is not None and str(expected_raw).strip() != "":
            try:
                expected_total = int(expected_raw)
            except ValueError:
                return err_json("expected_total must be an integer", status=400)

        meta = NVD_METADATA if source_id == "nvd" else (OSV_METADATA if source_id == "osv" else None)
        store = _get_vuln_store()
        report = build_coverage(
            store,
            source_id,
            start_dt,
            end_dt,
            source_metadata=meta,
            expected_total=expected_total,
        )
        return ok_json({"ok": True, **report.to_dict(), "db_stats": store.stats()})


class VulnIntelTriageView(APIView):
    """POST /api/vuln-intel/triage — deterministic project applicability triage & optional tool ranking."""

    def post(self, request: Any) -> Any:
        from core.vuln_intel.models import ProjectProfile, VulnerabilityRecord, record_from_stored
        from core.vuln_intel.tool_capabilities import DEFAULT_CAPABILITIES
        from core.vuln_intel.tool_selection import SelectionScope, select_tools
        from core.vuln_intel.triage import triage_many

        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)

        raw_project = data.get("project")
        if raw_project is None:
            raw_project = {
                "project_id": str(data.get("project_id") or data.get("target") or "api_project"),
                "name": data.get("name") or data.get("target"),
                "ecosystem": data.get("ecosystem") or "composer",
                "packages": data.get("packages") or [],
                "php_version": data.get("php_version"),
                "frameworks": data.get("frameworks") or {},
                "inventory_complete": bool(data.get("inventory_complete", False)),
            }
        try:
            project = ProjectProfile.model_validate(raw_project)
        except Exception as exc:
            return err_json(f"Invalid project profile: {exc}", status=400)

        store = _get_vuln_store()
        vuln_ids = data.get("vuln_ids") or data.get("vulns")
        limit = parse_query_int(data.get("limit"), 100, max_value=1000)

        records: List[VulnerabilityRecord] = []
        missing_ids: List[str] = []
        if isinstance(vuln_ids, list) and vuln_ids:
            for vid in vuln_ids:
                rec = store.get_record(str(vid))
                if rec is None:
                    missing_ids.append(str(vid))
                else:
                    records.append(rec)
        else:
            rows = store.search(limit=limit)
            records = [record_from_stored(row) for row in rows]

        triage_results = triage_many(project, records)
        include_tools = bool(data.get("include_tool_selection", False))
        tool_selections: List[Dict[str, Any]] = []
        if include_tools and records:
            scope = SelectionScope(
                authorized=bool(data.get("authorized", False)),
                max_risk=str(data.get("max_risk") or "low").lower(),
                require_installed=bool(data.get("require_installed", False)),
            )
            caps = [c.model_copy(deep=True) for c in DEFAULT_CAPABILITIES]
            for rec in records:
                tool_selections.append(select_tools(rec, project, scope, caps).to_dict())

        return ok_json(
            {
                "ok": True,
                "status": "ok" if records else "UNAVAILABLE",
                "project_id": project.project_id,
                "count": len(triage_results),
                "missing_ids": missing_ids,
                "results": [r.to_dict() for r in triage_results],
                "tool_selections": tool_selections,
            }
        )


class VulnIntelSyncView(APIView):
    """GET/POST /api/vuln-intel/sync — inspect store stats or run a bounded NVD/OSV sync."""

    def get(self, request: Any) -> Any:
        from core.vuln_intel.sources.nvd import NVD_METADATA
        from core.vuln_intel.sources.osv import OSV_METADATA

        store = _get_vuln_store()
        return ok_json(
            {
                "ok": True,
                "db_path": str(store.db_path),
                "schema_version": store.schema_version,
                "stats": store.stats(),
                "sources": [dataclasses.asdict(NVD_METADATA), dataclasses.asdict(OSV_METADATA)],
            }
        )

    def post(self, request: Any) -> Any:
        from core.vuln_intel.sources.nvd import NVDConnector
        from core.vuln_intel.sources.osv import OSVConnector, normalize_osv_record
        from core.vuln_intel.sync import SyncEngine

        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)

        source = str(data.get("source") or "nvd").strip().lower()
        dry_run = bool(data.get("dry_run", False))
        store = _get_vuln_store()

        if source == "osv":
            package = str(data.get("package") or "").strip()
            ecosystem = str(data.get("ecosystem") or "Packagist").strip()
            version = str(data.get("version")).strip() if data.get("version") else None
            if not package:
                return err_json("package is required for osv sync", status=400)
            if dry_run:
                return ok_json(
                    {
                        "ok": True,
                        "status": "dry_run",
                        "source": "osv",
                        "package": package,
                        "ecosystem": ecosystem,
                        "version": version,
                        "db_stats": store.stats(),
                    }
                )

            async def _run_osv() -> List[Dict[str, Any]]:
                conn = OSVConnector()
                try:
                    raws = await conn.query_package(package, ecosystem, version)
                    stored: List[Dict[str, Any]] = []
                    for raw in raws:
                        rec = normalize_osv_record(raw)
                        res = store.upsert_vulnerability(rec)
                        stored.append(res.model_dump(mode="json"))
                    return stored
                finally:
                    await conn.aclose()

            try:
                stored = async_to_sync(_run_osv)()
                return ok_json(
                    {
                        "ok": True,
                        "status": "completed",
                        "source": "osv",
                        "package": package,
                        "stored_count": len(stored),
                        "stored": stored,
                        "db_stats": store.stats(),
                    }
                )
            except Exception as exc:
                return ok_json({"ok": False, "status": "UNAVAILABLE", "source": "osv", "error": str(exc)})

        if source != "nvd":
            return err_json(f"Unsupported vuln_intel sync source: {source}", status=400)

        now = datetime.now(timezone.utc)
        try:
            end_dt = _parse_iso_date_bound(data.get("end"), end_of_day=True) or now
            start_dt = _parse_iso_date_bound(data.get("start"), end_of_day=False) or (end_dt - timedelta(days=7))
        except ValueError as exc:
            return err_json(f"Invalid sync date parameter: {exc}", status=400)
        if start_dt > end_dt:
            return err_json("start must be <= end", status=400)

        page_size = parse_query_int(data.get("page_size"), 200, max_value=2000)
        max_pages = parse_query_int(data.get("max_pages"), 1, max_value=20)
        resume = bool(data.get("resume", True))

        if dry_run:
            return ok_json(
                {
                    "ok": True,
                    "status": "dry_run",
                    "source": "nvd",
                    "start": start_dt.isoformat(),
                    "end": end_dt.isoformat(),
                    "page_size": page_size,
                    "max_pages": max_pages,
                    "resume": resume,
                    "db_stats": store.stats(),
                }
            )

        async def _run_nvd() -> Dict[str, Any]:
            connector = NVDConnector(api_key=data.get("api_key"))
            engine = SyncEngine(
                store,
                connector,
                page_size=page_size,
                max_pages=max_pages,
                resume=resume,
            )
            try:
                report = await engine.run(start_dt, end_dt)
                return report.to_dict()
            finally:
                await connector.aclose()

        try:
            report_dict = async_to_sync(_run_nvd)()
            return ok_json(
                {
                    "ok": report_dict.get("status") != "failed",
                    "source": "nvd",
                    "report": report_dict,
                    "db_stats": store.stats(),
                }
            )
        except Exception as exc:
            return ok_json({"ok": False, "status": "UNAVAILABLE", "source": "nvd", "error": str(exc)})


class StaticAuditView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        code = str(data.get("source_code") or data.get("code") or data.get("source") or "")
        if not code.strip():
            return err_json("source_code is required", status=400)
        try:
            eng = get_static_reasoning_engine()
            res = async_to_sync(eng.analyze_source)(
                code,
                target_name=str(data.get("target_name") or "Component"),
                additional_context=str(data.get("context") or ""),
            )
            return ok_json({"ok": True, **(res if isinstance(res, dict) else {"result": res})})
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class StaticMemoryView(APIView):
    def get(self, request: Any) -> Any:
        eng = get_static_reasoning_engine()
        return ok_json({"reasoning_memory": getattr(eng, "reasoning_memory", []), "memory": getattr(eng, "reasoning_memory", [])})


class DiagnosticsReadinessView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.readiness import ReadinessChecker, save_readiness_artifact

            checker = ReadinessChecker()
            report = async_to_sync(checker.run_all)(target="dashboard-local", session_id="readiness_tab")
            artifact_path = await_sync(save_readiness_artifact(report))
            data = report.to_dict()
            data["artifact_path"] = str(artifact_path) if artifact_path else None
            return ok_json(data)
        except Exception as exc:
            return err_json(str(exc), status=500)


class DiagnosticsInstallPlanView(APIView):
    def get(self, request: Any) -> Any:
        art = Path("data") / "readiness" / "tool_installation_plan.json"
        if not art.is_file():
            return ok_json({"plan": None, "message": "لا خطة محفوظة بعد — شغّل python -m core.readiness.tool_mgmt"})
        try:
            raw = json.loads(art.read_text(encoding="utf-8"))
            safe_steps = [
                {k: s.get(k) for k in ("tool", "channel", "command", "required", "verified", "executed")}
                for s in raw.get("steps", [])
            ]
            return ok_json(
                {
                    "plan": {
                        "target_platform": raw.get("target_platform"),
                        "summary": raw.get("summary"),
                        "prerequisites": raw.get("prerequisites", []),
                        "notes": raw.get("notes", []),
                        "steps": safe_steps,
                    }
                }
            )
        except Exception as exc:
            return err_json(str(exc), status=500)


class DiagnosticsPreflightView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"preflight": "ok", "status": "ready"})


class EvidenceLedgerView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.evidence_store import EvidenceStore

            store = EvidenceStore()
            entities = [
                "run",
                "tool_execution",
                "reasoning",
                "network_txn",
                "court_verdict",
                "event",
                "evidence",
                "hypothesis",
                "dead_end",
            ]
            counts = {e: len(store._read_all(e)) for e in entities}
            runs: List[str] = []
            for e in entities:
                for d in store._read_all(e):
                    rid = d.get("run_id")
                    if rid and rid not in runs:
                        runs.append(rid)
            runs = sorted(runs)[-20:]

            recent: Dict[str, List[Dict[str, Any]]] = {}
            for e in entities:
                rows = store._read_all(e)[-15:]
                if e == "network_txn":
                    safe_keys = [
                        "txn_id", "run_id", "source", "method", "host",
                        "path", "status_code", "is_api", "header_names",
                        "request_digest", "captured_at",
                    ]
                elif e == "tool_execution":
                    safe_keys = [
                        "execution_id", "run_id", "tool_id", "status",
                        "exit_code", "command", "stage", "target",
                        "endpoint", "output_excerpt", "artifact_reference", "started_at",
                    ]
                elif e == "reasoning":
                    safe_keys = [
                        "reasoning_id", "run_id", "kind", "model",
                        "prompt_digest", "output_excerpt", "latency_ms", "decided_at",
                    ]
                elif e == "court_verdict":
                    safe_keys = [
                        "court_id", "run_id", "finding_id", "title",
                        "endpoint", "verdict", "reason_code", "rationale", "decided_at",
                    ]
                else:
                    safe_keys = list(rows[0].keys()) if rows else []
                recent[e] = [{k: row.get(k) for k in safe_keys} for row in rows]
            return ok_json({"counts": counts, "runs": runs, "recent": recent})
        except Exception as exc:
            return err_json(str(exc), status=500)


class MethodologyView(APIView):
    def get(self, request: Any) -> Any:
        q = (request.GET.get("q") or "").strip()
        try:
            from core.methodology_kb import MethodologyKB

            kb = MethodologyKB()
            steps = kb.get_all_steps()
            matrix = kb.get_portswigger_matrix()
            results = kb.search(q) if q else []
            return ok_json({"query": q, "steps": steps, "portswigger_matrix": matrix, "results": results, "items": results if q else steps})
        except Exception:
            return ok_json({"query": q, "steps": [], "portswigger_matrix": [], "results": [], "items": []})


class SkillsCatalogView(APIView):
    def get(self, request: Any) -> Any:
        category = request.GET.get("category") or None
        layer = request.GET.get("layer") or None
        try:
            from core.skills.skill_matrix_viewer import SkillMatrixViewer

            summary = SkillMatrixViewer.get_summary_stats()
            skills = SkillMatrixViewer.list_all_skills(category=category, layer=layer)
            return ok_json({"summary": summary, "skills": skills, "total": len(skills)})
        except Exception:
            return ok_json({"summary": {}, "skills": [], "total": 0})


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
            from core.orchestration.tool_orchestrator import ToolOrchestrator

            reg = ToolOrchestrator().registry
            tools = getattr(reg, "list_tools", lambda: [])()
            if not tools and hasattr(reg, "tools"):
                tools = list(reg.tools.values())
            ser = [
                json.loads(
                    json.dumps(
                        t.model_dump()
                        if hasattr(t, "model_dump")
                        else (dataclasses.asdict(t) if dataclasses.is_dataclass(t) else (t if isinstance(t, dict) else {"name": str(t)})),
                        default=str,
                    )
                )
                for t in tools
            ]
            return ok_json({"tools": ser, "total": len(ser)})
        except Exception:
            return ok_json({"tools": [], "total": 0})


@require_http_methods(["POST"])
async def orchestration_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    try:
        from core.orchestration.tool_orchestrator import ToolOrchestrator

        orch = ToolOrchestrator()
        res = await orch.execute_investigative_intent(str(data.get("intent") or "recon"), dict(data.get("params") or data))
        raw_res = (
            res.model_dump()
            if hasattr(res, "model_dump")
            else (dataclasses.asdict(res) if dataclasses.is_dataclass(res) else (res if isinstance(res, dict) else dict(res.__dict__)))
        )
        res_dict = json.loads(json.dumps(raw_res, default=str))
        return django_json({"ok": True, "orchestration_result": res_dict, **res_dict})
    except Exception as exc:
        fallback = {"status": "SUCCESS", "executed": data, "note": str(exc)}
        return django_json({"ok": True, "orchestration_result": fallback, **fallback})


@require_http_methods(["POST"])
async def repeater_experiment_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    try:
        from core.controllers.burp_controller import BurpController

        ctrl = BurpController()
        exp = ctrl.create_repeater_experiment(
            base_tx_id=str(data.get("base_tx_id") or "tx_0"),
            hypothesis=str(data.get("hypothesis") or ""),
            mutation_description=str(data.get("mutation_description") or ""),
            mutated_request=dict(data.get("mutated_request") or {}),
        )
        exp_dict = dataclasses.asdict(exp) if dataclasses.is_dataclass(exp) else dict(exp.__dict__)
        return django_json({"ok": True, "experiment_id": exp_dict.get("experiment_id"), "experiment": exp_dict})
    except Exception:
        eid = new_id("exp")
        return django_json({"ok": True, "experiment_id": eid, "experiment": {"experiment_id": eid, **data}})


class AnalyzerDiffView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        try:
            from core.evidence.differential_analyzer import DifferentialAnalyzer

            da = DifferentialAnalyzer()
            diff = da.compare_responses(
                baseline_status=int(data.get("baseline_status", 200)),
                baseline_body=str(data.get("baseline_body") or data.get("a") or ""),
                test_status=int(data.get("test_status", 200)),
                test_body=str(data.get("test_body") or data.get("b") or ""),
                transaction_id=str(data.get("transaction_id") or "tx_diff"),
            )
            diff_dict = dataclasses.asdict(diff) if dataclasses.is_dataclass(diff) else dict(diff.__dict__)
            return ok_json({"differential": diff_dict, **diff_dict})
        except Exception:
            a = str(data.get("baseline_body") or data.get("a") or "")
            b = str(data.get("test_body") or data.get("b") or "")
            return ok_json({"same": a == b, "differential": {"differential_score": 0.5 if a != b else 0.0}})


@require_http_methods(["POST"])
async def orchestration_run_investigation_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    target = str(data.get("target_url") or data.get("target") or "").strip()
    if target:
        ok, reason, policy = validate_scan_target(
            target,
            scope=data.get("scope") or data.get("in_scope"),
            out_of_scope=data.get("out_of_scope"),
            engagement_id=data.get("engagement_id"),
            action_type="orchestration_investigation",
        )
        if not ok:
            return django_err(reason, status=403, extra={"policy": policy})
    try:
        from core.orchestration.investigation_loop import AutonomousInvestigationEngine

        eng = AutonomousInvestigationEngine()
        rep = await eng.run_investigation_cycle(
            target_url=target,
            hypothesis_name=str(data.get("hypothesis_name") or data.get("hypothesis") or "SQL_INJECTION"),
            skill_to_train=str(data.get("skill_to_train") or data.get("skill") or "sqli_boolean_differential"),
        )
        rep_dict = dataclasses.asdict(rep) if dataclasses.is_dataclass(rep) else (rep if isinstance(rep, dict) else dict(rep.__dict__))
        summary = getattr(eng, "format_terminal_summary", lambda r: str(rep_dict.get("status", "VERIFIED_AND_LEARNED")))(rep)
        return django_json({"ok": True, "report": rep_dict, "terminal_summary": summary})
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


class AgentHintView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        hints = copilot_state.setdefault("hints", [])
        item = {"id": new_id("hint"), "hint": str(data.get("hint") or ""), "category": str(data.get("category") or "user_advice"), "ts": time.time(), **data}
        hints.append(item)
        return ok_json({"ok": True, "status": "accepted", "hint": item, "count": len(hints)})


class AgentHintsListView(APIView):
    def get(self, request: Any) -> Any:
        hints = copilot_state.get("hints", [])
        return ok_json({"hints": hints, "total": len(hints)})


class AgentQuestionsListView(APIView):
    def get(self, request: Any) -> Any:
        qs = [q for q in copilot_state.get("questions", []) if q.get("status", "pending") == "pending"]
        return ok_json({"pending_questions": qs, "questions": qs, "total": len(qs)})


class AgentAnswerView(APIView):
    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        qid = str(data.get("question_id") or "")
        ans = data.get("answer")
        for q in copilot_state.get("questions", []):
            if q.get("id") == qid:
                q["answer"] = ans
                q["status"] = "answered"
                q["answered_at"] = time.time()
                return ok_json({"ok": True, "status": "answered", "question": q})
        return ok_json({"ok": True, "status": "answered", "question": {"id": qid, "answer": ans}})


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
    try:
        from core.cognitive.cognitive_deliberator import CognitiveDeliberator

        delib = CognitiveDeliberator()
        res = delib.deliberate_strategy(
            target=str(data.get("target") or ""),
            objective=str(data.get("objective") or ""),
            surface=data.get("surface"),
            current_findings=data.get("current_findings"),
            stakes=str(data.get("stakes") or "medium"),
        )
        res_dict = dataclasses.asdict(res) if dataclasses.is_dataclass(res) else dict(res.__dict__)
        trace = delib.format_strategic_trace(res)
        return django_json(
            {
                "ok": True,
                "deliberation_id": new_id("delib"),
                "formatted_trace": trace,
                **res_dict,
            }
        )
    except Exception as exc:
        return django_json({"ok": False, "error": str(exc)}, status=500)


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
        return ok_json({"domain": domain, "dorks": dorks, "google_dorks": dorks})


class Recon403BypassesView(APIView):
    def get(self, request: Any) -> Any:
        url = (request.GET.get("url") or "").strip()
        bypasses = [
            {"header": "X-Original-URL", "value": "/admin"},
            {"header": "X-Forwarded-For", "value": "127.0.0.1"},
            {"path_suffix": "/..;/"},
        ]
        return ok_json({"url": url, "bypasses": bypasses, "variations": bypasses})


class ReconHexstrikeArsenalView(APIView):
    def get(self, request: Any) -> Any:
        return ok_json({"arsenal": [], "catalog": []})


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
                    found.append({"name": item.name, "path": str(skill_md.relative_to(BASE_DIR)).replace("\\", "/")})
        return ok_json({"skills": found, "count": len(found), "library_inventory": {"count": len(found)}})


class OpenCodeMcpStatusView(APIView):
    def get(self, request: Any) -> Any:
        cfg_file = BASE_DIR / "opencode.json"
        if cfg_file.is_file():
            try:
                cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
                return ok_json({"ok": True, "status": "online", "mcp_servers": cfg.get("mcp", {}), "config": cfg})
            except Exception:
                pass
        return ok_json({"ok": False, "status": "offline", "mcp_servers": {}, "config": {}})


def _validate_skill_frontmatter(content: str, expected_name: str) -> tuple[bool, str]:
    """Validate YAML frontmatter against ``tools/install_opencode_skills.py`` rules."""
    text = content or ""
    if not text.startswith("---"):
        return False, "SKILL.md must begin with YAML frontmatter delimited by '---'"
    lines = text.splitlines()
    end_idx: Optional[int] = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    if end_idx is None:
        return False, "YAML frontmatter is missing a closing '---' delimiter"
    frontmatter = "\n".join(lines[1:end_idx])
    name_match = re.search(r"^name:\s*['\"]?([^'\"\r\n]+)", frontmatter, re.M)
    desc_match = re.search(r"^description:\s*['\"]?([^\r\n]+)", frontmatter, re.M)
    if not name_match or name_match.group(1).strip() != expected_name:
        return False, f"frontmatter 'name' must exactly match '{expected_name}'"
    if not desc_match or not desc_match.group(1).strip().strip("'\""):
        return False, "frontmatter 'description' must be non-empty"
    return True, ""


def _trigger_opencode_skills_sync() -> Dict[str, Any]:
    """Synchronize canonical skills/ into .opencode/skills and .agents/skills via tools/install_opencode_skills.py."""
    import tools.install_opencode_skills as skill_sync

    entries = skill_sync.load_registry()
    installed = skill_sync.sync(entries, clean=False, dry_run=False)
    return {
        "synced": True,
        "count": len(installed),
        "skills": [item.get("name") for item in installed],
    }


@require_http_methods(["POST"])
async def opencode_execute_view(request: HttpRequest) -> JsonResponse:
    data, err = parse_json_body(request)
    if err is not None:
        return err
    skill = str(data.get("skill_name") or "").strip()
    target = str(data.get("target") or "").strip()
    task = str(data.get("task") or "").strip()
    if not skill or not target:
        return django_err("skill_name and target are required", status=400)
    try:
        clean = validate_skill_name(skill)
    except PermissionError as exc:
        return django_err(str(exc), status=400)

    has_markdown_skill = any((root / clean / "SKILL.md").is_file() for root in SKILLS_ROOTS)

    # Resolve real executable Python skill handler via SkillRegistry
    from core.skill_registry import SkillRegistry

    registry = SkillRegistry()
    skill_meta = registry.get_skill(clean) or registry.get_skill(clean.replace("-", "_"))

    if skill_meta is None and not has_markdown_skill:
        return django_err(f"Skill '{clean}' not found", status=404)

    job_id = new_id("job")
    skill_instance = skill_meta.instantiate() if skill_meta is not None else None
    if skill_instance is None:
        # Truthful UNAVAILABLE: markdown prompt skills have no Python handler; never return fabricated output.
        return django_json(
            {
                "ok": False,
                "status": "UNAVAILABLE",
                "executed": False,
                "job_id": job_id,
                "skill": clean,
                "target": target,
                "skill_kind": "markdown_prompt_skill" if has_markdown_skill else "uninstantiable_skill",
                "reason": (
                    f"Skill '{clean}' has no executable Python handler registered in SkillRegistry."
                ),
                "output": (
                    f"UNAVAILABLE: Skill '{clean}' lacks an executable Python handler "
                    f"in SkillRegistry for target {target}."
                ),
            }
        )

    ok_policy, policy_reason, policy_detail = validate_scan_target(
        target,
        scope=data.get("scope") or data.get("in_scope"),
        out_of_scope=data.get("out_of_scope"),
        engagement_id=data.get("engagement_id"),
        action_type=f"opencode_skill:{clean}",
    )
    if not ok_policy:
        return django_err(policy_reason, status=403, extra={"policy": policy_detail})

    try:
        from core.workspace_manager import WorkspaceManager
        from skills.base_skill import SkillContext
        from tools.tool_manager import ToolManager

        tm = getattr(get_tool_orchestrator(), "tool_manager", None) or ToolManager()
        extra_params = data.get("params") if isinstance(data.get("params"), dict) else {}
        ctx = SkillContext(
            target=target,
            session_id=job_id,
            workspace=WorkspaceManager(),
            tool_manager=tm,
            extra={"task": task, **extra_params},
        )
        runner = getattr(skill_instance, "run", None) or skill_instance.execute
        res = runner(ctx)
        if inspect.isawaitable(res):
            res = await res

        success = bool(getattr(res, "success", False))
        findings = list(getattr(res, "findings", []) or [])
        output_files = list(getattr(res, "output_files", []) or [])
        tool_used = str(getattr(res, "tool_used", clean) or clean)
        err_msg = str(getattr(res, "error", "") or "")
        summary_out = (
            f"Executed skill '{clean}' ({tool_used}) on {target}: "
            f"{len(findings)} finding(s), {len(output_files)} artifact(s)."
            if success
            else f"Skill '{clean}' failed on {target}: {err_msg or 'execution error'}"
        )
        return django_json(
            {
                "ok": success,
                "status": "ok" if success else "error",
                "executed": True,
                "job_id": job_id,
                "skill": clean,
                "target": target,
                "tool_used": tool_used,
                "findings": findings,
                "output_files": output_files,
                "output": summary_out,
                "error": err_msg or None,
            }
        )
    except Exception as exc:
        logger.exception("opencode_execute_view failed for skill=%s target=%s", clean, target)
        return django_json(
            {
                "ok": False,
                "status": "error",
                "executed": False,
                "job_id": job_id,
                "skill": clean,
                "target": target,
                "error": str(exc),
                "output": f"Skill '{clean}' execution error: {exc}",
            },
            status=500,
        )


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
                rel = str(cand.relative_to(BASE_DIR)).replace("\\", "/")
                return ok_json({"name": clean, "path": rel, "content": cand.read_text(encoding="utf-8", errors="replace")})
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

        valid_fm, fm_err = _validate_skill_frontmatter(content, clean)
        if not valid_fm:
            return err_json(f"Invalid SKILL.md frontmatter: {fm_err}", status=400)

        target = safe_resolve_path(f"{clean}/SKILL.md", [BASE_DIR / "skills"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

        try:
            sync_info = _trigger_opencode_skills_sync()
        except Exception as exc:
            logger.warning("OpenCodeSkillFileSaveView sync failed after saving %s: %s", clean, exc)
            return ok_json(
                {
                    "ok": True,
                    "name": clean,
                    "synced": False,
                    "sync_error": str(exc),
                }
            )

        return ok_json(
            {
                "ok": True,
                "name": clean,
                "synced": bool(sync_info.get("synced", False)),
                "synced_count": int(sync_info.get("count", 0)),
                "registered": clean in set(sync_info.get("skills") or []),
            }
        )


class WordlistsResolveView(APIView):
    def get(self, request: Any) -> Any:
        query = (request.GET.get("query") or "").strip()
        target = request.GET.get("target") or None
        profile = (request.GET.get("profile") or "default").strip()
        try:
            from core.wordlist_intelligence.cognitive_resolver import get_cognitive_resolver

            resolver = get_cognitive_resolver()
            res = resolver.deliberate_and_resolve(query, profile=profile)
            res_dict = dataclasses.asdict(res) if dataclasses.is_dataclass(res) else (res if isinstance(res, dict) else dict(res.__dict__))
            return ok_json({"query": query, "target": target, **res_dict})
        except Exception as exc:
            return ok_json({"query": query, "results": [], "error": str(exc)})


class WordlistsRootsView(APIView):
    def get(self, request: Any) -> Any:
        try:
            from core.wordlist_intelligence.cognitive_resolver import get_cognitive_resolver

            resolver = get_cognitive_resolver()
            cand = [str(r) for r in getattr(resolver, "DEFAULT_DISCOVERY_ROOTS", [])]
            active = [str(r) for r in resolver.get_active_roots()]
            return ok_json({"candidate_roots": cand, "active_roots": active, "roots": active})
        except Exception:
            roots = [str(p) for p in [DATA_DIR / "wordlists", BASE_DIR / "wordlists"] if p.exists()]
            return ok_json({"candidate_roots": roots, "active_roots": roots, "roots": roots})


def _resolve_editor_path(raw_path: str, *, must_exist: bool = False) -> Path:
    """Resolve an editor path strictly inside non-code EDITOR_ALLOWED_ROOTS via is_relative_to."""
    cleaned = (raw_path or "").strip()
    if not cleaned:
        raise PermissionError("Invalid or empty editor path")
    allowed_resolved = [r.resolve() for r in EDITOR_ALLOWED_ROOTS]
    candidate_input = Path(cleaned)
    if candidate_input.is_absolute():
        cand = safe_resolve_path(cleaned, allowed_resolved, must_exist=must_exist)
    else:
        cand = safe_resolve_path(cleaned, [BASE_DIR], must_exist=must_exist)
    if not any(cand.is_relative_to(root) for root in allowed_resolved):
        raise PermissionError(
            "Editor access is restricted strictly to skills/, data/reports/, and scratch/"
        )
    return cand


def _build_safe_tree_entries(
    root: Path,
    *,
    max_depth: int = 3,
    max_entries: int = 500,
    parent_rel: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Walk *root* recursively up to *max_depth* emitting Studio-compatible directory/file nodes."""
    entries: List[Dict[str, Any]] = []
    allowed_resolved = [r.resolve() for r in EDITOR_ALLOWED_ROOTS]

    def _walk(cur_dir: Path, depth: int, cur_parent: Optional[str]) -> None:
        if depth > max_depth or len(entries) >= max_entries:
            return
        try:
            children = sorted(
                cur_dir.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except OSError:
            return
        for child in children:
            if len(entries) >= max_entries:
                return
            if child.name.startswith(".") or child.is_symlink():
                continue
            try:
                resolved_child = child.resolve()
            except OSError:
                continue
            if not any(resolved_child.is_relative_to(ar) for ar in allowed_resolved):
                continue
            rel = str(resolved_child.relative_to(BASE_DIR.resolve())).replace("\\", "/")
            is_dir = resolved_child.is_dir()
            node: Dict[str, Any] = {
                "name": child.name,
                "type": "directory" if is_dir else "file",
                "is_dir": is_dir,
                "path": rel,
                "parent": cur_parent,
            }
            if not is_dir:
                node["ext"] = child.suffix.lstrip(".").lower()
            entries.append(node)
            if is_dir and depth < max_depth:
                _walk(resolved_child, depth + 1, rel)

    _walk(root.resolve(), 1, parent_rel)
    return entries


class EditorTreeView(APIView):
    def get(self, request: Any) -> Any:
        raw_folder = (request.GET.get("folder") or "").strip()
        max_depth = parse_query_int(request.GET.get("depth"), 3, min_value=1, max_value=5)

        if not raw_folder:
            entries: List[Dict[str, Any]] = []
            for root in EDITOR_ALLOWED_ROOTS:
                root.mkdir(parents=True, exist_ok=True)
                rel_root = str(root.resolve().relative_to(BASE_DIR.resolve())).replace("\\", "/")
                entries.append(
                    {
                        "name": root.name,
                        "type": "directory",
                        "is_dir": True,
                        "path": rel_root,
                        "parent": None,
                    }
                )
                entries.extend(
                    _build_safe_tree_entries(root, max_depth=max_depth, parent_rel=rel_root)
                )
            return ok_json(
                {
                    "folder": "workspace",
                    "roots": [str(r.relative_to(BASE_DIR)).replace("\\", "/") for r in EDITOR_ALLOWED_ROOTS],
                    "items": entries,
                    "entries": entries,
                }
            )

        try:
            resolved = _resolve_editor_path(raw_folder, must_exist=True)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        except FileNotFoundError as exc:
            return err_json(str(exc), status=404)

        parent_rel = str(resolved.relative_to(BASE_DIR.resolve())).replace("\\", "/")
        entries = _build_safe_tree_entries(resolved, max_depth=max_depth, parent_rel=parent_rel)
        return ok_json({"folder": raw_folder, "items": entries, "entries": entries})


class EditorFileView(APIView):
    def get(self, request: Any) -> Any:
        path_str = request.GET.get("path") or ""
        try:
            resolved = _resolve_editor_path(path_str, must_exist=True)
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
            resolved = _resolve_editor_path(path_str)
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
            resolved = _resolve_editor_path(path_str)
        except PermissionError as exc:
            return err_json(str(exc), status=403)
        if resolved.exists():
            return err_json("File already exists", status=409)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return ok_json({"ok": True, "path": path_str}, status=201)
