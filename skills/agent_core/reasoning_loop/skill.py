"""
Reasoning Loop Skill — مهارة "حلقة التفكير السباعية" بالمعمارية ثلاثية الطبقات الحتمية
========================================================================================
تطبق القوانين الهندسية الثلاثة الصارمة للوكيل عبر دورة الـ 7 مراحل:
  Observe → Think → Plan → Act → Parse → Update Graph → Decide

القوانين المعمارية المطبقة:
  1. فصل "التفكير" (ReasoningPlane) عن "التحكم" (DeterministicControlPlane) عن "التنفيذ" (ExecutionPlane).
  2. تمثيل الحالة في رسم بياني (KnowledgeGraph) وآلة حالة منتهية (AgentStateMachine / FSM)، وليس في نص محادثة متزايد.
  3. فرض النطاق والسلامة عبر كود حتمي صارم (DeterministicSafetyGate + HMAC Directive Token)، وليس عبر "طلب" في الـ Prompt.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

from agents.security_intelligence.task_clue_cache import TaskClueCache
from core.architecture.deterministic_planes import (
    DeterministicControlPlane,
    ExecutionPlane,
    FSMState,
    ReasoningPlane,
)
from core.graph.knowledge_graph import KnowledgeGraph
from hunter_ai.knowledge.rag_engine import PreExecutionSyntaxValidator, RAGEngine
from hunter_ai.orchestration.triple_agents import TripleAgentSystem
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class ReasoningLoopSkill(BaseSkill):
    name = "agent_reasoning_loop"
    category = "agent_core"
    description = (
        "7-stage loop with 3-Plane Separation (Reasoning/Control/Execution), "
        "Graph+FSM State, and Deterministic Code-Enforced Scope & Safety."
    )
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 60.0
    max_retries = 1

    INTERESTING_PATTERNS = [
        r"id=", r"uid=", r"user_id=", r"account=", r"order=", r"invoice=",
        r"url=", r"callback=", r"webhook=", r"return=", r"next=", r"redirect=",
        r"price=", r"amount=", r"total=", r"coupon=", r"discount=",
        r"role=", r"is_admin=", r"token=", r"jwt=", r"prompt=", r"serialized=",
        r"\.git/", r"\.env", r"config", r"admin", r"swagger", r"graphql", r"\.json$",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rag_engine: Optional[RAGEngine] = None
        self.reasoning_plane = ReasoningPlane()
        self.execution_plane = ExecutionPlane()

    def _get_rag(self) -> RAGEngine:
        if self._rag_engine is None:
            self._rag_engine = RAGEngine()
        return self._rag_engine

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        target = ctx.target
        phase = ctx.extra.get("phase", "recon")
        findings_so_far: List[Dict[str, Any]] = ctx.extra.get("findings_so_far", []) or []
        goal = ctx.extra.get("goal", "Discover and validate security findings")
        surface = ctx.extra.get("surface", {}) or {}
        scope_domains = list(ctx.extra.get("scope_domains") or surface.get("domains") or [target])

        # Initialize Graph + ClueCache + TripleAgents + Deterministic Control Plane (FSM + SafetyGate)
        kg: KnowledgeGraph = ctx.extra.get("knowledge_graph") or KnowledgeGraph(root_asset=target)
        kg.load()
        clue_cache: TaskClueCache = ctx.extra.get("clue_cache") or TaskClueCache(persist=True)
        triple_agents: TripleAgentSystem = ctx.extra.get("triple_agents") or TripleAgentSystem(
            graph_id=f"tdg_{ctx.session_id or 'default'}",
            clue_cache=clue_cache,
            persist_cache=True,
        )
        control_plane: DeterministicControlPlane = ctx.extra.get("control_plane") or DeterministicControlPlane(
            target=target,
            scope_domains=scope_domains,
            phase=phase,
        )
        if control_plane.fsm.current_state != FSMState.INIT:
            control_plane.fsm.current_state = FSMState.INIT

        trace: List[Dict[str, Any]] = []
        t0 = time.time()

        # ── 1. Observe (Transition FSM -> OBSERVING; Read Graph & State Snapshot) ──
        control_plane.fsm.transition_to(FSMState.OBSERVING, reason="Stage 1: Observe")
        obs = self._observe(target, phase, findings_so_far, ctx, kg, control_plane, clue_cache)
        trace.append({"step": 1, "stage": "Observe", "phase": "observe", "fsm_state": control_plane.fsm.current_state.value, "data": obs, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(f"[1. Observe] [FSM={control_plane.fsm.current_state.value}] {obs['summary']}")

        # ── 2. Think (Reasoning Plane Only — Isolated from Execution & State Mutation) ──
        control_plane.fsm.transition_to(FSMState.THINKING, reason="Stage 2: ReasoningPlane deliberation")
        thought = await self._think(goal, phase, obs, findings_so_far, ctx)
        trace.append({"step": 2, "stage": "Think", "phase": "think", "plane": "ReasoningPlane", "fsm_state": control_plane.fsm.current_state.value, "data": thought, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(f"[2. Think] [ReasoningPlane] {thought['reasoning']} (confidence={thought['confidence']:.2f})")

        # ── 3. Plan (Formulate ReasoningIntent & Schedule in Control Plane) ──
        control_plane.fsm.transition_to(FSMState.PLANNING, reason="Stage 3: ControlPlane planning")
        plan = self._plan(thought, obs, ctx, triple_agents, control_plane, clue_cache, kg)
        trace.append({"step": 3, "stage": "Plan", "phase": "plan", "plane": "ControlPlane", "fsm_state": control_plane.fsm.current_state.value, "data": plan, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(f"[3. Plan] [ControlPlane] Selected tool={plan['tool']} skill={plan['skill']}")

        # ── 4. Act (Deterministic Safety Gate -> Signed Directive -> Execution Plane) ──
        action = self._act(plan, obs, ctx, triple_agents, control_plane)
        trace.append({"step": 4, "stage": "Act", "phase": "act", "plane": "ExecutionPlane", "fsm_state": control_plane.fsm.current_state.value, "data": action, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(
            f"[4. Act] [ExecutionPlane] GateAllowed={action['in_scope']} | SyntaxValid={action['syntax_validation']['valid']} | "
            f"{action['tool'] or action['skill']} → {action['reason']}"
        )

        # ── 5. Parse (Normalize Execution Output into Structured Records) ──
        if control_plane.fsm.current_state == FSMState.EXECUTING:
            control_plane.fsm.transition_to(FSMState.PARSING, reason="Stage 5: Parse")
        parsed = self._parse(action, obs, findings_so_far)
        trace.append({"step": 5, "stage": "Parse", "phase": "parse", "fsm_state": control_plane.fsm.current_state.value, "data": parsed, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(f"[5. Parse] Normalized {parsed['records_count']} structured records")

        # ── 6. Update Graph (Mutate Graph + FSM State, Zero Chat Bloat) ──
        if control_plane.fsm.current_state == FSMState.PARSING:
            control_plane.fsm.transition_to(FSMState.GRAPH_UPDATING, reason="Stage 6: Update KnowledgeGraph")
        graph_state = self._update_graph(target, obs, parsed, ctx, kg, clue_cache, control_plane)
        trace.append({"step": 6, "stage": "Update Graph", "phase": "update_graph", "fsm_state": control_plane.fsm.current_state.value, "data": graph_state, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(f"[6. Update Graph] Graph nodes={graph_state['nodes_count']} edges={graph_state['edges_count']}")

        # ── 7. Decide (Deterministic Control Plane State Transition Decision) ──
        if control_plane.fsm.current_state == FSMState.GRAPH_UPDATING:
            control_plane.fsm.transition_to(FSMState.DECIDING, reason="Stage 7: ControlPlane Decide")
        decision = self._decide(action, thought, obs, parsed, graph_state, triple_agents, control_plane)
        trace.append({"step": 7, "stage": "Decide", "phase": "decide", "plane": "ControlPlane", "fsm_state": control_plane.fsm.current_state.value, "data": decision, "timestamp": round(time.time() - t0, 4)})
        self.logger.info(f"[7. Decide] [FSM={control_plane.fsm.current_state.value}] Decision={decision['decision']} ({decision['arabic_decision']})")

        # Write trace, next action, and target graph
        p_trace = ctx.workspace.write_file(target, "agent_core", "thinking_trace.json", json.dumps(trace, indent=2, ensure_ascii=False), ctx.session_id)
        p_action = ctx.workspace.write_file(target, "agent_core", "next_action.json", json.dumps({**action, "decision": decision}, indent=2, ensure_ascii=False), ctx.session_id)
        p_graph = ctx.workspace.write_file(target, "agent_core", "target_graph.json", json.dumps(graph_state, indent=2, ensure_ascii=False), ctx.session_id)
        result.output_files = {
            "thinking_trace.json": str(p_trace),
            "next_action.json": str(p_action),
            "target_graph.json": str(p_graph),
        }

        if action.get("suggested_finding"):
            result.add_finding(
                title=action["suggested_finding"]["title"],
                evidence=action["suggested_finding"]["evidence"],
                severity=action["suggested_finding"].get("severity", "Medium"),
                vuln_type=action["suggested_finding"].get("type", "logic"),
                recommendation=action["suggested_finding"].get("recommendation", ""),
                url=action["suggested_finding"].get("url", ""),
            )

        result.next_skills = action.get("next_skills", [])
        result.metadata["decision"] = decision["decision"]
        result.metadata["fsm_state"] = control_plane.fsm.current_state.value
        result.metadata["graph_summary"] = {
            "nodes": graph_state["nodes_count"],
            "edges": graph_state["edges_count"],
            "verified_facts_count": graph_state.get("verified_facts", {}).get("verified_edges_count", 0),
        }
        result.raw_output = {
            "thinking_trace": json.dumps(trace, ensure_ascii=False),
            "next_action": json.dumps(action, ensure_ascii=False),
            "target_graph": json.dumps(graph_state, ensure_ascii=False),
            "decision": json.dumps(decision, ensure_ascii=False),
        }
        return result

    # ── 1. Observe ──────────────────────────────────────────────────────────

    def _observe(
        self,
        target: str,
        phase: str,
        findings: List[Dict],
        ctx: SkillContext,
        kg: KnowledgeGraph,
        control_plane: DeterministicControlPlane,
        clue_cache: TaskClueCache,
    ) -> Dict[str, Any]:
        available_tools = []
        try:
            for t in ("subfinder", "httpx", "nmap", "nuclei", "katana", "arjun", "ffuf", "sqlmap",
                      "dalfox", "feroxbuster", "paramspider", "rustscan", "trivy", "browser"):
                if ctx.tool_manager.is_available(t):
                    available_tools.append(t)
        except Exception:
            pass

        interesting_signals = []
        for f in findings:
            text = json.dumps(f, ensure_ascii=False)
            for pat in self.INTERESTING_PATTERNS:
                if re.search(pat, text, re.I):
                    interesting_signals.append(pat)

        surface = ctx.extra.get("surface", {}) or {}
        compact_fsm_state = control_plane.fsm.export_compact_state(kg, clue_cache)

        return {
            "target": target,
            "phase": phase,
            "fsm_compact_state": compact_fsm_state,
            "available_tools": available_tools,
            "findings_count": len(findings),
            "interesting_signals": sorted(set(interesting_signals))[:12],
            "surface_counts": {
                "subdomains": len(surface.get("subdomains", surface.get("domains", []))),
                "live_hosts": len(surface.get("live_hosts", [])),
                "endpoints": len(surface.get("endpoints", [])),
                "apis": len(surface.get("apis", [])),
                "parameters": len(surface.get("parameter_targets", [])),
                "open_ports": len(surface.get("open_ports", [])),
            },
            "verified_facts_prompt": compact_fsm_state["verified_facts_prompt"],
            "verified_facts_counts": compact_fsm_state["graph_verified_counts"],
            "retry_attempt": ctx.retry_attempt,
            "summary": (
                f"Phase={phase}, FSM={compact_fsm_state['fsm_state']}, tools={len(available_tools)}, "
                f"findings={len(findings)}, signals={len(set(interesting_signals))}, "
                f"chat_history={compact_fsm_state['chat_history_messages_retained']}"
            ),
        }

    # ── 2. Think (Reasoning Plane) ──────────────────────────────────────────

    async def _think(self, goal: str, phase: str, obs: Dict, findings: List[Dict], ctx: SkillContext) -> Dict[str, Any]:
        reasoning_parts: List[str] = []
        classifications: List[str] = []
        confidence = 0.35
        next_tool = None
        next_skill = None

        signals = obs["interesting_signals"]
        tools = obs["available_tools"]

        if any(s in signals for s in (r"url=", r"callback=", r"webhook=", r"return=", r"redirect=")):
            classifications.append("SSRF_OR_OPEN_REDIRECT_SURFACE")
            next_tool = "katana" if "katana" in tools else "httpx"
            next_skill = "ssrf_skill"
            reasoning_parts.append("URL/redirect parameters classified → prioritize SSRF & Open Redirect verification")
            confidence = max(confidence, 0.82)

        if any(s in signals for s in (r"id=", r"uid=", r"user_id=", r"account=", r"order=", r"invoice=")):
            classifications.append("OBJECT_REFERENCE_SURFACE")
            next_tool = "ffuf" if "ffuf" in tools else next_tool
            next_skill = "idor_tester"
            reasoning_parts.append("Object identifier parameters classified → prioritize IDOR / BOLA matrix testing")
            confidence = max(confidence, 0.78)

        if any(s in signals for s in (r"role=", r"is_admin=", r"price=", r"amount=", r"total=", r"coupon=", r"discount=")):
            classifications.append("BUSINESS_LOGIC_AND_BOPLA_SURFACE")
            next_skill = "mass_assignment_skill"
            reasoning_parts.append("Privilege/financial parameters classified → prioritize Mass Assignment & Logic Flaw testing")
            confidence = max(confidence, 0.76)

        if any(s in signals for s in (r"token=", r"jwt=")):
            classifications.append("AUTH_TOKEN_SURFACE")
            next_skill = "jwt_advanced_skill"
            reasoning_parts.append("Token/JWT parameters classified → prioritize JWT signature & key confusion audit")
            confidence = max(confidence, 0.80)

        if any(s in signals for s in (r"prompt=", r"serialized=")):
            classifications.append("ADVANCED_INJECTION_SURFACE")
            next_skill = "llm_prompt_injection_skill" if r"prompt=" in signals else "deserialization_skill"
            reasoning_parts.append("AI prompt or serialized state classified → prioritize specialized injection skill")
            confidence = max(confidence, 0.80)

        if any(s in signals for s in (r"\.git/", r"\.env", r"config", r"\.json$")):
            classifications.append("SECRET_AND_CONFIG_EXPOSURE")
            next_tool = "nuclei" if "nuclei" in tools else next_tool
            next_skill = "secrets_hunter"
            reasoning_parts.append("Sensitive config/bundle surface classified → run secret & template inspection")
            confidence = max(confidence, 0.70)

        if any(s in signals for s in (r"admin", r"swagger", r"graphql")):
            classifications.append("PRIVILEGED_API_SURFACE")
            next_tool = "katana" if "katana" in tools else next_tool
            next_skill = "bfla_auth_bypass_skill"
            reasoning_parts.append("Admin/API schema surface classified → test BFLA & GraphQL/OpenAPI exposure")
            confidence = max(confidence, 0.72)

        if phase == "recon" and not next_tool:
            classifications.append("INITIAL_RECON_SURFACE")
            if "subfinder" in tools:
                next_tool = "subfinder"
                next_skill = "subdomain_enum"
                reasoning_parts.append("Early recon phase → start with passive subdomain enumeration")
                confidence = 0.60
            elif "httpx" in tools:
                next_tool = "httpx"
                next_skill = "live_host_detection"
                reasoning_parts.append("Recon phase → probe live hosts")
                confidence = 0.55

        if not next_tool and not next_skill:
            classifications.append("GENERAL_ATTACK_SURFACE")
            next_skill = "attack_surface_ranker"
            reasoning_parts.append("General surface → rank discovered assets by exploitability")
            confidence = 0.45

        # Statistical RAG Retrieval (COAPT pattern)
        rag_matches: List[Dict[str, Any]] = []
        try:
            rag = self._get_rag()
            query_str = f"{phase} {' '.join(classifications)} {' '.join(signals)} web api security"
            items = rag.retrieve_statistically(query=query_str, top_k=3, min_score=0.05)
            for item in items:
                rag_matches.append({
                    "item_id": item.item_id,
                    "title": item.title,
                    "score": item.score,
                    "breakdown": item.metadata.get("statistical_breakdown", {}),
                })
            if rag_matches:
                reasoning_parts.append(f"RAG-top={rag_matches[0]['title']} (score={rag_matches[0]['score']:.2f})")
        except Exception as rag_err:
            self.logger.debug(f"RAG statistical lookup skipped: {rag_err}")

        # LLM deliberation strictly grounded in Verified Graph Facts & FSM State (Zero Chat History)
        llm = ctx.extra.get("llm")
        if llm:
            try:
                prompt = (
                    f"You are the ReasoningPlane of a deterministic agent. You receive ONLY the FSM state and Verified Graph Facts.\n"
                    f"Target={obs['target']} Phase={obs['phase']} FSM={obs['fsm_compact_state']['fsm_state']}.\n"
                    f"Verified Graph Facts:\n{obs.get('verified_facts_prompt', '')}\n"
                    f"Signals={signals}. Tools available={tools}. Goal={goal}.\n"
                    f"Propose a single ReasoningIntent (tool or skill) in JSON: "
                    f"{{\"tool\": ..., \"skill\": ..., \"reasoning\": ..., \"confidence\": 0.0-1.0}}"
                )
                llm_answer = await llm.execute_prompt(prompt) if hasattr(llm, "execute_prompt") else str(llm)
                reasoning_parts.append(f"LLM-enriched: {llm_answer[:200]}")
                confidence = min(confidence + 0.1, 0.95)
            except Exception as exc:
                self.logger.warning(f"LLM enrichment skipped: {exc}")

        return {
            "plane": "ReasoningPlane",
            "goal": goal,
            "phase": phase,
            "classifications": classifications,
            "rag_hypotheses": rag_matches,
            "reasoning": " | ".join(reasoning_parts),
            "confidence": round(confidence, 2),
            "next_tool": next_tool,
            "next_skill": next_skill,
        }

    # ── 3. Plan (Control Plane) ─────────────────────────────────────────────

    def _plan(
        self,
        thought: Dict,
        obs: Dict,
        ctx: SkillContext,
        triple_agents: TripleAgentSystem,
        control_plane: DeterministicControlPlane,
        clue_cache: TaskClueCache,
        kg: KnowledgeGraph,
    ) -> Dict[str, Any]:
        compact_state = control_plane.fsm.export_compact_state(kg, clue_cache)
        intent = self.reasoning_plane.formulate_intent(compact_state, thought, obs["target"])

        follow_up_map = {
            "subfinder": ["live_host_detection", "dns_enum", "subdomain_takeover_skill"],
            "httpx": ["tech_detection", "waf_detection", "bfla_auth_bypass_skill"],
            "katana": ["arjun", "idor_tester", "ssrf_hunter", "dom_xss_hunter"],
            "arjun": ["idor_tester", "mass_assignment_skill", "sqli_hunter"],
            "ffuf": ["idor_tester", "bypass_403"],
            "nuclei": ["triage_gate", "report_generator"],
        }
        chain_skills = list(follow_up_map.get(intent.proposed_tool or "", []))
        if intent.proposed_skill and intent.proposed_skill not in chain_skills:
            chain_skills.insert(0, intent.proposed_skill)

        triple_plan = triple_agents.plan_and_execute(
            target=obs["target"],
            technique=intent.proposed_skill or intent.proposed_tool or "assessment_step",
            description=intent.rationale[:160],
        )

        return {
            "plane": "ControlPlane",
            "target": obs["target"],
            "phase": obs["phase"],
            "tool": intent.proposed_tool,
            "skill": intent.proposed_skill,
            "candidate_command": intent.proposed_command,
            "reasoning_intent": {
                "proposed_tool": intent.proposed_tool,
                "proposed_skill": intent.proposed_skill,
                "proposed_command": intent.proposed_command,
                "confidence": intent.confidence,
            },
            "triple_tasks": triple_plan,
            "planned_chain": chain_skills,
            "priority": "HIGH" if thought["confidence"] >= 0.75 else "NORMAL",
            "rationale": intent.rationale,
        }

    # ── 4. Act (Deterministic Gate -> Execution Plane) ──────────────────────

    def _act(
        self,
        plan: Dict,
        obs: Dict,
        ctx: SkillContext,
        triple_agents: TripleAgentSystem,
        control_plane: DeterministicControlPlane,
    ) -> Dict[str, Any]:
        explicit_scope = bool(ctx.extra.get("scope_authorized", True))
        from core.architecture.deterministic_planes import ReasoningIntent

        intent = ReasoningIntent(
            phase=obs["phase"],
            classifications=[],
            proposed_tool=plan.get("tool"),
            proposed_skill=plan.get("skill"),
            proposed_command=plan.get("candidate_command", ""),
            confidence=float(ctx.extra.get("confidence", 0.75)),
            rationale=plan.get("rationale", ""),
        )

        # Control Plane deterministically validates & signs the directive
        directive = control_plane.authorize_intent(
            intent=intent,
            target=obs["target"],
            explicit_scope_flag=explicit_scope,
            planned_chain=plan.get("planned_chain", []),
        )

        # Execution Plane verifies the HMAC token and executes only if signed
        exec_output = self.execution_plane.execute_directive(directive, control_plane)

        exec_task_id = plan.get("triple_tasks", {}).get("executor_task")
        if exec_task_id:
            try:
                if exec_output["executed"]:
                    triple_agents.execute_task(
                        exec_task_id,
                        sensor_output={
                            "tool": exec_output.get("tool") or exec_output.get("skill") or "agent",
                            "target": obs["target"],
                            "command": exec_output.get("approved_command", ""),
                            "directive_id": exec_output.get("directive_id"),
                            "syntax_valid": True,
                        },
                    )
                else:
                    triple_agents.clue_cache.mark_task_failed(
                        exec_task_id,
                        reason=exec_output["reason"],
                    )
            except Exception:
                pass

        exec_output["confidence"] = float(ctx.extra.get("confidence", 0.75)) if exec_output["in_scope"] else 0.0
        return exec_output

    # ── 5. Parse ────────────────────────────────────────────────────────────

    def _parse(self, action: Dict, obs: Dict, findings: List[Dict]) -> Dict[str, Any]:
        structured_findings = []
        for idx, f in enumerate(findings):
            structured_findings.append({
                "id": f.get("task_id") or f"F-{idx+1:03d}",
                "title": f.get("title") or f.get("vuln_class") or "Candidate Signal",
                "vuln_class": f.get("vuln_class") or f.get("type") or "generic",
                "target": f.get("target") or f.get("url") or obs["target"],
                "verified": bool(f.get("verdict") == "CONFIRMED" or f.get("verified")),
                "confidence": float(f.get("confidence", 0.5) or 0.5),
            })
        return {
            "target": obs["target"],
            "phase": obs["phase"],
            "records_count": len(structured_findings) + sum(obs["surface_counts"].values()),
            "surface_counts": obs["surface_counts"],
            "signals": obs["interesting_signals"],
            "structured_findings": structured_findings,
        }

    # ── 6. Update Graph ─────────────────────────────────────────────────────

    def _update_graph(
        self,
        target: str,
        obs: Dict,
        parsed: Dict,
        ctx: SkillContext,
        kg: KnowledgeGraph,
        clue_cache: TaskClueCache,
        control_plane: DeterministicControlPlane,
    ) -> Dict[str, Any]:
        kg.register_host(target, empirically_verified=True)
        nodes: List[Dict[str, Any]] = [{"id": f"host:{target}", "type": "TARGET_HOST", "label": target}]
        edges: List[Dict[str, Any]] = []

        surface = ctx.extra.get("surface", {}) or {}
        subdomains = surface.get("subdomains") or surface.get("domains") or []
        for sub in subdomains[:15]:
            nid = f"sub:{sub}"
            nodes.append({"id": nid, "type": "SUBDOMAIN", "label": sub})
            edges.append({"from": f"host:{target}", "to": nid, "relation": "HAS_SUBDOMAIN"})
            kg.register_host(str(sub), empirically_verified=True)

        for port_entry in (surface.get("open_ports") or [])[:15]:
            try:
                p_str = str(port_entry)
                if ":" in p_str:
                    h_part, p_num = p_str.rsplit(":", 1)
                    kg.register_port_service(h_part, int(p_num), empirically_verified=True)
                else:
                    kg.register_port_service(target, int(p_str), empirically_verified=True)
                clue_cache.add_clue(
                    target=target,
                    source_tool="network_scanner",
                    clue_type="open_port",
                    content=str(port_entry),
                    confidence=0.9,
                )
            except Exception:
                pass

        for ep in (surface.get("endpoints") or [])[:20]:
            nid = f"ep:{ep}"
            nodes.append({"id": nid, "type": "ENDPOINT", "label": ep})
            edges.append({"from": f"host:{target}", "to": nid, "relation": "EXPOSES_ENDPOINT"})
            kg.register_endpoint(str(ep), method="GET", empirically_verified=True, host=target)
            clue_cache.add_clue(
                target=target,
                source_tool="crawler",
                clue_type="endpoint",
                content=str(ep),
                confidence=0.85,
            )

        for sig in parsed.get("signals", []):
            nid = f"sig:{sig}"
            nodes.append({"id": nid, "type": "SIGNAL", "label": sig})
            edges.append({"from": f"host:{target}", "to": nid, "relation": "EXHIBITS_SIGNAL"})
            clue_cache.add_clue(
                target=target,
                source_tool="signal_analyzer",
                clue_type="parameter",
                content=str(sig),
                confidence=0.75,
            )

        for sf in parsed.get("structured_findings", []):
            nid = f"finding:{sf['id']}"
            nodes.append({
                "id": nid,
                "type": "VULNERABILITY" if sf["verified"] else "HYPOTHESIS",
                "label": sf["title"],
                "vuln_class": sf["vuln_class"],
            })
            edges.append({"from": f"host:{target}", "to": nid, "relation": "CONFIRMED_ON" if sf["verified"] else "CANDIDATE_ON"})
            kg.register_cve_finding(
                finding_id=str(sf["id"]),
                host=str(sf["target"]),
                vuln_class=str(sf["vuln_class"]),
                confidence=float(sf["confidence"]),
                empirically_verified=bool(sf["verified"]),
                evidence_ref=str(sf["title"]),
            )
            clue_cache.add_clue(
                target=target,
                source_tool="verifier",
                clue_type="cve" if "cve" in str(sf["vuln_class"]).lower() else "misconfig",
                content=f"{sf['vuln_class']}: {sf['title']}",
                confidence=float(sf["confidence"]),
            )

        kg.save()
        clue_cache.save()
        verified_facts = kg.export_verified_facts_context(max_facts=25)

        return {
            "target": target,
            "fsm_state": control_plane.fsm.current_state.value,
            "fsm_transitions_count": len(control_plane.fsm.transitions_log),
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "verified_facts": verified_facts,
        }

    # ── 7. Decide (Deterministic Control Plane FSM Transition) ──────────────

    def _decide(
        self,
        action: Dict,
        thought: Dict,
        obs: Dict,
        parsed: Dict,
        graph_state: Dict,
        triple_agents: TripleAgentSystem,
        control_plane: DeterministicControlPlane,
    ) -> Dict[str, Any]:
        reviewer_recovery = triple_agents.review_and_recover_failed_tasks(obs["target"])

        if not action.get("in_scope", True):
            return {
                "decision": "HALT_OUT_OF_SCOPE",
                "fsm_state": control_plane.fsm.current_state.value,
                "arabic_decision": "إيقاف حتمي بالكود — الهدف أو الأمر خارج النطاق المصرح به",
                "confidence": 1.0,
                "next_step": "abort",
                "reviewer_recovery": reviewer_recovery,
            }

        unverified = [f for f in parsed.get("structured_findings", []) if not f.get("verified")]
        if unverified or thought["confidence"] >= 0.78:
            if control_plane.fsm.current_state == FSMState.DECIDING:
                control_plane.fsm.transition_to(FSMState.VERIFYING, reason="High-confidence signal -> VERIFYING")
            return {
                "decision": "VERIFY",
                "fsm_state": control_plane.fsm.current_state.value,
                "arabic_decision": "نتحقق — توجيه الفرضيات عالية الثقة إلى بوابة التحقق والإثبات (7-Question Gate)",
                "confidence": thought["confidence"],
                "next_step": action.get("skill") or "triage_gate",
                "reviewer_recovery": reviewer_recovery,
            }

        if reviewer_recovery.get("recovered_count", 0) > 0 or (obs["interesting_signals"] and obs["retry_attempt"] == 0):
            if control_plane.fsm.current_state == FSMState.DECIDING:
                control_plane.fsm.transition_to(FSMState.OBSERVING, reason="Continue current phase cycle")
            return {
                "decision": "CONTINUE",
                "fsm_state": control_plane.fsm.current_state.value,
                "arabic_decision": "نكمل — استكمال الفحص العميق وإعادة تشغيل المهام المستردة بواسطة المراجع",
                "confidence": thought["confidence"],
                "next_step": action.get("tool") or action.get("skill") or "continue_phase",
                "reviewer_recovery": reviewer_recovery,
            }

        if control_plane.fsm.current_state == FSMState.DECIDING:
            control_plane.fsm.transition_to(FSMState.ADVANCING, reason="Phase complete -> ADVANCING")
        return {
            "decision": "ADVANCE",
            "fsm_state": control_plane.fsm.current_state.value,
            "arabic_decision": "ننتقل — اكتملت معطيات المرحلة الحالية، الانتقال للمرحلة التالية في آلة الحالة",
            "confidence": thought["confidence"],
            "next_step": "next_phase",
            "reviewer_recovery": reviewer_recovery,
        }
