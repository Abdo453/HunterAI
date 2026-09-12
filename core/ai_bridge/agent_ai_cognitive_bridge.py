"""
Agent-AI Cognitive Bridge (v2.0) — Deep Bidirectional Awareness & Model Orchestration
=====================================================================================
Establishes deep mutual understanding between Autonomous Security Agents and AI Models:
- Dynamic Model Capability & Specialization Profiles (WhiteRabbitNeo, Qwen, Gemini, Llama 70B, Taskade)
- Role-Based Task Routing (Offensive Planning -> WhiteRabbitNeo, Code/PoC -> Qwen, Recon -> Gemini, Deep Logic -> Llama 70B)
- Live Hardware & Latency Adaptive Awareness (CUDA GPU VRAM checks, Local vs Cloud Fallback)
- Bidirectional Context Translation (Agent OODA State -> AI Prompt -> Structured Agent Actions)
"""

import os
import re
import json
import time
import logging
import asyncio
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from urllib.parse import urlparse

import httpx

log = logging.getLogger("agent_ai_bridge")


# ─────────────────────────────────────────────────────────────────────────────
# AI Model Specializations & Task Types
# ─────────────────────────────────────────────────────────────────────────────

class TaskType(Enum):
    OFFENSIVE_STRATEGY = "offensive_strategy"    # Attack vectors, bypass planning (WhiteRabbitNeo)
    POC_AND_CODE       = "poc_and_code"          # Exploit code, AST analysis (Qwen2.5-Coder)
    RECON_AND_MAPPING  = "recon_and_mapping"     # Large context, API schemas (Gemini Flash)
    DEEP_THREAT_LOGIC  = "deep_threat_logic"     # Business logic, false-positive pruning (Llama 3.3 70B)
    RAPID_TRIAGE       = "rapid_triage"          # Quick hypothesis & parameter ranking (xploiter)
    AUTOMATION_WORKFLOW= "automation_workflow"   # Multi-step task flows (Taskade)


class ModelTier(Enum):
    LOCAL_GPU   = "local_gpu"
    CLOUD_FAST  = "cloud_fast"
    CLOUD_DEEP  = "cloud_deep"
    AUTOMATION  = "automation"
    FALLBACK    = "fallback"


@dataclass
class AIModelProfile:
    model_id: str
    display_name: str
    role_title: str
    tier: ModelTier
    specialization: str
    strengths: List[str]
    context_window: int
    is_online: bool = False
    latency_ms: float = 0.0
    endpoint_url: str = ""
    hardware_notes: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# 1. AI Model Capability Matrix
# ─────────────────────────────────────────────────────────────────────────────

AI_MODEL_CATALOG: Dict[str, AIModelProfile] = {
    "whiterabbitneo": AIModelProfile(
        model_id="WhiteRabbitNeo",
        display_name="WhiteRabbitNeo (8B)",
        role_title="Offensive Security & Red Teaming Specialist",
        tier=ModelTier.LOCAL_GPU,
        specialization="Offensive attack chains, WAF evasions, filter breakout payloads",
        strengths=["Uncensored security reasoning", "Bypass syntax crafting", "Zero-refusal offensive tactics"],
        context_window=8192,
        endpoint_url="http://192.168.1.3:11434",
        hardware_notes="CUDA Hardware Accelerated on Windows Host (192.168.1.3)"
    ),
    "qwen_coder": AIModelProfile(
        model_id="qwen2.5-coder:14b",
        display_name="Qwen2.5-Coder (14B/7B)",
        role_title="Exploit & PoC Generation Engineer",
        tier=ModelTier.LOCAL_GPU,
        specialization="Source code auditing, AST parsing, high-precision PoC verification",
        strengths=["Code vulnerability analysis", "Safe differential probe generation", "Syntax validation"],
        context_window=32768,
        endpoint_url="http://192.168.1.3:11434",
        hardware_notes="VRAM Optimized on Ollama Host"
    ),
    "xploiter": AIModelProfile(
        model_id="xploiter/pentester",
        display_name="xploiter / pentester (2.8B)",
        role_title="Rapid Attack Vector & Parameter Triager",
        tier=ModelTier.LOCAL_GPU,
        specialization="High-speed parameter triage and initial vulnerability hypothesis",
        strengths=["Ultra-low latency", "Quick risk scoring", "Parameter surface ranking"],
        context_window=4096,
        endpoint_url="http://192.168.1.3:11434",
        hardware_notes="Lightweight in-memory model"
    ),
    "gemini_flash": AIModelProfile(
        model_id="gemini-2.0-flash",
        display_name="Google Gemini 2.0 Flash",
        role_title="High-Throughput Reconnaissance & Context Correlator",
        tier=ModelTier.CLOUD_FAST,
        specialization="Massive context parsing, full-site DOM mapping, API schema correlation",
        strengths=["1M token context window", "Sub-second cloud response", "Multimodal asset analysis"],
        context_window=1048576,
        endpoint_url="https://generativelanguage.googleapis.com",
        hardware_notes="Google Cloud TPU Infrastructure"
    ),
    "openrouter_llama": AIModelProfile(
        model_id="meta-llama/llama-3.3-70b-instruct",
        display_name="OpenRouter Llama 3.3 (70B)",
        role_title="Deep Threat Modeling & Business Logic Reasoner",
        tier=ModelTier.CLOUD_DEEP,
        specialization="Complex multi-tenant logic flaws, second-order tracking, false-positive elimination",
        strengths=["70B deep reasoning capacity", "Complex state verification", "High-fidelity CWE correlation"],
        context_window=131072,
        endpoint_url="https://openrouter.ai",
        hardware_notes="High-Capacity Cloud Inference Cluster"
    ),
    "taskade": AIModelProfile(
        model_id="taskade-ai",
        display_name="Taskade Cyber Agent",
        role_title="Automated Pentest Workflow Orchestrator",
        tier=ModelTier.AUTOMATION,
        specialization="Task decomposition and scheduled security checks",
        strengths=["Automated checklists", "Workflow state maintenance"],
        context_window=16384,
        endpoint_url="https://api.taskade.com",
        hardware_notes="Cloud Taskade Agent Mesh"
    )
}


# ─────────────────────────────────────────────────────────────────────────────
# 2. Agent-AI Cognitive Bridge Engine
# ─────────────────────────────────────────────────────────────────────────────

class AgentAICognitiveBridge:
    """
    Cognitive Bridge ensuring the Agent and AI models understand each other seamlessly:
    - Knows which model is best suited for each micro-task.
    - Frames agent operational state into specialized prompts.
    - Translates AI output into actionable OODA state transitions.
    - Continuously tracks model health and failovers transparently.
    """

    def __init__(self, ollama_host: str = "http://192.168.1.3:11434"):
        self.ollama_host = ollama_host
        self.catalog = AI_MODEL_CATALOG
        self._health_cache: Dict[str, bool] = {}
        self._last_health_check = 0.0

    async def refresh_model_health(self) -> Dict[str, bool]:
        """Checks availability and latency of all local & cloud models"""
        async with httpx.AsyncClient(timeout=3.0) as client:
            # 1. Check Local Ollama
            try:
                t0 = time.time()
                r = await client.get(f"{self.ollama_host}/api/tags")
                if r.status_code == 200:
                    installed = [m["name"].split(":")[0].lower() for m in r.json().get("models", [])]
                    lat = (time.time() - t0) * 1000.0
                    for k, prof in self.catalog.items():
                        if prof.tier == ModelTier.LOCAL_GPU:
                            base_name = prof.model_id.split(":")[0].lower()
                            prof.is_online = any(base_name in m for m in installed) or (len(installed) > 0)
                            prof.latency_ms = round(lat, 1)
                            self._health_cache[k] = prof.is_online
            except Exception:
                for k, prof in self.catalog.items():
                    if prof.tier == ModelTier.LOCAL_GPU:
                        prof.is_online = False
                        self._health_cache[k] = False

            # 2. Check Cloud Providers (based on API Keys)
            self.catalog["gemini_flash"].is_online = bool(os.getenv("GEMINI_API_KEY"))
            self.catalog["openrouter_llama"].is_online = bool(os.getenv("OPENROUTER_API_KEY"))
            self.catalog["taskade"].is_online = bool(os.getenv("TASKADE_API_KEY") or os.getenv("TASKADE_WORKSPACE_ID"))

            self._health_cache["gemini_flash"] = self.catalog["gemini_flash"].is_online
            self._health_cache["openrouter_llama"] = self.catalog["openrouter_llama"].is_online
            self._health_cache["taskade"] = self.catalog["taskade"].is_online

        self._last_health_check = time.time()
        return self._health_cache

    def select_best_model_for_task(self, task: TaskType) -> AIModelProfile:
        """
        Dynamically selects the optimal model based on task requirements and availability:
        - Offensive Planning -> WhiteRabbitNeo (Local) or OpenRouter 70B (Cloud fallback)
        - PoC / Code -> Qwen2.5-Coder (Local) or Gemini Flash (Cloud fallback)
        - Recon / Mapping -> Gemini Flash (Cloud) or xploiter (Local fallback)
        - Deep Logic -> OpenRouter Llama 70B (Cloud) or WhiteRabbitNeo (Local fallback)
        """
        if task == TaskType.OFFENSIVE_STRATEGY:
            if self.catalog["whiterabbitneo"].is_online:
                return self.catalog["whiterabbitneo"]
            elif self.catalog["openrouter_llama"].is_online:
                return self.catalog["openrouter_llama"]

        elif task == TaskType.POC_AND_CODE:
            if self.catalog["qwen_coder"].is_online:
                return self.catalog["qwen_coder"]
            elif self.catalog["gemini_flash"].is_online:
                return self.catalog["gemini_flash"]

        elif task == TaskType.RECON_AND_MAPPING:
            if self.catalog["gemini_flash"].is_online:
                return self.catalog["gemini_flash"]
            elif self.catalog["xploiter"].is_online:
                return self.catalog["xploiter"]

        elif task == TaskType.DEEP_THREAT_LOGIC:
            if self.catalog["openrouter_llama"].is_online:
                return self.catalog["openrouter_llama"]
            elif self.catalog["whiterabbitneo"].is_online:
                return self.catalog["whiterabbitneo"]

        # Default fallback to any online model
        for prof in self.catalog.values():
            if prof.is_online:
                return prof

        return self.catalog["gemini_flash"]

    def build_agent_to_ai_prompt(
        self,
        phase: str,
        target_url: str,
        param_name: str,
        observed_data: Dict[str, Any],
        model_profile: AIModelProfile
    ) -> Tuple[str, str]:
        """
        Frames Agent OODA Context into high-precision, defensive prompts
        tailored specifically to the chosen AI Model's specialization.
        """
        system_prompt = (
            f"You are {model_profile.display_name}, acting as the {model_profile.role_title} for PentestAI.\n"
            f"Specialization: {model_profile.specialization}.\n"
            "Analyze the target context and return a structured JSON decision object with: "
            "'analysis', 'recommended_payloads', 'next_agent_action', 'confidence', 'risk_factors'."
        )

        user_prompt = f"""[TACTICAL AGENT CONTEXT]
Phase: {phase.upper()}
Target: {target_url}
Parameter: {param_name}
Baseline Observation:
- Status: {observed_data.get('status_code', 200)}
- Body Length: {observed_data.get('body_length', 'N/A')}
- Detected Technology: {observed_data.get('tech_stack', 'Unknown')}
- Hypotheses: {observed_data.get('hypotheses', [])}

Provide optimal, non-destructive validation probes tailored to your expertise ({model_profile.role_title})."""

        return system_prompt, user_prompt

    def format_ai_awareness_summary(self) -> str:
        """Returns clean human-readable summary of the Agent-AI Neural Network"""
        lines = [
            "======================================================================",
            "   [+] PentestAI Unified — Agent-AI Neural Awareness Matrix",
            "======================================================================"
        ]
        for key, p in self.catalog.items():
            status_tag = "[ONLINE]" if p.is_online else "[OFFLINE]"
            lines.append(f" {status_tag:<9} {p.display_name:<28} -> {p.role_title}")
            lines.append(f"             Specialization: {p.specialization}")
            if p.hardware_notes:
                lines.append(f"             Infrastructure: {p.hardware_notes}")
            lines.append("")
        lines.append("======================================================================")
        return "\n".join(lines)


# Global Bridge Instance
cognitive_bridge = AgentAICognitiveBridge()
