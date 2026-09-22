"""
HunterAI AI Preflight Gate & Cognitive Model Verification
=========================================================
Strict 3-Tier Preflight System:
  Tier 1: Host Connectivity & HTTP Latency Probe (GET /api/tags)
  Tier 2: Model Manifest & Alias Availability Verification
  Tier 3: Live Model Inference Verification (Active Chat Probe)

Enforces Fail-Closed Execution:
  - If AI backend is offline/unresponsive and --allow-no-ai is NOT provided,
    the pipeline halts immediately with actionable remediation steps.
  - If --allow-no-ai is provided, pipeline transitions to DEGRADED_MODE with
    explicit heuristic fallback banners and zero false AI claims.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.ai_preflight")

# Standard Triad Model Specifications
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"

REQUIRED_MODELS = {
    "reasoning": {
        "canonical": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
        "display_name": "WhiteRabbitNeo 2.8B (Offensive Strategist)",
        "patterns": [
            r"whiterabbitneo",
            r"llama-3\.1-whiterabbitneo",
            r"white-rabbit-neo",
        ],
    },
    "recon": {
        "canonical": "xploiter/pentester:latest",
        "display_name": "xploiter/pentester (Recon & Triage)",
        "patterns": [
            r"xploiter",
            r"pentester",
        ],
    },
    "code": {
        "canonical": "qwen2.5-coder:14b",
        "display_name": "Qwen 2.5 Coder / Qwen3 (Code & AST Intelligence)",
        "patterns": [
            r"qwen2\.5-coder",
            r"qwen3",
            r"qwen-coder",
            r"qwen2\.5",
            r"qwen",
        ],
    },
}


@dataclass
class ModelProbeResult:
    role: str
    display_name: str
    canonical: str
    available: bool = False
    matched_tag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "display_name": self.display_name,
            "canonical": self.canonical,
            "available": self.available,
            "matched_tag": self.matched_tag,
        }


@dataclass
class AIPreflightResult:
    endpoint: str
    online: bool = False
    latency_ms: float = 0.0
    models: Dict[str, ModelProbeResult] = field(default_factory=dict)
    all_available_tags: List[str] = field(default_factory=list)
    inference_ok: bool = False
    inference_latency_ms: float = 0.0
    inference_model: Optional[str] = None
    inference_probe_output: str = ""
    status: str = "FAILED"  # "AI_READY", "DEGRADED", "FAILED"
    allowed: bool = False
    degraded: bool = False
    error_message: Optional[str] = None
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "online": self.online,
            "latency_ms": round(self.latency_ms, 2),
            "models": {k: v.to_dict() for k, v in self.models.items()},
            "all_available_tags": self.all_available_tags,
            "inference_ok": self.inference_ok,
            "inference_latency_ms": round(self.inference_latency_ms, 2),
            "inference_model": self.inference_model,
            "inference_probe_output": self.inference_probe_output,
            "status": self.status,
            "allowed": self.allowed,
            "degraded": self.degraded,
            "error_message": self.error_message,
            "remediation_steps": self.remediation_steps,
        }


class AIPreflightGate:
    """
    Evaluates 3-Tier Preflight Invariants for Local LLM / Triad Agent.
    """

    @staticmethod
    def normalize_host(host: Optional[str] = None) -> str:
        raw = (host or os.getenv("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)).strip().rstrip("/")
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        return raw.replace("://0.0.0.0:", "://127.0.0.1:")

    @classmethod
    def check_connectivity(cls, host: str, timeout_sec: float = 3.0) -> Tuple[bool, float, List[str], Optional[str]]:
        """
        Tier 1: Probe Ollama server connectivity & retrieve tags list.
        Returns: (online, latency_ms, tags, error_msg)
        """
        url = f"{host}/api/tags"
        t0 = time.time()
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "HunterAI-Preflight/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                if resp.status == 200:
                    latency = (time.time() - t0) * 1000.0
                    body = json.loads(resp.read().decode("utf-8"))
                    models = body.get("models", [])
                    tags = [m.get("name", "") for m in models if isinstance(m, dict) and "name" in m]
                    return True, latency, tags, None
                return False, (time.time() - t0) * 1000.0, [], f"HTTP {resp.status}"
        except urllib.error.URLError as e:
            return False, (time.time() - t0) * 1000.0, [], f"Connection error: {e.reason}"
        except Exception as e:
            return False, (time.time() - t0) * 1000.0, [], str(e)

    @classmethod
    def match_models(cls, available_tags: List[str]) -> Dict[str, ModelProbeResult]:
        """
        Tier 2: Match available Ollama tags against required Triad model patterns.
        """
        results: Dict[str, ModelProbeResult] = {}
        for role, spec in REQUIRED_MODELS.items():
            matched_tag: Optional[str] = None
            is_available = False
            for pattern in spec["patterns"]:
                for tag in available_tags:
                    if re.search(pattern, tag, re.IGNORECASE):
                        matched_tag = tag
                        is_available = True
                        break
                if is_available:
                    break

            results[role] = ModelProbeResult(
                role=role,
                display_name=spec["display_name"],
                canonical=spec["canonical"],
                available=is_available,
                matched_tag=matched_tag,
            )
        return results

    @classmethod
    def test_inference(
        cls,
        host: str,
        model_name: str,
        timeout_sec: float = 45.0,
        probe_phrase: str = "HUNTERAI_AI_READY"
    ) -> Tuple[bool, float, str, Optional[str]]:
        """
        Tier 3: Active inference verification with a fast probe prompt.
        Returns: (success, latency_ms, output, error_msg)
        """
        url = f"{host}/api/chat"
        payload = {
            "model": model_name,
            "messages": [
                {
                    "role": "user",
                    "content": f"Return exactly the token '{probe_phrase}' without additional text."
                }
            ],
            "stream": False,
            "keep_alive": "5m",
            "options": {
                "temperature": 0.0,
                "num_ctx": 256,
                "num_predict": 15,
            }
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "HunterAI-Preflight/1.0"}
        )
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                latency = (time.time() - t0) * 1000.0
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    content = body.get("message", {}).get("content", "").strip()
                    if content:
                        return True, latency, content, None
                    return False, latency, "", "Empty response from model"
                return False, latency, "", f"HTTP {resp.status}"
        except Exception as e:
            return False, (time.time() - t0) * 1000.0, "", str(e)

    @classmethod
    def run_preflight(
        cls,
        host: Optional[str] = None,
        allow_degraded: bool = False,
        timeout_sec: float = 5.0,
        inference_timeout_sec: float = 45.0,
        skip_inference_test: bool = False
    ) -> AIPreflightResult:
        """
        Executes synchronous 3-Tier Preflight check with multi-model fallback.
        """
        endpoint = cls.normalize_host(host)
        res = AIPreflightResult(endpoint=endpoint)

        # Tier 1: Check Connectivity
        online, latency, tags, conn_err = cls.check_connectivity(endpoint, timeout_sec=timeout_sec)
        res.online = online
        res.latency_ms = latency
        res.all_available_tags = tags

        if not online:
            res.error_message = conn_err or "Ollama host unreachable"
            res.remediation_steps = [
                "Start Ollama service: 'ollama serve'",
                f"Verify Ollama is listening on {endpoint}",
                "Or run with '--allow-no-ai' (or '--degraded') to proceed in deterministic heuristic mode."
            ]
            if allow_degraded:
                res.status = "DEGRADED"
                res.allowed = True
                res.degraded = True
            else:
                res.status = "FAILED"
                res.allowed = False
                res.degraded = False
            return res

        # Tier 2: Check Models
        model_results = cls.match_models(tags)
        res.models = model_results
        any_model_available = any(m.available for m in model_results.values())
        missing_roles = [m.display_name for m in model_results.values() if not m.available]

        # Tier 3: Active Inference
        if any_model_available and not skip_inference_test:
            # Build list of probe candidates in priority order: reasoning, code, recon
            probe_candidates = []
            for role in ["reasoning", "code", "recon"]:
                if model_results.get(role) and model_results[role].matched_tag:
                    probe_candidates.append(model_results[role].matched_tag)
            for t in tags:
                if t not in probe_candidates:
                    probe_candidates.append(t)

            last_err = None
            for candidate in probe_candidates:
                inf_ok, inf_lat, inf_out, inf_err = cls.test_inference(
                    endpoint, candidate, timeout_sec=inference_timeout_sec
                )
                if inf_ok:
                    res.inference_ok = True
                    res.inference_latency_ms = inf_lat
                    res.inference_probe_output = inf_out
                    res.inference_model = candidate
                    break
                else:
                    last_err = f"Model '{candidate}' probe failed: {inf_err}"

            if not res.inference_ok:
                res.error_message = last_err or "Inference probe failed on all candidates."
        elif skip_inference_test and any_model_available:
            res.inference_ok = True
            res.inference_model = "probe_skipped"
        else:
            res.inference_ok = False
            res.error_message = "No models available in local Ollama repository."

        # Final Evaluation
        if res.online and res.inference_ok:
            res.status = "AI_READY"
            res.allowed = True
            res.degraded = False
            if missing_roles:
                res.remediation_steps.append(
                    f"Optional models missing: {', '.join(missing_roles)}. Pipeline will use available local models or deterministic fallbacks."
                )
        else:
            if missing_roles:
                pull_cmds = [f"ollama pull {REQUIRED_MODELS[k]['canonical']}" for k, v in model_results.items() if not v.available]
                res.remediation_steps.extend(pull_cmds)
            res.remediation_steps.append("If model is loading into VRAM on cold start, re-run scan or use '--skip-ai-probe' / '--inference-timeout 90'.")
            res.remediation_steps.append("Or pass '--allow-no-ai' to proceed without AI assistance.")

            if allow_degraded:
                res.status = "DEGRADED"
                res.allowed = True
                res.degraded = True
            else:
                res.status = "FAILED"
                res.allowed = False
                res.degraded = False

        return res

    @classmethod
    async def run_preflight_async(
        cls,
        host: Optional[str] = None,
        allow_degraded: bool = False,
        timeout_sec: float = 5.0,
        inference_timeout_sec: float = 45.0,
        skip_inference_test: bool = False
    ) -> AIPreflightResult:
        """Asynchronous execution wrapper for asyncio loops"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            cls.run_preflight,
            host,
            allow_degraded,
            timeout_sec,
            inference_timeout_sec,
            skip_inference_test,
        )

    @classmethod
    def format_status_banner(cls, result: AIPreflightResult, use_color: bool = True) -> str:
        """
        Formats a structured preflight diagnostic banner.
        """
        dot_green = "[PASS]"
        dot_red = "[FAIL]"
        dot_yellow = "[WARN]"

        status_tag = dot_green if result.allowed and not result.degraded else (
            dot_yellow if result.degraded else dot_red
        )

        lines = []
        sep = "═" * 72
        lines.append(f"╔{sep}╗")
        lines.append(f"║ 🧠 HUNTERAI :: AI COGNITIVE PREFLIGHT GATE                            ║")
        lines.append(f"╠{sep}╣")

        # Host Line
        host_status = f"ONLINE ({result.latency_ms:.1f}ms)" if result.online else "OFFLINE / UNREACHABLE"
        host_icon = dot_green if result.online else dot_red
        lines.append(f"║  Host Endpoint    : {result.endpoint:<28} {host_icon} {host_status:<17} ║")

        # Models Lines
        if result.models:
            for role, model_res in result.models.items():
                m_icon = dot_green if model_res.available else dot_red
                tag_label = f"({model_res.matched_tag})" if model_res.matched_tag else "(Not Pulled)"
                display = f"{model_res.display_name.split('(')[0].strip()}"
                status_str = f"AVAILABLE {tag_label}" if model_res.available else "MISSING"
                lines.append(f"║  {display:<17}: {m_icon} {status_str:<47} ║")
        else:
            lines.append(f"║  Models Checked   : {dot_red} None discovered                               ║")

        # Inference Line
        if result.online:
            inf_icon = dot_green if result.inference_ok else dot_red
            if result.inference_ok:
                model_lbl = f" ({result.inference_model.split(':')[0]})" if result.inference_model and result.inference_model != "probe_skipped" else ""
                inf_str = f"PASS{model_lbl} ({result.inference_latency_ms:.0f}ms)"
            else:
                inf_str = f"FAIL ({result.error_message or 'No output'})"
            lines.append(f"║  Active Inference : {inf_icon} {inf_str:<50} ║")

        # Mode Line
        if result.status == "AI_READY":
            mode_desc = "AI_POWERED (Full Cognitive Triad Active)"
            mode_icon = dot_green
        elif result.status == "DEGRADED":
            mode_desc = "DEGRADED_MODE (Deterministic Heuristics Only)"
            mode_icon = dot_yellow
        else:
            mode_desc = "BLOCKED (AI Preflight Failed & Safe-Closed)"
            mode_icon = dot_red

        lines.append(f"║  Operating Mode   : {mode_icon} {mode_desc:<49} ║")
        lines.append(f"╠{sep}╣")

        # Guidance / Remediation
        if result.status == "AI_READY":
            lines.append(f"║  ✅ Local AI model server certified and ready for autonomous hunting. ║")
        elif result.status == "DEGRADED":
            lines.append(f"║  ⚠️  AI Reasoning is DISABLED. All stages running in deterministic mode.║")
            lines.append(f"║  ⚠️  No LLM queries will be issued. Findings use pure rule verification.║")
        else:
            lines.append(f"║  ❌ Pipeline execution BLOCKED to prevent un-reasoned execution.      ║")
            lines.append(f"║  💡 Remediation Steps:                                                 ║")
            for step in result.remediation_steps:
                lines.append(f"║     • {step:<64} ║")

        lines.append(f"╚{sep}╝")
        return "\n".join(lines)
