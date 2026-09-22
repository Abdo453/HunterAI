"""
HunterAI Local Triad Autonomous Agent (Council V2 Architecture)
===============================================================
Autonomous Offensive Security & Attack Surface Agent with Structured Evidence Bus:
1. xploiter/pentester (Rapid Recon Scout, Triage & Surface Extractor)
2. Qwen 2.5 Coder 14B (Code Intelligence, AST Parser, JS & API Auditor)
3. WhiteRabbitNeo 8B (Master Offensive Strategist, Reasoning & Verification)

Key Principles:
- Observation != Fact != Hypothesis != Vulnerability
- Orchestrator-Centric (Models communicate through Structured Contracts & Evidence Bus)
- Zero Direct Agent-to-Agent Drift or Loops
- Full Local Inference via Ollama (Zero Cloud Dependencies)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.local_triad")

MODEL_OFFENSIVE = os.getenv("MODEL_OFFENSIVE", "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest")
MODEL_RECON = os.getenv("MODEL_RECON", "xploiter/pentester:latest")
MODEL_CODE = os.getenv("MODEL_CODE", "qwen2.5-coder:14b")
MODEL_COORDINATOR = os.getenv("MODEL_COORDINATOR", "qwen3:8b")


# ── 1. UNIFIED CONTRACTS & SCHEMAS ──────────────────────────────────────────

@dataclass
class AgentEvidence:
    source: str
    category: str  # recon, code, traffic, browser, test_execution
    observation: str
    evidence_data: Any
    confidence: float = 0.85
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    is_contradiction: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "category": self.category,
            "observation": self.observation,
            "evidence_data": self.evidence_data,
            "confidence": round(self.confidence, 2),
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "is_contradiction": self.is_contradiction,
        }


@dataclass
class TriageResult:
    specialist: str = "xploiter/pentester"
    assets: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    interesting_targets: List[str] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.85
    raw_analysis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "specialist": self.specialist,
            "assets": self.assets,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "technologies": self.technologies,
            "interesting_targets": self.interesting_targets,
            "hypotheses": self.hypotheses,
            "confidence": round(self.confidence, 2),
            "raw_analysis": self.raw_analysis,
        }


@dataclass
class CodeIntelligenceResult:
    specialist: str = "Qwen 2.5 Coder 14B"
    routes: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    secrets_candidates: List[Dict[str, Any]] = field(default_factory=list)
    client_side_controls: List[str] = field(default_factory=list)
    interesting_code_paths: List[str] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.90
    raw_analysis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "specialist": self.specialist,
            "routes": self.routes,
            "api_endpoints": self.api_endpoints,
            "parameters": self.parameters,
            "secrets_candidates": self.secrets_candidates,
            "client_side_controls": self.client_side_controls,
            "interesting_code_paths": self.interesting_code_paths,
            "hypotheses": self.hypotheses,
            "confidence": round(self.confidence, 2),
            "raw_analysis": self.raw_analysis,
        }


@dataclass
class AgentDecision:
    agent: str = "WhiteRabbitNeo (8B)"
    hypothesis: str = ""
    target_url: str = ""
    parameter: Optional[str] = None
    vuln_type: str = "Generic"
    reasoning: str = ""
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    controlled_test_plan: str = ""
    refutation_criteria: str = ""
    confidence: float = 0.80
    raw_analysis: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "hypothesis": self.hypothesis,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "vuln_type": self.vuln_type,
            "reasoning": self.reasoning,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "controlled_test_plan": self.controlled_test_plan,
            "refutation_criteria": self.refutation_criteria,
            "confidence": round(self.confidence, 2),
            "raw_analysis": self.raw_analysis,
        }


# ── 2. STRUCTURED EVIDENCE BUS ──────────────────────────────────────────────

class EvidenceBus:
    """
    Central Message & Evidence Broker for the Triad.
    Prevents direct inter-model drift by routing observations through a structured ledger.
    """

    def __init__(self):
        self._evidence_stream: List[AgentEvidence] = []
        self._decisions: List[AgentDecision] = []

    def publish_evidence(self, evidence: AgentEvidence) -> None:
        self._evidence_stream.append(evidence)

    def record_decision(self, decision: AgentDecision) -> None:
        self._decisions.append(decision)

    def get_evidence_by_category(self, category: str) -> List[AgentEvidence]:
        return [e for e in self._evidence_stream if e.category == category]

    def compile_evidence_package(self, target_url: Optional[str] = None) -> Dict[str, Any]:
        """Synthesizes all gathered evidence into a structured bundle for reasoning."""
        recon_items = [e.to_dict() for e in self.get_evidence_by_category("recon")]
        code_items = [e.to_dict() for e in self.get_evidence_by_category("code")]
        traffic_items = [e.to_dict() for e in self.get_evidence_by_category("traffic")]
        test_items = [e.to_dict() for e in self.get_evidence_by_category("test_execution")]

        return {
            "target_url": target_url,
            "recon_evidence": recon_items[-15:],
            "code_evidence": code_items[-15:],
            "traffic_evidence": traffic_items[-15:],
            "previous_test_results": test_items[-15:],
            "total_evidence_count": len(self._evidence_stream),
        }


# ── 3. MASTER LOCAL TRIAD AGENT ─────────────────────────────────────────────

class LocalTriadAgent:
    """
    Orchestrates the 3-Model Local Triad over a structured Evidence Bus:
    - xploiter (Scout): Processes raw perimeter & OSINT into structured TriageResult.
    - Qwen 2.5 Coder: Processes JS & HTTP schemas into CodeIntelligenceResult.
    - WhiteRabbitNeo: Synthesizes multi-source Evidence Packages into AgentDecisions with controlled test plans.
    """

    def __init__(self, ollama_host: Optional[str] = None):
        raw = (ollama_host or os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")).strip().rstrip("/")
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        raw = raw.replace("://0.0.0.0:", "://127.0.0.1:")
        self.ollama_host = raw
        self.bus = EvidenceBus()
        self._ollama_online: Optional[bool] = None
        self._cached_tags: Optional[List[str]] = None

    def _resolve_model(self, preferred: str, candidates: Optional[List[str]] = None) -> str:
        """Dynamically matches installed Ollama tags (e.g. qwen3:8b, qwen2.5-coder:14b-tools)."""
        if self._cached_tags is None:
            try:
                url = f"{self.ollama_host}/api/tags"
                req = urllib.request.Request(url, headers={"User-Agent": "HunterAI/2.0"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    self._cached_tags = [m.get("name", "") for m in data.get("models", [])]
            except Exception:
                self._cached_tags = []

        tags = self._cached_tags or []
        for t in tags:
            if preferred.lower() == t.lower():
                return t
        for cand in (candidates or []):
            for t in tags:
                if cand.lower() in t.lower() or t.lower() in cand.lower():
                    return t
        return preferred

    async def _query_ollama(
        self,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        timeout: int = 15
    ) -> str:
        """Direct, reliable HTTP query to local Ollama instance with timeout protection."""
        if self._ollama_online is False:
            return ""

        resolved_model = self._resolve_model(
            model,
            [MODEL_COORDINATOR, MODEL_CODE, "qwen3:8b", "qwen2.5-coder:14b-tools", "qwen2.5-coder:14b", "whiterabbitneo", "xploiter"]
        )

        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": resolved_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False,
            "keep_alive": "5m",
            "options": {
                "temperature": temperature,
                "num_ctx": 4096
            }
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

        loop = asyncio.get_running_loop()

        def _do_request():
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    self._ollama_online = True
                    return res.get("message", {}).get("content", "").strip()
            except Exception as e:
                if self._ollama_online is None:
                    logger.debug(f"[AI] Local Ollama offline at {self.ollama_host} ({e})")
                return ""

        return await loop.run_in_executor(None, _do_request)

    # ── 1. RECON SCOUT & TRIAGE (xploiter/pentester) ──────────────────────────
    async def triage_recon_assets(
        self,
        target: str,
        subdomains: List[str],
        ports: List[str],
        endpoints: List[str]
    ) -> Dict[str, Any]:
        """
        Processes discovered perimeter assets and outputs structured TriageResult.
        Publishes observations to the Evidence Bus.
        """
        system = (
            "You are xploiter/pentester, an elite reconnaissance triage specialist. "
            "Analyze discovered assets, identify high-priority attack surfaces (APIs, admin portals, auth, uploads), "
            "and output structured JSON:\n"
            "{\n"
            '  "interesting_targets": ["..."],\n'
            '  "hypotheses": [{"target": "...", "vuln_type": "...", "rationale": "..."}],\n'
            '  "confidence": 0.85\n'
            "}"
        )
        user = f"""Target Domain: {target}
Subdomains ({len(subdomains)}):
{json.dumps(subdomains[:25], indent=2)}

Open Ports ({len(ports)}):
{json.dumps(ports[:15], indent=2)}

Discovered Endpoints ({len(endpoints)}):
{json.dumps(endpoints[:25], indent=2)}
"""
        raw_response = await self._query_ollama(MODEL_RECON, system, user, temperature=0.2)
        
        # Parse JSON
        result = TriageResult(
            assets=subdomains[:30],
            endpoints=endpoints[:30],
            raw_analysis=raw_response or "Recon triage completed via heuristics."
        )

        try:
            m = re.search(r"\{.*\}", raw_response, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                result.interesting_targets = data.get("interesting_targets", [])
                result.hypotheses = data.get("hypotheses", [])
                result.confidence = float(data.get("confidence", 0.85))
        except Exception:
            result.interesting_targets = [e for e in endpoints if "admin" in e or "api" in e][:5]

        # Publish to Evidence Bus
        self.bus.publish_evidence(AgentEvidence(
            source="xploiter",
            category="recon",
            observation=f"Triage completed for {target}: {len(result.interesting_targets)} high-value targets identified.",
            evidence_data=result.to_dict(),
            confidence=result.confidence,
        ))

        return {
            "specialist": result.specialist,
            "model": MODEL_RECON,
            "analysis": result.raw_analysis,
            "structured_triage": result.to_dict(),
        }

    # ── 2. CODE & JAVASCRIPT INTELLIGENCE (Qwen 2.5 Coder 14B) ───────────────
    async def audit_code_or_javascript(
        self,
        js_url: str,
        code_content: str
    ) -> Dict[str, Any]:
        """
        Audits JavaScript, AST nodes, and API schemas to extract routes, parameters, and secret tokens.
        Publishes findings to the Evidence Bus.
        """
        system = (
            "You are Qwen 2.5 Coder 14B, security code auditor and AST analysis expert. "
            "Analyze code snippets/client JS and output structured JSON:\n"
            "{\n"
            '  "routes": ["/api/v1/..."],\n'
            '  "parameters": ["token", "id"],\n'
            '  "secrets_candidates": [{"type": "api_key", "value": "..."}],\n'
            '  "hypotheses": [{"type": "idor", "endpoint": "..."}],\n'
            '  "confidence": 0.90\n'
            "}"
        )
        snippet = code_content[:3500]
        user = f"""Source File: {js_url}
Content Snippet:
```javascript
{snippet}
```
"""
        raw_response = await self._query_ollama(MODEL_CODE, system, user, temperature=0.1)

        result = CodeIntelligenceResult(
            raw_analysis=raw_response or "Code audit completed via regex heuristics."
        )

        try:
            m = re.search(r"\{.*\}", raw_response, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                result.routes = data.get("routes", [])
                result.parameters = data.get("parameters", [])
                result.secrets_candidates = data.get("secrets_candidates", [])
                result.hypotheses = data.get("hypotheses", [])
                result.confidence = float(data.get("confidence", 0.90))
        except Exception:
            # Fallback regex extraction
            result.routes = re.findall(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']', snippet)[:10]
            result.parameters = re.findall(r'[?&]([a-zA-Z0-9_]+)=', snippet)[:10]

        # Publish to Evidence Bus
        self.bus.publish_evidence(AgentEvidence(
            source="qwen_coder",
            category="code",
            observation=f"Audited {js_url}: found {len(result.routes)} routes, {len(result.secrets_candidates)} secret tokens.",
            evidence_data=result.to_dict(),
            confidence=result.confidence,
        ))

        return {
            "specialist": result.specialist,
            "model": MODEL_CODE,
            "analysis": result.raw_analysis,
            "structured_code_intelligence": result.to_dict(),
        }

    # ── 3. MASTER OFFENSIVE REASONING & VERIFICATION (WhiteRabbitNeo 8B) ─────
    async def synthesize_offensive_reasoning(
        self,
        target_url: str,
        param_name: Optional[str] = None,
        vuln_type: str = "Generic",
        context: Optional[str] = None,
    ) -> AgentDecision:
        """
        Consumes the synthesized Evidence Package from the Evidence Bus and generates
        a disciplined AgentDecision with non-destructive verification test plans.
        """
        evidence_pkg = self.bus.compile_evidence_package(target_url=target_url)

        system = (
            "You are WhiteRabbitNeo, Master Offensive Reasoning Strategist. "
            "You receive an Evidence Package (Recon + Code + Traffic). "
            "Formulate a disciplined hypothesis with supporting evidence, potential contradictions, "
            "and a controlled non-destructive test plan. Output structured JSON:\n"
            "{\n"
            '  "hypothesis": "...",\n'
            '  "vuln_type": "...",\n'
            '  "reasoning": "...",\n'
            '  "supporting_evidence": ["..."],\n'
            '  "contradicting_evidence": ["..."],\n'
            '  "controlled_test_plan": "curl -X GET ...",\n'
            '  "refutation_criteria": "If response status is 404 or body identical to baseline",\n'
            '  "confidence": 0.85\n'
            "}"
        )
        user = f"""Target: {target_url}
Parameter: {param_name or 'N/A'}
Suspected Class: {vuln_type}
Additional Context: {context or 'None'}

Evidence Package:
{json.dumps(evidence_pkg, indent=2, default=str)}
"""
        raw_response = await self._query_ollama(MODEL_OFFENSIVE, system, user, temperature=0.2)

        decision = AgentDecision(
            target_url=target_url,
            parameter=param_name,
            vuln_type=vuln_type,
            raw_analysis=raw_response or "Offensive strategy synthesized via baseline heuristics."
        )

        try:
            m = re.search(r"\{.*\}", raw_response, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                decision.hypothesis = data.get("hypothesis", f"Potential {vuln_type} on {target_url}")
                decision.reasoning = data.get("reasoning", "")
                decision.supporting_evidence = data.get("supporting_evidence", [])
                decision.contradicting_evidence = data.get("contradicting_evidence", [])
                decision.controlled_test_plan = data.get("controlled_test_plan", f"curl -s '{target_url}'")
                decision.refutation_criteria = data.get("refutation_criteria", "Response equals baseline")
                decision.confidence = float(data.get("confidence", 0.80))
        except Exception:
            decision.hypothesis = f"Suspected {vuln_type} on {target_url}"
            decision.controlled_test_plan = f"curl -s '{target_url}'"

        self.bus.record_decision(decision)
        return decision

    # ── 4. BACKWARDS-COMPATIBLE CONVENIENCE METHODS ───────────────────────────
    async def formulate_offensive_strategy(
        self,
        target_url: str,
        param_name: str,
        vuln_type: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        decision = await self.synthesize_offensive_reasoning(
            target_url=target_url,
            param_name=param_name,
            vuln_type=vuln_type,
            context=context
        )
        return {
            "specialist": decision.agent,
            "model": MODEL_OFFENSIVE,
            "analysis": decision.raw_analysis,
            "decision": decision.to_dict(),
        }

    async def process_prompt(self, user_prompt: str) -> Dict[str, Any]:
        """Routes generic prompts to the best specialist among the triad."""
        low = user_prompt.lower()
        if any(w in low for w in ["orchestrat", "coordinat", "workflow", "plan", "decompose", "task"]):
            system = "You are Qwen3 8B, master orchestrator and security reasoning coordinator. Break down tasks into structured execution plans, tool invocations, and agent assignments."
            resp = await self._query_ollama(MODEL_COORDINATOR, system, user_prompt, temperature=0.2)
            return {"assigned_model": MODEL_COORDINATOR, "role": "Master Orchestrator (Qwen3 8B)", "response": resp}

        if any(w in low for w in ["javascript", "js", "code", "regex", "parser", "ast", "deobfuscate"]):
            system = "You are Qwen 2.5 Coder 14B, specialized in security code analysis and AST parsing."
            resp = await self._query_ollama(MODEL_CODE, system, user_prompt, temperature=0.1)
            return {"assigned_model": MODEL_CODE, "role": "Code Intelligence (Qwen 2.5 Coder)", "response": resp}

        if any(w in low for w in ["exploit", "sqli", "injection", "bypass", "waf", "rce", "ssrf", "xss", "payload", "verify"]):
            system = "You are WhiteRabbitNeo, master offensive security and pentest reasoning strategist."
            resp = await self._query_ollama(MODEL_OFFENSIVE, system, user_prompt, temperature=0.2)
            return {"assigned_model": MODEL_OFFENSIVE, "role": "Master Offensive Strategist (WhiteRabbitNeo)", "response": resp}

        system = "You are xploiter/pentester, rapid reconnaissance and triage assistant."
        resp = await self._query_ollama(MODEL_RECON, system, user_prompt, temperature=0.2)
        return {"assigned_model": MODEL_RECON, "role": "Recon Scout (xploiter/pentester)", "response": resp}


# Global singleton instance
triad_agent = LocalTriadAgent()
