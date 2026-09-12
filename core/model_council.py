"""
Model Council — نظام تناقش الموديلات الـ 3
3 جولات للوصول لاستراتيجية مثلى
"""
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from models.base_model import BaseModel, ModelResponse


@dataclass
class CouncilRound:
    round_number: int
    responses: List[ModelResponse] = field(default_factory=list)


@dataclass
class ConsensusStrategy:
    target: str
    attack_vectors: List[str]
    tool_chain: List[str]
    priority_findings: List[str]
    recommended_agents: List[str]
    risk_level: str
    summary: str
    rounds: List[CouncilRound] = field(default_factory=list)
    final_model: str = ""


class ModelCouncil:
    """
    جولة 1: كل موديل يحلل الهدف باستقلالية
    جولة 2: كل موديل يقرأ آراء الباقيين ويعلق
    جولة 3: sylink يلخص ويقرر الاستراتيجية النهائية
    """

    def __init__(self, models: List[BaseModel], rounds: int = 3, progress_callback: Optional[Callable] = None):
        self.models = models
        self.rounds = rounds
        self.cb = progress_callback

    async def _emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    def _r1_prompt(self, target: str, mode: str) -> str:
        return f"""Model Council — Round 1 (Independent Analysis)
TARGET: {target}
MODE: {mode}

Analyze independently and provide:
1. ATTACK SURFACE: All potential attack vectors
2. TOP 5 PRIORITY ATTACKS: Most likely to succeed
3. TOOL CHAIN: Exact tools in order
4. EXPECTED VULNERABILITIES: What you expect to find
5. RISK LEVEL: Critical/High/Medium/Low"""

    def _r2_prompt(self, target: str, others: List[ModelResponse]) -> str:
        others_txt = "\n\n".join([f"[{r.model_name}]:\n{r.content[:600]}" for r in others])
        return f"""Model Council — Round 2 (Critique & Refine)
TARGET: {target}

OTHER MODELS' ANALYSIS:
{others_txt}

Your task:
1. AGREEMENTS: What did they get right?
2. DISAGREEMENTS: What did they miss?
3. ADDITIONS: Unique vectors you can add
4. REFINED TOOL CHAIN: Best combined approach"""

    def _r3_prompt(self, target: str, all_r2: List[ModelResponse]) -> str:
        txt = "\n\n".join([f"[{r.model_name}]:\n{r.content[:500]}" for r in all_r2])
        return f"""Model Council — Round 3 (FINAL CONSENSUS)
TARGET: {target}

ALL ROUND 2 ANALYSIS:
{txt}

Create FINAL UNIFIED STRATEGY — use this EXACT format:

ATTACK_VECTORS:
- vector1
- vector2

TOOL_CHAIN:
1. tool: reason
2. tool: reason

AGENTS_TO_RUN:
- recon_agent
- web_agent

RISK_LEVEL: [Critical/High/Medium/Low]

SUMMARY:
[2-3 sentence attack strategy summary]"""

    def _parse(self, target: str, resp: ModelResponse, rounds: List[CouncilRound]) -> ConsensusStrategy:
        vectors, tools, agents, risk, summary_lines = [], [], [], "Medium", []
        section = None
        for line in resp.content.split("\n"):
            line = line.strip()
            if not line: continue
            if "ATTACK_VECTORS:" in line: section = "v"
            elif "TOOL_CHAIN:" in line: section = "t"
            elif "AGENTS_TO_RUN:" in line: section = "a"
            elif "RISK_LEVEL:" in line:
                risk = line.replace("RISK_LEVEL:", "").strip()
                section = None
            elif "SUMMARY:" in line: section = "s"
            elif section == "v" and line.startswith("-"): vectors.append(line[1:].strip())
            elif section == "t" and (line[0].isdigit() or line.startswith("-")): tools.append(line)
            elif section == "a" and line.startswith("-"): agents.append(line[1:].strip())
            elif section == "s": summary_lines.append(line)

        return ConsensusStrategy(
            target=target,
            attack_vectors=vectors or ["Web Application", "Network Services", "Authentication"],
            tool_chain=tools or ["nmap", "gobuster", "nuclei"],
            priority_findings=[],
            recommended_agents=agents or ["recon_agent", "web_agent"],
            risk_level=risk,
            summary=" ".join(summary_lines) if summary_lines else resp.content[:300],
            rounds=rounds,
            final_model=resp.model_name,
        )

    async def discuss(self, target: str, mode: str = "full") -> ConsensusStrategy:
        all_rounds: List[CouncilRound] = []

        # تحقق من توفر الموديلات
        available = []
        for m in self.models:
            ok = await m.is_available()
            await self._emit("model_status", {"model": m.name, "role": m.role, "status": "online" if ok else "offline"})
            if ok:
                available.append(m)

        if not available:
            return ConsensusStrategy(
                target=target, attack_vectors=["Port scanning", "Web enumeration"],
                tool_chain=["nmap", "gobuster", "nuclei"], priority_findings=[],
                recommended_agents=["recon_agent", "web_agent"], risk_level="Unknown",
                summary="No models available. Using default strategy.",
            )

        # ── جولة 1 ──
        await self._emit("council_round", {"round": 1, "status": "starting"})
        r1_responses = await asyncio.gather(*[m.generate(self._r1_prompt(target, mode)) for m in available])
        for r in r1_responses:
            await self._emit("model_response", {"round": 1, "model": r.model_name, "role": r.role, "content": r.content})
        all_rounds.append(CouncilRound(1, list(r1_responses)))

        # ── جولة 2 ──
        await self._emit("council_round", {"round": 2, "status": "starting"})
        r2_tasks = [available[i].generate(self._r2_prompt(target, [r for j, r in enumerate(r1_responses) if j != i])) for i in range(len(available))]
        r2_responses = await asyncio.gather(*r2_tasks)
        for r in r2_responses:
            await self._emit("model_response", {"round": 2, "model": r.model_name, "role": r.role, "content": r.content})
        all_rounds.append(CouncilRound(2, list(r2_responses)))

        # ── جولة 3 — WhiteRabbitNeo يلخص ويقرر ──
        await self._emit("council_round", {"round": 3, "status": "starting"})
        # WhiteRabbitNeo الأفضل للتلخيص والقرار النهائي
        wrn_model = next(
            (m for m in available if "whiterabbit" in m.name.lower()),
            available[-1]  # fallback لآخر موديل
        )
        final = await wrn_model.generate(self._r3_prompt(target, list(r2_responses)))
        await self._emit("model_response", {"round": 3, "model": final.model_name, "role": "consensus", "content": final.content})
        all_rounds.append(CouncilRound(3, [final]))

        strategy = self._parse(target, final, all_rounds)
        await self._emit("consensus_reached", {
            "strategy": {"target": strategy.target, "risk_level": strategy.risk_level,
                         "agents": strategy.recommended_agents, "summary": strategy.summary}
        })
        return strategy
