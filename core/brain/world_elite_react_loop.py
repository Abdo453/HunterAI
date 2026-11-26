"""
╔══════════════════════════════════════════════════════════════════════════╗
║          WORLD ELITE AGENT BRAIN — Ollama ReAct Loop Engine             ║
║                                                                          ║
║  مستوحى من:                                                              ║
║  • XBOW          → ReAct loop + tool chaining                           ║
║  • PentAGI       → 50+ tool orchestration in Docker                     ║
║  • VAPOR PANDA   → Multi-target simultaneous execution                   ║
║  • Devin         → Code writing + PoC generation from CVE               ║
║  • Lazarus Group → AI-powered spear-phishing analysis simulation        ║
║  • Unit 8200     → OSINT graph building from open sources               ║
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
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

class ThoughtType(Enum):
    """أنواع أفكار الـ Agent — زي تفكير محلل أمني محترف"""
    RECON        = "recon"           # استطلاع أولي
    HYPOTHESIS   = "hypothesis"      # فرضية عن ثغرة محتملة
    EXPLOITATION = "exploitation"    # خطة استغلال
    VERIFICATION = "verification"    # التحقق من الثغرة
    PIVOTING     = "pivoting"        # التحرك للهدف التالي
    REPORTING    = "reporting"       # إعداد التقرير


@dataclass
class Thought:
    """فكرة واحدة في سلسلة التفكير"""
    type: ThoughtType
    content: str
    confidence: float = 0.0        # 0.0 → 1.0
    reasoning: str = ""
    suggested_tools: List[str] = field(default_factory=list)


@dataclass
class Action:
    """إجراء يتخذه الـ Agent"""
    tool_name: str
    parameters: Dict[str, Any]
    rationale: str = ""             # سبب اختيار هذه الأداة
    expected_outcome: str = ""


@dataclass
class Observation:
    """ملاحظة بعد تنفيذ الإجراء"""
    raw_output: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    new_findings: List[str] = field(default_factory=list)
    suggested_next: List[str] = field(default_factory=list)
    success: bool = True
    execution_time_ms: float = 0.0


@dataclass
class ReActStep:
    """خطوة واحدة كاملة: فكرة → إجراء → ملاحظة"""
    step_id: int
    thought: Thought
    action: Action
    observation: Observation
    timestamp: float = field(default_factory=time.time)


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA PROVIDER — المحرك الذكي
# ─────────────────────────────────────────────────────────────────────────────

class OllamaProvider:
    """
    واجهة موحدة لنماذج Ollama المحلية.
    
    الاستراتيجية:
    - qwen2.5-coder:14b-tools  → التخطيط + tool calling + كتابة كود
    - xploiter/pentester       → تحليل أمني + تقييم ثغرات
    - qwen3:8b                 → التفكير المنطقي + تقييم المخاطر
    """

    MODELS = {
        "planner":  "qwen2.5-coder:14b-tools",   # يخطط ويستدعي الأدوات
        "analyst":  "xploiter/pentester",          # يحلل الثغرات
        "reasoner": "qwen3:8b",                    # يفكر ويقيّم
        "coder":    "qwen2.5-coder:14b",           # يكتب الكود والـ PoC
    }

    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host
        self._client = None
        self._available = False

    def _get_client(self):
        """Lazy init للـ client"""
        if self._client is None:
            try:
                import ollama
                self._client = ollama.Client(host=self.host)
                self._available = True
            except ImportError:
                logger.warning("ollama package not installed — using mock mode")
                self._client = MockOllamaClient()
        return self._client

    async def think(
        self,
        context: str,
        role: str = "planner",
        tools: Optional[List[Dict]] = None,
    ) -> Thought:
        """
        يطلب من الـ LLM أن يفكر في الوضع الحالي ويقترح الخطوة التالية.
        مستوحى من XBOW: ReAct Thought phase.
        """
        model = self.MODELS.get(role, self.MODELS["planner"])
        system_prompt = self._build_system_prompt(role)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": context},
        ]

        try:
            client = self._get_client()
            loop = asyncio.get_running_loop()

            if tools:
                response = await loop.run_in_executor(
                    None,
                    lambda: client.chat(
                        model=model,
                        messages=messages,
                        tools=tools,
                    ),
                )
            else:
                response = await loop.run_in_executor(
                    None,
                    lambda: client.chat(model=model, messages=messages),
                )

            content = response["message"]["content"] or ""
            return self._parse_thought(content)

        except Exception as exc:
            logger.error("OllamaProvider.think failed: %s", exc)
            # Fallback: thought بسيط بدون LLM
            return Thought(
                type=ThoughtType.RECON,
                content=f"[FALLBACK] Continue with systematic recon. Error: {exc}",
                confidence=0.3,
            )

    async def analyze_finding(self, finding: str, context: str = "") -> Dict[str, Any]:
        """
        يحلل finding محتمل ويقرر:
        - هل هو حقيقي أم False Positive؟
        - ما خطورته (CVSS)؟
        - هل يستحق الـ PoC؟
        
        مستوحى من: XBOW validation engine
        """
        prompt = f"""
أنت محلل أمني خبير. حلّل هذا الـ finding وأجب بـ JSON فقط:

FINDING:
{finding}

CONTEXT:
{context}

أجب بهذا الشكل:
{{
  "is_real": true/false,
  "confidence": 0.0-1.0,
  "severity": "critical/high/medium/low/info",
  "cvss_estimate": 0.0-10.0,
  "false_positive_reason": "السبب إذا كان FP",
  "poc_recommended": true/false,
  "recommended_next_steps": ["خطوة 1", "خطوة 2"]
}}
"""
        try:
            client = self._get_client()
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.chat(
                    model=self.MODELS["analyst"],
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
            raw = response["message"]["content"]
            # استخراج JSON من الرد
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except Exception as exc:
            logger.error("analyze_finding error: %s", exc)

        # Fallback
        return {
            "is_real": False,
            "confidence": 0.0,
            "severity": "info",
            "cvss_estimate": 0.0,
            "false_positive_reason": "LLM unavailable",
            "poc_recommended": False,
            "recommended_next_steps": [],
        }

    async def generate_poc(self, vulnerability: Dict[str, Any]) -> str:
        """
        يولد PoC code تلقائياً للثغرة.
        مستوحى من: Devin + PentAGI
        """
        prompt = f"""
أنت باحث أمني. اكتب Python PoC للثغرة التالية للأغراض التعليمية فقط:

{json.dumps(vulnerability, indent=2, ensure_ascii=False)}

اكتب كود Python كامل، قابل للتشغيل، مع تعليقات توضيحية.
الكود يجب أن يتحقق من الثغرة فقط — لا تخريب.
"""
        try:
            client = self._get_client()
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.chat(
                    model=self.MODELS["coder"],
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
            return response["message"]["content"]
        except Exception as exc:
            logger.error("generate_poc error: %s", exc)
            return f"# PoC generation failed: {exc}"

    def _build_system_prompt(self, role: str) -> str:
        prompts = {
            "planner": (
                "أنت مخطط أمني خبير. مهمتك تحليل الوضع الحالي وتحديد الخطوة التالية "
                "الأمثل في عملية الـ penetration test. فكّر بمنهجية MITRE ATT&CK. "
                "دائماً اقترح أداة محددة وسبب اختيارها."
            ),
            "analyst": (
                "أنت محلل ثغرات أمنية خبير. مهمتك تقييم النتائج وتحديد إذا كانت "
                "ثغرات حقيقية. كن دقيقاً وتجنب الـ false positives."
            ),
            "reasoner": (
                "أنت مستشار أمني استراتيجي. مهمتك التفكير في المخاطر والأولويات "
                "وتحديد أهم الأهداف للاختبار."
            ),
            "coder": (
                "أنت مطور أمني خبير. مهمتك كتابة كود Python دقيق وفعّال للتحقق من "
                "الثغرات الأمنية. الكود للأغراض التعليمية فقط على أهداف مصرح بها."
            ),
        }
        return prompts.get(role, prompts["planner"])

    def _parse_thought(self, content: str) -> Thought:
        """يحلّل رد الـ LLM ويحوله لـ Thought object"""
        # محاولة استخراج JSON من الرد
        try:
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(content[start:end])
                return Thought(
                    type=ThoughtType[data.get("type", "RECON").upper()],
                    content=data.get("content", content),
                    confidence=float(data.get("confidence", 0.5)),
                    reasoning=data.get("reasoning", ""),
                    suggested_tools=data.get("suggested_tools", []),
                )
        except (json.JSONDecodeError, KeyError):
            pass

        # Fallback: treat as plain text
        return Thought(
            type=ThoughtType.RECON,
            content=content[:500],
            confidence=0.5,
        )


# ─────────────────────────────────────────────────────────────────────────────
# REACT LOOP ENGINE — قلب الـ Agent
# ─────────────────────────────────────────────────────────────────────────────

class WorldEliteReActLoop:
    """
    حلقة ReAct كاملة: Think → Act → Observe → Think → ...

    هذا هو القلب النابض للـ Agent — نفس المبدأ اللي بيستخدمه:
    • XBOW        → اكتشاف ثغرات HackerOne تلقائياً
    • PentAGI     → pentest كامل بدون تدخل
    • VAPOR PANDA → multi-target attack automation

    للأغراض التعليمية على أهداف مصرح بها فقط.
    """

    def __init__(
        self,
        llm: OllamaProvider,
        tool_registry: Dict[str, Callable],
        max_steps: int = 50,
        hallucination_filter: bool = True,
    ):
        self.llm = llm
        self.tool_registry = tool_registry
        self.max_steps = max_steps
        self.hallucination_filter = hallucination_filter
        self.history: List[ReActStep] = []
        self._step_counter = 0

    async def run(
        self,
        goal: str,
        target: str,
        scope: List[str],
        on_step: Optional[Callable[[ReActStep], None]] = None,
    ) -> Dict[str, Any]:
        """
        يشغل الحلقة الكاملة حتى يصل لهدف أو يستنفذ الخطوات.
        
        Args:
            goal:    ما يريد تحقيقه ("Find all SQLi vulnerabilities")
            target:  الهدف المصرح به ("http://192.168.43.128")
            scope:   قائمة IP/domains المصرح بها
            on_step: callback عند كل خطوة (للـ UI)
        """
        logger.info("🚀 WorldEliteReActLoop started | goal=%s | target=%s", goal, target)

        state = AgentState(goal=goal, target=target, scope=scope)
        
        while self._step_counter < self.max_steps:
            self._step_counter += 1
            logger.info("⚙️  Step %d/%d", self._step_counter, self.max_steps)

            # ── THINK ──────────────────────────────────────────────────────
            context = state.to_context_string()
            thought = await self.llm.think(context, role="planner")
            logger.debug("💭 Thought: %s", thought.content[:100])

            # ── SELECT ACTION ───────────────────────────────────────────────
            action = await self._select_action(thought, state)
            if action is None:
                logger.info("✅ Agent decided to stop — no more actions")
                break

            # ── HALLUCINATION FILTER ────────────────────────────────────────
            if self.hallucination_filter and not self._validate_action(action, state):
                logger.warning("🛡️  Action blocked by hallucination filter: %s", action.tool_name)
                state.add_note(f"Action {action.tool_name} blocked — validation failed")
                continue

            # ── ACT ─────────────────────────────────────────────────────────
            observation = await self._execute_action(action, state)
            
            # ── RECORD ──────────────────────────────────────────────────────
            step = ReActStep(
                step_id=self._step_counter,
                thought=thought,
                action=action,
                observation=observation,
            )
            self.history.append(step)
            state.update(observation)

            if on_step:
                on_step(step)

            # ── CHECK COMPLETION ────────────────────────────────────────────
            if self._is_goal_reached(state, goal):
                logger.info("🎯 Goal reached!")
                break

        return self._compile_results(state)

    async def _select_action(
        self, thought: Thought, state: "AgentState"
    ) -> Optional[Action]:
        """يختار الإجراء بناءً على الفكرة وحالة الـ Agent"""
        
        # إذا لم يقترح الـ LLM أدوات — نختار بناءً على مرحلة الـ pentest
        if not thought.suggested_tools:
            tool_name = self._phase_to_tool(state.phase)
        else:
            # نأخذ أول أداة مقترحة وهي موجودة في الـ registry
            tool_name = next(
                (t for t in thought.suggested_tools if t in self.tool_registry),
                None,
            )

        if tool_name is None:
            return None

        return Action(
            tool_name=tool_name,
            parameters={"target": state.target, "phase": state.phase},
            rationale=thought.content[:200],
        )

    async def _execute_action(self, action: Action, state: "AgentState") -> Observation:
        """ينفذ الإجراء باستخدام الأداة المناسبة"""
        tool_fn = self.tool_registry.get(action.tool_name)
        if tool_fn is None:
            return Observation(
                raw_output=f"Tool not found: {action.tool_name}",
                success=False,
            )

        t0 = time.perf_counter()
        try:
            if asyncio.iscoroutinefunction(tool_fn):
                result = await tool_fn(**action.parameters)
            else:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, lambda: tool_fn(**action.parameters))
            
            exec_ms = (time.perf_counter() - t0) * 1000
            return Observation(
                raw_output=str(result)[:2000],
                success=True,
                execution_time_ms=exec_ms,
            )
        except Exception as exc:
            exec_ms = (time.perf_counter() - t0) * 1000
            return Observation(
                raw_output=f"Tool execution error: {exc}",
                success=False,
                execution_time_ms=exec_ms,
            )

    def _validate_action(self, action: Action, state: "AgentState") -> bool:
        """
        Hallucination Filter — يتحقق إن الـ LLM مش بيخترع أدوات مش موجودة.
        مستوحى من درس Lazarus: التحقق من كل خطوة قبل التنفيذ.
        """
        if action.tool_name not in self.tool_registry:
            return False
        target = action.parameters.get("target", "")
        # تأكد إن الهدف في نطاق الصلاحية
        if target and not any(s in target for s in state.scope):
            logger.warning("🚫 Target %s not in scope %s", target, state.scope)
            return False
        return True

    def _phase_to_tool(self, phase: str) -> str:
        """يربط مرحلة الـ pentest بالأداة المناسبة"""
        mapping = {
            "recon":       "port_scanner",
            "enum":        "web_crawler",
            "vuln_scan":   "nuclei_scan",
            "exploit":     "exploit_runner",
            "post_exploit":"privilege_checker",
            "report":      "report_generator",
        }
        return mapping.get(phase, "port_scanner")

    def _is_goal_reached(self, state: "AgentState", goal: str) -> bool:
        """يقرر إذا كان الهدف قد تحقق"""
        if state.findings and "find" in goal.lower():
            return True
        if state.step_count >= self.max_steps:
            return True
        return False

    def _compile_results(self, state: "AgentState") -> Dict[str, Any]:
        """يجمع كل النتائج في تقرير نهائي"""
        return {
            "total_steps": self._step_counter,
            "findings": state.findings,
            "assets_discovered": state.assets,
            "notes": state.notes,
            "history_count": len(self.history),
        }


# ─────────────────────────────────────────────────────────────────────────────
# AGENT STATE — ذاكرة الـ Agent
# ─────────────────────────────────────────────────────────────────────────────

class AgentState:
    """
    حالة الـ Agent الكاملة — ذاكرة عاملة للـ ReAct loop.
    مستوحى من Unit 8200: تتبع كل شيء وربط الأصول بالنتائج.
    """

    PHASES = ["recon", "enum", "vuln_scan", "exploit", "post_exploit", "report"]

    def __init__(self, goal: str, target: str, scope: List[str]):
        self.goal = goal
        self.target = target
        self.scope = scope
        self.phase = "recon"
        self.phase_idx = 0
        self.findings: List[Dict] = []
        self.assets: List[str] = []
        self.notes: List[str] = []
        self.step_count = 0
        self.context_window: List[str] = []  # آخر 10 ملاحظات

    def update(self, observation: Observation):
        """يحدث الحالة بناءً على الملاحظة الجديدة"""
        self.step_count += 1
        summary = observation.raw_output[:300]
        self.context_window.append(summary)
        if len(self.context_window) > 10:
            self.context_window.pop(0)

        # إذا نجح الإجراء، تقدم للمرحلة التالية كل 5 خطوات
        if observation.success and self.step_count % 5 == 0:
            self._advance_phase()

        # استخراج findings من الملاحظة
        for finding in observation.new_findings:
            self.findings.append({"finding": finding, "step": self.step_count})

    def add_note(self, note: str):
        self.notes.append(note)

    def _advance_phase(self):
        """ينتقل للمرحلة التالية"""
        if self.phase_idx < len(self.PHASES) - 1:
            self.phase_idx += 1
            self.phase = self.PHASES[self.phase_idx]
            logger.info("📶 Phase advanced → %s", self.phase)

    def to_context_string(self) -> str:
        """يحول الحالة لنص لإرساله للـ LLM"""
        return f"""
=== CURRENT PENTEST STATE ===
GOAL:   {self.goal}
TARGET: {self.target}
PHASE:  {self.phase} (Step {self.step_count})
SCOPE:  {', '.join(self.scope)}

RECENT OBSERVATIONS:
{chr(10).join(f'  - {o}' for o in self.context_window[-5:])}

FINDINGS SO FAR: {len(self.findings)}
ASSETS FOUND:   {len(self.assets)}

What is the optimal next action? Think step by step.
Respond with JSON: {{"type": "RECON|HYPOTHESIS|EXPLOITATION|VERIFICATION", 
                     "content": "...", "confidence": 0.0-1.0,
                     "suggested_tools": ["tool1", "tool2"]}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# MOCK CLIENT — للتطوير بدون Ollama
# ─────────────────────────────────────────────────────────────────────────────

class MockOllamaClient:
    """يحاكي الـ Ollama client للاختبار"""

    def chat(self, model: str, messages: List[Dict], **kwargs) -> Dict:
        return {
            "message": {
                "content": json.dumps({
                    "type": "RECON",
                    "content": "Start with port scanning to discover open services",
                    "confidence": 0.8,
                    "reasoning": "Initial phase requires service discovery",
                    "suggested_tools": ["port_scanner", "web_crawler"],
                })
            }
        }
