"""
Decision Engine — WhiteRabbitNeo Strategic Planner + xploiter Attacker
يُنتج خطة JSON فقط — لا ينفّذ أوامر مباشرة.
التنفيذ يتم عبر TOOL_REGISTRY في AutonomousBrain فقط.
"""
import os
import re
import json
import logging
import ipaddress
from copy import deepcopy
from typing import Dict, Any, List, Optional, Callable

log = logging.getLogger("decision_engine")

# ─── Allowlists ─────────────────────────────────────────────────────────────
# النموذج مسموح له فقط باقتراح هذه الأدوات
ALLOWED_TOOLS: frozenset = frozenset({
    "SmartPoC", "BugBountyAgent", "ReconAgent",
    "BrowserAgent", "WebAgent", "dalfox", "sqlmap",
    "nuclei", "subfinder", "nmap", "gobuster",
    "VulnerabilityEngine", "LFISkill", "CmdInjectionSkill",
    "CSRFSkill", "SQLiSkill", "SSRFSkill", "IDORSkill", "XSSSkill",
    "SSTISkill", "XXESkill", "CORSSkill", "FileUploadSkill",
    "JWTOAuthSkill", "RaceConditionSkill", "GraphQLSkill",
    "WebSocketSkill", "IDORMatrixSkill",
})

# فقط هذه القيم مقبولة لـ primary_focus
ALLOWED_FOCUSES: frozenset = frozenset({
    "xss", "sqli", "ssrf", "idor", "auth", "recon", "api", "rce",
    "ssti", "xxe", "cors", "file_upload", "graphql", "websocket",
    "jwt", "race", "csrf", "lfi", "cmdi",
})

# فقط هذه القيم مقبولة لـ target_type
ALLOWED_TARGET_TYPES: frozenset = frozenset({
    "single_endpoint", "full_domain", "auth_portal", "lab",
})

# أنواع next_action المقبولة
ALLOWED_NEXT_ACTIONS: frozenset = frozenset({
    "verify", "skip", "browser_check",
})

# النموذج الاستراتيجي (WhiteRabbitNeo) — فحص اختراق وتحديد أدوات
MODEL_STRATEGIST: str = os.getenv(
    "MODEL_STRATEGIST", "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"
)
# النموذج الهجومي (xploiter) — تصنيف مخرجات الأدوات
MODEL_ATTACKER: str = os.getenv(
    "MODEL_ATTACKER", "xploiter/pentester:latest"
)

# ─── Default Values ──────────────────────────────────────────────────────────
_DEFAULT_PLAN: Dict[str, Any] = {
    "target_type": "full_domain",
    "needed_tools": ["ReconAgent", "SmartPoC", "gobuster", "nmap"],
    "skipped_tools": [],
    "skip_reasons": "",
    "primary_focus": "xss",
    "parameters_to_audit": ["search", "id", "q", "category", "url"],
    "use_browser": False,
    "use_burp": False,
    "needs_recon": True,
}

_DEFAULT_CLASSIFY: Dict[str, Any] = {
    "is_real_vuln": False,
    "next_action": "skip",
    "reasoning": "Could not classify output",
    "suggested_tool": "",
}

# ─── Blocked Internal Ranges ─────────────────────────────────────────────────
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def is_target_allowed(target: str) -> tuple[bool, str]:
    """
    تحقق من أن الهدف ليس عنوان داخلي محظور.
    Returns: (allowed: bool, reason: str)
    يُقبل localhost/127.x — مفيد لـ labs محلية.
    يُرفض 169.254.x.x وعناوين cloud metadata.
    """
    from urllib.parse import urlparse
    try:
        host = urlparse(target).hostname or target
        addr = ipaddress.ip_address(host)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return False, f"Blocked network range: {net}"
    except ValueError:
        pass  # hostname — not an IP
    return True, ""


def _parse_json_safe(text: str, fallback: dict) -> dict:
    """
    استخراج أول JSON object من النص.
    يُعيد نسخة عميقة من fallback عند الفشل.
    لا يستخدم greedy regex — يبحث عن أول { ويُحلّله بشكل تراكمي.
    """
    # محاولة 1: تحليل النص كاملاً
    try:
        data = json.loads(text.strip())
        return data if isinstance(data, dict) else deepcopy(fallback)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # محاولة 2: استخراج أول {} block
    try:
        start = text.index("{")
        # نحسب التوازن لإيجاد نهاية الـ block الصحيحة
        depth = 0
        end = start
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        chunk = text[start:end + 1]
        data = json.loads(chunk)
        return data if isinstance(data, dict) else deepcopy(fallback)
    except (ValueError, json.JSONDecodeError, TypeError):
        log.debug("_parse_json_safe: could not extract JSON from model output")

    return deepcopy(fallback)


def _validate_plan(raw_plan: dict) -> dict:
    """
    يُنظّف خطة النموذج ويطبّق allowlists.
    أيّ قيمة خارج الـ allowlist تُستبدل بالقيمة الافتراضية الآمنة.
    """
    plan = deepcopy(_DEFAULT_PLAN)

    # target_type
    if raw_plan.get("target_type") in ALLOWED_TARGET_TYPES:
        plan["target_type"] = raw_plan["target_type"]

    # needed_tools — filter to allowlist only
    if isinstance(raw_plan.get("needed_tools"), list):
        filtered = [t for t in raw_plan["needed_tools"] if t in ALLOWED_TOOLS]
        plan["needed_tools"] = filtered if filtered else ["SmartPoC"]

    # skipped_tools — filter to allowlist only
    if isinstance(raw_plan.get("skipped_tools"), list):
        plan["skipped_tools"] = [
            t for t in raw_plan["skipped_tools"] if t in ALLOWED_TOOLS
        ]

    # skip_reasons — string only, max 300 chars
    if isinstance(raw_plan.get("skip_reasons"), str):
        plan["skip_reasons"] = raw_plan["skip_reasons"][:300]

    # primary_focus
    if raw_plan.get("primary_focus") in ALLOWED_FOCUSES:
        plan["primary_focus"] = raw_plan["primary_focus"]

    # parameters_to_audit — sanitize: only safe param names
    if isinstance(raw_plan.get("parameters_to_audit"), list):
        safe_params = [
            re.sub(r"[^a-zA-Z0-9_\-\[\].]", "", str(p))[:64]
            for p in raw_plan["parameters_to_audit"]
            if p and isinstance(p, str)
        ]
        plan["parameters_to_audit"] = safe_params[:20]  # max 20 params

    # booleans
    plan["use_browser"] = bool(raw_plan.get("use_browser", False))
    plan["use_burp"] = bool(raw_plan.get("use_burp", False))
    plan["needs_recon"] = bool(raw_plan.get("needs_recon", False))

    return plan


def _validate_classify(raw: dict) -> dict:
    """يُنظّف نتيجة تصنيف xploiter"""
    result = deepcopy(_DEFAULT_CLASSIFY)
    result["is_real_vuln"] = bool(raw.get("is_real_vuln", False))
    if raw.get("next_action") in ALLOWED_NEXT_ACTIONS:
        result["next_action"] = raw["next_action"]
    if isinstance(raw.get("reasoning"), str):
        result["reasoning"] = raw["reasoning"][:500]
    if isinstance(raw.get("suggested_tool"), str):
        st = raw["suggested_tool"]
        result["suggested_tool"] = st if st in ALLOWED_TOOLS else ""
    return result


# ─── DecisionEngine ──────────────────────────────────────────────────────────

class DecisionEngine:
    """
    يُنتج خطة هجومية JSON بناءً على تحليل WhiteRabbitNeo.
    القاعدة: النموذج يقترح فقط — التنفيذ يتم عبر TOOL_REGISTRY.
    """

    def __init__(self, resource_manager, emit_fn: Optional[Callable] = None):
        self.rm = resource_manager
        self.emit_fn = emit_fn
        self._decision_log: List[Dict[str, Any]] = []  # audit trail

    async def _log(self, msg: str) -> None:
        log.debug(msg)
        if self.emit_fn:
            try:
                await self.emit_fn({"event": "log", "message": msg})
            except Exception:
                log.exception("DecisionEngine._log: emit failed")

    def _record(self, event: str, data: dict) -> None:
        """يسجّل كل قرار لـ audit trail"""
        import time as _time
        self._decision_log.append({
            "ts": _time.time(),
            "event": event,
            **data,
        })

    async def _ask_local(self, model: str, system_msg: str, user_msg: str) -> str:
        """
        يستدعي نموذجاً محلياً عبر ResourceManager (GPU lock).
        model يجب أن يكون من قائمة محددة مسبقاً — لا يُقبل من المستخدم.
        """
        # تحقق أن model واحد من النموذجين المعرّفين فقط
        if model not in (MODEL_STRATEGIST, MODEL_ATTACKER):
            log.warning(f"Rejected unknown model name: {model!r}")
            return ""
        try:
            result = await self.rm.run_local_model(
                model_name=model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.2,
                num_ctx=4096,
            )
            return result or ""
        except Exception:
            log.exception(f"_ask_local: model={model!r} failed")
            return ""

    async def _ask_api_fallback(self, prompt: str) -> str:
        """يستدعي AIReasoningCore كـ fallback لما اللوكل غير متاح"""
        try:
            from core.ai_reasoning_core import AIReasoningCore
            return await AIReasoningCore.ask_ai(prompt) or ""
        except Exception:
            log.exception("_ask_api_fallback failed")
            return ""

    # ── Deterministic Pre-checks ─────────────────────────────────────────────

    def _pre_classify_target(self, target: str, html_snippet: str, headers: dict) -> Dict[str, Any]:
        """
        قواعد حتمية قبل استدعاء النموذج.
        تضع القرارات الواضحة وتترك للنموذج التفسير والترتيب فقط.
        """
        from urllib.parse import urlparse
        hints: Dict[str, Any] = {}

        parsed = urlparse(target)
        path = parsed.path.lower()
        query = parsed.query

        # هل فيه params في URL؟
        hints["has_url_params"] = bool(query)

        # هل الهدف domain كامل أم endpoint محدد؟
        hints["is_full_domain"] = (
            not path or path == "/" or path == ""
        ) and not query

        # هل في auth headers أو login keywords؟
        html_lower = (html_snippet or "").lower()
        hints["has_auth_form"] = any(
            kw in html_lower
            for kw in ("login", "signin", "password", "username", "authenticate")
        )

        # هل الموقع يستخدم JS framework؟
        server_header = headers.get("server", "").lower()
        hints["is_api"] = (
            "application/json" in headers.get("content-type", "")
            or "/api/" in path
            or "/v1/" in path
            or "/graphql" in path
        )

        # Server-side tech
        powered_by = headers.get("x-powered-by", "").lower()
        hints["tech_hint"] = powered_by or server_header

        return hints

    # ── Main Methods ─────────────────────────────────────────────────────────

    async def make_plan(
        self,
        target: str,
        html_snippet: str,
        headers: dict,
        available_tools: List[str],
        mode: str = "auto",
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        يُنتج خطة هجومية JSON بعد:
        1. تحقق أمان الهدف
        2. تحليل حتمي (pre-classify)
        3. استشارة WhiteRabbitNeo
        4. التحقق من صحة الخطة (allowlist validation)
        Returns: dict خطة آمنة وجاهزة للتنفيذ
        """
        # ─ تحقق الهدف
        allowed, reason = is_target_allowed(target)
        if not allowed:
            await self._log(f"[DECIDE] BLOCKED target: {reason}")
            self._record("target_blocked", {"target": target, "reason": reason})
            plan = deepcopy(_DEFAULT_PLAN)
            plan["skip_reasons"] = f"Target blocked: {reason}"
            plan["needed_tools"] = []
            return plan

        await self._log(f"[DECIDE] WhiteRabbitNeo analyzing: {target}")

        if dry_run:
            await self._log("[DECIDE] dry_run=True — returning default plan without calling model")
            plan = deepcopy(_DEFAULT_PLAN)
            self._record("make_plan_dry_run", {"target": target, "mode": mode})
            return plan

        # ─ تحليل حتمي قبل النموذج
        hints = self._pre_classify_target(target, html_snippet, headers)
        await self._log(f"   -> Pre-classify hints: {hints}")

        # ─ بناء prompt آمن (نرسل للنموذج فقط ما يحتاجه)
        system_msg = (
            "You are an elite autonomous security strategist and cognitive auditor. "
            "You reason, analyze, and comprehend target architecture first. You are NOT a blind tool runner. "
            "Prioritize deep understanding and information gathering. You can choose to run NO tools at all "
            "(needed_tools: []) if passive observation and code analysis are sufficient to understand the target. "
            "Output ONLY a valid JSON object. No markdown, no explanation outside the JSON."
        )
        user_msg = (
            f"Target URL: {target}\n"
            f"Scan Mode: {mode}\n"
            f"Available tools (choose from these only if strictly necessary): {sorted(ALLOWED_TOOLS)}\n"
            f"Page HTML snippet: {html_snippet[:400] if html_snippet else 'N/A'}\n"
            f"HTTP Headers (sample): {dict(list(headers.items())[:5]) if headers else {}}\n"
            f"Pre-analysis hints: {hints}\n\n"
            "Analyze the target architecture, deduce data flow, and return a JSON plan with exactly these keys:\n"
            "  target_type: single_endpoint | full_domain | auth_portal | lab\n"
            "  needed_tools: list (can be empty [] if information gathering / code reading is sufficient)\n"
            "  skipped_tools: list (tools intentionally omitted)\n"
            "  skip_reasons: string (rationale for why tools were skipped or why passive understanding was chosen)\n"
            f"  primary_focus: one of {sorted(ALLOWED_FOCUSES)}\n"
            "  parameters_to_audit: list of param names (strings only)\n"
            "  use_browser: boolean\n"
            "  use_burp: boolean\n"
            "  needs_recon: boolean (true only for full domain)\n"
            "Do NOT include executable commands or shell instructions in the JSON."
        )

        raw = await self._ask_local(MODEL_STRATEGIST, system_msg, user_msg)
        if not raw:
            await self._log("[DECIDE] Local model unavailable — using API fallback")
            raw = await self._ask_api_fallback(user_msg)

        # ─ تحليل + تحقق من الخطة
        raw_plan = _parse_json_safe(raw, _DEFAULT_PLAN)
        plan = _validate_plan(raw_plan)

        # ─ تجاوز حتمي: لو الهدف full domain → needs_recon يجب True
        if hints.get("is_full_domain") and not plan["needs_recon"]:
            plan["needs_recon"] = True
            await self._log("   -> Pre-classify override: needs_recon=True (full domain)")

        # ─ تجاوز حتمي: auth portal → use_browser
        if hints.get("has_auth_form") and not plan["use_browser"]:
            plan["use_browser"] = True
            await self._log("   -> Pre-classify override: use_browser=True (auth form detected)")

        self._record("make_plan", {
            "target": target, "mode": mode,
            "focus": plan["primary_focus"],
            "tools": plan["needed_tools"],
            "skipped": plan["skipped_tools"],
        })
        await self._log(
            f"[DECIDE] Plan: focus={plan['primary_focus']} | "
            f"tools={plan['needed_tools']} | skip={plan['skipped_tools']}"
        )
        if plan.get("skipped_tools"):
            await self._log(f"   -> Skip reason: {plan['skip_reasons']}")

        return plan

    async def classify_tool_output(
        self, tool_name: str, raw_output: str, target: str
    ) -> Dict[str, Any]:
        """
        xploiter يقرأ مخرجات الأداة ويحدد: ثغرة حقيقية أم false positive؟
        يُنتج JSON فقط — لا ينفّذ أوامر.
        """
        # tool_name يجب من allowlist
        if tool_name not in ALLOWED_TOOLS and tool_name not in ("SmartPoC",):
            await self._log(f"[XPLOITER] Rejected unknown tool: {tool_name!r}")
            return deepcopy(_DEFAULT_CLASSIFY)

        await self._log(f"[XPLOITER] Classifying {tool_name} output...")

        system_msg = (
            "You are an offensive security expert. Classify the tool output as a real "
            "vulnerability or false positive. Output ONLY a valid JSON object."
        )
        user_msg = (
            f"Tool: {tool_name}\n"
            f"Target: {target}\n"
            f"Tool Output:\n{raw_output[:2000]}\n\n"
            "Return JSON with exactly these keys:\n"
            "  is_real_vuln: boolean\n"
            f"  next_action: one of {sorted(ALLOWED_NEXT_ACTIONS)}\n"
            "  reasoning: string (one sentence max)\n"
            f"  suggested_tool: string (one of {sorted(ALLOWED_TOOLS)} or empty string)\n"
            "Do NOT include shell commands or executable instructions."
        )

        raw = await self._ask_local(MODEL_ATTACKER, system_msg, user_msg)
        if not raw:
            raw = await self._ask_api_fallback(user_msg)

        raw_result = _parse_json_safe(raw, _DEFAULT_CLASSIFY)
        result = _validate_classify(raw_result)

        self._record("classify_tool_output", {
            "tool": tool_name, "target": target,
            "is_real_vuln": result["is_real_vuln"],
            "next_action": result["next_action"],
        })
        await self._log(
            f"   -> xploiter: real={result['is_real_vuln']} "
            f"action={result['next_action']} reasoning={result['reasoning'][:80]}"
        )
        return result

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        """يُعيد سجل قرارات القيود (audit trail)"""
        return list(self._decision_log)
