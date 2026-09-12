"""
Artifact Analyzer — Qwen2.5-Coder trigger on JS files and tool outputs
يشتغل Qwen تلقائياً لما تظهر ملفات JS أو مخرجات أدوات تستحق التحليل العميق
"""
import json
import logging
import re
from copy import deepcopy
from typing import Any, Dict, Optional, Callable

log = logging.getLogger("artifact_analyzer")

MODEL_CODER: str = "qwen2.5-coder:14b"

# ─── Safe JSON parser ────────────────────────────────────────────────────────

def _parse_json_safe(text: str, fallback: dict) -> dict:
    """
    استخراج أول JSON object من نص النموذج بشكل آمن.
    يُعيد deepcopy من fallback عند أي فشل.
    """
    # محاولة 1: النص كاملاً JSON
    try:
        data = json.loads(text.strip())
        return data if isinstance(data, dict) else deepcopy(fallback)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # محاولة 2: بحث بالعمق عن أول {}
    try:
        start = text.index("{")
        depth, end = 0, start
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
        log.debug("_parse_json_safe: no valid JSON found in model output")

    return deepcopy(fallback)


# ─── ArtifactAnalyzer ────────────────────────────────────────────────────────

class ArtifactAnalyzer:
    """
    يُشغّل Qwen2.5-Coder عبر ResourceManager (GPU lock) لتحليل:
    - ملفات JS: secrets, endpoints, eval risks
    - مخرجات الأدوات: true/false positive + remediation code
    - HTML forms: injection points + CSRF
    """

    def __init__(self, resource_manager, emit_fn: Optional[Callable] = None):
        self.rm = resource_manager
        self.emit_fn = emit_fn

    async def _log(self, msg: str) -> None:
        log.debug(msg)
        if self.emit_fn:
            try:
                await self.emit_fn({"event": "log", "message": msg})
            except Exception:
                log.exception("ArtifactAnalyzer._log: emit failed")

    async def _ask_qwen(self, system_msg: str, user_msg: str) -> str:
        """يستدعي Qwen عبر GPU lock — يُعيد النص الخام"""
        try:
            return await self.rm.run_local_model(
                model_name=MODEL_CODER,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                num_ctx=4096,
            ) or ""
        except Exception:
            log.exception("ArtifactAnalyzer._ask_qwen: model call failed")
            return ""

    async def analyze_js_file(self, js_content: str, source_url: str = "") -> Dict[str, Any]:
        """
        Qwen يحلل كود JavaScript ويستخرج:
        secrets, hidden_endpoints, eval_risks, api_keys
        """
        fallback: Dict[str, Any] = {
            "secrets": [],
            "hidden_endpoints": [],
            "eval_risks": [],
            "api_keys": [],
            "summary": "Qwen analysis unavailable",
        }
        await self._log(f"[QWEN-JS] Analyzing: {source_url[:80]}")

        system_msg = (
            "You are a security code auditor specializing in JavaScript. "
            "Find hardcoded secrets, hidden API endpoints, dangerous eval() calls, "
            "and leaked API keys. Output ONLY a valid JSON object, no markdown."
        )
        user_msg = (
            f"Source URL: {source_url}\n"
            f"JavaScript code:\n{js_content[:3500]}\n\n"
            "Return JSON:\n"
            '{"secrets": ["..."], "hidden_endpoints": ["/api/v1/..."], '
            '"eval_risks": ["..."], "api_keys": ["..."], "summary": "one sentence"}'
        )
        raw = await self._ask_qwen(system_msg, user_msg)
        result = _parse_json_safe(raw, fallback)

        await self._log(
            f"   -> Qwen-JS: secrets={len(result.get('secrets', []))} | "
            f"endpoints={len(result.get('hidden_endpoints', []))}"
        )
        return result

    async def analyze_tool_output(
        self, tool_name: str, raw_output: str, target: str
    ) -> Dict[str, Any]:
        """
        Qwen يقرأ مخرجات الأداة ويُنتج:
        - is_real_finding: bool
        - vuln_type, severity
        - remediation_code
        """
        fallback: Dict[str, Any] = {
            "is_real_finding": False,
            "vuln_type": "unknown",
            "severity": "Low",
            "remediation_code": "",
            "reasoning": "Could not analyze",
        }
        await self._log(f"[QWEN-TOOL] Analyzing {tool_name!r} output for {target[:50]}")

        system_msg = (
            "You are a penetration testing expert and secure code reviewer. "
            "Analyze the tool output and determine if it is a real vulnerability. "
            "Also write a remediation code snippet. Output ONLY a valid JSON object."
        )
        user_msg = (
            f"Tool: {tool_name}\n"
            f"Target: {target}\n"
            f"Tool Output:\n{raw_output[:3000]}\n\n"
            "Return JSON:\n"
            '{"is_real_finding": true, "vuln_type": "xss", '
            '"severity": "Critical|High|Medium|Low", '
            '"remediation_code": "// sanitize input\\n...", "reasoning": "one sentence"}'
        )
        raw = await self._ask_qwen(system_msg, user_msg)
        result = _parse_json_safe(raw, fallback)

        await self._log(
            f"   -> Qwen-Tool: real={result.get('is_real_finding')} | "
            f"severity={result.get('severity')}"
        )
        return result

    async def analyze_html_forms(self, html: str, target: str) -> Dict[str, Any]:
        """
        Qwen يُحلّل HTML ويجد:
        - forms, parameters
        - csrf_present
        - injection_risks, auth_fields
        """
        fallback: Dict[str, Any] = {
            "forms": [],
            "parameters": [],
            "csrf_present": False,
            "injection_risks": [],
            "auth_fields": [],
        }
        await self._log(f"[QWEN-FORMS] Analyzing HTML forms for {target[:50]}")

        system_msg = (
            "You are a web security expert. Analyze HTML source code and identify "
            "all forms, injection points, CSRF protection, and authentication fields. "
            "Output ONLY a valid JSON object."
        )
        user_msg = (
            f"Target: {target}\n"
            f"HTML:\n{html[:3000]}\n\n"
            "Return JSON:\n"
            '{"forms": [{"action": "/login", "method": "POST"}], '
            '"parameters": ["username", "password"], "csrf_present": false, '
            '"injection_risks": ["username field lacks sanitization"], '
            '"auth_fields": ["username", "password"]}'
        )
        raw = await self._ask_qwen(system_msg, user_msg)
        result = _parse_json_safe(raw, fallback)

        await self._log(
            f"   -> Qwen-Forms: params={len(result.get('parameters', []))} | "
            f"risks={len(result.get('injection_risks', []))} | "
            f"csrf={result.get('csrf_present')}"
        )
        return result
