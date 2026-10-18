"""
WAF Detection Skill
===================
يكتشف ويبصم جدران حماية التطبيقات (WAF) باستخدام ``wafw00f``، مع fallback
قائم على بصمات رؤوس HTTP عبر ``curl``/``httpx`` عندما لا تتوفر ``wafw00f``.

القاعدة الجوهرية (Creed): كل ما يُنتجه هذا الـ Skill هو "مرشّح" (candidate)
قابل للتحقق فقط — لا يُؤكَّد أي اكتشاف تلقائيًا ولا يُدرج في التقرير النهائي
إلا بعد تحكيمه في محكمة الأدلة (Evidence Court).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from skills.base_skill import BaseSkill, SkillContext, SkillResult

# ── بصمات WAF الشائعة في رؤوس/جسم الاستجابة (تُستخدم عند غياب wafw00f) ─────────
_WAF_SIGNATURES: List[Tuple[str, List[str]]] = [
    ("Cloudflare", ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status", "cf-request-id"]),
    ("AWS WAF / CloudFront", ["awselb", "x-amz-cf-id", "x-amzn-requestid", "x-amz-cf-pop", "x-amz-apigw-id"]),
    ("Akamai", ["akamai", "x-akamai", "akamaighost", "x-akamai-transformed"]),
    ("Imperva / Incapsula", ["incap_ses", "visid_incap", "_incap_", "x-iinfo", "x-cdn"]),
    ("F5 BIG-IP ASM", ["bigipserver", "x-wa-info", "tsxxxxxxxx", "x-f5-"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "sucuri"]),
    ("ModSecurity", ["mod_security", "modsecurity"]),
    ("Barracuda", ["barra_counter_session", "barracuda"]),
    ("FortiWeb", ["fortiweb", "fortiwafsid"]),
    ("Fastly", ["x-served-by", "x-fastly-request-id", "x-fastly-"]),
    ("Wordfence", ["wordfence"]),
    ("Wallarm", ["wallarm"]),
    ("Azure Front Door / App Gateway", ["x-azure-ref", "x-fd-", "x-azure-"]),
    ("Google Cloud Armor", ["via: 1.1 google", "gws", "x-cloud-trace-context"]),
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class WafDetectionSkill(BaseSkill):
    name = "waf_detection"
    category = "recon"
    description = "Detect and fingerprint Web Application Firewalls (wafw00f + heuristics)"
    tools_required = ["wafw00f"]
    fallback_tools = ["httpx", "curl"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="wafw00f")

        targets = self._load_targets(ctx)
        if not targets:
            result.errors.append("No targets available to probe for WAF")
            result.success = False
            return result

        detected: List[Tuple[str, str, str]] = []   # (url, waf_name, evidence)
        undetected: List[str] = []
        raw_sections: List[str] = []

        if ctx.tool_manager.is_available("wafw00f"):
            result.tool_used = "wafw00f"
            for url in targets[:15]:
                res = await ctx.tool_manager.execute(f"wafw00f {url}", timeout=25)
                out = _clean((res.stdout or "") + (res.stderr or ""))
                if not out.strip():
                    continue
                raw_sections.append(f"# {url}\n{out.strip()}")
                name, is_waf = self._parse_wafw00f(out)
                if is_waf:
                    detected.append((url, name, out.strip()[:600]))
                else:
                    undetected.append(url)
        else:
            # Heuristic fallback — لاحظ أننا نبقى ضمن مجالات HTTP المصرّح بها.
            curl_available = ctx.tool_manager.is_available("curl")
            result.tool_used = "curl" if curl_available else "httpx"
            for url in targets[:10]:
                if curl_available:
                    res = await ctx.tool_manager.execute(f"curl -s -I -m 10 {url}", timeout=15)
                else:
                    res = await ctx.tool_manager.execute(
                        f"{ctx.tool_manager.resolve_binary('httpx')} -u {url} -silent -include-chain -no-color",
                        timeout=20,
                    )
                headers = _clean((res.stdout or "") + (res.stderr or ""))
                if not headers.strip():
                    continue
                raw_sections.append(f"# {url}\n{headers.strip()}")
                name = self._match_signatures(headers)
                if name:
                    detected.append((url, name, headers.strip()[:500]))
                else:
                    undetected.append(url)

        # ── بناء التقرير النصي ──────────────────────────────────────────────
        lines: List[str] = [f"# WAF Detection — {ctx.target}", ""]
        lines.append(f"- **Targets probed:** {len(targets)}")
        lines.append(f"- **WAF detected:** {len(detected)}")
        lines.append(f"- **Tool used:** `{result.tool_used}`")
        lines.append("")

        if detected:
            lines.append("## Detected WAFs")
            for url, name, ev in detected:
                lines.append(f"### {name} — {url}")
                lines.append("```")
                lines.append(ev)
                lines.append("```")
                lines.append("")

        if undetected:
            lines.append("## No WAF Detected")
            for url in undetected:
                lines.append(f"- {url}")
            lines.append("")

        if raw_sections:
            lines.append("## Raw Output")
            lines.extend(raw_sections)

        content = "\n".join(lines)
        p = ctx.workspace.write_file(ctx.target, "recon", "waf_detection.txt", content, ctx.session_id)
        result.output_files["waf_detection.txt"] = str(p)

        # ── Findings (كلها candidates — لا تأكيد تلقائي) ────────────────────
        for url, name, ev in detected:
            self._add_finding(
                result,
                title=f"WAF Detected: {name}",
                evidence=ev,
                severity="Info",
                vuln_type="waf_detection",
                url=url,
                recommendation=(
                    "A WAF is present in front of the application. Expect payload filtering and "
                    "rate limiting — rely on encoding/normalization bypass variants and keep request "
                    "rates low. The WAF is a mitigating control and not a fix for underlying flaws."
                ),
            )

        if not detected and undetected:
            self._add_finding(
                result,
                title="No WAF Detected (direct origin exposure)",
                evidence="\n".join(undetected[:20]),
                severity="Info",
                vuln_type="waf_detection",
                recommendation=(
                    "No WAF was identified in front of the target. Treat the origin as directly "
                    "reachable: ensure application-level input validation, rate limiting and DDoS "
                    "protection, since there is no external filtering layer."
                ),
            )

        if not detected and not undetected:
            result.errors.append("WAF detection produced no parsable output")
            result.success = False

        result.raw_output["waf_detection"] = content[:5000]
        return result

    # ── helpers ─────────────────────────────────────────────────────────────

    def _load_targets(self, ctx: SkillContext) -> List[str]:
        targets: List[str] = []
        live = ctx.state_files.get("live_host_detection", {})
        live_path = live.get("live_hosts.txt", "") if isinstance(live, dict) else live
        if live_path and Path(live_path).exists():
            for ln in Path(live_path).read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                url = ln.split()[0]
                if not url.startswith("http"):
                    url = f"http://{url}"
                targets.append(url)

        if not targets:
            base = ctx.target.replace("https://", "").replace("http://", "").split("/")[0]
            targets = [f"http://{base}"]

        # de-duplicate while preserving order
        seen = set()
        uniq: List[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        return uniq

    @staticmethod
    def _parse_wafw00f(out: str) -> Tuple[str, bool]:
        """يفك مخرجات wafw00f إلى (اسم الـ WAF، هل اكتُشف)."""
        low = out.lower()
        if "no waf detected" in low or "no waf" in low:
            return "None", False
        if "is behind" in low or "behind a" in low or "is protected by" in low:
            m = re.search(r"is behind (?:a )?(.+?)\s+WAF", out, re.IGNORECASE)
            if not m:
                m = re.search(r"is protected by (?:a )?(.+?)\s+WAF", out, re.IGNORECASE)
            if not m:
                m = re.search(r"is behind (?:a )?(.+)", out, re.IGNORECASE)
            name = m.group(1).strip().rstrip(".") if m else "Unknown WAF"
            return name, True
        return "Unknown", False

    @staticmethod
    def _match_signatures(headers: str) -> Optional[str]:
        low = headers.lower()
        for name, sigs in _WAF_SIGNATURES:
            if any(sig in low for sig in sigs):
                return name
        return None

    @staticmethod
    def _add_finding(
        result: SkillResult,
        *,
        title: str,
        evidence: str,
        severity: str,
        vuln_type: str,
        recommendation: str,
        url: str = "",
    ) -> None:
        result.add_finding(
            title=title,
            evidence=evidence,
            severity=severity,
            vuln_type=vuln_type,
            url=url,
            recommendation=recommendation,
        )
        # Creed: outputs are raw candidate observations, never confirmed findings.
        result.findings[-1].update({"status": "candidate", "evidence_level": "E0"})


def _clean(text: str) -> str:
    """يزيل رموز ANSI حتى يُطابق النص والبحث عن البصمات بشكل موثوق."""
    return _ANSI_RE.sub("", text or "")
