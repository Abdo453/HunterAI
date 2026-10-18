"""
TLS Audit Skill
===============
يدقّق إعدادات خدمة TLS/SSL (أصدارات البروتوكول، الشفرات الضعيفة، الشهادة) باستخدام
``testssl.sh``، مع fallback إلى ``sslscan`` ثم ``openssl s_client``.

القاعدة الجوهرية (Creed): كل ناتج "مرشّح" (candidate, E0) لا يُؤكَّد تلقائيًا ولا
يُدرج في التقرير النهائي إلا بعد تحكيمه في محكمة الأدلة.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from skills.base_skill import BaseSkill, SkillContext, SkillResult

# بصمات شفرات ضعيفة داخل سطور الشفرات
_WEAK_CIPHER_MARKERS = (
    "des-cbc3", "3des", "rc4", "rc2", "null", "export", "des-cbc",
    "md5", "anon", "exp", "_des_",
)

# بروتوكول يبدأ السطر ثم وصف الحالة
_PROTO_LINE_RE = re.compile(
    r"^(SSLv?\d(?:\.\d)?|TLSv?\s*\d(?:\.\d)?)\b\s+(.*)$",
    re.IGNORECASE,
)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _protocol_level(token: str) -> Optional[str]:
    """يحوّل رمز بروتوكول (SSLv3 / TLS 1.0 / TLSv1.1) إلى درجة خطورة أو None."""
    t = token.lower().replace(" ", "").replace(".", "").replace("v", "")
    # t ∈ {ssl2, ssl3, tls1, tls10, tls11, tls12, tls13}
    if t in ("ssl2", "ssl3"):
        return "HIGH"
    if t in ("tls1", "tls10", "tls11"):
        return "MEDIUM"
    return None


def _is_enabled(text: str) -> bool:
    low = text.lower()
    if "not offered" in low or "disabled" in low:
        return False
    return "offered" in low or "enabled" in low


class TlsAuditSkill(BaseSkill):
    name = "tls_audit"
    category = "analysis"
    description = "Audit TLS/SSL configuration and certificate posture"
    tools_required = ["testssl.sh"]
    fallback_tools = ["sslscan", "openssl"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="testssl.sh")

        host = ctx.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ports = self._detect_tls_ports(ctx)
        port = ports[0]

        raw_output = ""
        issues: List[Dict[str, str]] = []
        certificate: List[str] = []

        testssl_bin = self._first_available(ctx, ["testssl.sh", "testssl"])
        if testssl_bin:
            result.tool_used = testssl_bin
            res = await ctx.tool_manager.execute(
                f"{testssl_bin} --quiet --color 0 --protocols --ciphers --server-defaults "
                f"--vulnerabilities {host}:{port}",
                timeout=120,
            )
            raw_output = _clean((res.stdout or "") + (res.stderr or ""))
            issues, certificate = self._parse_testssl(raw_output)

        elif ctx.tool_manager.is_available("sslscan"):
            result.tool_used = "sslscan"
            res = await ctx.tool_manager.execute(f"sslscan --no-colour {host}:{port}", timeout=90)
            raw_output = _clean((res.stdout or "") + (res.stderr or ""))
            issues, certificate = self._parse_sslscan(raw_output)

        elif ctx.tool_manager.is_available("openssl"):
            result.tool_used = "openssl"
            res = await ctx.tool_manager.execute(
                f"openssl s_client -connect {host}:{port} -servername {host} -brief < /dev/null",
                timeout=30,
            )
            raw_output = _clean((res.stdout or "") + (res.stderr or ""))
            issues, certificate = self._parse_openssl(raw_output)

        else:
            result.errors.append("No TLS auditing tool available (testssl.sh/sslscan/openssl)")
            result.success = False
            return result

        # ── التقرير النصي ───────────────────────────────────────────────────
        lines: List[str] = [f"# TLS Audit — {host}:{port}", ""]
        lines.append(f"- **Tool used:** `{result.tool_used}`")
        lines.append(f"- **Issues found:** {len(issues)}")
        lines.append("")

        if certificate:
            lines.append("## Certificate")
            lines.extend(f"- {c}" for c in certificate)
            lines.append("")

        if issues:
            lines.append("## Findings")
            lines.append("| Kind | Level | Detail |")
            lines.append("| :--- | :--- | :--- |")
            for it in issues:
                detail = it["detail"].replace("|", "/").strip()
                lines.append(f"| {it['kind']} | {it['level']} | {detail} |")
            lines.append("")
        else:
            lines.append("## Findings")
            lines.append("_لم تُرصد مشاكل TLS صريحة في مخرجات الأداة._")
            lines.append("")

        if raw_output.strip():
            lines.append("## Raw Output")
            lines.append("```")
            lines.append(raw_output.strip()[:6000])
            lines.append("```")

        content = "\n".join(lines)
        p1 = ctx.workspace.write_file(ctx.target, "analysis", "tls_audit.txt", content, ctx.session_id)
        result.output_files["tls_audit.txt"] = str(p1)

        p2 = ctx.workspace.write_file(
            ctx.target, "analysis", "tls_audit_findings.json",
            json.dumps(issues, indent=2, ensure_ascii=False), ctx.session_id,
        )
        result.output_files["tls_audit_findings.json"] = str(p2)

        # ── Findings (كلها candidates) ──────────────────────────────────────
        for it in issues:
            self._add_finding(
                result,
                title=f"TLS Issue: {it['kind']}",
                evidence=it["detail"],
                severity=it["level"],
                vuln_type="tls_misconfiguration",
                recommendation=self._recommendation(it["kind"]),
            )

        if not issues:
            self._add_finding(
                result,
                title="TLS Configuration: No Explicit Issues Reported",
                evidence=f"{result.tool_used} reported no weak protocols, ciphers, or vulnerabilities "
                         f"for {host}:{port}.",
                severity="Info",
                vuln_type="tls_audit",
                recommendation="Maintain current TLS configuration and keep the service patched.",
            )

        result.raw_output["tls_audit"] = content[:5000]
        return result

    # ── internals ───────────────────────────────────────────────────────────

    @staticmethod
    def _first_available(ctx: SkillContext, names: List[str]) -> Optional[str]:
        for n in names:
            if ctx.tool_manager.is_available(n):
                return n
        return None

    def _detect_tls_ports(self, ctx: SkillContext) -> List[int]:
        ports: List[int] = []
        for skill_name in ("port_scan", "masscan"):
            state = ctx.state_files.get(skill_name, {})
            if not isinstance(state, dict):
                continue
            for fname in ("nmap_services.txt", "nmap_open_ports.txt"):
                path = state.get(fname, "")
                if not path or not Path(path).exists():
                    continue
                for ln in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                    low = ln.lower()
                    if not any(k in low for k in ("https", "ssl", "tls", "443/tcp", "8443/tcp")):
                        continue
                    m = re.search(r"(\d{1,5})/tcp", ln)
                    if m:
                        p = int(m.group(1))
                        if p not in ports:
                            ports.append(p)
        return ports or [443]

    def _parse_testssl(self, raw: str) -> Tuple[List[Dict[str, str]], List[str]]:
        issues: List[Dict[str, str]] = []
        cert: List[str] = []
        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            m = _PROTO_LINE_RE.match(s)
            if m:
                level = _protocol_level(m.group(1))
                if level and _is_enabled(m.group(2)):
                    issues.append({"kind": f"Obsolete protocol {m.group(1).strip()}",
                                   "level": level, "detail": s})
                continue

            if "vulnerable" in low and "not vulnerable" not in low:
                issues.append({"kind": "TLS Vulnerability", "level": "HIGH", "detail": s})
            elif any(mk in low for mk in _WEAK_CIPHER_MARKERS) and \
                    any(k in low for k in ("offered", "accepted", "preferred")):
                issues.append({"kind": "Weak TLS cipher", "level": "MEDIUM", "detail": s})

            if low.startswith(("subject:", "issuer:", "not valid", "certificate validity",
                               "common name", "alt names", "signature algorithm")):
                cert.append(s[:300])
        return self._dedup(issues), cert[:12]

    def _parse_sslscan(self, raw: str) -> Tuple[List[Dict[str, str]], List[str]]:
        issues: List[Dict[str, str]] = []
        cert: List[str] = []
        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            m = _PROTO_LINE_RE.match(s)
            if m:
                level = _protocol_level(m.group(1))
                if level and _is_enabled(m.group(2)):
                    issues.append({"kind": f"Obsolete protocol {m.group(1).strip()}",
                                   "level": level, "detail": s})
                continue

            if low.startswith("accepted") or "accepted" in low:
                if any(mk in low for mk in _WEAK_CIPHER_MARKERS):
                    issues.append({"kind": "Weak TLS cipher", "level": "MEDIUM", "detail": s})
                continue

            if "vulnerable" in low and "not vulnerable" not in low:
                issues.append({"kind": "TLS Vulnerability", "level": "HIGH", "detail": s})

            if low.startswith(("subject:", "issuer:", "not valid", "signature algorithm",
                               "rsa key strength", "ec key strength")):
                cert.append(s[:300])
        return self._dedup(issues), cert[:12]

    def _parse_openssl(self, raw: str) -> Tuple[List[Dict[str, str]], List[str]]:
        issues: List[Dict[str, str]] = []
        cert: List[str] = []
        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            m = re.match(r"^(?:Protocol version|Protocol)\s*:\s*(.+)$", s, re.IGNORECASE)
            if m:
                level = _protocol_level(m.group(1).strip())
                if level:
                    issues.append({"kind": f"Obsolete protocol {m.group(1).strip()}",
                                   "level": level, "detail": s})
            if "cipher" in low and any(mk in low for mk in _WEAK_CIPHER_MARKERS):
                issues.append({"kind": "Weak TLS cipher", "level": "MEDIUM", "detail": s})

            if low.startswith(("subject", "issuer", "notbefore", "notafter", "verify return code")):
                cert.append(s[:300])
        return self._dedup(issues), cert[:12]

    @staticmethod
    def _dedup(issues: List[Dict[str, str]]) -> List[Dict[str, str]]:
        seen = set()
        out: List[Dict[str, str]] = []
        for it in issues:
            key = (it["kind"], it["detail"][:80])
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    @staticmethod
    def _recommendation(kind: str) -> str:
        k = kind.lower()
        if "obsolete protocol" in k:
            return ("Disable SSLv2/SSLv3/TLS1.0/TLS1.1 and allow only TLS 1.2+ "
                    "(preferably TLS 1.3). Update clients that still depend on legacy protocols.")
        if "weak tls cipher" in k:
            return ("Disable weak ciphers (RC4, 3DES, DES, NULL, EXPORT, MD5-based) and "
                    "prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.")
        if "vulnerability" in k:
            return ("Patch the affected TLS stack/library for the reported vulnerability "
                    "(e.g. Heartbleed, CCS injection, ROBOT) and re-run the audit.")
        return "Review and harden the TLS configuration according to current baselines."

    @staticmethod
    def _add_finding(
        result: SkillResult,
        *,
        title: str,
        evidence: str,
        severity: str,
        vuln_type: str,
        recommendation: str,
    ) -> None:
        result.add_finding(
            title=title,
            evidence=evidence,
            severity=severity,
            vuln_type=vuln_type,
            recommendation=recommendation,
        )
        # Creed: outputs are raw candidate observations, never confirmed findings.
        result.findings[-1].update({"status": "candidate", "evidence_level": "E0"})


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", text or "")
