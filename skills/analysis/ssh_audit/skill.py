"""
SSH Audit Skill
===============
يدقّق إعدادات خادم SSH (KEX، التشفير، MACs، مفاتيح المضيف) بحثًا عن خوارزميات
ضعيفة/مهجورة باستخدام ``ssh-audit``، مع fallback عبر ``nmap`` (NSE) أو لقطة
بانر خام عبر ``nc`` عندما لا تتوفر ``ssh-audit``.

القاعدة الجوهرية (Creed): كل ناتج هو "مرشّح" (candidate, E0) — لا يُؤكَّد تلقائيًا
ولا يُدرج في التقرير النهائي إلا بعد تحكيمه في محكمة الأدلة.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from skills.base_skill import BaseSkill, SkillContext, SkillResult

# تصنيف شدة الخوارزميات الضعيفة/المهجورة بناءً على النص المرافق من ssh-audit
_HIGH_MARKERS = (
    "fail", "insecure", "removed", "broken", "untrusted",
    "arcfour", "ssh-dss", "diffie-hellman-group1", "1024",
)
_MEDIUM_MARKERS = (
    "warn", "deprecated", "weak", "sha1", "3des", "cbc", "md5", "blowfish",
    "cast128", "ssh-rsa", "ripemd", "umac-64",
)

_TXT_LINE_RE = re.compile(
    r"^\s*\((?P<section>[a-z0-9_]+)\)\s+(?P<algo>\S+)\s+--\s+"
    r"\[(?P<level>fail|warn|info)\]\s*(?P<msg>.*)$",
    re.IGNORECASE,
)
_TXT_LINE_BARE_RE = re.compile(
    r"^\s*\((?P<section>[a-z0-9_]+)\)\s+(?P<algo>\S+)\s+--\s*(?P<msg>.*)$",
    re.IGNORECASE,
)


class SshAuditSkill(BaseSkill):
    name = "ssh_audit"
    category = "analysis"
    description = "Audit SSH server algorithms and configuration with ssh-audit"
    tools_required = ["ssh-audit"]
    fallback_tools = ["nmap", "nc"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="ssh-audit")

        host = ctx.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ports = self._detect_ssh_ports(ctx)
        port = ports[0]

        raw_output = ""
        banner = ""
        weak: List[Dict[str, str]] = []          # {section, algorithm, level, message}
        banner_notes: List[str] = []

        if ctx.tool_manager.is_available("ssh-audit"):
            result.tool_used = "ssh-audit"
            res = await ctx.tool_manager.execute(
                f"ssh-audit -j -p {port} {host}", timeout=60
            )
            raw_output = (res.stdout or "") + (res.stderr or "")
            parsed = self._parse_ssh_audit(raw_output)
            if parsed is not None:
                banner, banner_notes, weak = parsed
            else:
                banner_notes.append("ssh-audit JSON could not be parsed; see raw output.")

        elif ctx.tool_manager.is_available("nmap"):
            result.tool_used = "nmap"
            res = await ctx.tool_manager.execute(
                f"nmap -Pn -p {port} --script ssh2-enum-algos,ssh-hostkey {host}", timeout=60
            )
            raw_output = (res.stdout or "") + (res.stderr or "")
            weak = self._parse_nmap_algos(raw_output)

        elif ctx.tool_manager.is_available("nc"):
            result.tool_used = "nc"
            res = await ctx.tool_manager.execute(
                f"nc -w 5 {host} {port} < /dev/null", timeout=15
            )
            banner = (res.stdout or "") + (res.stderr or "")
            banner_notes.append(
                "Only SSH banner captured (ssh-audit and nmap unavailable); "
                "algorithm audit is incomplete — treat as negative space."
            )
        else:
            result.errors.append("No SSH auditing tool available (ssh-audit/nmap/nc)")
            result.success = False
            return result

        # ── بناء التقرير النصي ──────────────────────────────────────────────
        lines: List[str] = [f"# SSH Audit — {host}:{port}", ""]
        lines.append(f"- **Tool used:** `{result.tool_used}`")
        if banner:
            lines.append(f"- **Banner:** `{banner.strip()[:200]}`")
        lines.append(f"- **Weak/deprecated algorithm notes:** {len(weak)}")
        lines.append("")

        if banner_notes:
            lines.append("## Notes")
            for n in banner_notes:
                lines.append(f"- {n}")
            lines.append("")

        if weak:
            lines.append("## Weak / Deprecated Algorithms")
            lines.append("| Section | Algorithm | Level | Note |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for w in weak:
                note = w["message"].replace("|", "/").strip()
                lines.append(f"| `{w['section']}` | `{w['algorithm']}` | {w['level']} | {note} |")
            lines.append("")
        else:
            lines.append("## Weak / Deprecated Algorithms")
            lines.append("_لا توجد خوارزميات ضعيفة/مهجورة صريحة في مخرجات الأداة._")
            lines.append("")

        if raw_output.strip():
            lines.append("## Raw Output")
            lines.append("```")
            lines.append(raw_output.strip()[:6000])
            lines.append("```")

        content = "\n".join(lines)
        p1 = ctx.workspace.write_file(ctx.target, "analysis", "ssh_audit.txt", content, ctx.session_id)
        result.output_files["ssh_audit.txt"] = str(p1)

        findings_payload: List[Dict[str, Any]] = []
        for w in weak:
            findings_payload.append({
                "section": w["section"],
                "algorithm": w["algorithm"],
                "level": w["level"],
                "message": w["message"],
            })
        p2 = ctx.workspace.write_file(
            ctx.target, "analysis", "ssh_audit_findings.json",
            json.dumps(findings_payload, indent=2, ensure_ascii=False), ctx.session_id,
        )
        result.output_files["ssh_audit_findings.json"] = str(p2)

        # ── Findings (كلها candidates — لا تأكيد تلقائي) ────────────────────
        if banner and banner.strip():
            self._add_finding(
                result,
                title="SSH Service Banner Disclosure",
                evidence=banner.strip()[:300],
                severity="Info",
                vuln_type="ssh_banner",
                recommendation=(
                    "Banner exposes SSH implementation/version. Consider limiting banner detail "
                    "and ensure the server runs a supported, patched release."
                ),
            )

        for w in weak:
            algo = w["algorithm"]
            self._add_finding(
                result,
                title=f"Weak SSH Algorithm: {w['level']} — {algo}",
                evidence=f"({w['section']}) {algo} -- [{w['level']}] {w['message']}",
                severity=w["level"],
                vuln_type="ssh_weak_algorithm",
                recommendation=self._remediation(w["section"]),
            )

        if not weak and result.tool_used == "ssh-audit":
            self._add_finding(
                result,
                title="SSH Algorithm Configuration: No Weak Algorithms Reported",
                evidence=f"ssh-audit reported no fail/warn algorithm notes for {host}:{port}.",
                severity="Info",
                vuln_type="ssh_audit",
                recommendation="Maintain current SSH configuration and keep the server patched.",
            )

        result.raw_output["ssh_audit"] = content[:5000]
        return result

    # ── internals ───────────────────────────────────────────────────────────

    def _detect_ssh_ports(self, ctx: SkillContext) -> List[int]:
        ports: List[int] = []
        for skill_name in ("port_scan", "masscan"):
            state = ctx.state_files.get(skill_name, {})
            if not isinstance(state, dict):
                continue
            for fname in ("nmap_services.txt", "nmap_open_ports.txt", "masscan.txt"):
                path = state.get(fname, "")
                if not path or not Path(path).exists():
                    continue
                for ln in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                    if "ssh" not in ln.lower() and "22/tcp" not in ln:
                        continue
                    m = re.search(r"(\d{1,5})/tcp", ln)
                    if m:
                        p = int(m.group(1))
                        if p not in ports:
                            ports.append(p)
        return ports or [22]

    def _parse_ssh_audit(self, raw: str) -> Optional[Tuple[str, List[str], List[Dict[str, str]]]]:
        """يفك مخرجات ssh-audit (JSON أولاً ثم نص) إلى (banner, notes, weak)."""
        data = _extract_json(raw)
        if isinstance(data, dict):
            return self._parse_json_payload(data)

        weak = self._parse_text(raw)
        if not weak and not raw.strip():
            return None
        banner = ""
        m = re.search(r"^#?\s*(SSH-2\.0-\S+.*)$", raw, re.MULTILINE)
        if m:
            banner = m.group(1).strip()
        return banner, [], weak

    def _parse_json_payload(self, data: Dict[str, Any]) -> Tuple[str, List[str], List[Dict[str, str]]]:
        banner = ""
        b = data.get("banner")
        if isinstance(b, dict):
            raw = b.get("raw") or ""
            sw = b.get("software") or ""
            banner = raw or sw
        elif isinstance(b, str):
            banner = b

        notes: List[str] = []
        weak: List[Dict[str, str]] = []
        for section in ("kex", "key", "enc", "mac", "compression"):
            items = data.get(section)
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                algo = str(item.get("algorithm") or item.get("name") or "").strip()
                if not algo:
                    continue
                note_text = _notes_to_text(item.get("notes"))
                level = _classify(algo, note_text)
                if level is None:
                    continue
                weak.append({
                    "section": section,
                    "algorithm": algo,
                    "level": level,
                    "message": note_text or "flagged by ssh-audit",
                })
        return banner, notes, weak

    def _parse_text(self, raw: str) -> List[Dict[str, str]]:
        weak: List[Dict[str, str]] = []
        for line in raw.splitlines():
            m = _TXT_LINE_RE.match(line)
            if m:
                lv = m.group("level").lower()
                if lv == "info":
                    # ملاحظات [info] وصفية وليست ضعفًا — تُتجاهل لتفادي الضجيج.
                    continue
                weak.append({
                    "section": m.group("section").lower(),
                    "algorithm": m.group("algo"),
                    "level": _severity_from_level(lv),
                    "message": m.group("msg").strip(),
                })
                continue
            m = _TXT_LINE_BARE_RE.match(line)
            if m:
                msg = m.group("msg").strip()
                level = _classify(m.group("algo"), msg)
                if level is None:
                    continue
                weak.append({
                    "section": m.group("section").lower(),
                    "algorithm": m.group("algo"),
                    "level": level,
                    "message": msg,
                })
        return weak

    def _parse_nmap_algos(self, raw: str) -> List[Dict[str, str]]:
        """استخراج خوارزميات ضعيفة من مخرجات NSE ssh2-enum-algos."""
        weak: List[Dict[str, str]] = []
        section = "kex"
        for line in raw.splitlines():
            s = line.strip()
            if s.lower().startswith(("kex_algorithms", "kex algorithms")):
                section = "kex"
                continue
            if s.lower().startswith(("encryption_algorithms", "encryption algorithms")):
                section = "enc"
                continue
            if s.lower().startswith(("mac_algorithms", "mac algorithms")):
                section = "mac"
                continue
            if s.lower().startswith(("server_host_key_algorithms", "server host key algorithms")):
                section = "key"
                continue
            if not s or "_" not in s and "-" not in s:
                continue
            algo = s.split("(")[0].strip()
            if not algo or "/" in algo:
                continue
            level = _classify(algo, s)
            if level is None:
                continue
            weak.append({
                "section": section,
                "algorithm": algo,
                "level": level,
                "message": "flagged by nmap ssh2-enum-algos",
            })
        return weak

    @staticmethod
    def _remediation(section: str) -> str:
        mapping = {
            "kex": "Disable weak key-exchange algorithms (e.g. diffie-hellman-group1-sha1, "
                   "diffie-hellman-group14-sha1) and prefer curve25519-sha256 or ecdh-sha2-*.",
            "key": "Replace weak host-key algorithms (ssh-dss, ssh-rsa with SHA-1) with "
                   "ssh-ed25519 or rsa-sha2-* (2048-bit+ keys).",
            "enc": "Disable CBC/3DES/RC4 ciphers and prefer AEAD ciphers such as "
                   "chacha20-poly1305@openssh.com or aes*-gcm@openssh.com.",
            "mac": "Disable MD5/SHA-1 based MACs (hmac-md5, umac-64) and prefer "
                   "hmac-sha2-256-etm@openssh.com or better.",
            "compression": "Disable zlib compression to avoid compression-oracle issues; "
                           "prefer none unless operationally required.",
        }
        return mapping.get(
            section,
            "Review and harden SSH algorithm configuration in accordance with current baselines.",
        )

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


# ── module-level helpers ─────────────────────────────────────────────────────


def _extract_json(raw: str) -> Optional[Any]:
    """يحاول استخراج أول كائن JSON من مخرجات ssh-audit (قد تسبقه أسطر banner)."""
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            return None
    return None


def _notes_to_text(notes: Any) -> str:
    """تطبيع حقل notes من JSON ssh-audit (dict/list/str) إلى نص واحد."""
    texts: List[str] = []
    if isinstance(notes, dict):
        for k, v in notes.items():
            if isinstance(v, str) and v.strip():
                texts.append(v.strip())
            elif isinstance(v, (list, tuple)):
                texts.extend(str(x) for x in v if str(x).strip())
            elif v:
                texts.append(str(k))
    elif isinstance(notes, (list, tuple)):
        texts.extend(str(x) for x in notes if str(x).strip())
    elif isinstance(notes, str) and notes.strip():
        texts.append(notes.strip())
    return "; ".join(texts)


def _severity_from_level(level: str) -> str:
    lv = (level or "").lower()
    if lv == "fail":
        return "HIGH"
    if lv == "warn":
        return "MEDIUM"
    return "LOW"


def _classify(algo: str, note: str) -> Optional[str]:
    """يصنّف خطورة خوارزمية SSH بناءً على اسمها والنص المرافق.

    يعيد ``None`` عندما لا يوجد دليل على ضعف، حتى لا تُدرج ملاحظات وصفية
    (مثل "available since OpenSSH x.y") كخوارزميات ضعيفة.
    """
    combined = f"{algo} {note}".lower()
    if any(k in combined for k in _HIGH_MARKERS):
        return "HIGH"
    if any(k in combined for k in _MEDIUM_MARKERS):
        return "MEDIUM"
    return None
