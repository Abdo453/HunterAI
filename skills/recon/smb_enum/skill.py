"""
SMB / Active Directory Enumeration Skill
========================================
يعُدّ سطع SMB/NetBIOS (توقيع SMB، إصدار SMBv1، الجلسات المجهولة، المشاركات،
المستخدمون، النطاق) باستخدام ``netexec``، مع fallback إلى ``enum4linux-ng`` ثم
``smbclient``.

القاعدة الجوهرية (Creed): كل ناتج "مرشّح" (candidate, E0) لا يُؤكَّد تلقائيًا ولا
يُدرج في التقرير النهائي إلا بعد تحكيمه في محكمة الأدلة.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from skills.base_skill import BaseSkill, SkillContext, SkillResult

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SIGNING_RE = re.compile(r"signing:\s*(True|False)", re.IGNORECASE)
_SMBV1_RE = re.compile(r"SMBv1:\s*(True|False)", re.IGNORECASE)
_SHARE_ROW_RE = re.compile(r"^\S+\s+(Disk|IPC|Print|Special)\b", re.IGNORECASE)


class SmbEnumSkill(BaseSkill):
    name = "smb_enum"
    category = "recon"
    description = "Enumerate SMB/NetBIOS/AD surface for misconfigurations"
    tools_required = ["netexec"]
    fallback_tools = ["enum4linux-ng", "smbclient"]

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="netexec")

        host = ctx.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        raw_output = ""
        issues: List[Dict[str, str]] = []          # {kind, level, detail}
        shares: List[str] = []
        users: List[str] = []
        domain_info: List[str] = []

        if ctx.tool_manager.is_available("netexec"):
            result.tool_used = "netexec"
            res = await ctx.tool_manager.execute(
                f"netexec smb {host} --shares", timeout=120
            )
            raw_output = _clean((res.stdout or "") + (res.stderr or ""))
            issues, shares, users, domain_info = self._parse_netexec(raw_output)

        elif ctx.tool_manager.is_available("enum4linux-ng"):
            result.tool_used = "enum4linux-ng"
            res = await ctx.tool_manager.execute(f"enum4linux-ng -A {host}", timeout=150)
            raw_output = _clean((res.stdout or "") + (res.stderr or ""))
            issues, shares, users, domain_info = self._parse_enum4linux(raw_output)

        elif ctx.tool_manager.is_available("smbclient"):
            result.tool_used = "smbclient"
            res = await ctx.tool_manager.execute(f"smbclient -N -L //{host}", timeout=45)
            raw_output = _clean((res.stdout or "") + (res.stderr or ""))
            issues, shares, users, domain_info = self._parse_smbclient(raw_output)

        else:
            result.errors.append("No SMB enumeration tool available (netexec/enum4linux-ng/smbclient)")
            result.success = False
            return result

        # ── التقرير النصي ───────────────────────────────────────────────────
        lines: List[str] = [f"# SMB / AD Enumeration — {host}", ""]
        lines.append(f"- **Tool used:** `{result.tool_used}`")
        lines.append(f"- **Issues found:** {len(issues)}")
        lines.append(f"- **Shares discovered:** {len(shares)}")
        lines.append(f"- **Users discovered:** {len(users)}")
        lines.append("")

        if domain_info:
            lines.append("## Domain / Host Information")
            lines.extend(f"- {d}" for d in domain_info[:20])
            lines.append("")

        if shares:
            lines.append("## Shares")
            lines.extend(f"- `{s}`" for s in shares[:50])
            lines.append("")

        if users:
            lines.append("## Users")
            lines.extend(f"- `{u}`" for u in users[:50])
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
            lines.append("_لم تُرصد مشاكل SMB صريحة في مخرجات الأداة._")
            lines.append("")

        if raw_output.strip():
            lines.append("## Raw Output")
            lines.append("```")
            lines.append(raw_output.strip()[:6000])
            lines.append("```")

        content = "\n".join(lines)
        p1 = ctx.workspace.write_file(ctx.target, "recon", "smb_enum.txt", content, ctx.session_id)
        result.output_files["smb_enum.txt"] = str(p1)

        payload = {"issues": issues, "shares": shares, "users": users, "domain_info": domain_info}
        p2 = ctx.workspace.write_file(
            ctx.target, "recon", "smb_enum_findings.json",
            json.dumps(payload, indent=2, ensure_ascii=False), ctx.session_id,
        )
        result.output_files["smb_enum_findings.json"] = str(p2)

        # ── Findings (كلها candidates) ──────────────────────────────────────
        for it in issues:
            self._add_finding(
                result,
                title=f"SMB Issue: {it['kind']}",
                evidence=it["detail"],
                severity=it["level"],
                vuln_type="smb_misconfiguration",
                recommendation=self._recommendation(it["kind"]),
            )

        if shares:
            self._add_finding(
                result,
                title=f"SMB Shares Enumerated ({len(shares)})",
                evidence="\n".join(shares[:30]),
                severity="Info",
                vuln_type="smb_shares",
                recommendation="Review share permissions for anonymous/guest read/write access "
                               "and remove unnecessary administrative shares from the network surface.",
            )

        if users:
            self._add_finding(
                result,
                title=f"SMB/AD Users Enumerated ({len(users)})",
                evidence="\n".join(users[:30]),
                severity="Info",
                vuln_type="smb_users",
                recommendation="Restrict anonymous user enumeration (RestrictAnonymous / "
                               "RestrictAnonymousSAM) and limit RID-cycling exposure.",
            )

        if not issues and not shares and not users:
            self._add_finding(
                result,
                title="SMB Enumeration: No Notable Exposure",
                evidence=f"{result.tool_used} returned no shares, users, or misconfigurations for {host}.",
                severity="Info",
                vuln_type="smb_enum",
                recommendation="Maintain current SMB hardening and continue monitoring.",
            )

        result.raw_output["smb_enum"] = content[:5000]
        return result

    # ── parsers ─────────────────────────────────────────────────────────────

    def _parse_netexec(self, raw: str) -> Tuple[List[Dict[str, str]], List[str], List[str], List[str]]:
        issues: List[Dict[str, str]] = []
        shares: List[str] = []
        users: List[str] = []
        domain_info: List[str] = []

        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            m = _SIGNING_RE.search(s)
            if m and m.group(1).lower() == "false":
                issues.append({"kind": "SMB signing not required",
                               "level": "HIGH",
                               "detail": s})

            m = _SMBV1_RE.search(s)
            if m and m.group(1).lower() == "true":
                issues.append({"kind": "SMBv1 enabled",
                               "level": "HIGH",
                               "detail": s})

            if "(pwn3d!)" in low:
                issues.append({"kind": "SMB authenticated administrative access",
                               "level": "HIGH", "detail": s})
            elif "[+]" in s:
                if "\\" in s or "null" in low or "anonymous" in low:
                    issues.append({"kind": "SMB null/anonymous session allowed",
                                   "level": "MEDIUM", "detail": s})
                else:
                    domain_info.append(s)

            if "[*]" in s and any(k in low for k in ("windows", "domain:", "name:", "enumerated shares")):
                domain_info.append(s)

            # صفوف المشاركات في netexec: العمود الخامس هو اسم المشاركة
            if s.upper().startswith("SMB") and "-----" not in s and "share" not in low:
                parts = s.split()
                if len(parts) >= 5:
                    cand = parts[4]
                    if cand and not cand.startswith(("[", "-")) and cand not in shares:
                        shares.append(cand)
                for admin_share in ("ADMIN$", "C$", "IPC$"):
                    if admin_share in s and admin_share not in shares:
                        shares.append(admin_share)

        # إزالة التكرارات
        shares = list(dict.fromkeys(shares))
        users = list(dict.fromkeys(users))
        return self._dedup(issues), shares, users, list(dict.fromkeys(domain_info))

    def _parse_enum4linux(self, raw: str) -> Tuple[List[Dict[str, str]], List[str], List[str], List[str]]:
        issues: List[Dict[str, str]] = []
        shares: List[str] = []
        users: List[str] = []
        domain_info: List[str] = []

        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()

            if _SIGNING_RE.search(s) and "false" in low:
                issues.append({"kind": "SMB signing not required", "level": "HIGH", "detail": s})
            if "smbv1" in low and ("true" in low or "enabled" in low):
                issues.append({"kind": "SMBv1 enabled", "level": "HIGH", "detail": s})
            if "null session" in low and "allowed" in low:
                issues.append({"kind": "SMB null/anonymous session allowed",
                               "level": "MEDIUM", "detail": s})

            if _SHARE_ROW_RE.match(s):
                parts = s.split()
                name = parts[0]
                if name not in shares and not name.lower().startswith(("sharename", "----")):
                    shares.append(name)

            if low.startswith("[+]"):
                body = s[3:].strip()
                bl = body.lower()
                if bl.startswith(("domain:", "domain sid", "fqdn", "host", "os:", "os version")):
                    domain_info.append(body)
                elif bl.startswith(("user:", "username", "user '")):
                    users.append(body)
                elif "share" in bl:
                    m = re.search(r"['\"]([^'\"]+)['\"]", body)
                    if m and m.group(1) not in shares:
                        shares.append(m.group(1))
                    else:
                        domain_info.append(body)
                else:
                    domain_info.append(body)

        shares = list(dict.fromkeys(shares))
        users = list(dict.fromkeys(users))
        return self._dedup(issues), shares, users, list(dict.fromkeys(domain_info))

    def _parse_smbclient(self, raw: str) -> Tuple[List[Dict[str, str]], List[str], List[str], List[str]]:
        issues: List[Dict[str, str]] = []
        shares: List[str] = []
        users: List[str] = []
        domain_info: List[str] = []

        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            if _SHARE_ROW_RE.match(s):
                name = s.split()[0]
                if name not in shares and not name.lower().startswith(("sharename", "----")):
                    shares.append(name)
            elif "session setup failed" in s.lower() or "nt_status" in s.lower():
                issues.append({"kind": "SMB anonymous listing denied", "level": "LOW", "detail": s})

        return self._dedup(issues), shares, users, domain_info

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
        if "signing" in k:
            return ("Require SMB signing (Microsoft network server/client: Digitally sign "
                    "communications = Required) to prevent NTLM relay attacks.")
        if "smbv1" in k:
            return ("Disable SMBv1 entirely (it is deprecated and vulnerable); "
                    "remove the SMBv1 feature and rely on SMBv2/v3.")
        if "null" in k or "anonymous" in k:
            return ("Block anonymous/null SMB sessions and disable insecure guest logons "
                    "(RestrictAnonymous, guest access disabled).")
        if "administrative access" in k:
            return ("Rotate the exposed credentials immediately and restrict administrative "
                    "access to SMB services.")
        return "Review and harden the SMB service configuration."

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
