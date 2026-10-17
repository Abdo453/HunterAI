"""
Bug Bounty Master Skill (Program-Level Pipeline)
================================================
مهارة مستوى البرنامج (ليست مستوى بارامتر) — تنفّذ خط الملك كامل:

  Phase 0 — Scope Gate      : الهدف يجب أن يكون داخل النطاق المصرح به
                              (إن قُدّم in_scope) — خلاف ذلك لا يكمل نهائياً
  Phase 1 — Passive Recon   : crt.sh CT logs (شبكة على target-td ثالث معروف
                              للاختراق من السيرفرات) — passive فقط
  Phase 2 — Asset Probing   : GET لكل أصل (حراك قراءة فقط passive_read)
  Phase 3 — Active Testing  : فقط مع authorized=True — يوجّه البارامترات
                              المُسجلة عبر SkillRegistry.run_best() — إثبات
                              تفاضلي (Proof-of-Execution) لا Reflection
  Phase 4 — Report          : تقرير Bug Bounty Markdown + Provenance المقولات
                              من مستودعات GitHub (PayloadsAllTheThings / nahamsec)

Contract: BaseSkill.run(target_url, param_name=...) — لكن هذه مهارة برنامجية،
          فلا تُشارك في التوجيه التلقائي للبارامترات (can_handle → 0.0).
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

# ── ثوابت التشغيل الحذرة ──────────────────────────────────────────────────────
MAX_RECON_SUBDOMAINS = 50     # حد أعلى للنطاقات من crt.sh قبل الترخيص
DEFAULT_PROBE_LIMIT = 8       # حد أعلى للأصول المُفحوصة في طور proactively
RECON_TIMEOUT = 10.0          # مهلة short للـ crt.sh (خدمة عامة)

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _max_severity(sev_list: Sequence[str]) -> str:
    for s in _SEVERITY_ORDER:
        if s in sev_list:
            return s
    return "Info"


class BugBountyMasterSkill(BaseSkill):
    """مهارة bug bounty كاملة على مستوى البرنامج — سماء المشروع"""

    name = "bug_bounty_master_skill"
    vuln_type = "bug_bounty_pipeline"
    cwe = "CWE-000"        # مستوى برنامج — لا مخترقة بتوقيع واحد
    owasp_top10 = "A00:2021"
    default_severity = "Info"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    # ────────────────────────────────────────────────────────────────────────
    # Entry point
    # ────────────────────────────────────────────────────────────────────────
    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        in_scope: Optional[List[str]] = kwargs.get("in_scope")
        authorized: bool = bool(kwargs.get("authorized", False))
        transport = kwargs.get("transport")
        probe_limit: int = int(kwargs.get("probe_limit", DEFAULT_PROBE_LIMIT))
        param_candidates: List[Tuple[str, str]] = list(kwargs.get("param_candidates") or [])

        parsed = urlparse(target_url)
        domain = (parsed.hostname or "").lower()
        if not domain:
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title=f"Invalid target URL: {target_url!r}",
                severity=self.default_severity,
                endpoint=target_url, param_name="", evidence="")

        logs: List[str] = []

        # ── Phase 0 — Scope Gate ─────────────────────────────────────────
        if in_scope and not self._scope_allows(domain, in_scope):
            logs.append(f"[scope] target '{domain}' NOT in scope {in_scope} — pipeline refused")
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title="Target outside declared scope — pipeline refused",
                severity=self.default_severity,
                endpoint=target_url, param_name="",
                evidence="Scope violation: refusal (no request issued)",
                logs=logs,
                extra={"phase_reached": "scope", "scope_ok": False})

        logs.append(f"[scope] target '{domain}' accepted (in_scope={in_scope or 'not provided (operator responsibility)'})")

        client_kwargs: Dict[str, Any] = {"timeout": min(self.timeout, RECON_TIMEOUT),
                                         "follow_redirects": False}
        if transport is not None:
            client_kwargs["transport"] = transport
        elif self.proxy:
            client_kwargs["proxies"] = self.proxy

        subdomains: List[str] = []
        assets: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(**client_kwargs) as client:

            # ── Phase 1 — Passive Recon (crt.sh) ─────────────────────────
            subdomains = await self._crtsh_subdomains(client, domain)
            logs.append(f"[recon] crt.sh yielded {len(subdomains)} subdomains for {domain}")

            # ── Phase 2 — Asset Probing (passive_read فقط) ───────────────
            targets = [(target_url, domain)]
            for s in subdomains[: max(0, probe_limit - 1)]:
                targets.append((f"http://{s}", s))
            for url_, sub in targets[:probe_limit]:
                assets.append(await self._probe_asset(client, url_, sub))
            live = [a for a in assets if a.get("reachable")]
            logs.append(f"[probe] {len(live)}/{len(assets)} assets reachable")

            # ── Phase 3 — Active Testing (authorized فقط) ────────────────
            if authorized and param_candidates:
                from agents.skills.registry import SkillRegistry
                reg = SkillRegistry.instance()
                for cand_url, cand_param in param_candidates:
                    result = await reg.run_best(cand_url, cand_param)
                    if result is None:
                        continue
                    findings.append(self._finding_from(result))
                    logs.append(f"[active] {reg.best_for(cand_param).name if reg.best_for(cand_param) else '?'}"
                                f" on {cand_param} → verified={result.verified}")
            elif param_candidates and not authorized:
                logs.append("[active] SKIPPED — authorized=False (passive-only mode)")

            # ── Phase 4 — Report ─────────────────────────────────────────
            report_md = self._build_report(target_url, domain, in_scope, authorized,
                                           subdomains, assets, findings)

        verified = any(f["verified"] for f in findings)
        severities = [f["severity"] for f in findings if f["verified"]]
        confidence = max((f["confidence"] for f in findings if f["verified"]), default=0.0)

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Bug Bounty pipeline — {domain}: "
                  f"{len(live)} live assets, {len([f for f in findings if f['verified']])} verified findings",
            severity=_max_severity(severities) if verified else self.default_severity,
            endpoint=target_url,
            param_name=param_name or "",
            evidence="; ".join(f["title"] for f in findings if f["verified"])
                     or f"recon={len(subdomains)} subs / live={len(live)} assets / no verified findings",
            remediation=("", "Apply per-finding remediation sections in report")[bool(findings)],
            confidence=confidence,
            tool=self.name,
            evidence_sources=["crt.sh/CT-logs", "AssetProbe/passive_read"] + list(
                {f.get("tool", "") for f in findings if f["verified"]}),
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            logs=logs,
            extra={
                "phase_reached": "report",
                "scope_ok": True,
                "subdomains": subdomains,
                "assets": assets,
                "findings": findings,
                "report_md": report_md,
            },
        )

    # ────────────────────────────────────────────────────────────────────────
    # Phase helpers
    # ────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _scope_allows(domain: str, in_scope: List[str]) -> bool:
        """مطابقة نطاقات مسموحة: exact / *.suffix / bare host"""
        for pat in in_scope:
            p = str(pat).strip().lower().lstrip("*").lstrip(".")
            if not p:
                continue
            if domain == p or domain.endswith("." + p):
                return True
        return False

    async def _crtsh_subdomains(self, client: httpx.AsyncClient, domain: str) -> List[str]:
        """crt.sh Certificate-Transparency — مصدر استكشاف سلبي"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = await client.get(url)
            data = resp.json()
        except Exception:
            return []
        subs: set = set()
        if isinstance(data, list):
            for item in data:
                for raw in str(item.get("name_value", "")).split("\n"):
                    s = raw.strip().lower().lstrip("*").lstrip(".")
                    if s and s.endswith(domain) and s != domain:
                        subs.add(s)
        return sorted(subs)[:MAX_RECON_SUBDOMAINS]

    async def _probe_asset(self, client: httpx.AsyncClient, url: str, sub: str) -> Dict[str, Any]:
        """قراءة GET واحدة لكل أصل — passive_read، بلا حقن ولا تدمير"""
        try:
            resp = await client.get(url)
            server = resp.headers.get("server", "")
            return {"asset": sub, "url": url, "status": resp.status_code,
                    "server": server, "reachable": True}
        except Exception:
            return {"asset": sub, "url": url, "status": None,
                    "server": "", "reachable": False}

    @staticmethod
    def _finding_from(result: SkillResult) -> Dict[str, Any]:
        return {
            "verified": bool(result.verified),
            "type": result.vuln_type,
            "title": result.title,
            "severity": result.severity,
            "endpoint": result.endpoint,
            "param": result.param_name,
            "evidence": result.evidence,
            "payload": result.payload_used,
            "tool": result.tool,
            "confidence": float(result.confidence or 0.0),
        }

    def _build_report(self, target_url: str, domain: str, in_scope: Optional[List[str]],
                      authorized: bool, subdomains: List[str],
                      assets: List[Dict[str, Any]],
                      findings: List[Dict[str, Any]]) -> str:
        # منهجية + المصادر من مستودعات GitHub
        from core.bug_bounty.resources import get_github_resources
        ghr = get_github_resources()
        recon_tools = ghr.names_for("bug_bounty_recon_checklist")
        prov = ghr.provenance("bug_bounty_recon_checklist")

        mode = "authorized (active)" if authorized else "passive-only"
        lines: List[str] = [
            f"# Bug Bounty Report — {domain}",
            f"**Target:** {target_url}  ",
            f"**Mode:** {mode}  ",
            f"**Date:** {datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}  ",
            "**Evidence standard:** differential Proof-of-Execution — "
            "Reflection-only or WAF-block results are NOT counted as findings.",
            "",
            "## 1. Scope",
            "- " + (", ".join(in_scope) if in_scope else
                    "_not provided — operator responsibility before submission_"),
            "",
            "## 2. Recon (passive — crt.sh CT logs)",
        ]
        lines += [f"- `{s}`" for s in subdomains] if subdomains else ["- (no subdomains discovered)"]
        lines += [
            "",
            f"## 3. Live Assets ({len([a for a in assets if a.get('reachable')])}/{len(assets)})",
            "| asset | status | server |",
            "|---|---|---|",
        ]
        for a in assets:
            st = a["status"] if a["status"] is not None else "unreachable"
            lines.append(f"| {a['asset']} | {st} | {a['server'] or '—'} |")
        lines += [
            "",
            "## 4. Findings",
        ]
        if findings:
            lines += ["| # | verified | type | severity | endpoint | param | title |",
                      "|---|---|---|---|---|---|---|"]
            for i, f in enumerate(findings, 1):
                lines.append(
                    f"| {i} | {'✅' if f['verified'] else '❌'} | {f['type']} | "
                    f"{f['severity']} | {f['endpoint']} | {f['param'] or '—'} | {f['title']} |")
            lines += ["", "### Evidence details"]
            for f in findings:
                if f["verified"]:
                    lines += [f"#### {f['title']}",
                              f"- endpoint: {f['endpoint']}",
                              f"- param: {f['param']}",
                              f"- payload: `{f['payload'] or '—'}`",
                              f"- evidence: {f['evidence']}",
                              f"- confidence: {f['confidence']}", ""]
        else:
            lines.append("- No findings in this run (passive mode records observations only).")
        lines += [
            "",
            "## 5. Methodology (GitHub sources)",
            f"- Source: `{prov['source_git']}` — {prov['url']}",
            "-", "Passive tools checklist: " + ", ".join(map(str, recon_tools[:8])),
            "",
            "---",
            "_Generated by HunterAI BugBountyMasterSkill — court-grade evidence only._",
        ]
        return "\n".join(lines)

    # ────────────────────────────────────────────────────────────────────────
    # Explicitly program-level: never hijacks param routing
    # ────────────────────────────────────────────────────────────────────────
    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        return 0.0
