"""
BurpTrafficAnalyzerSkill — AI-powered Burp Suite traffic analysis.

Reads live Burp proxy traffic from the local BurpGateway (127.0.0.1:8085)
or falls back to synthetic traffic when Burp is unavailable.
Analyzes requests for IDOR, SSRF, JWT issues, Mass Assignment, LFI, XSS/SQLi.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

from skills.base_skill import BaseSkill, SkillContext, SkillResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerability pattern scoring helpers
# ---------------------------------------------------------------------------

_IDOR_PARAMS = re.compile(r"^(id|uid|user_id|account_id|profile_id|order_id|item_id)$", re.I)
_REDIRECT_PARAMS = re.compile(r"^(url|redirect|redirect_url|next|return|return_url|dest|goto)$", re.I)
_FILE_PARAMS = re.compile(r"^(file|path|filename|dir|folder|include|page|template)$", re.I)
_SEARCH_PARAMS = re.compile(r"^(q|query|search|s|keyword|term|input|filter)$", re.I)
_PRICE_PARAMS = re.compile(r"^(price|amount|total|cost|fee|discount|qty|quantity)$", re.I)


class BurpTrafficAnalyzerSkill(BaseSkill):
    """Reads Burp proxy traffic and identifies likely vulnerability classes."""

    name = "burp_traffic_analyzer"
    category = "burp"
    description = (
        "AI-powered Burp Suite traffic analysis -- reads live Burp proxy traffic "
        "and routes to vuln skills"
    )
    timeout_seconds = 120.0
    max_retries = 1

    # ------------------------------------------------------------------
    # Main entry-point
    # ------------------------------------------------------------------

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=False, tool_used=self.name)

        burp_port: int = int(ctx.extra.get("burp_port", 8085))
        traffic_limit: int = int(ctx.extra.get("traffic_limit", 50))

        # 1. Fetch traffic -----------------------------------------------
        traffic: List[Dict[str, Any]] = []
        burp_live = False
        if httpx is not None:
            try:
                async with httpx.AsyncClient(timeout=5.0, trust_env=False, verify=False) as client:
                    resp = await client.get(
                        f"http://127.0.0.1:{burp_port}/api/traffic",
                        params={"limit": traffic_limit},
                    )
                    resp.raise_for_status()
                    traffic = resp.json().get("requests", [])
                    burp_live = True
                    logger.info("[burp_traffic_analyzer] Fetched %d live requests from Burp", len(traffic))
            except Exception as exc:
                logger.info("[burp_traffic_analyzer] Burp unavailable (%s) -- using fallback traffic", exc)
                traffic = self._fallback_traffic(ctx.target)
        else:
            logger.info("[burp_traffic_analyzer] httpx not available -- using fallback traffic")
            traffic = self._fallback_traffic(ctx.target)

        # 2. Analyse each request ----------------------------------------
        analyses: List[Dict[str, Any]] = [self._analyze_request(r) for r in traffic]

        # 3. Sort by risk & group by vuln type ---------------------------
        analyses.sort(key=lambda x: x["risk_score"], reverse=True)
        vuln_groups: Dict[str, List[Dict[str, Any]]] = {}
        high_risk: List[Dict[str, Any]] = []
        for a in analyses:
            for vuln in a["likely_vulns"]:
                vuln_groups.setdefault(vuln, []).append(a)
            if a["risk_score"] >= 7.0:
                high_risk.append(a)
                result.add_finding(
                    title=f"[{a['likely_vulns'][0] if a['likely_vulns'] else 'Suspicious'}] High-risk request",
                    evidence=f"URL: {a['url']} | Method: {a['method']} | Score: {a['risk_score']}",
                    severity="High" if a["risk_score"] >= 8.0 else "Medium",
                    vuln_type=a["likely_vulns"][0] if a["likely_vulns"] else "Unknown",
                    url=a["url"],
                    recommendation="Review and test this endpoint for the indicated vulnerability class.",
                )

        # 4. Write output files ------------------------------------------
        findings_data = {
            "target": ctx.target,
            "burp_live": burp_live,
            "total_requests": len(traffic),
            "high_risk_count": len(high_risk),
            "analyses": analyses,
            "vuln_groups": {k: [a["url"] for a in v] for k, v in vuln_groups.items()},
        }
        findings_path = ctx.workspace.write_file(
            ctx.target, ctx.session_id, "burp_findings.json",
            json.dumps(findings_data, indent=2, ensure_ascii=False),
        )

        report_path = ctx.workspace.write_file(
            ctx.target, ctx.session_id, "burp_analysis_report.md",
            self._build_report(ctx.target, analyses, vuln_groups, burp_live),
        )

        result.output_files["burp_findings.json"] = findings_path
        result.output_files["burp_analysis_report.md"] = report_path
        result.metadata = {"high_risk_requests": high_risk}  # type: ignore[attr-defined]
        result.success = True
        return result

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _analyze_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Return structured analysis for a single request dict."""
        url: str = req.get("url", req.get("path", ""))
        method: str = req.get("method", "GET").upper()
        headers: Dict[str, str] = req.get("headers", {}) or {}
        body: Any = req.get("body", req.get("json_body", {})) or {}
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except Exception:
                body = {}

        likely_vulns: List[str] = []
        risk_score: float = 0.0

        # Parse query params
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            flat_params = {k: v[0] if v else "" for k, v in params.items()}
        except Exception:
            flat_params = {}

        # --- IDOR ---
        for k in flat_params:
            if _IDOR_PARAMS.match(k):
                likely_vulns.append("IDOR")
                risk_score = max(risk_score, 8.0)
                break

        # --- Open Redirect / SSRF ---
        for k in flat_params:
            if _REDIRECT_PARAMS.match(k):
                likely_vulns.append("SSRF/Open-Redirect")
                risk_score = max(risk_score, 7.5)
                break

        # --- JWT / Authorization ---
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header.startswith("Bearer "):
            likely_vulns.append("JWT-Analysis")
            risk_score = max(risk_score, 5.0)

        # --- Mass Assignment (JSON body with nested objects) ---
        if isinstance(body, dict) and len(body) >= 2:
            if any(isinstance(v, dict) for v in body.values()):
                likely_vulns.append("Mass-Assignment")
                risk_score = max(risk_score, 7.0)

        # --- LFI / Path Traversal ---
        for k in flat_params:
            if _FILE_PARAMS.match(k):
                likely_vulns.append("LFI/Path-Traversal")
                risk_score = max(risk_score, 7.5)
                break
        if "../" in url or "..%2F" in url.upper():
            likely_vulns.append("LFI/Path-Traversal")
            risk_score = max(risk_score, 8.5)

        # --- XSS / SQLi (search/query params) ---
        for k in flat_params:
            if _SEARCH_PARAMS.match(k):
                likely_vulns.append("XSS/SQLi")
                risk_score = max(risk_score, 6.5)
                break

        # --- Price Tampering ---
        for k in flat_params:
            if _PRICE_PARAMS.match(k):
                likely_vulns.append("Price-Tampering")
                risk_score = max(risk_score, 7.0)
                break

        if not likely_vulns:
            likely_vulns.append("Unknown")
            risk_score = max(risk_score, 1.0)

        return {
            "url": url,
            "method": method,
            "params": flat_params,
            "headers": {k: ("***" if k.lower() in {"authorization", "cookie"} else v) for k, v in headers.items()},
            "likely_vulns": list(dict.fromkeys(likely_vulns)),  # deduplicate, preserve order
            "risk_score": round(risk_score, 1),
        }

    def _fallback_traffic(self, target: str) -> List[Dict[str, Any]]:
        """Synthetic traffic for offline/hermetic execution."""
        base = target.rstrip("/")
        return [
            {"url": f"{base}/api/users?id=42", "method": "GET", "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.test"}, "body": {}},
            {"url": f"{base}/api/profile?uid=100&redirect_url=https://evil.com", "method": "GET", "headers": {}, "body": {}},
            {"url": f"{base}/api/file?path=../../etc/passwd", "method": "GET", "headers": {}, "body": {}},
            {"url": f"{base}/api/search?q=<script>alert(1)</script>", "method": "GET", "headers": {}, "body": {}},
            {"url": f"{base}/api/order", "method": "POST", "headers": {"Content-Type": "application/json"},
             "body": {"order_id": "55", "user": {"id": 1, "role": "admin"}, "price": "0.01"}},
            {"url": f"{base}/dashboard", "method": "GET", "headers": {}, "body": {}},
        ]

    def _build_report(
        self,
        target: str,
        analyses: List[Dict[str, Any]],
        vuln_groups: Dict[str, List[Dict[str, Any]]],
        burp_live: bool,
    ) -> str:
        source = "Live Burp Proxy" if burp_live else "Fallback Synthetic Traffic"
        lines = [
            f"# Burp Traffic Analysis Report",
            f"",
            f"**Target:** {target}",
            f"**Traffic Source:** {source}",
            f"**Total Requests Analyzed:** {len(analyses)}",
            f"**High-Risk Requests:** {sum(1 for a in analyses if a['risk_score'] >= 7.0)}",
            f"",
            f"## Vulnerability Group Summary",
            f"",
        ]
        for vuln, items in sorted(vuln_groups.items(), key=lambda x: -len(x[1])):
            lines.append(f"### {vuln} ({len(items)} endpoints)")
            for item in items[:5]:
                lines.append(f"- `{item['method']}` {item['url']} (risk={item['risk_score']})")
            lines.append("")

        lines += [
            "## Top 10 High-Risk Requests",
            "",
        ]
        for a in analyses[:10]:
            lines.append(
                f"- **[{a['risk_score']}]** `{a['method']}` `{a['url']}` -> {', '.join(a['likely_vulns'])}"
            )
        lines.append("")
        lines.append("*Generated by BurpTrafficAnalyzerSkill*")
        return "\n".join(lines)
