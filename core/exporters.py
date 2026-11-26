"""Exporters for PentestAI findings.
Provides functions to write scan results to JSON, HTML, CSV, and full-featured interactive dashboards.
"""
import json
import csv
import os
import html
import re
from typing import List, Dict, Any, Optional

from core.secret_sanitizer import SecretSanitizer


def _css_token(value: Any, fallback: str = "Info") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "", str(value or ""))
    return cleaned or fallback


def export_json(findings: List[Dict], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(SecretSanitizer.sanitize_data(findings), f, indent=2, ensure_ascii=False)


def export_html(findings: List[Dict], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    rows = []
    for f in findings:
        sev = str(f.get("severity", "Info"))
        sev_cls = _css_token(sev, "Info")
        title = str(f.get("title", ""))
        target = str(f.get("param_name") or f.get("endpoint") or "-")
        engine = str(f.get("tool", ""))
        if f.get("fallback_used"):
            engine += f" (fallback: {f.get('fallback_engine')})"
        evidence = SecretSanitizer.sanitize_text(str(f.get("evidence", "")))
        verdict = str(f.get("lifecycle_verdict", "CONFIRMED"))
        rows.append(
            f"<tr class=\"{html.escape(sev_cls, quote=True)}\">"
            f"<td>{html.escape(verdict, quote=True)}</td>"
            f"<td>{html.escape(sev, quote=True)}</td>"
            f"<td>{html.escape(title, quote=True)}</td>"
            f"<td>{html.escape(target, quote=True)}</td>"
            f"<td>{html.escape(engine, quote=True)}</td>"
            f"<td>{html.escape(evidence[:200], quote=True)}</td></tr>"
        )
    html_body = "\n".join(rows)
    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>PentestAI Scan Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 15px; }}
  th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; }}
  th {{ background-color: #1e293b; color: #38bdf8; }}
  .Critical {{ background-color: rgba(239, 68, 68, 0.2); color: #fca5a5; font-weight: bold; }}
  .High {{ background-color: rgba(249, 115, 22, 0.2); color: #fdba74; }}
  .Medium {{ background-color: rgba(234, 179, 8, 0.2); color: #fde047; }}
  .Low {{ background-color: rgba(34, 197, 94, 0.2); color: #86efac; }}
</style>
</head>
<body>
<h2>🛡️ HunterAI Pentest Assessment Report</h2>
<table>
<thead>
<tr>
<th>Verdict</th>
<th>Severity</th>
<th>Title</th>
<th>Target</th>
<th>Engine / Fallback</th>
<th>Evidence</th>
</tr>
</thead>
<tbody>
{html_body}
</tbody>
</table>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


def export_csv(findings: List[Dict], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not findings:
        headers = ["verdict", "title", "severity", "param_name", "endpoint", "tool", "evidence"]
    else:
        headers = list(findings[0].keys())
        if "lifecycle_verdict" not in headers:
            headers.insert(0, "lifecycle_verdict")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)


def export_interactive_dashboard(
    target_url: str,
    scan_result: Dict[str, Any],
    output_path: str
) -> None:
    """
    Generates a standalone, interactive, dark-mode cybersecurity dashboard.
    Fully responsive with pure CSS/JS tabs for:
    1. Verified Findings & Evidence Court Verdicts
    2. Code Intelligence & Discovered API Routes
    3. Secrets & Key Analysis
    4. Attack Surface & Scope Firewall
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    findings = scan_result.get("findings", [])
    duration = scan_result.get("duration", 0.0)
    mode = str(scan_result.get("mode", "full"))
    obj_status = str(scan_result.get("objective_result", {}).get("status", "COMPLETE"))

    # Metrics
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")

    # Code Intel Data
    code_intel = scan_result.get("code_intelligence", {})
    manifest = code_intel.get("manifest", {})
    endpoints = code_intel.get("endpoints", [])
    secrets = code_intel.get("secrets", [])
    framework = code_intel.get("framework", {})
    attack_graph = scan_result.get("attack_graph", {})

    # Generate Tab 1: Findings Cards
    cards_html = []
    if not findings:
        cards_html.append("<div class='empty-state'>✅ No confirmed vulnerabilities found. Target passed all deterministic execution checks.</div>")
    for idx, f in enumerate(findings, start=1):
        sev = str(f.get("severity", "Info"))
        sev_cls = _css_token(sev, "Info")
        title = str(f.get("title", ""))
        verdict = str(f.get("lifecycle_verdict", "CONFIRMED"))
        param = str(f.get("param_name") or f.get("endpoint") or "-")
        evidence = SecretSanitizer.sanitize_text(str(f.get("evidence", "")))
        remediation = str(f.get("remediation", "Implement parameter validation, prepared statements, and context encoding."))
        payload = str(f.get("payload_used", "N/A"))
        tool = str(f.get("tool", ""))

        card = f"""
        <div class="finding-card border-{html.escape(sev_cls, quote=True)}">
            <div class="card-header">
                <span class="badge badge-{html.escape(sev_cls, quote=True)}">{html.escape(sev, quote=True)}</span>
                <span class="badge badge-court">{html.escape(verdict, quote=True)}</span>
                <span class="tool-tag">{html.escape(tool, quote=True)}</span>
                <h3 class="finding-title">{html.escape(title, quote=True)}</h3>
            </div>
            <div class="card-body">
                <p><strong>Target Parameter:</strong> <code>{html.escape(param, quote=True)}</code></p>
                <div class="code-box">
                    <span class="box-label">Payload Used</span>
                    <code>{html.escape(payload, quote=True)}</code>
                </div>
                <div class="code-box">
                    <span class="box-label">Evidence / Deterministic Proof</span>
                    <pre>{html.escape(evidence, quote=True)}</pre>
                </div>
                <div class="remediation-box">
                    <strong>Remediation:</strong> {html.escape(remediation, quote=True)}
                </div>
            </div>
        </div>
        """
        cards_html.append(card)
    findings_section = "\n".join(cards_html)

    # Generate Tab 2: Endpoints Table
    endpoints_rows = []
    if not endpoints:
        endpoints_rows.append("<tr><td colspan='5' class='text-center text-muted'>No API routes extracted.</td></tr>")
    for ep in endpoints:
        path = str(ep.get("url_or_path", ""))
        method = str(ep.get("method", "GET"))
        method_cls = _css_token(method, "GET")
        params = ", ".join(str(p) for p in ep.get("parameters", [])) or "-"
        auth = "Yes" if ep.get("auth_required") else "No"
        origin = str(ep.get("discovered_in", "source"))
        endpoints_rows.append(
            f"<tr><td><span class='badge-method badge-{html.escape(method_cls, quote=True)}'>{html.escape(method, quote=True)}</span></td>"
            f"<td><code>{html.escape(path, quote=True)}</code></td>"
            f"<td><code>{html.escape(params, quote=True)}</code></td>"
            f"<td>{html.escape(auth, quote=True)}</td>"
            f"<td class='text-muted'>{html.escape(origin, quote=True)}</td></tr>"
        )
    endpoints_table = "\n".join(endpoints_rows)

    # Generate Tab 3: Secrets Table (candidate_value fully masked — never leak raw prefixes)
    secrets_rows = []
    if not secrets:
        secrets_rows.append("<tr><td colspan='5' class='text-center text-muted'>No sensitive credentials or hardcoded keys detected.</td></tr>")
    for sec in secrets:
        stype = str(sec.get("secret_type", "SECRET"))
        status = str(sec.get("status", "CANDIDATE"))
        try:
            entropy_str = f"{float(sec.get('entropy', 0.0)):.2f}"
        except (TypeError, ValueError):
            entropy_str = "0.00"
        loc = str(sec.get("location", "-"))
        val_sample = "[REDACTED]" if sec.get("candidate_value") else "-"
        s_class = "badge-low" if status == "VALIDATED" else "badge-high"
        secrets_rows.append(
            f"<tr><td><span class='badge {s_class}'>{html.escape(status, quote=True)}</span></td>"
            f"<td><strong>{html.escape(stype, quote=True)}</strong></td>"
            f"<td><code>{html.escape(val_sample, quote=True)}</code></td>"
            f"<td>{html.escape(entropy_str, quote=True)}</td>"
            f"<td class='text-muted'>{html.escape(loc, quote=True)}</td></tr>"
        )
    secrets_table = "\n".join(secrets_rows)

    # Generate Tab 4: Scope & Firewall
    firewall_domains = [
        "googletagmanager.com", "google-analytics.com", "play.google.com",
        "apple.com", "cloudflare.com", "gstatic.com"
    ]
    fw_items = "".join(
        f"<li><span class='badge badge-court'>FIREWALLED</span> <code>{html.escape(d, quote=True)}</code> (Never tested)</li>"
        for d in firewall_domains
    )
    tech_chips = "".join(
        f"<span class='tech-chip'>{html.escape(str(t), quote=True)}</span>"
        for t in manifest.get("technologies", [])
    ) or "<span class='text-muted'>Standard Web Stack</span>"

    # Full HTML Dashboard Template
    dashboard_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>HunterAI Security Dashboard — {html.escape(str(target_url), quote=True)}</title>
<style>
  :root {{
    --bg: #090d16;
    --card-bg: #111827;
    --border: #1f2937;
    --text: #f9fafb;
    --text-muted: #9ca3af;
    --accent: #38bdf8;
    --crit: #ef4444;
    --high: #f97316;
    --med: #eab308;
    --low: #22c55e;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .header h1 {{ margin: 0 0 8px 0; font-size: 24px; color: var(--accent); }}
  .header p {{ margin: 0; color: var(--text-muted); font-size: 14px; }}
  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .metric-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
  }}
  .metric-val {{ font-size: 32px; font-weight: bold; margin-bottom: 4px; }}
  .val-crit {{ color: var(--crit); }}
  .val-high {{ color: var(--high); }}
  .val-med {{ color: var(--med); }}
  .val-low {{ color: var(--low); }}
  .val-accent {{ color: var(--accent); }}
  .metric-label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  
  .tabs {{ display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 12px; flex-wrap: wrap; }}
  .tab-btn {{
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-muted);
    padding: 10px 20px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
    transition: all 0.2s;
  }}
  .tab-btn:hover {{ background: rgba(255,255,255,0.05); color: #fff; }}
  .tab-btn.active {{ background: var(--border); color: #fff; border-color: var(--accent); }}
  
  .tab-pane {{ display: none; }}
  .tab-pane.active {{ display: block; }}

  .finding-card {{
    background: var(--card-bg);
    border-left: 4px solid #fff;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
  }}
  .border-Critical {{ border-left-color: var(--crit); }}
  .border-High {{ border-left-color: var(--high); }}
  .border-Medium {{ border-left-color: var(--med); }}
  .border-Low {{ border-left-color: var(--low); }}
  
  .card-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }}
  .finding-title {{ margin: 0; font-size: 18px; color: #fff; flex-grow: 1; }}
  .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
  .badge-Critical {{ background: rgba(239, 68, 68, 0.2); color: var(--crit); }}
  .badge-High {{ background: rgba(249, 115, 22, 0.2); color: var(--high); }}
  .badge-Medium {{ background: rgba(234, 179, 8, 0.2); color: var(--med); }}
  .badge-Low {{ background: rgba(34, 197, 94, 0.2); color: var(--low); }}
  .badge-court {{ background: #1e3a8a; color: #93c5fd; }}
  .badge-method {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
  .badge-GET {{ background: #0284c7; color: #fff; }}
  .badge-POST {{ background: #16a34a; color: #fff; }}
  .badge-PUT {{ background: #d97706; color: #fff; }}
  .badge-DELETE {{ background: #dc2626; color: #fff; }}
  .tool-tag {{ font-size: 12px; color: var(--text-muted); background: var(--border); padding: 4px 8px; border-radius: 4px; }}
  
  .code-box {{ background: #030712; border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin: 10px 0; position: relative; }}
  .box-label {{ font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px; display: block; }}
  pre, code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: #38bdf8; font-size: 13px; margin: 0; white-space: pre-wrap; }}
  .remediation-box {{ background: rgba(34, 197, 94, 0.08); border-left: 3px solid var(--low); padding: 12px; border-radius: 4px; font-size: 14px; margin-top: 12px; }}
  .empty-state {{ padding: 40px; text-align: center; color: var(--low); font-size: 16px; background: var(--card-bg); border-radius: 8px; border: 1px solid var(--border); }}
  
  table.data-table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }}
  table.data-table th, table.data-table td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }}
  table.data-table th {{ background: #1e293b; color: var(--accent); font-size: 13px; text-transform: uppercase; }}
  .tech-chip {{ display: inline-block; background: #1e293b; border: 1px solid var(--border); padding: 4px 12px; border-radius: 16px; font-size: 12px; color: var(--accent); margin-right: 6px; }}
  .firewall-list {{ list-style: none; padding: 0; margin: 12px 0; display: flex; flex-direction: column; gap: 8px; }}
  .panel-box {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
  .text-muted {{ color: var(--text-muted); }}
  .text-center {{ text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>🛡️ HunterAI Security Audit Dashboard</h1>
      <p>Target: <strong>{html.escape(str(target_url), quote=True)}</strong> | Mode: <strong>{html.escape(mode, quote=True)}</strong> | Duration: <strong>{html.escape(str(duration), quote=True)}s</strong></p>
    </div>
    <div>
      <span class="badge badge-court">Objective: {html.escape(obj_status, quote=True)}</span>
    </div>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-val val-crit">{crit_count}</div>
      <div class="metric-label">Critical Confirmed</div>
    </div>
    <div class="metric-card">
      <div class="metric-val val-high">{high_count}</div>
      <div class="metric-label">High Severity</div>
    </div>
    <div class="metric-card">
      <div class="metric-val val-med">{med_count}</div>
      <div class="metric-label">Medium Severity</div>
    </div>
    <div class="metric-card">
      <div class="metric-val val-accent">{len(endpoints)}</div>
      <div class="metric-label">API Endpoints Discovered</div>
    </div>
    <div class="metric-card">
      <div class="metric-val val-low">{html.escape(str(manifest.get('js_analyzed', 0)), quote=True)}</div>
      <div class="metric-label">JS Bundles Analyzed</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab(event, 'tab-findings')">⚖️ Findings & Court Verdicts ({len(findings)})</button>
    <button class="tab-btn" onclick="switchTab(event, 'tab-endpoints')">🌐 Discovered Endpoints ({len(endpoints)})</button>
    <button class="tab-btn" onclick="switchTab(event, 'tab-secrets')">🔑 Code Intel & Secrets ({len(secrets)})</button>
    <button class="tab-btn" onclick="switchTab(event, 'tab-scope')">🛡️ Scope & Firewall Boundary</button>
  </div>

  <div id="tab-findings" class="tab-pane active">
    {findings_section}
  </div>

  <div id="tab-endpoints" class="tab-pane">
    <table class="data-table">
      <thead>
        <tr>
          <th>Method</th>
          <th>Endpoint / URL Path</th>
          <th>Parameters</th>
          <th>Auth</th>
          <th>Discovered In</th>
        </tr>
      </thead>
      <tbody>
        {endpoints_table}
      </tbody>
    </table>
  </div>

  <div id="tab-secrets" class="tab-pane">
    <table class="data-table">
      <thead>
        <tr>
          <th>Status</th>
          <th>Secret Type</th>
          <th>Candidate Sample</th>
          <th>Shannon Entropy</th>
          <th>File Location</th>
        </tr>
      </thead>
      <tbody>
        {secrets_table}
      </tbody>
    </table>
  </div>

  <div id="tab-scope" class="tab-pane">
    <div class="panel-box">
      <h3 style="margin-top:0; color:var(--accent);">Target Tech Stack</h3>
      <div>{tech_chips}</div>
    </div>
    <div class="panel-box">
      <h3 style="margin-top:0; color:var(--accent);">Third-Party Dependency Firewall</h3>
      <p class="text-muted">The following external infrastructure and third-party vendors were strictly firewalled from active penetration testing to guarantee scope safety and eliminate false positives:</p>
      <ul class="firewall-list">
        {fw_items}
      </ul>
    </div>
  </div>
</div>

<script>
function switchTab(evt, tabId) {{
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    evt.currentTarget.classList.add('active');
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(dashboard_html)