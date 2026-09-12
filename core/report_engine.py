"""Report Engine — تقارير CVSS HTML + JSON"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict
from core.session_manager import PentestSession

SEV_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
SEV_COLOR = {"Critical": "#ff3333", "High": "#ff6600", "Medium": "#ffaa00", "Low": "#00aa00", "Info": "#3399ff"}
SEV_CVSS  = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 2.5, "Info": 0.0}


class ReportEngine:
    def __init__(self, reports_dir: str = "data/reports"):
        self.dir = Path(reports_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _sort(self, session):
        return sorted(session.findings, key=lambda f: SEV_ORDER.get(f.severity, 0), reverse=True)

    def json_report(self, session: PentestSession) -> str:
        findings = self._sort(session)
        data = {
            "meta": {"session_id": session.id, "target": session.target,
                     "mode": session.mode, "generated_at": datetime.now().isoformat()},
            "summary": {
                "total": len(findings),
                **{s.lower(): sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
            },
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity,
                           "cvss": f.cvss_score or SEV_CVSS.get(f.severity, 0),
                           "description": f.description, "evidence": f.evidence,
                           "recommendation": f.recommendation, "tool": f.tool} for f in findings],
            "tools_run": session.tools_run,
        }
        p = self.dir / f"{session.id}_report.json"
        with open(p, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)
        return str(p)

    def html_report(self, session: PentestSession) -> str:
        findings = self._sort(session)
        cards = ""
        for f in findings:
            c = SEV_COLOR.get(f.severity, "#888")
            cvss = f.cvss_score or SEV_CVSS.get(f.severity, 0)
            cards += f"""
            <div class="finding" style="border-left:5px solid {c}">
              <div class="fh">
                <span class="badge" style="background:{c}">{f.severity}</span>
                <span class="cvss">CVSS {cvss:.1f}</span>
                <strong>{f.title}</strong>
                <span class="tool-tag">{f.tool}</span>
              </div>
              <p>{f.description}</p>
              <pre>{f.evidence[:400]}</pre>
              <p><em>💊 Fix: {f.recommendation}</em></p>
            </div>"""

        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
        summary_html = "".join([
            f'<div class="sc" style="color:{SEV_COLOR[s]}">'
            f'<div class="sn">{counts[s]}</div><div>{s}</div></div>'
            for s in SEV_ORDER if counts[s] > 0
        ])

        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>PentestAI Report — {session.target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',monospace}}
.hdr{{background:#1a0000;border-bottom:3px solid #ff3333;padding:25px 40px}}
.hdr h1{{color:#ff3333;font-size:1.8em}}.hdr p{{color:#888;margin-top:5px}}
.wrap{{max-width:1100px;margin:0 auto;padding:30px}}
.summary{{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}}
.sc{{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:15px 20px;text-align:center;min-width:90px}}
.sn{{font-size:2.2em;font-weight:bold}}
h2{{color:#ff3333;margin:25px 0 12px;font-size:1.1em;border-bottom:1px solid #222;padding-bottom:8px}}
.finding{{background:#111;border-radius:8px;padding:15px 20px;margin:10px 0}}
.fh{{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}}
.badge{{padding:3px 9px;border-radius:4px;color:#fff;font-size:.75em;font-weight:bold}}
.cvss{{background:#333;padding:3px 8px;border-radius:4px;font-size:.75em}}
.tool-tag{{margin-left:auto;color:#666;font-size:.8em}}
pre{{background:#050505;padding:10px;border-radius:4px;font-size:.78em;color:#00ff41;overflow-x:auto;white-space:pre-wrap;margin:8px 0}}
em{{color:#888;font-size:.85em}}
</style></head><body>
<div class="hdr">
  <h1>🔥 PentestAI Unified — Security Report</h1>
  <p>Target: {session.target} | Mode: {session.mode} | Session: {session.id} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
</div>
<div class="wrap">
  <h2>Executive Summary</h2>
  <div class="summary">{summary_html}
    <div class="sc" style="color:#fff"><div class="sn">{len(findings)}</div><div>Total</div></div>
  </div>
  <h2>Findings</h2>
  {cards or '<p style="color:#555">No findings recorded.</p>'}
</div></body></html>"""

        p = self.dir / f"{session.id}_report.html"
        with open(p, "w", encoding="utf-8") as fp:
            fp.write(html)
        return str(p)

    def generate_all(self, session: PentestSession) -> Dict[str, str]:
        return {"json": self.json_report(session), "html": self.html_report(session)}
