"""Exporters for PentestAI findings.
Provides simple functions to write scan results to JSON, HTML, and CSV formats.
These utilities are used by the CLI to generate reports.
"""
import json
import csv
import os
from typing import List, Dict


def export_json(findings: List[Dict], output_path: str) -> None:
    """Export findings to a JSON file.

    Args:
        findings: List of finding dictionaries returned by the scan.
        output_path: Destination file path (including filename).
    """
    # Ensure the parent directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)


def export_html(findings: List[Dict], output_path: str) -> None:
    """Export findings to a simple HTML report.

    The HTML contains a table with the most relevant columns.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    html_header = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"UTF-8\" />
<title>PentestAI Scan Report</title>
<style>
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: 8px; }
  th { background-color: #f2f2f2; }
  .Critical { background-color: #f8d7da; }
  .High { background-color: #f5c6cb; }
  .Medium { background-color: #ffeeba; }
  .Low { background-color: #d4edda; }
</style>
</head>
<body>
<h2>PentestAI Scan Report</h2>
<table>
<thead>
<tr>
<th>Severity</th>
<th>Title</th>
<th>Target</th>
<th>Engine / Fallback</th>
<th>Evidence</th>
</tr>
</thead>
<tbody>
"""
    html_footer = """</tbody>
</table>
</body>
</html>"""
    rows = []
    for f in findings:
        sev = f.get("severity", "Info")
        title = f.get("title", "")
        target = f.get("param_name") or f.get("endpoint") or "-"
        engine = f.get("tool", "")
        if f.get("fallback_used"):
            engine += f" (fallback: {f.get('fallback_engine')})"
        evidence = str(f.get("evidence", ""))
        # Escape minimal HTML
        def esc(text: str) -> str:
            return (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;")
            )
        rows.append(
            f"<tr class=\"{sev}\"><td>{esc(sev)}</td><td>{esc(title)}</td><td>{esc(str(target))}</td><td>{esc(engine)}</td><td>{esc(evidence)}</td></tr>"
        )
    html_body = "\n".join(rows)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_header)
        f.write(html_body)
        f.write(html_footer)


def export_csv(findings: List[Dict], output_path: str) -> None:
    """Export findings to a CSV file.

    Columns include all primary fields that appear in a finding.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    # Determine column headers from keys of the first finding (if any)
    if not findings:
        headers = []
    else:
        # Preserve order: use a fixed set of common fields first
        common = ["severity", "title", "param_name", "endpoint", "tool", "fallback_used", "fallback_engine", "evidence", "logs"]
        extra = [k for k in findings[0].keys() if k not in common]
        headers = common + extra
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            writer.writerow(f)
