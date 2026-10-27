#!/usr/bin/env python
# SecretFinder - Tool for discovering API keys / access tokens / sensitive data in JS files
# based on LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k
# Enhanced by PentestAI-Unified: extra patterns, JSON/CSV/SARIF output,
# recursive scanning, concurrency, exclusions, severity scoring and better HTML report.

import os
import sys
import re
import glob
import json
import csv
import argparse
import threading
import concurrent.futures
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
from datetime import datetime
from urllib.parse import urlparse

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

# for read local file with file:// protocol
try:
    from requests_file import FileAdapter
except Exception:  # pragma: no cover
    FileAdapter = None

try:
    from lxml import html as lxml_html
except Exception:  # pragma: no cover
    lxml_html = None

# ---------------------------------------------------------------------------
# Regex signatures (extended)
# ---------------------------------------------------------------------------
_regex = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_token': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2': r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_ec_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds': r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    # --- Added ideas below (عرض أفكارك المضافة هنا) ---
    'discord_token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
    'discord_webhook': r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
    'stripe_test_api': r'sk_test_[0-9a-zA-Z]{24}',
    'sendgrid_api_key': r'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}',
    'mailchimp_api_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'shopify_access_token': r'shpat_[0-9a-zA-Z]{32}',
    'slack_webhook': r'hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+',
    'aws_secret_access_key': r'(?i)aws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}',
    'private_rsa_key_block': r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    'json_web_token_header': r'eyJ[a-zA-Z0-9_-]{5,}',
    'generic_api_key': r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}',
    'generic_secret': r'(?i)(?:secret|token|client_secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}',
    'db_connection_string': r'(?i)(?:mongodb|mysql|postgres|postgresql|redis)://[^\s"\']+',
    'azure_storage_key': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
    'gcp_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'pypi_api_key': r'pypi-[A-Za-z0-9_\-]{32,}',
    'npm_token': r'npm_[A-Za-z0-9_\-]{36,}',
    'dockerhub_token': r'dckr_[A-Za-z0-9_\-]{20,}',
    'heroku_api_key_full': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'graphql_endpoint': r'(?i)graphql[^\s"\']*',
    'internal_ip': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
    'basic_auth_url': r'https?://[^:/\s@]+:[^/\s@]+@[^\s"\']+',
    'aws_role_arn': r'arn:aws:iam::\d{12}:role/[A-Za-z0-9_+=,.@-]+',
    'google_cloud_credentials': r'"type"\s*:\s*"service_account"',
}

# Severity scoring per signature type
_SEVERITY = {
    'google_api': 'high',
    'firebase': 'high',
    'google_oauth': 'high',
    'amazon_aws_access_key_id': 'critical',
    'amazon_mws_auth_token': 'critical',
    'amazon_aws_url': 'medium',
    'amazon_aws_url2': 'medium',
    'aws_secret_access_key': 'critical',
    'aws_role_arn': 'high',
    'facebook_access_token': 'high',
    'authorization_basic': 'high',
    'authorization_bearer': 'high',
    'authorization_api': 'high',
    'mailgun_api_key': 'high',
    'twilio_api_key': 'high',
    'twilio_account_sid': 'medium',
    'twilio_app_sid': 'medium',
    'paypal_braintree_access_token': 'critical',
    'square_oauth_secret': 'high',
    'square_access_token': 'high',
    'stripe_standard_api': 'critical',
    'stripe_restricted_api': 'critical',
    'stripe_test_api': 'medium',
    'github_access_token': 'high',
    'rsa_private_key': 'critical',
    'ssh_dsa_private_key': 'critical',
    'ssh_ec_private_key': 'critical',
    'pgp_private_block': 'critical',
    'private_rsa_key_block': 'critical',
    'json_web_token': 'medium',
    'json_web_token_header': 'low',
    'slack_token': 'critical',
    'slack_webhook': 'medium',
    'discord_token': 'critical',
    'discord_webhook': 'medium',
    'sendgrid_api_key': 'high',
    'mailchimp_api_key': 'high',
    'shopify_access_token': 'high',
    'SSH_privKey': 'critical',
    'Heroku API KEY': 'high',
    'heroku_api_key_full': 'high',
    'possible_Creds': 'medium',
    'generic_api_key': 'high',
    'generic_secret': 'high',
    'db_connection_string': 'critical',
    'azure_storage_key': 'critical',
    'gcp_api_key': 'high',
    'pypi_api_key': 'high',
    'npm_token': 'high',
    'dockerhub_token': 'high',
    'graphql_endpoint': 'low',
    'internal_ip': 'low',
    'basic_auth_url': 'high',
    'google_cloud_credentials': 'critical',
}

_SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

# ---------------------------------------------------------------------------
# HTML report template ( improved )
# ---------------------------------------------------------------------------
_template = '''
<!DOCTYPE html>
<html lang="en" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecretFinder Report</title>
  <style>
       body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #222; margin: 0; padding: 0; direction: rtl; }
       h1 { font-family: sans-serif; text-align: center; color: #1a1a1a; }
       a { color: #0066cc; text-decoration: none; }
       a:hover { text-decoration: underline; }
       .text { font-size: 14px; font-family: Helvetica, sans-serif; color: #323232; background-color: white; }
       .container { background-color: #e9e9e9; padding: 20px; max-width: 1200px; margin: 20px auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
       table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
       th, td { border: 1px solid #ccc; padding: 8px 10px; text-align: right; }
       th { background: #333; color: #fff; }
       tr:nth-child(even) { background: #f9f9f9; }
       .sev-critical { color: #b00020; font-weight: bold; }
       .sev-high { color: #d43d00; font-weight: bold; }
       .sev-medium { color: #b8860b; font-weight: bold; }
       .sev-low { color: #555; font-weight: bold; }
       .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: #fff; }
       .badge-critical { background: #b00020; }
       .badge-high { background: #d43d00; }
       .badge-medium { background: #b8860b; }
       .badge-low { background: #666; }
       .summary { background: #fff; border: 1px solid #ddd; padding: 14px; margin-bottom: 20px; border-radius: 6px; }
       .summary h2 { margin-top: 0; font-size: 16px; }
       .mono { font-family: "Courier New", Courier, monospace; white-space: pre-wrap; word-break: break-all; background: #f0f0f0; padding: 4px 6px; border-radius: 4px; display: inline-block; max-width: 60%; }
       .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }
       .filter { margin-bottom: 12px; text-align: right; }
       .filter select, .filter input { padding: 6px 8px; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>تقرير SecretFinder —езультаты المسح</h1>
    <div class="summary">
      <h2>ملخص النتائج</h2>
      <p><strong>الهدف المستهدف:</strong> {target}</p>
      <p><strong>تاريخ المسح:</strong> {timestamp}</p>
      <p><strong>إجمالي النتائج:</strong> <span id="total">{total}</span></p>
      <div id="severity-counts">{severity_counts}</div>
    </div>

    <div class="filter">
      <label for="sevFilter">تصفية حسب الخطورة:</label>
      <select id="sevFilter" onchange="filterTable()">
        <option value="">الكل</option>
        <option value="critical">حرج (Critical)</option>
        <option value="high">عالي (High)</option>
        <option value="medium">متوسط (Medium)</option>
        <option value="low">منخفض (Low)</option>
      </select>
      <label for="typeFilter">نوع السر:</label>
      <select id="typeFilter" onchange="filterTable()">
        <option value="">الكل</option>
        {type_options}
      </select>
      <label for="searchInput">بحث:</label>
      <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="ابحث في القيم أو الأنواع...">
    </div>

    <table id="resultsTable">
      <thead>
        <tr>
          <th>#</th>
          <th>الخطورة</th>
          <th>النوع</th>
          <th>القيمة المكتشفة</th>
          <th>المصدر (السطر)</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>

    <div class="footer">
      تم الإنشاء بواسطة SecretFinder (مُحسَّن) — PentestAI-Unified. يُستخدم فقط على الأصول المصرح بمسحها.
    </div>
  </div>

  <script>
    function filterTable() {
      const sev = document.getElementById("sevFilter").value.toLowerCase();
      const type = document.getElementById("typeFilter").value.toLowerCase();
      const q = document.getElementById("searchInput").value.toLowerCase();
      const rows = document.querySelectorAll("#resultsTable tbody tr");
      let visible = 0;
      rows.forEach(row => {
        const sevCell = row.cells[1].textContent.toLowerCase();
        const typeCell = row.cells[2].textContent.toLowerCase();
        const valCell = row.textContent.toLowerCase();
        const ok = (!sev || sevCell.includes(sev)) &&
                   (!type || typeCell.includes(type)) &&
                   (!q || valCell.includes(q));
        row.style.display = ok ? "" : "none";
        if (ok) visible++;
      });
      document.getElementById("total").textContent = visible;
    }
  </script>
</body>
</html>
'''

_lock = threading.Lock()

def severity_of(otype):
    return _SEVERITY.get(otype, 'medium')

def scan_text(text, patterns):
    """Scan text with compiled regexes and return list of (otype, match)."""
    findings = []
    for otype, pattern in patterns.items():
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        for m in rx.finditer(text):
            val = m.group(0)
            findings.append((otype, val))
    return findings

def beautify_js(content):
    try:
        return jsbeautifier.beautify(content)
    except Exception:
        return content

def read_file(path):
    encodings = ['utf-8', 'latin-1', 'cp1252']
    for enc in encodings:
        try:
            with open(path, 'r', encoding=enc, errors='ignore') as f:
                return f.read()
        except Exception:
            continue
    return ''

def process_file(path, patterns, beautify, line_numbers=True):
    """Return list of findings with optional line numbers."""
    raw = read_file(path)
    if not raw:
        return []
    content = beautify_js(raw) if beautify else raw
    findings = scan_text(content, patterns)
    results = []
    if line_numbers:
        lines = content.splitlines()
        for otype, val in findings:
            line_no = 1
            for i, line in enumerate(lines, 1):
                if val in line:
                    line_no = i
                    break
            results.append({
                'file': os.path.abspath(path),
                'type': otype,
                'value': val,
                'line': line_no,
                'severity': severity_of(otype),
            })
    else:
        for otype, val in findings:
            results.append({
                'file': os.path.abspath(path),
                'type': otype,
                'value': val,
                'line': '',
                'severity': severity_of(otype),
            })
    return results

def collect_files(target, recursive):
    if os.path.isdir(target):
        pat = '**/*.js' if recursive else '*.js'
        files = glob.glob(os.path.join(target, pat), recursive=recursive)
        # also .json, .html, .htm sometimes contain keys
        if recursive:
            for ext in ('*.json', '*.html', '*.htm', '*.txt', '*.env', '*.yml', '*.yaml'):
                files += glob.glob(os.path.join(target, '**', ext), recursive=True)
        return sorted(set(files))
    return [target]

def deduplicate(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f['file'], f['type'], f['value'])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

def sort_findings(findings):
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f['severity'], 9), f['file'], f['type']))

def write_html(findings, target, output='report.html'):
    type_set = sorted({f['type'] for f in findings})
    type_options = ''.join(f'<option value="{escape(t)}">{escape(t)}</option>' for t in type_set)
    rows = []
    for i, f in enumerate(findings, 1):
        sev = f['severity']
        rows.append(
            '<tr>'
            f'<td>{i}</td>'
            f'<td class="sev-{sev}"><span class="badge badge-{sev}">{sev}</span></td>'
            f'<td class="mono">{escape(f["type"])}</td>'
            f'<td class="mono">{escape(f["value"])}</td>'
            f'<td>{escape(os.path.basename(f["file"]))} — السطر {f["line"]}</td>'
            '</tr>'
        )
    counts = {s: sum(1 for f in findings if f['severity'] == s) for s in _SEVERITY_ORDER}
    counts_html = ' '.join(
        f'<span class="badge badge-{s}">{s.upper()}: {counts.get(s, 0)}</span>'
        for s in ['critical', 'high', 'medium', 'low']
    )
    html = _template.format(
        target=escape(target),
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        total=len(findings),
        severity_counts=counts_html,
        type_options=type_options,
        rows='\n'.join(rows),
    )
    with open(output, 'w', encoding='utf-8') as f:
        f.write(html)
    return output

def write_json(findings, output='results.json'):
    data = {
        'generated_at': datetime.now().isoformat(),
        'total': len(findings),
        'results': findings,
    }
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return output

def write_csv(findings, output='results.csv'):
    with open(output, 'w', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        w.writerow(['file', 'type', 'value', 'line', 'severity'])
        for f in findings:
            w.writerow([f['file'], f['type'], f['value'], f['line'], f['severity']])
    return output

def write_sarif(findings, output='results.sarif'):
    runs = [{
        'tool': {'driver': {'name': 'SecretFinder', 'version': '1.1.0'}},
        'results': [
            {
                'ruleId': f['type'],
                'level': 'error' if f['severity'] in ('critical', 'high') else ('warning' if f['severity'] == 'medium' else 'note'),
                'message': {'text': f"{f['type']}: {f['value']}"},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': f['file']},
                        'region': {'startLine': f['line'] or 1, 'snippet': {'text': f['value']}}
                    }
                }]
            } for f in findings
        ]
    }]
    sarif = {
        '$schema': 'https://docs.oasis-open.org/sarif/2.1.0/cos-02/schemas/sarif-2.1.0-rc.2.json',
        'version': '2.1.0',
        'runs': runs
    }
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)
    return output

def main():
    if not sys.version_info.major >= 3:
        print("[ + ] Run this tool with python version 3.+")
        sys.exit(0)

    os.environ["BROWSER"] = "open"

    parser = argparse.ArgumentParser(description='SecretFinder — discover secrets in JS / web files')
    parser.add_argument('target', help='File, directory, or URL to scan')
    parser.add_argument('-o', '--output', default='report.html', help='Output report file (html/json/csv/sarif)')
    parser.add_argument('--format', choices=['html', 'json', 'csv', 'sarif'], default='html', help='Report format')
    parser.add_argument('--no-beautify', action='store_true', help='Do not beautify JS before scanning')
    parser.add_argument('--recursive', action='store_true', help='Scan directories recursively')
    parser.add_argument('--workers', type=int, default=5, help='Number of concurrent workers (default: 5)')
    parser.add_argument('--exclude', nargs='*', default=[], help='Exclude files matching these substrings')
    parser.add_argument('--open', action='store_true', help='Open HTML report in browser after scan')
    args = parser.parse_args()

    beautify = not args.no_beautify

    files = collect_files(args.target, args.recursive)
    if args.exclude:
        files = [fp for fp in files if not any(ex in fp for ex in args.exclude)]

    if not files:
        print('[!] No files found to scan.')
        sys.exit(0)

    print(f'[+] Scanning {len(files)} file(s) ...')
    all_findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_file, fp, _regex, beautify): fp for fp in files}
        for future in concurrent.futures.as_completed(futures):
            fp = futures[future]
            try:
                res = future.result()
                if res:
                    all_findings.extend(res)
                    print(f'    [+] {fp}: {len(res)} finding(s)')
            except Exception as e:
                print(f'    [!] Error scanning {fp}: {e}')

    all_findings = deduplicate(all_findings)
    all_findings = sort_findings(all_findings)

    print(f'\n[+] Total unique findings: {len(all_findings)}')

    fmt = args.format
    out = args.output
    if fmt == 'html':
        out = write_html(all_findings, args.target, output=out)
        print(f'[+] HTML report saved: {out}')
        if args.open:
            webbrowser.open('file://' + os.path.abspath(out))
    elif fmt == 'json':
        out = write_json(all_findings, output=out)
        print(f'[+] JSON report saved: {out}')
    elif fmt == 'csv':
        out = write_csv(all_findings, output=out)
        print(f'[+] CSV report saved: {out}')
    elif fmt == 'sarif':
        out = write_sarif(all_findings, output=out)
        print(f'[+] SARIF report saved: {out}')

if __name__ == '__main__':
    main()
