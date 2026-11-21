import httpx
import json
import sys

BASE_URL = "http://127.0.0.1:7070"

client = httpx.Client(base_url=BASE_URL, timeout=10.0, follow_redirects=False)

print("=" * 70)
print("1. LIVE SERVER HTTP ROUTE & REDIRECT TESTS")
print("=" * 70)

all_passed = True

routes = [
    ("/", 200),
    ("/?section=redteam", 200),
    ("/?section=editor", 200),
    ("/?section=chat", 200),
    ("/?section=radar", 200),
    ("/opencode", 200),
]

for r, exp in routes:
    try:
        resp = client.get(r)
        passed = (resp.status_code == exp)
        if not passed: all_passed = False
        print(f"[{'PASS' if passed else 'FAIL'}] {r:25} -> {resp.status_code} (len: {len(resp.text)} bytes)")
    except Exception as e:
        all_passed = False
        print(f"[FAIL] {r:25} -> Error: {e}")

# Check 302 redirects
for r, exp_loc in [("/chat", "/?section=chat"), ("/command", "/?section=overview")]:
    try:
        resp = client.get(r)
        loc = resp.headers.get("location", "")
        passed = (resp.status_code == 302 and loc == exp_loc)
        if not passed: all_passed = False
        print(f"[{'PASS' if passed else 'FAIL'}] {r:25} -> {resp.status_code} Redirect to: {loc}")
    except Exception as e:
        all_passed = False
        print(f"[FAIL] {r:25} -> Error: {e}")

print("\n" + "=" * 70)
print("2. HTML DOM SECTIONS VERIFICATION (LITERAL EXISTENCE)")
print("=" * 70)

resp = client.get("/")
html = resp.text

sections_to_check = [
    ("sec-overview", "System Overview Dashboard"),
    ("sec-agents", "Specialized Agents Management"),
    ("sec-skills", "Skills Explorer & Dependency Inspector"),
    ("sec-tools", "Tools Center & Health Check"),
    ("sec-mcp", "MCP Servers Center"),
    ("sec-browser", "Interactive Browser Manager"),
    ("sec-burp", "Burp Suite Integration Monitor"),
    ("sec-models", "AI Models Manager"),
    ("sec-targets", "Target & Scope Guard"),
    ("sec-radar", "Live Target Radar & test.py Analyzer"),
    ("sec-activity", "Live Activity Center"),
    ("sec-results", "Results & Vulnerabilities Explorer"),
    ("sec-diagnostics", "System Diagnostics"),
    ("sec-settings", "Settings & Security Policies"),
    ("sec-redteam", "Red Team Cockpit & Checklists"),
    ("sec-editor", "Monaco Code Editor & Burp Repeater"),
    ("sec-chat", "Multi-Model Autonomous Agent Chat"),
]

for sec_id, name in sections_to_check:
    needle = f'id="{sec_id}"'
    present = needle in html
    if not present: all_passed = False
    print(f"[{'PASS' if present else 'FAIL'}] Section #{sec_id:18} : {name}")

print("\n" + "=" * 70)
print("3. JAVASCRIPT LOGIC & BINDINGS VERIFICATION")
print("=" * 70)

scripts_to_check = [
    ("Monaco CDN Loader", "cdnjs.cloudflare.com/ajax/libs/monaco-editor"),
    ("RedTeam JS Cockpit", "function loadRedTeamCockpit"),
    ("Checklists Toggle JS", "function toggleChecklistItem"),
    ("7-Question Gate JS", "function evaluateSevenGate"),
    ("Lead Board Touch JS", "function touchLeadStatus"),
    ("Monaco Editor Init JS", "function initCodeEditor"),
    ("Burp Repeater Send JS", "function sendRepeaterRequest"),
    ("Unified Chat Stream JS", "function sendUnifiedChatMessage"),
    ("Auto-Switch Script", "window._defaultSection"),
]

for label, needle in scripts_to_check:
    present = needle in html
    if not present: all_passed = False
    print(f"[{'PASS' if present else 'FAIL'}] {label:24} : present in DOM")

print("\n" + "=" * 70)
print("4. LIVE BACKEND API ENDPOINTS VERIFICATION")
print("=" * 70)

api_endpoints = [
    ("GET", "/api/control/system-status", None),
    ("GET", "/api/control/agents", None),
    ("GET", "/api/control/skills", None),
    ("GET", "/api/control/tools", None),
    ("GET", "/api/control/browser", None),
    ("GET", "/api/control/burp", None),
    ("GET", "/api/control/models", None),
    ("GET", "/api/control/targets", None),
    ("GET", "/api/control/test-radar", None),
    ("GET", "/api/control/activity", None),
    ("GET", "/api/control/results", None),
    ("GET", "/api/control/settings", None),
    ("GET", "/api/control/checklists", None),
    ("GET", "/api/control/redteam-policy", None),
    ("GET", "/api/control/lead-board", None),
    ("GET", "/api/editor/tree", None),
    ("POST", "/api/control/checklists/toggle", {"item_id": "WEB-01", "checked": True}),
    ("POST", "/api/control/seven-gate/evaluate", {
        "title": "BOLA on Payment Gateway",
        "asset": "api.target.com",
        "poc": "GET /api/pay/99 HTTP/1.1",
        "impact": "Account takeover of customer transactions",
        "reproducibility": "100% reproducible",
        "vulnerability_class": "idor"
    }),
    ("POST", "/api/control/test-radar/simulate", {}),
]

for method, ep, payload in api_endpoints:
    try:
        if method == "GET":
            resp = client.get(ep)
        else:
            resp = client.post(ep, json=payload)
        passed = (resp.status_code == 200)
        if not passed: all_passed = False
        res_json = resp.json()
        extra = ""
        if ep == "/api/control/system-status":
            extra = f"CPU: {res_json.get('telemetry',{}).get('cpu_percent')}% | RAM: {res_json.get('telemetry',{}).get('ram_percent')}%"
        elif ep == "/api/control/browser":
            extra = f"Status: {res_json.get('connection_status')} | Chrome: {bool(res_json.get('chrome_available'))}"
        elif ep == "/api/control/checklists":
            extra = f"{res_json.get('total_items')} items | Completed: {res_json.get('completed_items')}"
        elif ep == "/api/control/redteam-policy":
            extra = f"Profile: {res_json.get('current_profile')} | Grant: {res_json.get('grant',{}).get('grant_id','None')}"
        elif ep == "/api/control/seven-gate/evaluate":
            extra = f"Score: {res_json.get('score')} | Passed: {res_json.get('passed')}"
        elif ep == "/api/editor/tree":
            extra = f"{len(res_json.get('items',[]))} files in workspace"
        
        print(f"[{'PASS' if passed else 'FAIL'}] {method:4} {ep:35} -> {resp.status_code} ({extra})")
    except Exception as e:
        all_passed = False
        print(f"[FAIL] {method:4} {ep:35} -> Error: {e}")

print("\n" + "=" * 70)
print(f"FINAL RESULT: {'✅ ALL TESTS PASSED (100% OPERATIONAL)' if all_passed else '❌ SOME TESTS FAILED'}")
print("=" * 70)
sys.exit(0 if all_passed else 1)
