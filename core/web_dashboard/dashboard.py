"""
HunterAI Web Dashboard — واجهة ويب تفاعلية لإدارة المسحات والنتائج
مقتبس من فكرة Xalgorix dashboard ولكن مدمج مع هيكل HunterAI
"""
from __future__ import annotations

import json
import logging
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from core.methodology.phases import get_all_phases, MethodologyPhase
from core.evidence_court.exploit_verifier import ExploitVerifier

log = logging.getLogger("hunter_ai.web_dashboard")


class ConnectionManager:
    """إدارة اتصالات WebSocket للبث اللحظي"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        data = json.dumps(message, ensure_ascii=False)
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                pass


manager = ConnectionManager()


class WebDashboard:
    """
    واجهة ويب تفاعلية لـ HunterAI.
    تعتمد على FastAPI إن كانت مثبتة، وإلا تقدم واجهة بسيطة.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9137):
        self.host = host
        self.port = port
        self.app: Optional[FastAPI] = None
        self.findings: List[Dict[str, Any]] = []
        self.sessions: List[Dict[str, Any]] = []
        self.verifier = ExploitVerifier()

        if HAS_FASTAPI:
            self._build_app()

    def _build_app(self):
        self.app = FastAPI(title="HunterAI Dashboard", version="1.0.0")

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_home():
            return HTMLResponse(content=self._dashboard_html(), status_code=200)

        @self.app.get("/api/sessions")
        async def list_sessions():
            return JSONResponse(content=self.sessions)

        @self.app.get("/api/findings")
        async def list_findings():
            return JSONResponse(content=self.findings)

        @self.app.post("/api/scan")
        async def start_scan(payload: dict):
            target = payload.get("target", "")
            mission = payload.get("mission", "full")
            session = {
                "session_id": f"sess_{int(asyncio.get_event_loop().time())}",
                "target": target,
                "mission": mission,
                "status": "running",
                "started_at": datetime.utcnow().isoformat(),
                "findings_count": 0,
            }
            self.sessions.append(session)
            await manager.broadcast({"event": "session_started", "session": session})
            return JSONResponse(content=session)

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await manager.connect(websocket)
            try:
                while True:
                    await websocket.receive_text()
            except WebSocketDisconnect:
                manager.disconnect(websocket)

    def _dashboard_html(self) -> str:
        return """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HunterAI — لوحة التحكم الأمنية</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; direction: rtl; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #38bdf8; font-size: 24px; }
        .badge { background: #38bdf8; color: #0f172a; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
        .card h3 { color: #38bdf8; margin-bottom: 10px; font-size: 18px; }
        .stat { font-size: 32px; font-weight: bold; color: #f8fafc; margin: 10px 0; }
        .stat-label { color: #94a3b8; font-size: 14px; }
        .table-container { background: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: right; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        tr:hover { background: #334155; }
        .severity-high { color: #f87171; }
        .severity-medium { color: #fbbf24; }
        .severity-low { color: #4ade80; }
        .severity-info { color: #38bdf8; }
        .status-running { color: #fbbf24; animation: pulse 2s infinite; }
        .status-completed { color: #4ade80; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .input-group { display: flex; gap: 10px; margin-bottom: 20px; }
        input[type="text"] { flex: 1; padding: 10px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0; }
        button { background: #38bdf8; color: #0f172a; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }
        button:hover { background: #7dd3fc; }
        .ws-status { display: inline-block; width: 8px; height: 8px; background: #4ade80; border-radius: 50%; margin-right: 8px; }
        .ws-disconnected { background: #f87171; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ HunterAI Dashboard</h1>
                <div class="badge">نظام التحقيق الأمني الذاتي</div>
            </div>
            <div>
                <span class="ws-status" id="wsStatus"></span>
                <span id="wsText">متصل</span>
            </div>
        </div>

        <div class="input-group">
            <input type="text" id="targetInput" placeholder="أدخل الهدف (مثل: https://example.com)">
            <select id="missionSelect" style="padding: 10px; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0;">
                <option value="full">فحص شامل</option>
                <option value="auth">تدقيق المصادقة</option>
                <option value="bola">فحص BOLA/IDOR</option>
                <option value="api">تدقيق API</option>
            </select>
            <button onclick="startScan()">بدء المسح</button>
        </div>

        <div class="grid">
            <div class="card">
                <h3>الجلسات النشطة</h3>
                <div class="stat" id="sessionsCount">0</div>
                <div class="stat-label">جلسة مسح</div>
            </div>
            <div class="card">
                <h3>النتائج المكتشفة</h3>
                <div class="stat" id="findingsCount">0</div>
                <div class="stat-label">نتيجة أمنية</div>
            </div>
            <div class="card">
                <h3>النتائج المؤكدة</h3>
                <div class="stat" id="verifiedCount">0</div>
                <div class="stat-label">نتيجة مؤكدة بالاستغلال</div>
            </div>
            <div class="card">
                <h3>مستوى الخطر الأعلى</h3>
                <div class="stat" id="maxSeverity">—</div>
                <div class="stat-label">أعلى درجة خطر</div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>المعرف</th>
                        <th>النوع</th>
                        <th>الهدف</th>
                        <th>الشدة</th>
                        <th>الحالة</th>
                        <th>الثقة</th>
                        <th>التاريخ</th>
                    </tr>
                </thead>
                <tbody id="findingsTable">
                </tbody>
            </table>
        </div>

        <div class="card" style="margin-top: 20px;">
            <h3>السجل اللحظي</h3>
            <div id="logContainer" style="height: 300px; overflow-y: auto; background: #0f172a; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #94a3b8;">
            </div>
        </div>
    </div>

    <script>
        const wsStatus = document.getElementById('wsStatus');
        const wsText = document.getElementById('wsText');
        const logContainer = document.getElementById('logContainer');

        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        ws.onopen = () => {
            wsStatus.className = 'ws-status';
            wsText.textContent = 'متصل';
            addLog('تم الاتصال بلوحة التحكم');
        };
        ws.onclose = () => {
            wsStatus.className = 'ws-disconnected';
            wsText.textContent = 'غير متصل';
            addLog('انقطع الاتصال بلوحة التحكم');
        };
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.event === 'session_started') {
                addLog(`بدء مسح جديد: ${data.session.target}`);
                loadData();
            }
        };

        function addLog(msg) {
            const time = new Date().toLocaleTimeString();
            const div = document.createElement('div');
            div.textContent = `[${time}] ${msg}`;
            logContainer.appendChild(div);
            logContainer.scrollTop = logContainer.scrollHeight;
        }

        async function startScan() {
            const target = document.getElementById('targetInput').value;
            const mission = document.getElementById('missionSelect').value;
            if (!target) {
                alert('يرجى إدخال الهدف');
                return;
            }
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target, mission})
            });
            const data = await res.json();
            addLog(`تم بدء مسح: ${data.target} (${data.mission})`);
            loadData();
        }

        async function loadData() {
            const [sessionsRes, findingsRes] = await Promise.all([
                fetch('/api/sessions'),
                fetch('/api/findings')
            ]);
            const sessions = await sessionsRes.json();
            const findings = await findingsRes.json();

            document.getElementById('sessionsCount').textContent = sessions.length;
            document.getElementById('findingsCount').textContent = findings.length;
            const verified = findings.filter(f => f.evidence_level === 'E1').length;
            document.getElementById('verifiedCount').textContent = verified;

            const tbody = document.getElementById('findingsTable');
            tbody.innerHTML = '';
            findings.forEach(f => {
                const tr = document.createElement('tr');
                const severityClass = `severity-${(f.severity || 'info').toLowerCase()}`;
                tr.innerHTML = `
                    <td>${f.record_id || f.id || '—'}</td>
                    <td>${f.template_id || f.type || '—'}</td>
                    <td>${f.matched_at || f.url || f.target || '—'}</td>
                    <td class="${severityClass}">${f.severity || 'Info'}</td>
                    <td>${f.status || 'pending'}</td>
                    <td>${(f.confidence * 100).toFixed(0)}%</td>
                    <td>${new Date().toLocaleDateString()}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        setInterval(loadData, 5000);
        loadData();
    </script>
</body>
</html>"""

    def run(self):
        if not HAS_FASTAPI:
            log.error("FastAPI not installed. Install with: pip install fastapi uvicorn jinja2")
            return
        import uvicorn
        uvicorn.run(self.app, host=self.host, port=self.port)
