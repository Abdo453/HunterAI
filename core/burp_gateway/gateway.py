"""
HunterAI Burp Gateway
=====================
High-performance local REST bridge (127.0.0.1:8085) connecting Burp Suite to HunterAI:
- Ingests live traffic from Proxy & Repeater
- Manages Task Queue (Scan / Plan / Add Scope from Context Menu)
- Directs findings through Evidence Court
- Exports confirmed findings to Burp Target tab
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction
from core.burp_gateway.issue_exporter import BurpIssueExporter
from core.burp_gateway.task_queue import BurpTask, TaskAction, TaskQueue

logger = logging.getLogger("hunter_ai.burp_gateway")


class BurpGateway:
    """RESTful local bridge for bidirectional Burp Suite cooperation"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8085,
        capture_store: Optional[CaptureStore] = None,
        on_traffic_cb: Optional[Callable] = None,
        task_executor_fn: Optional[Callable[[BurpTask], Any]] = None,
    ):
        self.host = host
        self.port = port
        self.capture_store = capture_store or CaptureStore("target_gateway")
        self.on_traffic_cb = on_traffic_cb
        self.task_queue = TaskQueue(executor_fn=task_executor_fn)

        self.confirmed_findings: List[Dict[str, Any]] = []
        self.active_scope: Dict[str, List[str]] = {
            "include": [],
            "exclude": []
        }

        self.app = FastAPI(title="HunterAI Burp Suite Gateway Bridge", docs_url=None, redoc_url=None)
        self._server = None
        self._setup_routes()

    def _setup_routes(self):
        @self.app.get("/health")
        @self.app.get("/status")
        async def health():
            return {
                "status": "online",
                "service": "HunterAI Burp Gateway",
                "port": self.port,
                "capture_store": self.capture_store.get_summary(),
                "tasks_queued": len(self.task_queue.list_tasks()),
                "confirmed_findings": len(self.confirmed_findings),
            }

        @self.app.post("/api/traffic")
        async def ingest_traffic(req: Request, bg: BackgroundTasks):
            """Receives live HTTP transaction from Burp Extender"""
            try:
                payload = await req.json()
                req_str = payload.get("request", "")
                resp_str = payload.get("response", "")
                host = payload.get("host", "target.local")
                port = payload.get("port", 80)
                proto = payload.get("protocol", "http")

                # Parse request line
                lines = req_str.splitlines() if req_str else []
                first_line = lines[0] if lines else "GET / HTTP/1.1"
                parts = first_line.split()
                method = parts[0] if len(parts) > 0 else "GET"
                path = parts[1] if len(parts) > 1 else "/"
                full_url = f"{proto}://{host}:{port}{path}" if port not in (80, 443) else f"{proto}://{host}{path}"

                # Parse status code
                resp_lines = resp_str.splitlines() if resp_str else []
                resp_first = resp_lines[0] if resp_lines else "HTTP/1.1 200 OK"
                status_parts = resp_first.split()
                status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200

                tx = CapturedTransaction(
                    tx_id=payload.get("tx_id", ""),
                    target_host=host,
                    method=method,
                    url=full_url,
                    status_code=status_code,
                    req_body=req_str,
                    resp_body=resp_str,
                    tool_source=payload.get("tool", "proxy")
                )

                # Persist to CaptureStore
                self.capture_store.store_transaction(tx)

                # Broadcast to on_traffic_cb
                if self.on_traffic_cb:
                    bg.add_task(self.on_traffic_cb, payload)

                return {"status": "INGESTED", "tx_id": tx.tx_id, "url": full_url}
            except Exception as e:
                logger.error(f"[GATEWAY] Traffic ingestion error: {e}")
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.post("/api/tasks")
        async def create_task(req: Request):
            """Receives task dispatch from Burp Context Menu"""
            try:
                data = await req.json()
                action_str = data.get("action", "SCAN").upper()
                target_url = data.get("target_url") or data.get("url")
                if not target_url:
                    return JSONResponse(status_code=400, content={"error": "target_url is required"})

                action = TaskAction[action_str] if action_str in TaskAction.__members__ else TaskAction.SCAN
                task = self.task_queue.enqueue(action, target_url, data.get("payload", {}))
                return {"status": "QUEUED", "task": task.to_dict()}
            except Exception as e:
                logger.error(f"[GATEWAY] Task creation error: {e}")
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.get("/api/tasks")
        async def list_tasks():
            return {"tasks": self.task_queue.list_tasks()}

        @self.app.get("/api/tasks/{task_id}")
        async def get_task(task_id: str):
            t = self.task_queue.get_task(task_id)
            if not t:
                return JSONResponse(status_code=404, content={"error": "Task not found"})
            return t.to_dict()

        @self.app.post("/api/scope")
        async def update_scope(req: Request):
            """Adds a host to HunterAI scope directly from Burp"""
            try:
                data = await req.json()
                host = data.get("host")
                if host and host not in self.active_scope["include"]:
                    self.active_scope["include"].append(host)
                    self.capture_store.save_scope(self.active_scope["include"], self.active_scope["exclude"])
                return {"status": "UPDATED", "scope": self.active_scope}
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.get("/api/scope")
        async def get_scope():
            return self.active_scope

        @self.app.post("/api/issues/burp")
        async def receive_burp_issue(req: Request):
            """Receives native Burp Scanner issues to correlate into Evidence Graph"""
            try:
                data = await req.json()
                self.capture_store.record_timeline_event("BURP_SCANNER_ISSUE_INGESTED", data)
                return {"status": "INGESTED", "issue": data.get("name", "Burp Issue")}
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.get("/api/issues/export")
        async def export_issues_for_burp():
            """Exports confirmed HunterAI findings formatted for Burp Suite Target tab import"""
            formatted = BurpIssueExporter.export_all(self.confirmed_findings)
            return {"issues_count": len(formatted), "issues": formatted}

    def register_confirmed_finding(self, finding: Dict[str, Any]):
        """Called by Evidence Court when a finding is CONFIRMED"""
        self.confirmed_findings.append(finding)
        self.capture_store.record_finding(finding)

    async def start(self):
        await self.task_queue.start()
        config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="warning",
            lifespan="off"
        )
        self._server = uvicorn.Server(config)
        self._server.install_signal_handlers = lambda: None
        logger.info(f"[GATEWAY] HunterAI Burp Gateway running on http://{self.host}:{self.port}")
        await self._server.serve()

    def stop(self):
        if self._server:
            self._server.should_exit = True
        asyncio.create_task(self.task_queue.stop())
