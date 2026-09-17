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
from core.burp_gateway.provenance import EvidenceProvenanceEngine, ProvenanceStage
from core.burp_gateway.handoff_contract import AgentHandoffContract
from core.burp_gateway.correlation import BurpCorrelationContext
from core.burp_gateway.traffic_normalizer import BurpTrafficNormalizer, CanonicalRequest
from core.burp_gateway.experiment_queue import BurpExperimentQueue, BurpExperimentItem
from core.burp_gateway.event_stream import BurpLiveEventStream



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
        scope_engine: Optional[Any] = None,
    ):
        self.host = host
        self.port = port
        self.capture_store = capture_store or CaptureStore("target_gateway")
        self.on_traffic_cb = on_traffic_cb
        self.task_queue = TaskQueue(executor_fn=task_executor_fn)
        self.provenance_engine = EvidenceProvenanceEngine()
        self.cases: Dict[str, AgentHandoffContract] = {}

        self.confirmed_findings: List[Dict[str, Any]] = []
        self.active_scope: Dict[str, List[str]] = {
            "include": [],
            "exclude": []
        }
        if scope_engine is not None:
            self.scope_engine = scope_engine
            if hasattr(scope_engine, "in_scope"):
                self.active_scope["include"] = list(scope_engine.in_scope)
            if hasattr(scope_engine, "out_of_scope"):
                self.active_scope["exclude"] = list(scope_engine.out_of_scope)
        else:
            from core.scope_guard import ScopeGuard
            self.scope_engine = ScopeGuard(
                in_scope=self.active_scope["include"],
                out_of_scope=self.active_scope["exclude"]
            )

        self.event_stream = BurpLiveEventStream()
        self.experiment_queue = BurpExperimentQueue()
        from core.controllers.burp_research_controller import BurpResearchController
        self.research_controller = BurpResearchController(
            scope_guard=self.scope_engine,
            capture_store=self.capture_store,
            experiment_queue=self.experiment_queue,
            event_stream=self.event_stream,
        )
        from core.burp_gateway.bcsl import BurpControlSensorLayer
        self.bcsl = BurpControlSensorLayer(
            research_controller=self.research_controller,
            scope_guard=self.scope_engine,
            event_stream=self.event_stream,
            capture_store=self.capture_store,
        )

        self.app = FastAPI(title="HunterAI Burp Suite Gateway Bridge", docs_url=None, redoc_url=None)
        self._server = None
        self._setup_routes()

    def set_scope(self, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None):
        """Programmatically updates active scope filters and recompiles scope engine"""
        if include is not None:
            self.active_scope["include"] = list(include)
        if exclude is not None:
            self.active_scope["exclude"] = list(exclude)
        from core.scope_guard import ScopeGuard
        self.scope_engine = ScopeGuard(
            in_scope=self.active_scope["include"],
            out_of_scope=self.active_scope["exclude"]
        )
        self.capture_store.save_scope(self.active_scope["include"], self.active_scope["exclude"])
        if hasattr(self, "research_controller"):
            self.research_controller.scope_guard = self.scope_engine
        if hasattr(self, "bcsl"):
            self.bcsl.scope_guard = self.scope_engine

    def check_scope(self, target: str, url: Optional[str] = None) -> tuple[bool, str]:
        """Checks target or full URL against configured scope engine"""
        target_to_check = url or target
        if hasattr(self.scope_engine, "is_allowed"):
            return self.scope_engine.is_allowed(target_to_check)
        elif hasattr(self.scope_engine, "is_in_scope"):
            return self.scope_engine.is_in_scope(target_to_check)
        return True, "Authorized (Permissive)"

    def _setup_routes(self):
        from core.controllers.burp_research_controller import ScopeViolationError

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

                # Parse request line & headers vs body
                req_headers = {}
                req_body = ""
                clean_req = req_str.replace("\\r\\n", "\r\n").replace("\\n", "\n") if "\\r\\n" in req_str or "\\n" in req_str else req_str
                if "\r\n\r\n" in clean_req:
                    hdr_part, req_body = clean_req.split("\r\n\r\n", 1)
                elif "\n\n" in clean_req:
                    hdr_part, req_body = clean_req.split("\n\n", 1)
                else:
                    hdr_part = clean_req
                    req_body = ""

                lines = hdr_part.splitlines() if hdr_part else []
                first_line = lines[0] if lines else "GET / HTTP/1.1"
                parts = first_line.split()
                method = parts[0] if len(parts) > 0 else "GET"
                path = parts[1] if len(parts) > 1 else "/"
                full_url = f"{proto}://{host}:{port}{path}" if port not in (80, 443) else f"{proto}://{host}{path}"

                for hline in lines[1:]:
                    if ":" in hline:
                        hk, hv = hline.split(":", 1)
                        req_headers[hk.strip()] = hv.strip()

                # Parse response line & headers vs body
                resp_headers = {}
                resp_body = ""
                clean_resp = resp_str.replace("\\r\\n", "\r\n").replace("\\n", "\n") if "\\r\\n" in resp_str or "\\n" in resp_str else resp_str
                if "\r\n\r\n" in clean_resp:
                    rhdr_part, resp_body = clean_resp.split("\r\n\r\n", 1)
                elif "\n\n" in clean_resp:
                    rhdr_part, resp_body = clean_resp.split("\n\n", 1)
                else:
                    rhdr_part = clean_resp
                    resp_body = ""

                resp_lines = rhdr_part.splitlines() if rhdr_part else []
                resp_first = resp_lines[0] if resp_lines else "HTTP/1.1 200 OK"
                status_parts = resp_first.split()
                status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200

                for hline in resp_lines[1:]:
                    if ":" in hline:
                        hk, hv = hline.split(":", 1)
                        resp_headers[hk.strip()] = hv.strip()

                # ── ACTIVE SCOPE ENFORCEMENT BARRIER ──────────────────────────
                is_in_scope, scope_reason = self.check_scope(host, full_url)
                if not is_in_scope:
                    self.capture_store.record_timeline_event(
                        "TRAFFIC_DROPPED_OUT_OF_SCOPE",
                        {
                            "host": host,
                            "url": full_url,
                            "tool": payload.get("tool", "proxy"),
                            "reason": scope_reason,
                            "status": "BLOCKED"
                        }
                    )
                    logger.warning(f"[GATEWAY SCOPE GUARD] Dropped out-of-scope traffic: {host} ({scope_reason})")
                    return JSONResponse(
                        status_code=403,
                        content={
                            "status": "DROPPED_OUT_OF_SCOPE",
                            "reason": scope_reason,
                            "host": host,
                            "url": full_url
                        }
                    )

                tx = CapturedTransaction(
                    tx_id=payload.get("tx_id", ""),
                    target_host=host,
                    method=method,
                    url=full_url,
                    status_code=status_code,
                    req_headers=req_headers,
                    req_body=req_body,
                    resp_headers=resp_headers,
                    resp_body=resp_body,
                    tool_source=payload.get("tool", "proxy"),
                    parent_request=payload.get("parent_request")
                )

                # Persist to CaptureStore (In-Scope Only)
                self.capture_store.store_transaction(tx)

                # Broadcast to event stream & normalize into research controller
                self.event_stream.publish_event("REQUEST_INGESTED", {
                    "tx_id": tx.tx_id,
                    "host": host,
                    "url": full_url,
                    "method": method,
                    "status_code": status_code,
                    "tool": payload.get("tool", "proxy")
                })
                can_tx = BurpTrafficNormalizer.normalize_dict(payload)
                self.research_controller.ingest_canonical(can_tx)

                # Broadcast to on_traffic_cb (In-Scope Only)
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

                # Scope check before queueing task
                is_in_scope, scope_reason = self.check_scope(target_url)
                if not is_in_scope:
                    self.capture_store.record_timeline_event(
                        "TASK_REJECTED_OUT_OF_SCOPE",
                        {
                            "target_url": target_url,
                            "action": action_str,
                            "reason": scope_reason,
                            "status": "REJECTED"
                        }
                    )
                    return JSONResponse(
                        status_code=403,
                        content={"status": "REJECTED_OUT_OF_SCOPE", "reason": scope_reason, "target_url": target_url}
                    )

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
            """Adds a host or updates scope directly from Burp"""
            try:
                data = await req.json()
                host = data.get("host")
                action = data.get("action", "include")
                includes = data.get("include")
                excludes = data.get("exclude")

                if includes is not None or excludes is not None:
                    self.set_scope(include=includes, exclude=excludes)
                elif host:
                    if action == "exclude":
                        if host not in self.active_scope["exclude"]:
                            self.active_scope["exclude"].append(host)
                    else:
                        if host not in self.active_scope["include"]:
                            self.active_scope["include"].append(host)
                    self.set_scope(self.active_scope["include"], self.active_scope["exclude"])

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

        @self.app.get("/api/traffic/{tx_id}/lineage")
        async def get_traffic_lineage(tx_id: str):
            """Returns parent/child request ancestry lineage"""
            lineage = self.capture_store.get_request_lineage(tx_id)
            return {"tx_id": tx_id, "lineage_depth": len(lineage), "lineage": lineage}

        @self.app.post("/api/cases")
        async def create_or_update_case(req: Request):
            """Receives structured AgentHandoffContract / InvestigationCase"""
            try:
                data = await req.json()
                case = AgentHandoffContract.from_dict(data)
                self.cases[case.case_id] = case
                case.save(self.capture_store.root_dir / "cases")
                return {"status": "STORED", "case_id": case.case_id}
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.get("/api/cases")
        async def list_cases():
            """Lists active investigation cases"""
            return {"cases": [c.to_dict() for c in self.cases.values()]}

        @self.app.get("/api/cases/{case_id}")
        async def get_case(case_id: str):
            """Retrieves an investigation case dossier"""
            case = self.cases.get(case_id) or AgentHandoffContract.load(case_id, self.capture_store.root_dir / "cases")
            if not case:
                return JSONResponse(status_code=404, content={"error": "Case not found"})
            return case.to_dict()

        @self.app.get("/api/provenance/{trace_or_case_id}")
        async def get_provenance(trace_or_case_id: str):
            """Retrieves 7-stage causal provenance trace"""
            trace = self.provenance_engine.get_trace(trace_or_case_id)
            if not trace:
                return JSONResponse(status_code=404, content={"error": "Provenance trace not found"})
            return trace.to_dict()
        @self.app.post("/api/research/replay")
        async def research_replay(req: Request):
            """Executes active verification replay via Research Controller"""
            try:
                data = await req.json()
                req_id = data.get("request_id")
                if not req_id:
                    return JSONResponse(status_code=400, content={"error": "request_id is required"})
                mutation = data.get("mutation")
                reason = data.get("reason", "API Replay")
                try:
                    res = self.research_controller.replay(request_id=req_id, mutation=mutation, reason=reason)
                    return res.to_dict()
                except ScopeViolationError as sve:
                    return JSONResponse(status_code=403, content={"error": "ScopeViolation", "detail": str(sve)})
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.post("/api/research/repeater")
        async def research_send_repeater(req: Request):
            """Provisions a Repeater tab via Research Controller"""
            try:
                data = await req.json()
                req_id = data.get("request_id")
                tab_name = data.get("tab_name")
                if req_id:
                    tab_id = self.research_controller.send_to_repeater(req_id, tab_name=tab_name)
                    return {"status": "PROVISIONED", "tab_id": tab_id}
                elif "url" in data:
                    c_req = CanonicalRequest(
                        method=data.get("method", "GET"),
                        url=data["url"],
                        headers=data.get("headers", {}),
                        body=data.get("body", ""),
                    )
                    tab_id = self.research_controller.send_to_repeater(c_req, tab_name=tab_name)
                    return {"status": "PROVISIONED", "tab_id": tab_id}
                return JSONResponse(status_code=400, content={"error": "request_id or url required"})
            except ScopeViolationError as sve:
                return JSONResponse(status_code=403, content={"error": "ScopeViolation", "detail": str(sve)})
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.post("/api/research/queue")
        async def research_queue_exp(req: Request):
            """Enqueues an experiment in BurpExperimentQueue"""
            try:
                data = await req.json()
                url = data.get("url")
                if not url:
                    return JSONResponse(status_code=400, content={"error": "url is required"})
                c_req = CanonicalRequest(
                    method=data.get("method", "GET"),
                    url=url,
                    headers=data.get("headers", {}),
                    body=data.get("body", "")
                )
                exp_id = self.research_controller.queue(
                    request=c_req,
                    priority=int(data.get("priority", 5)),
                    eig=float(data.get("eig", 0.5)),
                    risk_tier=data.get("risk_tier", "LOW_RISK"),
                )
                return {"status": "QUEUED", "experiment_id": exp_id}
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})

        @self.app.get("/api/research/queue")
        async def research_list_queue():
            """Returns queue metrics and experiment items"""
            return {
                "metrics": self.experiment_queue.get_metrics(),
                "items": [it.to_dict() for it in self.experiment_queue.list_items()],
            }

        @self.app.delete("/api/research/queue/{exp_id}")
        async def research_cancel_queue(exp_id: str):
            """Cancels an experiment in the queue"""
            ok = self.research_controller.cancel(exp_id)
            if ok:
                return {"status": "CANCELLED", "experiment_id": exp_id}
            return JSONResponse(status_code=404, content={"error": "Experiment not found or already executed"})

        @self.app.get("/api/stream/events")
        async def stream_events(limit: int = 50):
            """Returns recent events from the live event stream"""
            events = self.event_stream.get_recent_events(limit=limit)
            return {"events_count": len(events), "events": [e.to_dict() for e in events]}

        @self.app.post("/api/research/experiment")
        async def research_experiment(req: Request):
            """Executes structured ExperimentContract through BCSL"""
            try:
                data = await req.json()
                from core.burp_gateway.experiment_contract import ExperimentContract
                contract = ExperimentContract.from_dict(data)
                record = self.bcsl.submit_experiment(contract)
                return record.to_dict()
            except Exception as e:
                return JSONResponse(status_code=400, content={"error": str(e)})



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
