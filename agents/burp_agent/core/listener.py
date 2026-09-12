"""
Async HTTP Listener Server for Burp Suite Traffic (FastAPI/Uvicorn)
Receives forwarded HTTP requests and responses on 127.0.0.1:8085
"""
import asyncio
import logging
from typing import Optional, Callable
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn

log = logging.getLogger("burp_agent.listener")


class BurpTrafficListener:
    """سيرفر استقبال الترافيك المباشر القادم من إضافة Burp Extender"""

    def __init__(self, host: str = "127.0.0.1", port: int = 8085, on_traffic_cb: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.on_traffic_cb = on_traffic_cb
        self.app = FastAPI(title="HunterAI Burp Traffic Receiver", docs_url=None, redoc_url=None)
        self._server = None
        self._setup_routes()

    def _setup_routes(self):
        @self.app.get("/health")
        async def health():
            return {"status": "online", "receiver": "HunterAI Burp Agent"}

        @self.app.post("/api/traffic")
        async def receive_traffic(req: Request, bg: BackgroundTasks):
            """استقبال حزمة الترافيك (طلب + رد) القادمة من Burp Suite"""
            try:
                data = await req.json()
                if self.on_traffic_cb:
                    bg.add_task(self.on_traffic_cb, data)
                return {"status": "queued", "received": True}
            except Exception as e:
                log.error(f"[Listener] Error processing traffic payload: {e}")
                return JSONResponse(status_code=400, content={"error": str(e)})

    async def start(self):
        """بدء الاستماع في الخلفية بشكل غير متزامن وآمن"""
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((self.host, self.port)) == 0:
                    log.info(f"[Listener] Port {self.port} is already bound by another process. Skipping secondary listener.")
                    return
        except Exception:
            pass

        try:
            config = uvicorn.Config(
                app=self.app,
                host=self.host,
                port=self.port,
                log_level="warning",
                lifespan="off"
            )
            self._server = uvicorn.Server(config)
            self._server.install_signal_handlers = lambda: None
            log.info(f"[Listener] Burp Traffic Listener listening on http://{self.host}:{self.port}")
            await self._server.serve()
        except (Exception, SystemExit) as e:
            log.warning(f"[Listener] Burp Traffic Listener on {self.host}:{self.port} terminated cleanly: {e}")

    def stop(self):
        if self._server:
            self._server.should_exit = True

