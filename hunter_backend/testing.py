"""Django + Pure ASGI synchronous/async test client helpers.

Placed inside ``hunter_backend`` so third-party ``site-packages/tests`` packages
never shadow test helper imports.
"""
from __future__ import annotations

import asyncio
import os
import threading
from typing import Any, Optional

import django
import httpx

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hunter_backend.settings")
django.setup()


def get_test_auth_headers(
    *,
    tier: str = "userTier",
    token: Optional[str] = None,
) -> dict[str, str]:
    """Build explicit test-only Authorization headers using the active local auth token."""
    from hunter_backend.auth import TOKEN_TIER, USER_TIER, get_or_create_api_token, issue_session_token

    if token is not None:
        return {"Authorization": f"Bearer {token}"}
    if tier == TOKEN_TIER:
        signed = issue_session_token(principal="test-agent", tier=TOKEN_TIER)
        return {"Authorization": f"Bearer {signed}"}
    if tier == USER_TIER:
        return {"Authorization": f"Bearer {get_or_create_api_token()}"}
    raise ValueError(f"Unsupported test auth tier: {tier!r}")


class ASGISyncClient:
    """Synchronous HTTP client driving ``hunter_backend.asgi.application`` over ASGI."""

    def __init__(
        self,
        app: Any = None,
        *,
        base_url: str = "http://127.0.0.1:8000",
        follow_redirects: bool = False,
        timeout: float = 30.0,
        raise_app_exceptions: bool = True,
        authenticated: bool = True,
        api_token: Optional[str] = None,
        auth_tier: str = "userTier",
    ) -> None:
        if app is None:
            from hunter_backend.asgi import application

            app = application
        self.app = app
        self.base_url = base_url
        self.follow_redirects = follow_redirects
        self.timeout = timeout
        self.raise_app_exceptions = raise_app_exceptions
        self.authenticated = authenticated
        self.api_token = api_token
        self.auth_tier = auth_tier
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._lifespan_in: Optional[asyncio.Queue[dict[str, Any]]] = None
        self._lifespan_out: Optional[asyncio.Queue[dict[str, Any]]] = None
        self._closed = False
        self._ensure_loop()

    def _ensure_loop(self) -> None:
        if self._loop is not None and not self._loop.is_closed():
            return
        ready = threading.Event()
        created: dict[str, asyncio.AbstractEventLoop] = {}

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            created["loop"] = loop
            ready.set()
            try:
                loop.run_forever()
            finally:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()

        t = threading.Thread(target=_runner, name="asgi-sync-client", daemon=True)
        t.start()
        ready.wait(timeout=5.0)
        self._loop = created["loop"]
        self._thread = t
        transport = httpx.ASGITransport(
            app=self.app,
            raise_app_exceptions=self.raise_app_exceptions,
        )
        self._client = httpx.AsyncClient(
            transport=transport,
            base_url=self.base_url,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
        )

    def _run(self, coro: Any) -> Any:
        self._ensure_loop()
        assert self._loop is not None
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=max(self.timeout + 5.0, 30.0))

    async def _send_lifespan(self, msg_type: str, expected: str) -> None:
        assert self._lifespan_in is not None and self._lifespan_out is not None
        await self._lifespan_in.put({"type": msg_type})
        while True:
            ev = await asyncio.wait_for(self._lifespan_out.get(), timeout=10.0)
            if ev.get("type") == expected:
                return
            if ev.get("type", "").endswith(".failed"):
                raise RuntimeError(ev.get("message") or f"ASGI lifespan failure: {ev}")

    def __enter__(self) -> "ASGISyncClient":
        self._ensure_loop()

        async def _setup_lifespan() -> None:
            self._lifespan_in = asyncio.Queue()
            self._lifespan_out = asyncio.Queue()

            async def _recv() -> dict[str, Any]:
                assert self._lifespan_in is not None
                return await self._lifespan_in.get()

            async def _send(msg: dict[str, Any]) -> None:
                assert self._lifespan_out is not None
                await self._lifespan_out.put(msg)

            scope = {"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}}
            asyncio.create_task(self.app(scope, _recv, _send))
            await self._send_lifespan("lifespan.startup", "lifespan.startup.complete")

        self._run(_setup_lifespan())
        return self

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._loop is not None and not self._loop.is_closed():
            if self._lifespan_in is not None and self._lifespan_out is not None:
                try:
                    self._run(self._send_lifespan("lifespan.shutdown", "lifespan.shutdown.complete"))
                except Exception:
                    pass
            if self._client is not None:
                try:
                    self._run(self._client.aclose())
                except Exception:
                    pass
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def __exit__(self, *args: Any) -> None:
        self.close()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        assert self._client is not None
        if self.authenticated:
            headers = dict(kwargs.get("headers") or {})
            lower_keys = {k.lower() for k in headers}
            if "authorization" not in lower_keys and "x-hunter-token" not in lower_keys:
                headers.update(
                    get_test_auth_headers(tier=self.auth_tier, token=self.api_token)
                )
                kwargs["headers"] = headers
        return self._run(self._client.request(method, url, **kwargs))

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("OPTIONS", url, **kwargs)


def make_async_client(
    *,
    base_url: str = "http://127.0.0.1:8000",
    follow_redirects: bool = False,
    timeout: float = 30.0,
    authenticated: bool = True,
    api_token: Optional[str] = None,
    auth_tier: str = "userTier",
) -> httpx.AsyncClient:
    """Create an ``httpx.AsyncClient`` bound to ``hunter_backend.asgi.application``."""
    from hunter_backend.asgi import application

    default_headers = (
        get_test_auth_headers(tier=auth_tier, token=api_token) if authenticated else {}
    )
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url=base_url,
        follow_redirects=follow_redirects,
        timeout=timeout,
        headers=default_headers,
    )
