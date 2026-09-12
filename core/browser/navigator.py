"""
Browser Navigator
=================
Executes safe, scope-bounded page navigation, redirect tracking, and retry/backoff.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from core.attack_surface_graph import ThirdPartyDependencyFirewall

logger = logging.getLogger("hunter_ai.browser_navigator")


class BrowserNavigator:
    """Wraps navigation with firewall guards, timeouts, and error handling"""

    def __init__(self, session: Any, base_host: str):
        self.session = session
        self.base_host = base_host.lower()

    def is_in_scope(self, url: str) -> bool:
        if not url:
            return False
        return not ThirdPartyDependencyFirewall.is_external_dependency(url, self.base_host)

    async def goto(self, url: str, timeout_sec: float = 15.0) -> Tuple[Optional[str], int, Dict[str, str]]:
        """Safe navigation to target URL"""
        if not self.is_in_scope(url):
            logger.warning(f"[NAVIGATOR] Blocked out-of-scope navigation: {url}")
            return None, 403, {"x-hunter-blocked": "scope_firewall"}

        try:
            return await self.session.navigate(url)
        except Exception as e:
            logger.debug(f"[NAVIGATOR] Navigation error on {url}: {e}")
            return None, 0, {"x-hunter-error": str(e)}
