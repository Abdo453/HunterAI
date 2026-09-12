"""
JS Inventory & De-duplication Registry
======================================
Maintains SHA-256 fingerprint database to eliminate redundant analysis
of identical JavaScript bundles across multiple pages.
"""
import hashlib
import logging
from typing import Dict, Optional, Tuple

from core.code_intel.models import JSInventoryItem

logger = logging.getLogger("hunter_ai.code_intel.inventory")


class JSInventory:
    """Registry for discovered JavaScript files with cryptographic de-duplication"""

    def __init__(self):
        self._by_sha256: Dict[str, JSInventoryItem] = {}
        self._by_url: Dict[str, str] = {}  # url -> sha256

    def register(self, url: str, content: str, local_path: str = "") -> Tuple[JSInventoryItem, bool]:
        """
        Registers JS content.
        Returns: (JSInventoryItem, is_duplicate)
        """
        raw_bytes = content.encode("utf-8", errors="ignore")
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        if sha256 in self._by_sha256:
            existing = self._by_sha256[sha256]
            self._by_url[url] = sha256
            logger.debug(f"[JSInventory] Duplicate bundle detected: {url} matches sha256:{sha256[:8]}")
            return existing, True

        # Detect Framework
        framework = "vanilla"
        c_lower = content[:5000].lower() + content[-2000:].lower()
        if "next" in c_lower or "__next_data__" in c_lower or "_next/static" in url:
            framework = "next.js"
        elif "react" in c_lower or "reactdom" in c_lower:
            framework = "react"
        elif "vue" in c_lower:
            framework = "vue"
        elif "angular" in c_lower:
            framework = "angular"

        # Detect Minification
        lines = content.splitlines()[:50]
        avg_line_len = (sum(len(l) for l in lines) / len(lines)) if lines else 0
        minified = avg_line_len > 250 or ".min.js" in url

        # Detect Source Map
        has_map = "//# sourceMappingURL=" in content or "//@ sourceMappingURL=" in content
        map_url = None
        if has_map:
            for l in reversed(content.splitlines()[-5:]):
                if "sourceMappingURL=" in l:
                    map_url = l.split("sourceMappingURL=")[-1].strip()
                    break

        item = JSInventoryItem(
            url=url,
            local_path=local_path,
            sha256=sha256,
            size_bytes=len(raw_bytes),
            framework=framework,
            minified=minified,
            has_source_map=has_map,
            source_map_url=map_url,
            status="analyzed"
        )
        self._by_sha256[sha256] = item
        self._by_url[url] = sha256
        return item, False

    def get_by_sha256(self, sha256: str) -> Optional[JSInventoryItem]:
        return self._by_sha256.get(sha256)

    def get_by_url(self, url: str) -> Optional[JSInventoryItem]:
        sha = self._by_url.get(url)
        return self._by_sha256.get(sha) if sha else None

    @property
    def total_unique_bundles(self) -> int:
        return len(self._by_sha256)