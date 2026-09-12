"""
High-Speed In-Memory Cache with TTL & LRU eviction for BurpAgent
"""
import time
import collections
from typing import Any, Optional, Dict, Set

class TrafficCache:
    """كاش سريع بالذاكرة لمنع تكرار معالجة الطلبات المتطابقة وتخفيف الحمل"""
    
    def __init__(self, max_size: int = 50000, ttl_seconds: float = 3600.0):
        self.max_size = max_size
        self.ttl = ttl_seconds
        self._cache: collections.OrderedDict = collections.OrderedDict()
        self._seen_urls: Set[str] = set()
        self._seen_endpoints: Set[str] = set()

    def get(self, key: str) -> Optional[Any]:
        if key not in self._cache:
            return None
        val, expire_at = self._cache[key]
        if time.time() > expire_at:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return val

    def set(self, key: str, value: Any, custom_ttl: Optional[float] = None):
        if key in self._cache:
            del self._cache[key]
        elif len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
            
        expire = time.time() + (custom_ttl or self.ttl)
        self._cache[key] = (value, expire)

    def is_duplicate_request(self, method: str, url: str, body: Optional[str] = None) -> bool:
        key = f"req:{method}:{url}:{hash(body or '')}"
        if self.get(key):
            return True
        self.set(key, True, custom_ttl=300.0) # 5 min deduplication
        return False

    def is_new_endpoint(self, endpoint_id: str) -> bool:
        if endpoint_id in self._seen_endpoints:
            return False
        self._seen_endpoints.add(endpoint_id)
        return True

    def clear(self):
        self._cache.clear()
        self._seen_urls.clear()
        self._seen_endpoints.clear()
