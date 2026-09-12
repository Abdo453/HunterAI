"""
Tool Registry & Deterministic Triage Helpers
Fast deterministic filtering for traffic before triggering cognitive pipelines.
"""
import re
import urllib.parse
from typing import Dict, Any, List


class ToolRegistry:
    """سجل الأدوات المساعدة وفلاتر الفرز السريع لتوفير استهلاك الـ AI والموارد"""

    # Cheap static file extensions that do not warrant cognitive reasoning
    STATIC_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".map"
    }

    @classmethod
    def is_interesting_traffic(cls, url: str, method: str, headers: Dict[str, Any], body: Any) -> bool:
        """
        فلترة الترافيك السريعة: هل الطلب يستحق التحليل الذكي بالذكاء الاصطناعي؟
        """
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()

        # Reject static assets
        for ext in cls.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return False

        # Always interest if state-changing method
        if method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
            return True

        # Check for interesting path indicators
        if any(kw in path for kw in ["/api/", "/v1/", "/v2/", "/admin", "/user", "/auth", "/login", "/profile", "/order", "/account", "/manage", "/graphql"]):
            return True

        # Check for query parameters with potential logic
        if parsed.query and any(p in parsed.query.lower() for p in ["id=", "user=", "file=", "url=", "redirect=", "key=", "query=", "admin="]):
            return True

        return False

    @classmethod
    def extract_json_parameters(cls, data: Any) -> List[str]:
        if isinstance(data, dict):
            return list(data.keys())
        return []
