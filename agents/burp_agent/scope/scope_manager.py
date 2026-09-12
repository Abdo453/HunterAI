"""
Scope Manager for BurpAgent
Filters in-scope targets vs out-of-scope noise (e.g. analytics, CDNs, tracking).
"""
import fnmatch
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

log = logging.getLogger("burp_agent.scope")


class ScopeManager:
    """متحكم نطاق الفحص والفلترة الذكية للترافيك المسموح بتحليله"""

    DEFAULT_EXCLUDES = [
        "*.google-analytics.com",
        "*.doubleclick.net",
        "*.googletagmanager.com",
        "*.facebook.com",
        "*.clarity.ms",
        "*.hotjar.com",
        "*.sentry.io",
        "*.segment.io",
        "*.optimizely.com",
        "*.bootstrapcdn.com",
        "*.fontawesome.com"
    ]

    def __init__(self, include_rules: Optional[List[str]] = None, exclude_rules: Optional[List[str]] = None):
        self.include_rules = include_rules or ["*"]
        self.exclude_rules = (exclude_rules or []) + self.DEFAULT_EXCLUDES

    def is_in_scope(self, url: str) -> bool:
        """التحقق مما إذا كان الرابط يقع داخل نطاق التحليل المصرح به"""
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or "").split(":")[0].lower()
            if not host:
                return False

            # 1. Check explicit excludes first
            for pattern in self.exclude_rules:
                if fnmatch.fnmatch(host, pattern.lower()) or fnmatch.fnmatch(url.lower(), pattern.lower()):
                    return False

            # 2. Check includes
            if "*" in self.include_rules:
                return True

            for pattern in self.include_rules:
                if fnmatch.fnmatch(host, pattern.lower()) or fnmatch.fnmatch(url.lower(), pattern.lower()):
                    return True

            return False
        except Exception as e:
            log.warning(f"Error checking scope for {url}: {e}")
            return True

    def add_include(self, pattern: str):
        if pattern not in self.include_rules:
            self.include_rules.append(pattern)

    def add_exclude(self, pattern: str):
        if pattern not in self.exclude_rules:
            self.exclude_rules.append(pattern)
