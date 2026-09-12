"""
Application & Security Memory for BurpAgent
Maintains long-term knowledge of targets, roles, observed IDs, and privilege states across the entire assessment.
"""
import logging
from typing import Dict, Any, List, Set

log = logging.getLogger("burp_agent.memory")


class ApplicationMemory:
    """ذاكرة التطبيق لفهم بنية وصلاحيات ومستخدمي الهدف أثناء تصفح الترافيك"""

    def __init__(self):
        self.known_roles: Set[str] = set()
        self.known_users: Set[str] = set()
        self.admin_routes: Set[str] = set()
        self.api_versions: Set[str] = set()
        self.auth_tokens: Dict[str, str] = {} # token -> role/user
        self.observed_ids: Set[str] = set()

    def record_user_identifier(self, user_id: str):
        self.observed_ids.add(str(user_id))

    def record_admin_route(self, route: str):
        self.admin_routes.add(route)

    def record_role(self, role: str):
        self.known_roles.add(role.lower())

    def get_context_for_ai(self) -> Dict[str, Any]:
        return {
            "known_roles": list(self.known_roles),
            "admin_routes": list(self.admin_routes)[:10],
            "observed_user_ids": list(self.observed_ids)[:10],
            "api_versions": list(self.api_versions)
        }
