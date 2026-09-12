"""
Application Target State & Session Context Manager
"""
import time
from typing import Dict, Any, List, Optional, Set

class ApplicationContext:
    """إدارة الحالة والسياق الزمني للهدف أثناء التقاط الترافيك"""

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.session_id: Optional[str] = None
        self.auth_tokens: Set[str] = set()
        self.jwt_claims: List[Dict[str, Any]] = []
        self.observed_users: Set[str] = set()
        self.observed_roles: Set[str] = set()
        self.admin_endpoints: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.start_time: float = time.time()
        self.last_activity: float = time.time()

    def update_activity(self):
        self.last_activity = time.time()

    def add_auth_token(self, token: str):
        self.auth_tokens.add(token)

    def add_admin_endpoint(self, endpoint_id: str):
        self.admin_endpoints.add(endpoint_id)

    def add_user_role(self, role: str):
        self.observed_roles.add(role)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "roles_observed": list(self.observed_roles),
            "admin_endpoints_count": len(self.admin_endpoints),
            "api_endpoints_count": len(self.api_endpoints),
            "auth_tokens_count": len(self.auth_tokens),
            "active_duration_sec": round(time.time() - self.start_time, 2)
        }
