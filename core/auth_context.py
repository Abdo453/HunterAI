"""
HunterAI Multi-Role Authentication Context Engine
=================================================
Maintains distinct authenticated and unauthenticated sessions:
- Anonymous
- User A (Role A)
- User B (Role B)
- Admin (Authorized only)
- Expired / Revoked

Enables rigorous IDOR, Broken Object Level Authorization (BOLA),
and Broken Function Level Authorization (BFLA) differential testing.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.auth_context")


class AuthRole(str, Enum):
    ANONYMOUS = "anonymous"
    USER_A = "user_a"
    USER_B = "user_b"
    ADMIN = "admin"
    EXPIRED = "expired"


@dataclass
class AuthSession:
    role: AuthRole
    username: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    owned_object_ids: List[str] = field(default_factory=list)
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DifferentialAuthTest:
    endpoint: str
    method: str
    target_object_id: str
    owner_role: AuthRole
    tester_role: AuthRole
    test_headers: Dict[str, str]
    test_cookies: Dict[str, str]
    expected_safe_status: List[int]  # Typically [401, 403, 404]
    vuln_class: str = "IDOR / Broken Access Control"
    hypothesis_text: str = ""


class AuthContextManager:
    """
    Manages session state across all roles and outputs artifacts to auth_context/
    """

    def __init__(self, storage_dir: str):
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: Dict[AuthRole, AuthSession] = {}

        # Default anonymous session
        self.sessions[AuthRole.ANONYMOUS] = AuthSession(role=AuthRole.ANONYMOUS)
        self._save_session(self.sessions[AuthRole.ANONYMOUS])

    def _save_session(self, session: AuthSession) -> None:
        file_path = self.storage_dir / f"{session.role.value}.json"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to persist auth session {session.role}: {e}")

    def register_user(
        self,
        role: AuthRole,
        username: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        tokens: Optional[Dict[str, str]] = None,
        owned_object_ids: Optional[List[str]] = None,
    ) -> AuthSession:
        """Register or update an authenticated role session"""
        sess = AuthSession(
            role=role,
            username=username,
            cookies=cookies or {},
            headers=headers or {},
            tokens=tokens or {},
            owned_object_ids=owned_object_ids or [],
        )
        self.sessions[role] = sess
        self._save_session(sess)
        logger.info(f"AUTH CONTEXT: Registered session for role '{role.value}' (User: {username})")
        return sess

    def get_session(self, role: AuthRole) -> Optional[AuthSession]:
        return self.sessions.get(role)

    def generate_differential_test(
        self,
        endpoint: str,
        method: str,
        target_object_id: str,
        owner_role: AuthRole = AuthRole.USER_A,
        tester_role: AuthRole = AuthRole.USER_B,
    ) -> Optional[DifferentialAuthTest]:
        """
        Generates a strictly formulated differential authorization test plan:
        Owner owns target_object_id, but request is sent with tester_role's credentials.
        """
        tester_sess = self.get_session(tester_role)
        if not tester_sess:
            logger.warning(f"Cannot generate differential test: Tester role '{tester_role}' not configured.")
            return None

        # Prepare test headers / cookies
        headers = dict(tester_sess.headers)
        if "Authorization" not in headers and "bearer_token" in tester_sess.tokens:
            headers["Authorization"] = f"Bearer {tester_sess.tokens['bearer_token']}"

        hyp_text = (
            f"Endpoint '{endpoint}' allows {tester_role.value} to access object '{target_object_id}' "
            f"owned by {owner_role.value} without strict server-side authorization enforcement."
        )

        return DifferentialAuthTest(
            endpoint=endpoint,
            method=method.upper(),
            target_object_id=target_object_id,
            owner_role=owner_role,
            tester_role=tester_role,
            test_headers=headers,
            test_cookies=tester_sess.cookies,
            expected_safe_status=[401, 403, 404],
            vuln_class="IDOR / Broken Object Level Authorization",
            hypothesis_text=hyp_text,
        )
