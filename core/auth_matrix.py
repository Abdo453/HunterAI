"""
Authorization State Matrix (AuthMatrix)
=======================================
Models security testing states:
- STATE_0: Unauthenticated / Guest
- STATE_1: Standard Authenticated User
- STATE_2: Privileged / Admin User
Builds an Object x Role matrix to rigorously verify IDOR / BOLA / BFLA.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class SecurityState(str, Enum):
    STATE_0_GUEST = "STATE_0_GUEST"
    STATE_1_USER = "STATE_1_USER"
    STATE_2_ADMIN = "STATE_2_ADMIN"


@dataclass
class AuthMatrixRecord:
    object_id: str
    endpoint: str
    allowed_states: List[SecurityState] = field(default_factory=list)
    tested_states: Dict[str, int] = field(default_factory=dict)  # State -> HTTP status code


class AuthMatrix:
    """Manages multi-state authorization access evaluation"""

    @classmethod
    def evaluate_bola(
        cls,
        object_owner_state: SecurityState,
        accessor_state: SecurityState,
        accessor_status_code: int,
        data_leaked: bool
    ) -> Tuple[bool, str]:
        """
        BOLA / IDOR Invariant:
        If accessor is STATE_0_GUEST on a public page, this is normal public access (GUEST_READ).
        BOLA is only confirmed if accessor has different role/tenant than owner AND receives private object data.
        """
        if accessor_state == SecurityState.STATE_0_GUEST and not data_leaked:
            return False, "Public guest access to public endpoint. Not BOLA/IDOR."

        if accessor_state != object_owner_state and accessor_status_code == 200 and data_leaked:
            return True, f"BOLA confirmed: {accessor_state.value} accessed object belonging to {object_owner_state.value}."

        return False, "Access permitted or properly restricted."