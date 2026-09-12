"""
Cookie & Identity State Collector for BurpAgent
Tracks session cookies, tokens, and authorization state transitions across HTTP transactions.
"""
import re
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("burp_agent.collectors.cookie")


class CapturedToken(BaseModel):
    token_name: str
    token_value: str
    token_kind: str                    # "COOKIE" | "BEARER_JWT" | "API_KEY"
    domain: str
    is_jwt: bool = False
    jwt_claims: Dict[str, Any] = Field(default_factory=dict)
    first_seen_tx: str


class CookieCollector:
    """
    مجمع ومحلل الكوكيز والرموز المصادقية
    """

    def __init__(self):
        self._tokens: Dict[str, CapturedToken] = {}

    def inspect_transaction(
        self,
        transaction_id: str,
        domain: str,
        request_headers: Dict[str, str],
        response_headers: Dict[str, str]
    ) -> List[CapturedToken]:
        found: List[CapturedToken] = []

        # 1. Inspect Request Authorization headers
        for h, v in request_headers.items():
            if h.lower() == "authorization":
                is_jwt = "eyj" in v.lower()
                token = CapturedToken(
                    token_name="Authorization",
                    token_value=v[:40] + "...",
                    token_kind="BEARER_JWT" if "bearer" in v.lower() else "AUTH_HEADER",
                    domain=domain,
                    is_jwt=is_jwt,
                    first_seen_tx=transaction_id
                )
                self._tokens[f"{domain}_auth"] = token
                found.append(token)

            elif h.lower() == "cookie":
                for part in v.split(";"):
                    if "=" in part:
                        c_name, c_val = part.strip().split("=", 1)
                        token = CapturedToken(
                            token_name=c_name,
                            token_value=c_val[:40] + "...",
                            token_kind="COOKIE",
                            domain=domain,
                            is_jwt="eyj" in c_val.lower(),
                            first_seen_tx=transaction_id
                        )
                        self._tokens[f"{domain}_{c_name}"] = token
                        found.append(token)

        # 2. Inspect Response Set-Cookie headers
        for h, v in response_headers.items():
            if h.lower() == "set-cookie":
                c_part = v.split(";")[0]
                if "=" in c_part:
                    c_name, c_val = c_part.strip().split("=", 1)
                    token = CapturedToken(
                        token_name=c_name,
                        token_value=c_val[:40] + "...",
                        token_kind="COOKIE",
                        domain=domain,
                        is_jwt="eyj" in c_val.lower(),
                        first_seen_tx=transaction_id
                    )
                    self._tokens[f"{domain}_{c_name}"] = token
                    found.append(token)

        return found

    def get_all_tokens(self) -> List[CapturedToken]:
        return list(self._tokens.values())
