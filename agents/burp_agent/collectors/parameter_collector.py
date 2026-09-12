"""
Parameter Classification Collector for BurpAgent
"""
import logging
from typing import List
from agents.burp_agent.storage.models import ParameterModel, HTTPRequestModel

log = logging.getLogger("burp_agent.parameter_collector")


class ParameterCollector:
    """تصنيف وفهرسة الباراميترات الحساسة والمتحكم بها"""

    SENSITIVE_NAMES = {
        "password", "passwd", "pwd", "secret", "token", "auth",
        "api_key", "apikey", "access_token", "private_key", "ssn", "credit_card"
    }

    @classmethod
    def classify_parameters(cls, req: HTTPRequestModel) -> List[ParameterModel]:
        for p in req.parameters:
            p_low = p.name.lower()
            if any(s in p_low for s in cls.SENSITIVE_NAMES):
                p.is_sensitive = True
            if p.is_user_controlled_id or p.is_role_indicator:
                p.is_sensitive = True
        return req.parameters
