"""
BurpAgent Normalization Layer
"""
from agents.burp_agent.normalization.request_normalizer import RequestNormalizer, NormalizedRequest
from agents.burp_agent.normalization.response_normalizer import ResponseNormalizer, NormalizedResponse

__all__ = [
    "RequestNormalizer",
    "NormalizedRequest",
    "ResponseNormalizer",
    "NormalizedResponse",
]
