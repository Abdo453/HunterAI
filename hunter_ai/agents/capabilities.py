"""
HunterAI Standardized Capability Enumeration & Agent Capabilities Definitions
"""
from __future__ import annotations

from enum import Enum
from typing import Set


class AgentCapability(str, Enum):
    # Web & Application Capabilities
    WEB_ANALYSIS = "web_analysis"
    HTTP_ANALYSIS = "http_analysis"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    API_ANALYSIS = "api_analysis"

    # Traffic & Session Capabilities
    TRAFFIC_ANALYSIS = "traffic_analysis"
    REQUEST_CORRELATION = "request_correlation"
    SESSION_AUDIT = "session_audit"

    # Recon & Infrastructure Capabilities
    RECONNAISSANCE = "reconnaissance"
    ASSET_DISCOVERY = "asset_discovery"
    DNS_ANALYSIS = "dns_analysis"
    OSINT_ANALYSIS = "osint_analysis"

    # Intelligence & Cognitive Capabilities
    PLANNING = "planning"
    DEEP_REASONING = "deep_reasoning"
    CRITIC_VALIDATION = "critic_validation"
    REPORT_SYNTHESIS = "report_synthesis"
    SECRET_DETECTION = "secret_detection"
