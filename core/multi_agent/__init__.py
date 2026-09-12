"""
Multi-Agent Specialized Reasoning Package (SickHackShark-Inspired)
"""
from core.multi_agent.contracts import (
    SpecialistRole,
    SpecialistTask,
    SpecialistReport
)
from core.multi_agent.specialists import (
    BaseSpecialist,
    ReconSpecialist,
    WebSpecialist,
    APISpecialist,
    AuthSpecialist,
    VulnSpecialist,
    CriticSpecialist,
    LeadAnalyst
)

__all__ = [
    "SpecialistRole",
    "SpecialistTask",
    "SpecialistReport",
    "BaseSpecialist",
    "ReconSpecialist",
    "WebSpecialist",
    "APISpecialist",
    "AuthSpecialist",
    "VulnSpecialist",
    "CriticSpecialist",
    "LeadAnalyst"
]
