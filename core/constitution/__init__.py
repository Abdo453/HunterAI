"""HunterAI Machine Constitution Package"""
from core.constitution.constitution import (
    MachineConstitution, ConstitutionRule, ConstitutionViolation,
    ConstitutionLevel, constitution, get_constitution,
)

__all__ = [
    "MachineConstitution",
    "ConstitutionRule",
    "ConstitutionViolation",
    "ConstitutionLevel",
    "constitution",
    "get_constitution",
]
__version__ = "1.0.0"
