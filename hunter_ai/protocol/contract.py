"""
Hunter Agent Protocol v1: Agent Contract Definition & Validation
================================================================
Defines explicit contracts for all Autonomous Agents:
- Name and capabilities/skills
- Input format & Output format schema declarations
- Required permissions & access levels
- Preferred AI model tier (Local Fast, Local Code, Cloud Fast, Cloud Deep)
"""
from __future__ import annotations

import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Callable


class ModelTierPreference(str, Enum):
    LOCAL_FAST = "local_fast"          # xploiter / pentester (2.8B)
    LOCAL_CODE = "local_code"          # Qwen 2.5 Coder (14B)
    LOCAL_OFFENSIVE = "local_off"      # WhiteRabbitNeo (8B)
    CLOUD_FAST = "cloud_fast"          # Gemini 2.0 Flash
    CLOUD_DEEP = "cloud_deep"          # Llama 3.3 70B / DeepSeek
    DETERMINISTIC = "deterministic"    # Pure Python / Zero-AI


@dataclass
class AgentContract:
    """
    عقد الوكيل (Agent Contract):
    يحدد هوية الوكيل، المهارات التي يقدمها، صِيغ المدخلات والمخرجات، والصلاحيات المطلوبة.
    """
    name: str
    skills: List[str]
    input_format: str
    output_format: str
    version: str = "1.0.0"
    required_permissions: List[str] = field(default_factory=lambda: ["scope_enforced"])
    preferred_model_tier: ModelTierPreference = ModelTierPreference.LOCAL_FAST
    description: str = ""
    max_concurrency: int = 2
    is_active: bool = True
    created_at: float = field(default_factory=time.time)

    def matches_task(self, required_skill: str, input_format: str) -> bool:
        """Checks whether the agent contract can satisfy the requested task and input format"""
        skill_match = any(required_skill.lower() in s.lower() for s in self.skills)
        format_match = (self.input_format.lower() == input_format.lower()) or (input_format == "*") or (self.input_format == "*")
        return skill_match and format_match and self.is_active

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "skills": self.skills,
            "input_format": self.input_format,
            "output_format": self.output_format,
            "version": self.version,
            "required_permissions": self.required_permissions,
            "preferred_model_tier": self.preferred_model_tier.value,
            "description": self.description,
            "is_active": self.is_active
        }
