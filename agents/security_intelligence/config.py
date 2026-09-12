"""
Configuration for HunterAI Security Intelligence & Education Agent
"""
import os
from typing import Dict, Any

class SecurityIntelligenceConfig:
    # Confidence Score Thresholds
    CONFIDENCE_UNKNOWN_MAX = 0.20
    CONFIDENCE_WEAK_MAX = 0.40
    CONFIDENCE_POSSIBLE_MAX = 0.60
    CONFIDENCE_STRONG_MAX = 0.80
    CONFIDENCE_HIGH_MAX = 0.95
    CONFIDENCE_CONFIRMED_MIN = 0.95

    # Gating Thresholds
    MIN_CONFIDENCE_TO_FLAG_FINDING = 0.50
    MIN_CONFIDENCE_TO_CONFIRM = 0.85

    # Critic weights & penalties
    CRITIC_MISSING_EVIDENCE_PENALTY = 0.25
    CRITIC_FALSE_POSITIVE_MATCH_PENALTY = 0.40
    CRITIC_BEHAVIORAL_DIFF_BONUS = 0.20

    # Default Language & Teaching settings
    DEFAULT_LANGUAGE = "ar"  # "ar" or "en"
    DEFAULT_EXPLANATION_LEVEL = "technical"

    # Storage paths
    PROJECT_MEMORY_PATH = "data/memory/project_memory.json"
    TARGET_MEMORY_PATH = "data/memory/target_memory.json"
    FALSE_POSITIVE_MEMORY_PATH = "data/memory/false_positive_memory.json"
    LEARNING_MEMORY_PATH = "data/memory/learning_memory.json"
    KNOWLEDGE_BASE_DIR = "knowledge"

    # Model Routing Settings
    LOCAL_FAST_MODEL = os.getenv("LOCAL_FAST_MODEL", "qwen2.5:7b")
    LOCAL_REASONING_MODEL = os.getenv("LOCAL_REASONING_MODEL", "WhiteRabbitNeo")
    LOCAL_CODING_MODEL = os.getenv("LOCAL_CODING_MODEL", "qwen2.5-coder:14b")
