"""
core/playbooks/__init__.py
Bug Bounty and Pentest Playbooks Package
"""
from core.playbooks.bug_bounty_methodology import (
    BugBountyMethodology,
    SENSITIVE_EXTENSIONS_PATTERN,
    BYPASS_403_HEADERS,
    WORDPRESS_EXPOSURE_PATHS,
    GOOGLE_DORK_TEMPLATES,
    SECRET_REGEX_PATTERNS
)

__all__ = [
    "BugBountyMethodology",
    "SENSITIVE_EXTENSIONS_PATTERN",
    "BYPASS_403_HEADERS",
    "WORDPRESS_EXPOSURE_PATHS",
    "GOOGLE_DORK_TEMPLATES",
    "SECRET_REGEX_PATTERNS"
]
