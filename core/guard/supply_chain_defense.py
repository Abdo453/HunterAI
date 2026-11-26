"""
==============================================================================
  ARTEX Ecosystem Supply-Chain Defense & Mandatory Scope Enforcement Guard
==============================================================================
Provides automated protection against:
  1. Backdoored Docker images & repositories (e.g. trhhubsd/ARTEX).
  2. Unconstrained / dangerous tool injection (mrjohnnyyang/artex-pro).
  3. Incomplete, leaky, or optional scope gates (wpsec, drush012, Adyanming).
  4. Unvetted third-party mirrors and unverified external scripts.
==============================================================================
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.supply_chain_defense")

# Blacklisted repositories, images, and threat signatures
BLOCKED_REPOSITORIES: Set[str] = {
    "trhhubsd/artex",
    "badbyte.io",
    "mrjohnnyyang/artex-pro",
    "wpsec/artex-pro",
    "drush012/artex-pro",
    "adyanming/artex-pro",
    "xsywl945/artex-mirror",
    "ruoji6/artex",
    "jiwoochris/artex-global",
    "cskwork/scopeweaver",
}

BLOCKED_DOCKER_IMAGES: Set[str] = {
    "trhhubsd/artex",
    "artex-backdoor",
    "badbyte/artex",
}

class SupplyChainDefenseGuard:
    """
    Evaluates actions to ensure:
    - Zero malicious or backdoored external images/repos are loaded.
    - Scope boundaries are enforced strictly and non-optionally.
    - All tool commands conform to authorized boundaries.
    """

    def __init__(self, intel_file: Optional[Path] = None):
        self.intel_file = intel_file or (Path(__file__).resolve().parent.parent.parent / "memory" / "knowledge" / "artex_supply_chain_intel.json")
        self.threat_intel = self._load_intel()

    def _load_intel(self) -> Dict[str, Any]:
        if self.intel_file.exists():
            try:
                return json.loads(self.intel_file.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning("Could not load supply chain intel: %s", e)
        return {}

    def inspect_command(self, command: str) -> Tuple[bool, str]:
        """
        Scans a shell command or parameter string for blacklisted image/repo references.
        Returns (is_blocked, reason).
        """
        cmd_lower = command.lower()

        # 1. Check for malicious Docker image usage
        for img in BLOCKED_DOCKER_IMAGES:
            if img in cmd_lower:
                return True, f"CRITICAL: Blocked reference to known backdoored Docker image '{img}' (Ref: badbyte.io / trhhubsd/ARTEX)"

        # 2. Check for unvetted or vulnerable repository URLs
        for repo in BLOCKED_REPOSITORIES:
            if repo in cmd_lower:
                return True, f"HIGH: Blocked untrusted/vulnerable repository reference '{repo}' from unvetted ARTEX fork"

        # 3. Block unconstrained curl-to-bash executions
        if re.search(r"curl\s+[^|]+\|\s*(?:ba|z|sh)", cmd_lower) or re.search(r"wget\s+[^|]+-O-\s*\|\s*(?:ba|z|sh)", cmd_lower):
            return True, "HIGH: Blocked unconstrained remote script execution pipeline (curl | sh)"

        return False, "Clean"

    def enforce_mandatory_scope(self, target_url: str, authorized_scope: List[str]) -> Tuple[bool, str]:
        """
        Enforces non-optional, strict scope boundaries across all targets.
        Fixes the weaknesses identified in wpsec, drush012, and Adyanming forks.
        """
        if not authorized_scope:
            return False, "Scope enforcement active: Authorized scope cannot be empty"

        target_clean = target_url.lower().strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        is_allowed = False
        for item in authorized_scope:
            item_clean = item.lower().strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if target_clean == item_clean or target_clean.endswith("." + item_clean):
                is_allowed = True
                break

        if not is_allowed:
            return False, f"STRICT SCOPE REJECTION: Target '{target_url}' is strictly outside the authorized scope: {authorized_scope}"

        return True, "In Scope"
