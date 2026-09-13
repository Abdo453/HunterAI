"""
HunterAI Safe Lab Orchestrator
===============================
Provides an automated sandbox environment enabling safe, 1-click demonstration runs:
- Pre-configured targets: OWASP Juice Shop, DVWA, Built-in Arena Targets
- Generates reproducible docker-compose configs
- Fallback to zero-dependency in-memory mock lab when Docker is unavailable
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.arena.arena_targets import get_all_arena_targets


class LabTargetType(str, Enum):
    BUILTIN_ARENA = "builtin_arena"
    JUICE_SHOP = "juice_shop"
    DVWA = "dvwa"


@dataclass
class SafeLabConfig:
    lab_type: LabTargetType
    name: str
    description: str
    default_port: int
    container_image: Optional[str] = None
    health_endpoint: str = "/"
    ground_truth_vulns: List[str] = field(default_factory=list)


class SafeLabOrchestrator:
    """Manages creation, execution, and verification of safe demonstration lab targets"""

    PRESETS: Dict[LabTargetType, SafeLabConfig] = {
        LabTargetType.BUILTIN_ARENA: SafeLabConfig(
            lab_type=LabTargetType.BUILTIN_ARENA,
            name="HunterAI Built-in Ground-Truth Arena",
            description="12 deterministic high-fidelity mock vulnerability targets (0% external deps)",
            default_port=8089,
            container_image=None,
            health_endpoint="/health",
            ground_truth_vulns=["cmd_injection", "sqli", "idor", "ssrf", "jwt", "ssti", "xss", "auth_bypass"]
        ),
        LabTargetType.JUICE_SHOP: SafeLabConfig(
            lab_type=LabTargetType.JUICE_SHOP,
            name="OWASP Juice Shop Sandbox",
            description="Modern web security sandbox running securely on localhost",
            default_port=3000,
            container_image="bkimminich/juice-shop:v16.0.0",
            health_endpoint="/rest/admin/application-version",
            ground_truth_vulns=["sqli", "xss", "idor", "jwt", "broken_auth"]
        ),
        LabTargetType.DVWA: SafeLabConfig(
            lab_type=LabTargetType.DVWA,
            name="Damn Vulnerable Web Application (DVWA)",
            description="PHP/MySQL vulnerability testing ground",
            default_port=8080,
            container_image="vulnerables/web-dvwa:latest",
            health_endpoint="/login.php",
            ground_truth_vulns=["sqli", "cmd_injection", "file_upload", "csrf"]
        ),
    }

    @classmethod
    def get_compose_template(cls, lab_type: LabTargetType) -> str:
        cfg = cls.PRESETS.get(lab_type)
        if not cfg or not cfg.container_image:
            return ""

        return f"""version: '3.8'
services:
  hunter-safe-lab:
    image: {cfg.container_image}
    container_name: hunter-lab-{cfg.lab_type.value}
    ports:
      - "127.0.0.1:{cfg.default_port}:{cfg.default_port if cfg.lab_type == LabTargetType.JUICE_SHOP else 80}"
    environment:
      - SAFE_LAB_ORIGIN=hunterai
    restart: unless-stopped
"""

    @classmethod
    def export_docker_compose(cls, lab_type: LabTargetType, output_dir: Path) -> Path:
        content = cls.get_compose_template(lab_type)
        compose_file = output_dir / f"docker-compose.{lab_type.value}.yml"
        compose_file.write_text(content, encoding="utf-8")
        return compose_file

    @classmethod
    def run_builtin_arena_benchmark(cls) -> Dict[str, Any]:
        """Executes full built-in benchmark targets directly in-memory without external Docker"""
        targets = get_all_arena_targets()
        results = []
        for t in targets:
            status, _, body = t.execute_http("GET", t.path)
            results.append({
                "target_id": t.target_id,
                "name": t.name,
                "status_code": status,
                "expected_verdict": t.ground_truth.expected_verdict,
                "vuln_class": t.ground_truth.vulnerability_class
            })
        return {
            "lab_type": LabTargetType.BUILTIN_ARENA.value,
            "total_targets": len(targets),
            "executed_cleanly": True,
            "targets": results
        }
