"""
Project Memory
Persistent memory for project architecture, technologies, user roles, APIs, and decisions.
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.project_memory")


class ProjectMemory:
    """ذاكرة المشروع: التقنيات، الأدوار، هيكل الـ APIs، والعلاقات المعمارية"""

    def __init__(self, storage_file: Optional[str] = None):
        self.storage_file = storage_file or SecurityIntelligenceConfig.PROJECT_MEMORY_PATH
        self.technologies: List[str] = []
        self.domains: List[str] = []
        self.subdomains: List[str] = []
        self.api_endpoints: Dict[str, Dict[str, Any]] = {}
        self.auth_mechanisms: List[str] = []
        self.user_roles: List[str] = []
        self.attack_paths: List[Dict[str, Any]] = []
        self.architecture_summary: str = ""
        self.decisions_log: List[Dict[str, Any]] = []
        self._load()

    def record_technology(self, tech_name: str):
        if tech_name and tech_name not in self.technologies:
            self.technologies.append(tech_name)
            self._save()

    def record_endpoint(self, path: str, method: str = "GET", params: Optional[List[str]] = None, auth_required: bool = True):
        key = f"{method.upper()} {path}"
        if key not in self.api_endpoints:
            self.api_endpoints[key] = {
                "method": method.upper(),
                "path": path,
                "params": params or [],
                "auth_required": auth_required,
                "first_seen": time.time(),
                "times_seen": 1
            }
        else:
            self.api_endpoints[key]["times_seen"] += 1
            if params:
                existing = set(self.api_endpoints[key]["params"])
                existing.update(params)
                self.api_endpoints[key]["params"] = list(existing)
        self._save()

    def record_role(self, role_name: str):
        if role_name and role_name not in self.user_roles:
            self.user_roles.append(role_name)
            self._save()

    def record_decision(self, decision: str, rationale: str):
        self.decisions_log.append({
            "timestamp": time.time(),
            "decision": decision,
            "rationale": rationale
        })
        self._save()

    def get_summary(self) -> Dict[str, Any]:
        return {
            "technologies": self.technologies,
            "roles": self.user_roles,
            "endpoints_count": len(self.api_endpoints),
            "auth_mechanisms": self.auth_mechanisms,
            "architecture_summary": self.architecture_summary
        }

    def _save(self):
        try:
            p = Path(self.storage_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "technologies": self.technologies,
                "domains": self.domains,
                "subdomains": self.subdomains,
                "api_endpoints": self.api_endpoints,
                "auth_mechanisms": self.auth_mechanisms,
                "user_roles": self.user_roles,
                "attack_paths": self.attack_paths,
                "architecture_summary": self.architecture_summary,
                "decisions_log": self.decisions_log
            }
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Failed to save ProjectMemory: {e}")

    def _load(self):
        try:
            p = Path(self.storage_file)
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                self.technologies = data.get("technologies", [])
                self.domains = data.get("domains", [])
                self.subdomains = data.get("subdomains", [])
                self.api_endpoints = data.get("api_endpoints", {})
                self.auth_mechanisms = data.get("auth_mechanisms", [])
                self.user_roles = data.get("user_roles", [])
                self.attack_paths = data.get("attack_paths", [])
                self.architecture_summary = data.get("architecture_summary", "")
                self.decisions_log = data.get("decisions_log", [])
        except Exception as e:
            log.warning(f"Failed to load ProjectMemory: {e}")
