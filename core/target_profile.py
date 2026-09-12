"""
Target Profiler — مستوحى من HexStrike's TargetProfile + PentestGPT's TaskKind
يحسب confidence_score للهدف ويحدد متى يُسمح بالـ EXPLOIT
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


# ── PentestGPT TaskKind Pipeline ─────────────────────────────
class TaskKind(str, Enum):
    DISCOVER  = "discover"   # passive recon
    ENUMERATE = "enumerate"  # expand surface
    TEST      = "test"       # single bounded probe — NO exploitation
    EXPLOIT   = "exploit"    # only allowed after TEST evidence
    VERIFY    = "verify"     # re-run exact evidence command
    RECOVER   = "recover"    # address failure


class TaskStatus(str, Enum):
    BLOCKED = "blocked"
    READY   = "ready"
    ACTIVE  = "active"
    DONE    = "done"
    FAILED  = "failed"


# ── HexStrike TargetProfile ───────────────────────────────────
@dataclass
class TargetProfile:
    target: str
    target_type: str = "WEB"           # WEB | NETWORK | API | CLOUD | BINARY
    ip_addresses: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    cms_type: Optional[str] = None
    waf_detected: bool = False

    # Scores
    attack_surface_score: float = 0.0   # 0.0–10.0
    confidence_score: float = 0.0       # 0.0–1.0
    risk_level: str = "unknown"

    # PentestGPT evidence gating
    test_observations: List[str] = field(default_factory=list)   # verbatim evidence
    current_task_kind: TaskKind = TaskKind.DISCOVER


    def calculate_confidence(self) -> float:
        """HexStrike _calculate_confidence() logic"""
        conf = 0.5  # base
        if self.ip_addresses:                     conf += 0.1
        if self.technologies:                     conf += 0.2
        if self.cms_type:                         conf += 0.1
        if self.target_type not in ("unknown",""): conf += 0.1
        if self.open_ports:                        conf += 0.05
        if self.subdomains:                        conf += 0.05
        self.confidence_score = min(conf, 1.0)
        return self.confidence_score

    def calculate_attack_surface(self) -> float:
        """HexStrike _calculate_attack_surface() logic"""
        base = {"WEB": 7.0, "NETWORK": 8.0, "API": 6.0, "CLOUD": 5.0, "BINARY": 4.0}.get(
            self.target_type, 5.0
        )
        score = base
        score += 0.5 * min(len(self.technologies), 5)
        score += 0.3 * min(len(self.open_ports), 10)
        score += 0.2 * min(len(self.subdomains), 10)
        if self.cms_type:  score += 1.5
        if self.waf_detected: score -= 1.0  # harder to exploit
        self.attack_surface_score = min(score, 10.0)
        self._set_risk_level()
        return self.attack_surface_score

    def _set_risk_level(self):
        s = self.attack_surface_score
        self.risk_level = (
            "critical" if s >= 8.5 else
            "high"     if s >= 7.0 else
            "medium"   if s >= 5.0 else
            "low"      if s >= 3.0 else
            "minimal"
        )

    def can_exploit(self) -> bool:
        """
        PentestGPT rule: EXPLOIT أُسمح فقط إذا:
        1. confidence_score >= 0.65
        2. يوجد test_observation واحد على الأقل (verbatim evidence)
        """
        return (
            self.confidence_score >= 0.65 and
            len(self.test_observations) > 0
        )

    def add_test_observation(self, evidence: str):
        """
        إضافة evidence من TEST — verbatim substring من tool output
        يرفع الـ confidence تلقائياً
        """
        # PentestGPT: evidence must be bounded substring
        bounded = evidence[:4000] if len(evidence) > 4000 else evidence
        self.test_observations.append(bounded)
        # رفع الـ confidence لو في دليل
        if self.confidence_score < 0.9:
            self.confidence_score = min(self.confidence_score + 0.1, 0.95)
        self.current_task_kind = TaskKind.TEST

    def step_success_probability(self, tool_name: str) -> float:
        """
        HexStrike compound probability:
        = tool_effectiveness[target_type][tool] × confidence_score
        """
        effectiveness = {
            "WEB": {
                "nuclei": 0.85, "sqlmap": 0.80, "gobuster": 0.75,
                "ffuf": 0.80, "dalfox": 0.75, "wpscan": 0.90,
                "nmap": 0.70, "nikto": 0.75, "burpsuite": 0.90,
            },
            "NETWORK": {
                "nmap": 0.95, "masscan": 0.90, "rustscan": 0.88,
                "netexec": 0.85, "enum4linux": 0.80,
            },
        }.get(self.target_type, {})
        tool_eff = effectiveness.get(tool_name.lower(), 0.65)
        return tool_eff * self.confidence_score

    def summary(self) -> dict:
        return {
            "target": self.target,
            "type": self.target_type,
            "confidence": round(self.confidence_score, 2),
            "attack_surface": round(self.attack_surface_score, 1),
            "risk_level": self.risk_level,
            "can_exploit": self.can_exploit(),
            "test_observations": len(self.test_observations),
            "current_phase": self.current_task_kind.value,
            "technologies": self.technologies[:5],
            "open_ports": self.open_ports[:10],
        }
