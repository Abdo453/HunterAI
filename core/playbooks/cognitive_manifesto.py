"""
HunterAI Cognitive Manifesto Programmatic Interface
Loads and provides cognitive guidance, golden principles, and ethical heuristics
from AGENT_COGNITIVE_MANIFESTO.md for runtime injection into Agent prompts and reasoning loops.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

MANIFESTO_PATH = Path(__file__).parent / "AGENT_COGNITIVE_MANIFESTO.md"


class CognitiveManifesto:
    """
    الواجهة البرمجية لميثاق الدستور المعرفي للـ Agent (Cognitive Manifesto):
    - تتيح للـ Agents استدعاء المبادئ التوجيهية في أي مرحلة من مراحل التفكير.
    - تقدم نصوص التحذير وفلاتر فحص الـ False Positives للمحركات المعرفية.
    """

    _cached_content: Optional[str] = None
    _cached_sections: Optional[Dict[str, str]] = None

    @classmethod
    def get_full_manifesto(cls) -> str:
        if cls._cached_content is None:
            if MANIFESTO_PATH.exists():
                cls._cached_content = MANIFESTO_PATH.read_text(encoding="utf-8")
            else:
                cls._cached_content = "Cognitive Manifesto document not found."
        return cls._cached_content

    @classmethod
    def get_section(cls, keyword: str) -> str:
        """البحث عن باب أو مبدأ معين بالكلمة المفتاحية"""
        full = cls.get_full_manifesto()
        lines = full.split("\n")
        section_lines = []
        capturing = False

        kw_lower = keyword.lower()
        for line in lines:
            if line.startswith("## ") or line.startswith("### "):
                if kw_lower in line.lower():
                    capturing = True
                    section_lines = [line]
                    continue
                elif capturing:
                    break

            if capturing:
                section_lines.append(line)

        return "\n".join(section_lines).strip() if section_lines else f"Section matching '{keyword}' not found."

    @classmethod
    def get_golden_rules_summary(cls) -> List[str]:
        """استرجاع القواعد الذهبية الأسرع للحقن اللحظي في الـ Prompts"""
        return [
            "Architect First: Understand developer intent, full-stack data flow, and trust boundaries before probing.",
            "Zero-Noise Probing: 3 requests max (Baseline -> Canary probe -> Differential delta) instead of blind fuzzing.",
            "Multi-Role Matrix: Always audit endpoints across Admin, Standard User, and Guest to prove BOLA/BFLA.",
            "Skeptic's Creed: A 403 Forbidden is a working security control, NOT a vulnerability. A 500 error is not RCE.",
            "Context-Aware Canaries: Check reflection context (DOM, Attribute, Script, JSON) before escaping.",
            "Out-of-Band Verification: Use unique correlation tokens for blind flows (webhooks, async queues, exports).",
            "Internal Debate: Require agreement between Analyst, Skeptic Critic, and Verifier before reporting.",
            "Impact & Reproducibility: Every finding must include a 30-second curl proof and a clear code-level patch."
        ]
