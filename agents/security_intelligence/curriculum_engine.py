"""
Curriculum & Learning Path Engine
Structures security learning tracks, prerequisites, modules, and tracks user educational progress.
"""
from typing import Dict, List, Any, Optional
from agents.security_intelligence.learning_memory import LearningMemory


class CurriculumEngine:
    """محرك المناهج والمسارات التعليمية الأمنية"""

    def __init__(self, learning_memory: Optional[LearningMemory] = None):
        self.memory = learning_memory or LearningMemory()
        self.tracks = self._init_tracks()

    def get_tracks(self) -> List[Dict[str, Any]]:
        return self.tracks

    def get_recommended_next_module(self) -> Dict[str, Any]:
        """تحديد الموديول التالي المقترح بناءً على المفاهيم المتقنة ونقاط الضعف"""
        mastered = set(self.memory.mastered_concepts)
        for track in self.tracks:
            for mod in track["modules"]:
                if mod["id"] not in mastered:
                    return {
                        "track_name": track["name"],
                        "module": mod,
                        "reason": f"Prerequisites met, ready to learn {mod['title']}."
                    }
        return {
            "track_name": "Advanced Research",
            "module": {"id": "ADV-01", "title": "Advanced 0-Day & Novel Attack Vector Research"},
            "reason": "All baseline tracks completed."
        }

    def _init_tracks(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "TRACK-API",
                "name": "API Security & Broken Access Controls",
                "level": "Intermediate",
                "modules": [
                    {
                        "id": "bola",
                        "title": "BOLA / IDOR Deep Dive",
                        "description": "Understanding object-level access controls and cross-user testing."
                    },
                    {
                        "id": "bfla",
                        "title": "BFLA & Privilege Escalation",
                        "description": "Function-level role verification and administrative endpoint protection."
                    },
                    {
                        "id": "mass_assignment",
                        "title": "Mass Assignment & Property Injection",
                        "description": "Defeating unvalidated model binding in modern REST & GraphQL APIs."
                    }
                ]
            },
            {
                "id": "TRACK-INJ",
                "name": "Injection & Server-Side Flaws",
                "level": "Advanced",
                "modules": [
                    {
                        "id": "sqli",
                        "title": "SQL Injection & ORM Escaping",
                        "description": "Error-based, blind, and time-based SQL injection detection and mitigation."
                    },
                    {
                        "id": "ssrf",
                        "title": "Server-Side Request Forgery (SSRF)",
                        "description": "Cloud metadata exfiltration and internal network pivoting."
                    }
                ]
            },
            {
                "id": "TRACK-AUTH",
                "name": "Authentication & Token Security",
                "level": "Intermediate",
                "modules": [
                    {
                        "id": "jwt_weakness",
                        "title": "JWT Architecture & Signature Verification",
                        "description": "Algorithm confusion, none-alg, and key-confusion attack analysis."
                    }
                ]
            }
        ]
