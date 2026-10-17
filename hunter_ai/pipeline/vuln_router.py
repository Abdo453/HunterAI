"""
Vulnerability Router — تنفيذIVulnRouter باستخدام SkillRegistry الموحد
======================================================================
يُرجم البارامترات المسكوبة (ParameterRecord) إلى مهارات متخصصة من
SkillRegistry، بما يضمن أن كل بارامتر يُساق لأفضل مهارة ملائمة حسب:
  - palabras clave المسجلة (param_keywords)
  - can_handle() المهارة نفسها
  - تخميد 30% عند غياب دليل الكلمات (ضد الازدحام الخاطئ)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from hunter_ai.pipeline.contracts import IVulnRouter
from hunter_ai.pipeline.schemas import ParameterRecord
from agents.skills.registry import SkillRegistry


class VulnRouter(IVulnRouter):
    """
    Router المهارات على مستوى خط الأنابيب (Pipeline).
    """

    def __init__(self, registry: Optional[SkillRegistry] = None):
        self.registry = registry or SkillRegistry.instance()

    def route_tasks(self, params: List[ParameterRecord], tech_stack: List[str] = None) -> List[Dict[str, Any]]:
        """
        يُحَوّل كل بارامتر إلى Task موجه لأفضل مهارة.
        يرجّع قائمة: {"skill", "target", "param", "method", "sample_value", ...}
        """
        tech_stack = tech_stack or []
        tasks: List[Dict[str, Any]] = []
        seen = set()

        for p in params:
            key = (p.endpoint, p.parameter)
            if key in seen:
                continue
            meta = self.registry.best_for(
                p.parameter, url=p.endpoint, sample_value=p.sample_value or ""
            )
            if meta is None:
                continue
            seen.add(key)
            tasks.append({
                "skill": meta.name,
                "vuln_type": meta.vuln_type,
                "cwe": meta.cwe,
                "target": p.endpoint,
                "param": p.parameter,
                "method": p.method,
                "sample_value": p.sample_value,
                "potential_classes": p.potential_classes,
                "tech_stack": tech_stack,
            })

        # الأولوية: المهارات الأعلى درجة أولاً (rank داخلي من best_for يُرتب تنازلياً)
        return tasks


# 싱글تون عالمي للخط أنابيب
vuln_router = VulnRouter()
