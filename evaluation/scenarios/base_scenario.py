"""
Base Benchmark Scenario Framework
Defines the standard contract for realistic security investigation benchmark environments.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple

from core.reasoning.action_model import ActionDescriptor
from core.reasoning.belief_state import BeliefState
from core.attack_graph.graph import CausalAttackGraph
from agents.security_intelligence.schemas import EvidenceItem


class BenchmarkScenario(ABC):
    """
    بيئة اختبار معيارية لقياس جودة وكفاءة استدلال الـ Agent
    """

    def __init__(self, name: str, category: str, optimal_steps: int = 2):
        self.name = name
        self.category = category
        self.optimal_steps = optimal_steps

    @abstractmethod
    def get_initial_hypotheses(self) -> Dict[str, float]:
        """توزيع الاحتمالات المبدئي للفرضيات المتنافسة"""
        pass

    @abstractmethod
    def get_candidate_actions(self) -> List[ActionDescriptor]:
        """قائمة الأفعال المتاحة للـ Agent للاختيار من بينها"""
        pass

    @abstractmethod
    def simulate_execution(self, action: ActionDescriptor) -> Tuple[str, Optional[EvidenceItem]]:
        """محاكاة رد البيئة التجريبية على الأكشن المنفذ"""
        pass

    @abstractmethod
    def check_goal(self, belief: BeliefState, graph: CausalAttackGraph) -> Tuple[bool, str]:
        """فحص ما إذا كان الهدف الاستقصائي قد تحقق بإثبات قطعي"""
        pass

    @abstractmethod
    def get_ground_truth(self) -> Dict[str, Any]:
        """الحقيقة الفعلية للبيئة لقياس دقة الاستدلال ومنع الإنذارات الكاذبة"""
        pass
