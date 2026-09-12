"""
Interaction Planner (Information Gain Planner)
==============================================
Calculates Information Gain (IG) for every available interactive affordance
to pick the action that will discover the most new attack surface.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.interaction_planner")


class InteractionPlanner:
    """Selects the action candidate with the highest predicted Information Gain"""

    CATEGORY_WEIGHTS = {
        "AUTH": 1.0,
        "USER_INPUT": 0.85,
        "API_TRIGGER": 0.75,
        "NAVIGATION": 0.50,
        "STATIC": 0.10,
        "EXTERNAL": 0.0,
    }

    @classmethod
    def calculate_information_gain(
        cls,
        action: Any,  # ActionCandidate or dict
        has_clicked_fn: Any,
        is_loop_fn: Any,
        current_state_id: str,
    ) -> float:
        """
        Computes Information Gain:
        IG = w_category * w_novelty * w_input * (1 - loop_penalty)
        """
        cat = getattr(action, "category", None)
        cat_val = cat.value if hasattr(cat, "value") else str(cat or "STATIC")
        w_cat = cls.CATEGORY_WEIGHTS.get(cat_val.upper(), 0.3)

        selector = getattr(action, "selector", "")
        target_url = getattr(action, "target_url", "")

        # Novelty weight: 1.0 if never clicked, 0.0 if already executed
        already_clicked = has_clicked_fn(selector) if callable(has_clicked_fn) else False
        w_novelty = 0.0 if already_clicked else 1.0

        # Input bonus: higher for forms with input elements
        w_input = 1.2 if cat_val.upper() in ("USER_INPUT", "AUTH") else 1.0

        # Loop penalty: 1.0 if cyclical loop detected
        action_id = getattr(action, "action_id", selector)
        is_loop = is_loop_fn(current_state_id, action_id) if callable(is_loop_fn) else False
        penalty = 1.0 if is_loop else 0.0

        score = w_cat * w_novelty * w_input * (1.0 - penalty)
        return max(0.0, round(score, 3))

    @classmethod
    def rank_actions(
        cls,
        actions: List[Any],
        has_clicked_fn: Any,
        is_loop_fn: Any,
        current_state_id: str,
    ) -> List[Any]:
        """Ranks actions by Information Gain in descending order"""
        scored = []
        for a in actions:
            ig = cls.calculate_information_gain(a, has_clicked_fn, is_loop_fn, current_state_id)
            if ig > 0.0:
                scored.append((ig, a))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored]
