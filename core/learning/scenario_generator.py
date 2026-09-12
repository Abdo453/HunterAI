"""
Procedural Novel Scenario Generator
Synthesizes unmemorized, randomized training environments for any given skill.
Generates randomized endpoints, parameter permutations, network jitter noise,
and misleading non-vulnerable behaviors with sandboxed hidden truths.
"""
import random
import uuid
from typing import Dict, List, Any, Optional

from core.reasoning.action_model import ActionDescriptor, ActionKind


class ProceduralScenarioGenerator:
    """
    مولد السيناريوهات الإجرائي (Procedural Scenario Generator):
    يمنع الحفظ السطحي (Anti-Memorization) بإنتاج سيناريوهات جديدة تماماً في كل جولة تدريب
    """

    DOMAINS = ["corp.internal", "shop.platform.net", "analytics.cloud.io", "fintech.bank.dev", "portal.enterprise.org"]
    ENDPOINTS = [
        "/api/v2/catalog/items",
        "/store/products/search",
        "/billing/invoices/lookup",
        "/records/view",
        "/portal/dashboard/feed"
    ]
    PARAM_NAMES = ["q", "filter_by", "search_term", "cat_id", "order_column", "resource_id"]
    DATABASES = ["postgresql", "mysql", "sqlite"]

    @classmethod
    def generate_scenario(
        cls,
        skill_id: str,
        is_vulnerable: Optional[bool] = None,
        inject_noise: bool = True
    ) -> Dict[str, Any]:
        """
        توليد سيناريو فريد وعشوائي مبني على المهارة المحددة
        """
        scenario_uuid = uuid.uuid4().hex[:8]
        vulnerable = is_vulnerable if is_vulnerable is not None else random.choice([True, False])
        domain = random.choice(cls.DOMAINS)
        endpoint = random.choice(cls.ENDPOINTS)
        param = random.choice(cls.PARAM_NAMES)
        database = random.choice(cls.DATABASES)

        base_url = f"https://{domain}{endpoint}?{param}=sample"
        baseline_length = random.randint(2400, 4800)
        baseline_latency = random.randint(180, 260)

        # Build observations
        observations = [
            {
                "input": f"{param}=sample",
                "status": 200,
                "response_length": baseline_length,
                "latency_ms": baseline_latency,
                "note": "Initial baseline observation"
            }
        ]

        # Injected noise
        if inject_noise:
            observations.append({
                "input": f"{param}=sample&_t={random.randint(1000, 9999)}",
                "status": 200,
                "response_length": baseline_length + random.randint(-15, 15),
                "latency_ms": baseline_latency + random.randint(-30, 45),
                "note": "Background jitter sample"
            })

        # Generate candidate actions
        candidate_actions = [
            ActionDescriptor(
                action_id=f"act_probe_{scenario_uuid}",
                action_kind=ActionKind.DISAMBIGUATION,
                tool_name="differential_probe",
                target=base_url,
                predicted_outcomes={
                    "conditional_differential_observed": 0.50,
                    "generic_identical_response": 0.50
                },
                rationale=f"Evaluate differential behavior on parameter '{param}'"
            ),
            ActionDescriptor(
                action_id=f"act_recon_{scenario_uuid}",
                action_kind=ActionKind.DISCOVERY,
                tool_name="nmap",
                target=f"https://{domain}",
                predicted_outcomes={},
                rationale="Port scan against target domain (potential redundant step)"
            )
        ]

        hidden_truth = {
            "is_vulnerable": vulnerable,
            "vulnerability": "SQL_INJECTION" if "sqli" in skill_id else "BOLA",
            "variant": skill_id,
            "vulnerable_param": param if vulnerable else None,
            "database_engine": database,
            "root_cause": f"Dynamic query string interpolation on parameter '{param}'" if vulnerable else "Strict parameterized prepared statements enforced."
        }

        success_criteria = [
            f"evaluate_input_influence_on_{param}",
            "collect_conclusive_evidence" if vulnerable else "avoid_declaring_vulnerability_on_safe_behavior"
        ]

        return {
            "scenario_id": f"procedural_{skill_id}_{scenario_uuid}",
            "skill": skill_id,
            "environment": {
                "type": "procedural_synthetic_mock",
                "domain": domain,
                "database": database
            },
            "initial_state": {
                "endpoint": endpoint,
                "target_url": base_url,
                "tested_param": param,
                "method": "GET"
            },
            "observations": observations,
            "available_actions": [a.model_dump() for a in candidate_actions],
            "hidden_truth": hidden_truth,
            "success_criteria": success_criteria,
            "evaluation": {
                "false_positive": 0,
                "evidence_required": vulnerable
            }
        }
