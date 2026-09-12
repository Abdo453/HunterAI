"""
Scientific Experiment Library
Catalog of standardized, reusable security experiments for the Epistemic Decision Policy.
Defines preconditions, expected outcome distributions, information value (EIG),
costs, and applicable hypotheses to replace blind action guessing.
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class ExperimentTemplate(BaseModel):
    """قالب تجربة علمية مقننة"""
    experiment_id: str
    skill_id: str
    name: str
    preconditions: List[str] = Field(default_factory=list)
    target_state: str = ""
    probe_kind: str             # BOOLEAN_PAIR, ERROR_SYNTAX, COLUMN_BOUNDARY, TIME_DELAY_SAMPLING, CROSS_TENANT_SWAP
    expected_outcomes: Dict[str, float] = Field(default_factory=dict)
    estimated_cost: float = 1.0
    reliability: float = 0.95
    applicable_hypotheses: List[str] = Field(default_factory=list)
    evidence_type_produced: str = "BEHAVIOR_DIFF"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# ── Canonical Experiment Catalog ───────────────────────────────────────
CANONICAL_EXPERIMENTS: List[ExperimentTemplate] = [
    ExperimentTemplate(
        experiment_id="exp_sqli_boolean_pair",
        skill_id="sqli_boolean_differential",
        name="Contrasting Boolean Pair Injection",
        preconditions=["endpoint_accepts_parameters"],
        target_state="Query parameter evaluated in database predicate",
        probe_kind="BOOLEAN_PAIR",
        expected_outcomes={
            "differential_response_observed": 0.50,
            "identical_response_observed": 0.50
        },
        estimated_cost=1.0,
        reliability=0.95,
        applicable_hypotheses=["SQLi", "boolean_differential"],
        evidence_type_produced="BEHAVIOR_DIFF",
        description="Injects logical true and false predicates (' AND 1=1-- vs ' AND 1=2--) to measure conditional output divergence."
    ),
    ExperimentTemplate(
        experiment_id="exp_sqli_syntax_error",
        skill_id="sqli_error_analysis",
        name="RDBMS Syntax Exception Probe",
        preconditions=["endpoint_accepts_parameters"],
        target_state="Query parameter concatenated into SQL command",
        probe_kind="ERROR_SYNTAX",
        expected_outcomes={
            "db_syntax_error_leaked": 0.50,
            "application_validation_error": 0.30,
            "generic_200_normal": 0.20
        },
        estimated_cost=1.0,
        reliability=0.92,
        applicable_hypotheses=["SQLi", "error_based"],
        evidence_type_produced="ERROR_DISCLOSURE",
        description="Supplies unbalanced delimiter character to provoke and classify underlying database exception signatures."
    ),
    ExperimentTemplate(
        experiment_id="exp_sqli_order_by_boundary",
        skill_id="sqli_union_enumeration",
        name="ORDER BY Column Count Boundary Discovery",
        preconditions=["endpoint_returns_tabular_data"],
        target_state="Original query returns multiple columns",
        probe_kind="COLUMN_BOUNDARY",
        expected_outcomes={
            "column_boundary_identified": 0.60,
            "unaffected_sorting": 0.40
        },
        estimated_cost=1.5,
        reliability=0.90,
        applicable_hypotheses=["SQLi", "union_based"],
        evidence_type_produced="BEHAVIOR_DIFF",
        description="Progressively increments ORDER BY indices until a column out-of-bounds error reveals exact SELECT column count."
    ),
    ExperimentTemplate(
        experiment_id="exp_sqli_time_delay_sampling",
        skill_id="sqli_time_statistical",
        name="Time Delay Statistical Jitter Sampling",
        preconditions=["endpoint_accepts_parameters"],
        target_state="Query executed synchronously by backend RDBMS",
        probe_kind="TIME_DELAY_SAMPLING",
        expected_outcomes={
            "statistically_significant_delay": 0.40,
            "network_jitter_baseline": 0.60
        },
        estimated_cost=3.0,
        reliability=0.88,
        applicable_hypotheses=["SQLi", "time_based_blind"],
        evidence_type_produced="TIMING_ANOMALY",
        description="Executes sleep delay queries against multi-sample network latency baselines to establish statistical confidence."
    ),
    ExperimentTemplate(
        experiment_id="exp_authz_cross_tenant_swap",
        skill_id="authz_object_isolation",
        name="Cross-Tenant Object Identifier Substitution",
        preconditions=["two_distinct_authenticated_identities", "resource_identifier_present"],
        target_state="Endpoint requires authentication and serves user-specific entities",
        probe_kind="CROSS_TENANT_SWAP",
        expected_outcomes={
            "200_cross_tenant_data": 0.50,
            "403_forbidden_strict_auth": 0.50
        },
        estimated_cost=1.0,
        reliability=0.98,
        applicable_hypotheses=["BOLA", "IDOR"],
        evidence_type_produced="BEHAVIOR_DIFF",
        description="Substitutes Victim resource identifier into Attacker session request and compares response bodies against ownership baseline."
    ),
    ExperimentTemplate(
        experiment_id="exp_authz_unauthenticated_baseline",
        skill_id="authz_object_isolation",
        name="Unauthenticated Baseline Gate Measurement",
        preconditions=["resource_identifier_present"],
        target_state="Endpoint authentication requirement unknown",
        probe_kind="DIFFERENTIAL_AUTH",
        expected_outcomes={
            "401_unauthorized": 0.80,
            "200_public_resource": 0.20
        },
        estimated_cost=0.5,
        reliability=0.99,
        applicable_hypotheses=["BOLA", "Public_Resource"],
        evidence_type_produced="AUTH_ANOMALY",
        description="Sends anonymous request without headers to eliminate the hypothesis that resource is publicly accessible."
    )
]


class ExperimentLibrary:
    """
    مكتبة التجارب العلمية:
    تزود الـ Decision Policy والـ Planner بقوالب اختبارات مقننة
    """

    def __init__(self):
        self._experiments: Dict[str, ExperimentTemplate] = {
            exp.experiment_id: exp for exp in CANONICAL_EXPERIMENTS
        }

    def get_experiment(self, exp_id: str) -> Optional[ExperimentTemplate]:
        return self._experiments.get(exp_id)

    def get_all_experiments(self) -> List[ExperimentTemplate]:
        return list(self._experiments.values())

    def find_experiments_for_hypothesis(self, hypothesis: str) -> List[ExperimentTemplate]:
        """استرجاع التجارب المؤهلة لفحص أو إثبات فرضية معينة"""
        hyp_lower = hypothesis.lower()
        matched = []
        for exp in self._experiments.values():
            for app_hyp in exp.applicable_hypotheses:
                if app_hyp.lower() in hyp_lower or hyp_lower in app_hyp.lower():
                    matched.append(exp)
                    break
        return matched

    def find_experiments_by_skill(self, skill_id: str) -> List[ExperimentTemplate]:
        """استرجاع التجارب المرتبطة بمهارة محددة في الـ Skill Graph"""
        return [exp for exp in self._experiments.values() if exp.skill_id == skill_id]

    def register_experiment(self, experiment: ExperimentTemplate):
        self._experiments[experiment.experiment_id] = experiment
