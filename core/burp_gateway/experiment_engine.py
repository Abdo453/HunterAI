"""
HunterAI Experiment Engine & Reasoning Memory
==============================================
Transforms HunterAI from a naive payload runner into a scientific Security Reasoning Agent:
- Methodical multi-step investigation:
    Discovery -> Baseline -> Differential -> Error Behavior -> Boolean Behavior ->
    Time Behavior -> Context ID -> Hypothesis Refinement -> Targeted Verification
- Reasoning Memory:
    Hypothesis ├── Why generated ├── Evidence ├── Tests attempted ├── Payload/Mutation
               ├── Response delta ├── Interpretation ├── Confidence ├── Failed tests └── Next experiment
- Cross-Sensor Correlator:
    Browser (DOM/State) + Burp (Traffic/Headers) + Code (AST/Endpoints) -> Combined Hypothesis
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.experiment_engine")


class ExperimentStage(str, Enum):
    DISCOVERY = "DISCOVERY"
    BASELINE = "BASELINE"
    DIFFERENTIAL = "DIFFERENTIAL"
    ERROR_PROBE = "ERROR_PROBE"
    BOOLEAN_PROBE = "BOOLEAN_PROBE"
    TIME_DELAY_PROBE = "TIME_DELAY_PROBE"
    CONTEXT_IDENTIFICATION = "CONTEXT_IDENTIFICATION"
    TARGETED_VERIFICATION = "TARGETED_VERIFICATION"


@dataclass
class ExperimentStep:
    stage: ExperimentStage
    payload: str
    description: str
    expected_signal: str
    observed_response: Optional[Dict[str, Any]] = None
    delta_score: float = 0.0
    succeeded: bool = False
    interpretation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["stage"] = self.stage.value
        return d


@dataclass
class ReasoningExperiment:
    """
    Reasoning Memory Container:
    Maintains complete epistemic history of an investigation hypothesis.
    The agent learns from failures and response deltas inside the engagement.
    """
    experiment_id: str
    hypothesis_title: str
    vuln_class: str
    target_url: str
    parameter: str
    why_generated: str
    evidence_collected: List[Dict[str, Any]] = field(default_factory=list)
    tests_attempted: List[ExperimentStep] = field(default_factory=list)
    failed_tests: List[Dict[str, Any]] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    response_deltas: List[Dict[str, Any]] = field(default_factory=list)
    interpretation: str = "Initial hypothesis formulated from discovery observation."
    confidence: float = 0.40
    next_experiment: Optional[str] = None
    status: str = "OPEN"  # OPEN, IN_PROGRESS, VERIFIED, REFUTED
    created_at: float = field(default_factory=time.time)

    def record_attempt(
        self,
        stage: ExperimentStage,
        payload: str,
        description: str,
        expected_signal: str,
        observed: Dict[str, Any],
        delta_score: float,
        succeeded: bool,
        interpretation: str,
        next_step: Optional[str] = None
    ) -> ExperimentStep:
        """Records a test attempt and adapts reasoning memory"""
        step = ExperimentStep(
            stage=stage,
            payload=payload,
            description=description,
            expected_signal=expected_signal,
            observed_response=observed,
            delta_score=delta_score,
            succeeded=succeeded,
            interpretation=interpretation,
        )
        self.tests_attempted.append(step)
        self.mutations.append(payload)
        self.interpretation = interpretation

        if delta_score > 0:
            self.response_deltas.append({
                "stage": stage.value,
                "delta": delta_score,
                "timestamp": step.timestamp
            })

        if succeeded:
            self.confidence = min(0.99, self.confidence + (0.15 * delta_score))
            self.evidence_collected.append({
                "stage": stage.value,
                "payload": payload,
                "observed": observed,
                "delta": delta_score,
                "interpretation": interpretation
            })
        else:
            self.failed_tests.append({
                "stage": stage.value,
                "payload": payload,
                "observed": observed,
                "reason": interpretation
            })
            # Settle confidence slightly on failure without zeroing valid previous steps
            self.confidence = max(0.10, self.confidence - 0.05)

        self.next_experiment = next_step
        return step

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "hypothesis_title": self.hypothesis_title,
            "vuln_class": self.vuln_class,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "why_generated": self.why_generated,
            "evidence_collected": self.evidence_collected,
            "tests_attempted": [t.to_dict() for t in self.tests_attempted],
            "failed_tests": self.failed_tests,
            "mutations": self.mutations,
            "response_deltas": self.response_deltas,
            "interpretation": self.interpretation,
            "confidence": round(self.confidence, 4),
            "next_experiment": self.next_experiment,
            "status": self.status,
            "created_at": self.created_at
        }


class ExperimentEngine:
    """
    Executes methodical scientific security experimentation:
    Generates structured test plans, analyzes response deltas, and prevents naive repetitive fuzzing.
    """

    @staticmethod
    def create_experiment(
        experiment_id: str,
        target_url: str,
        parameter: str,
        vuln_class: str,
        why_generated: str,
        initial_confidence: float = 0.45
    ) -> ReasoningExperiment:
        return ReasoningExperiment(
            experiment_id=experiment_id,
            hypothesis_title=f"Investigate {vuln_class.upper()} on {parameter}",
            vuln_class=vuln_class.lower(),
            target_url=target_url,
            parameter=parameter,
            why_generated=why_generated,
            confidence=initial_confidence,
            next_experiment="Establish normal baseline request behavior"
        )

    @staticmethod
    def generate_methodical_plan(vuln_class: str, parameter: str) -> List[Dict[str, Any]]:
        """
        Returns the scientific investigation sequence for a given vulnerability class.
        """
        vclass = vuln_class.lower()
        if "sqli" in vclass or "sql" in vclass:
            return [
                {
                    "stage": ExperimentStage.BASELINE,
                    "description": "Send benign query to calibrate response status, length, and timing.",
                    "payload": "1",
                    "expected": "Normal 200 OK baseline"
                },
                {
                    "stage": ExperimentStage.ERROR_PROBE,
                    "description": "Inject single quote to provoke syntax differential.",
                    "payload": "1'",
                    "expected": "HTTP 500 or SQL syntax error string"
                },
                {
                    "stage": ExperimentStage.BOOLEAN_PROBE,
                    "description": "Inject tautology (AND 1=1 vs AND 1=2) to verify boolean branch.",
                    "payload": "1 AND 1=1",
                    "expected": "Response matches baseline for TRUE, differs for FALSE"
                },
                {
                    "stage": ExperimentStage.CONTEXT_IDENTIFICATION,
                    "description": "Inject comment style (-- vs # vs /* */) to identify DBMS engine.",
                    "payload": "1-- -",
                    "expected": "Restoration of baseline behavior indicates comment syntax valid"
                },
                {
                    "stage": ExperimentStage.TARGETED_VERIFICATION,
                    "description": "Evaluate deterministic arithmetic expression (e.g. 53+19 = 72).",
                    "payload": "1+(53-52)",
                    "expected": "Deterministic arithmetic evaluation proves SQL expression parsing"
                }
            ]
        elif "idor" in vclass or "bola" in vclass:
            return [
                {
                    "stage": ExperimentStage.BASELINE,
                    "description": "Request authorized object with primary user credentials.",
                    "payload": "original_id",
                    "expected": "200 OK returning user's own data"
                },
                {
                    "stage": ExperimentStage.DIFFERENTIAL,
                    "description": "Request adjacent object ID using primary session credentials.",
                    "payload": "adjacent_id",
                    "expected": "403 Forbidden or 404 Not Found in secure applications"
                },
                {
                    "stage": ExperimentStage.TARGETED_VERIFICATION,
                    "description": "Verify unauthorized access: Cross-tenant data returned to unauthorized caller.",
                    "payload": "cross_tenant_id",
                    "expected": "200 OK with ownership mismatch proving authorization boundary failure"
                }
            ]
        elif "cmd" in vclass or "rce" in vclass:
            return [
                {
                    "stage": ExperimentStage.BASELINE,
                    "description": "Send benign input to establish normal process output.",
                    "payload": "127.0.0.1",
                    "expected": "Standard execution output"
                },
                {
                    "stage": ExperimentStage.ERROR_PROBE,
                    "description": "Inject metacharacters (;, |, `) to test shell breakout.",
                    "payload": "127.0.0.1;",
                    "expected": "Command syntax error or differential exit code"
                },
                {
                    "stage": ExperimentStage.TARGETED_VERIFICATION,
                    "description": "Inject deterministic arithmetic proof: $((53+19)) -> 72.",
                    "payload": "127.0.0.1; echo $((53+19));",
                    "expected": "Exact integer 72 reflected in response proves shell arithmetic evaluation"
                }
            ]
        else:
            return [
                {
                    "stage": ExperimentStage.BASELINE,
                    "description": "Send benign input.",
                    "payload": "test",
                    "expected": "Baseline response"
                },
                {
                    "stage": ExperimentStage.DIFFERENTIAL,
                    "description": "Send modified parameter.",
                    "payload": "test_mod",
                    "expected": "Response differential"
                },
                {
                    "stage": ExperimentStage.TARGETED_VERIFICATION,
                    "description": "Execute deterministic verification probe.",
                    "payload": "proof_payload",
                    "expected": "Deterministic proof"
                }
            ]


class CrossSensorCorrelator:
    """
    Correlates observations across the Sensor Triad:
    - Browser Sensor (DOM, localStorage, session cookies, forms)
    - Burp Sensor (Proxy/Repeater HTTP streams, headers, status codes)
    - Code Sensor (AST extracted routes, parameter types, role checks)
    """

    @staticmethod
    def correlate(
        browser_signals: Optional[List[Dict[str, Any]]] = None,
        burp_signals: Optional[List[Dict[str, Any]]] = None,
        code_signals: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Synthesizes multi-sensor observations into unified high-confidence hypotheses.
        """
        browser_signals = browser_signals or []
        burp_signals = burp_signals or []
        code_signals = code_signals or []

        combined: List[Dict[str, Any]] = []

        # 1. Correlate Auth / Role Boundaries
        # e.g. Browser sees admin UI role or session, Burp sees redirect or admin paths, Code sees role variables
        admin_browser = any("admin" in str(s).lower() or "role" in str(s).lower() for s in browser_signals)
        admin_burp = any("/admin" in str(s).lower() or "302" in str(s) or "auth" in str(s).lower() for s in burp_signals)
        admin_code = any("role" in str(s).lower() or "is_admin" in str(s).lower() or "auth" in str(s).lower() for s in code_signals)

        if (admin_browser and admin_burp) or (admin_burp and admin_code) or (admin_browser and admin_code):
            combined.append({
                "hypothesis_type": "CROSS_SENSOR_AUTH_BYPASS",
                "title": "Cross-Sensor Authorization Boundary Weakness",
                "sensors_involved": [
                    s for s, matched in [
                        ("BrowserSensor", admin_browser),
                        ("BurpSensor", admin_burp),
                        ("CodeSensor", admin_code)
                    ] if matched
                ],
                "confidence": 0.88,
                "rationale": "Client-side state, network redirect behavior, and backend route inspection indicate unverified privilege boundary.",
                "action_recommended": "Execute BFLA / Privilege Escalation targeted verification probe."
            })

        # 2. Correlate Direct Object Identifiers / IDOR
        id_params = {"id", "user_id", "account_id", "profile_id"}
        burp_has_id = any(any(p in str(s).lower() for p in id_params) for s in burp_signals)
        code_has_id = any(any(p in str(s).lower() for p in id_params) for s in code_signals)
        browser_has_session = any("session" in str(s).lower() or "role" in str(s).lower() or "localstorage" in str(s).lower() for s in browser_signals)

        if burp_has_id and (code_has_id or browser_has_session):
            combined.append({
                "hypothesis_type": "CROSS_SENSOR_IDOR_EXPOSURE",
                "title": "Cross-Sensor Object Boundary Verification (IDOR/BOLA)",
                "sensors_involved": [
                    s for s, matched in [
                        ("BrowserSensor", browser_has_session),
                        ("BurpSensor", burp_has_id),
                        ("CodeSensor", code_has_id)
                    ] if matched
                ],
                "confidence": 0.85,
                "rationale": "Direct object identifier observed in live Burp traffic correlated with client session and route parameters.",
                "action_recommended": "Execute horizontal IDOR differential probe with alternate tenant token."
            })

        # 3. Correlate Parameter Exposure
        for c in code_signals:
            param = c.get("parameter")
            route = c.get("route")
            if param and route:
                base_route = route.split(":")[0].rstrip("/")
                for b in burp_signals:
                    b_url = b.get("url", "")
                    if base_route and base_route in b_url and param not in b.get("parameters", []):
                        combined.append({
                            "hypothesis_type": "UNDOCUMENTED_PARAMETER_DISCOVERY",
                            "title": f"Undocumented Parameter '{param}' on {route}",
                            "sensors_involved": ["CodeSensor", "BurpSensor"],
                            "confidence": 0.82,
                            "rationale": f"Source/JS intelligence discovered parameter '{param}' which was never observed in live Burp proxy traffic.",
                            "action_recommended": f"Inject '{param}' with probe values to test for hidden administrative flags or debug modes."
                        })

        return combined
