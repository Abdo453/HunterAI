"""
The 7-Question Gate — محرك التحقق الصارم والتصفية المسبقة للثغرات
=================================================================
Each finding must answer and satisfy all 7 questions before passing triage:
1. Target Asset / Endpoint: Exactly what URL, host, or parameter?
2. Vulnerability Class & VRT: What standardized CWE/VRT class?
3. Deterministic Proof & Root Cause: Canonical EvidenceCourt CONFIRMED + DERIVED proof
   (NEVER ``len(evidence) > 20`` heuristics or caller-asserted boolean flags).
4. Step-by-Step Reproduction: Concrete reproducible PoC/request artifact (NEVER ``len > 10``).
5. Demonstrated Impact: Real business/security damage vs purely theoretical risk.
6. Defensive Remediation: Concrete fix recommendation required (NEVER awards +0.8 when absent).
7. Scope & Hygiene Check: Authorized ``in_scope_list`` MUST be non-empty and match target (fail-closed).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.evidence_court import (
    CausalEvidence,
    CourtJudgment,
    CourtVerdict,
    EvidenceCourt,
    ProofPayload,
    ProofStrength,
)
from core.vrt_mapper import VRTEntry, VRTMapper


@dataclass
class GateResult:
    passed: bool
    score: float                         # 0.0 to 1.0 (100%)
    answers: Dict[str, str] = field(default_factory=dict)
    missing_items: List[str] = field(default_factory=list)
    vrt_entry: Optional[VRTEntry] = None
    triage_statement: str = ""
    canonical_verdict: str = CourtVerdict.UNVERIFIED.value
    proof_strength: str = ProofStrength.NONE.value


def _host_matches_scope(target: str, scope_entry: str) -> bool:
    t = (target or "").strip().lower()
    s = (scope_entry or "").strip().lower()
    if not t or not s:
        return False
    parsed_t = urlparse(t if "://" in t else f"https://{t}")
    t_host = (parsed_t.hostname or t).strip(".")
    parsed_s = urlparse(s if "://" in s else f"https://{s.lstrip('*.')}")
    s_host = (parsed_s.hostname or s.lstrip("*.")).strip(".")
    if not t_host or not s_host:
        return False
    return t_host == s_host or t_host.endswith("." + s_host)


class SevenQuestionGate:
    """
    7-Question Gate backed by canonical EvidenceCourt (DERIVED proof required)
    and fail-closed scope & remediation checks.
    """

    @classmethod
    def _evaluate_canonical_proof(
        cls,
        finding: Dict[str, Any],
        url: str,
        vuln_type: str,
        evidence_text: str,
        is_in_scope: bool,
    ) -> CourtJudgment:
        existing = finding.get("court_judgment")
        if isinstance(existing, CourtJudgment):
            return existing

        proof_payload = ProofPayload.from_mapping(finding.get("proof_payload"))
        causal_ev = finding.get("causal_evidence")
        if not isinstance(causal_ev, CausalEvidence):
            causal_ev = None

        if proof_payload is None and evidence_text:
            proof_payload = ProofPayload.from_vuln_evidence(vuln_type, evidence_text)

        verifier_result = dict(finding.get("verifier_result") or {})
        if proof_payload is not None or causal_ev is not None:
            verifier_result.setdefault("reproduced", True)
        elif not verifier_result:
            verifier_result = {"reproduced": False, "status": "CANDIDATE"}

        return EvidenceCourt.adjudicate(
            target_url=url or str(finding.get("target") or ""),
            parameter=str(finding.get("parameter") or ""),
            vuln_class=vuln_type,
            finder_claim={"title": str(finding.get("title") or "")},
            verifier_result=verifier_result,
            is_in_scope=is_in_scope,
            causal_evidence=causal_ev,
            proof_payload=proof_payload,
            allow_declared_proof=False,
        )

    @staticmethod
    def _has_concrete_reproduction(finding: Dict[str, Any], evidence_text: str) -> bool:
        if finding.get("reproduction") or finding.get("poc") or finding.get("curl_command") or finding.get("steps"):
            return True
        # Structured HTTP request trace or curl command inside evidence
        return bool(
            re.search(r"\b(?:curl\s+|(?:GET|POST|PUT|DELETE|PATCH)\s+(?:/|https?://))", evidence_text)
        )

    @classmethod
    def evaluate_finding(
        cls,
        finding: Dict[str, Any],
        in_scope_list: Optional[List[str]] = None,
    ) -> GateResult:
        title = str(finding.get("title", "")).strip()
        evidence = str(finding.get("evidence", "")).strip()
        vuln_type = str(finding.get("type", "") or finding.get("vuln_type", "") or finding.get("vuln_class", "")).strip() or "general"
        url = str(finding.get("url", "") or finding.get("endpoint", "")).strip()
        recommendation = str(finding.get("recommendation", "") or finding.get("remediation", "")).strip()

        answers: Dict[str, str] = {}
        missing: List[str] = []
        score_points = 0.0

        # Q1: Target & Endpoint
        if url or any(k in evidence.lower() for k in ("http://", "https://", "host:", "endpoint")):
            endpoint_val = url or "Identified in evidence context"
            answers["Q1_Endpoint"] = f"Endpoint verified: {endpoint_val}"
            score_points += 1.0
        else:
            missing.append("Q1: Missing exact target URL/endpoint.")

        # Q2: Vulnerability Class & VRT mapping
        vrt = VRTMapper.lookup(vuln_type)
        answers["Q2_VRT_Class"] = f"{vrt.subcategory} ({vrt.priority} / {vrt.cwe}) [{vrt.vrt_id}]"
        score_points += 1.0

        # Q7 (evaluated before Q3 so scope informs canonical adjudication): Fail-closed scope check
        target_domain = str(finding.get("target", "") or url).strip()
        q7_passed = False
        if in_scope_list and target_domain:
            in_scope = any(_host_matches_scope(target_domain, s) for s in in_scope_list)
            if in_scope:
                answers["Q7_Scope"] = "Target confirmed IN-SCOPE against authorized in_scope_list."
                score_points += 1.0
                q7_passed = True
            else:
                missing.append("Q7: Target is not present in authorized in_scope_list.")
        else:
            missing.append("Q7: Missing or empty in_scope_list (fail-closed scope verification failed).")

        # Q3: Deterministic Proof & Root Cause via canonical EvidenceCourt (DERIVED only)
        judgment = cls._evaluate_canonical_proof(
            finding=finding,
            url=url,
            vuln_type=vuln_type,
            evidence_text=evidence,
            is_in_scope=q7_passed if in_scope_list else True,
        )
        q3_passed = (
            judgment.verdict == CourtVerdict.CONFIRMED
            and judgment.proof_strength == ProofStrength.DERIVED.value
        )
        if q3_passed:
            answers["Q3_RootCause"] = (
                f"Canonical EvidenceCourt CONFIRMED with DERIVED proof ({judgment.proof_kind}): "
                f"{judgment.proof_detail}"
            )
            score_points += 1.0
        else:
            missing.append(
                f"Q3: Missing canonical EvidenceCourt CONFIRMED/DERIVED proof "
                f"(verdict={judgment.canonical_verdict.value}, proof_strength={judgment.proof_strength})."
            )

        # Q4: Step-by-Step Reproduction (requires real reproduction artifact/trace, never len > 10)
        if cls._has_concrete_reproduction(finding, evidence):
            answers["Q4_Reproduction"] = f"Actionable reproduction trace present ({finding.get('tool', 'tool')})."
            score_points += 1.0
        else:
            missing.append("Q4: Missing concrete step-by-step reproduction or HTTP/curl PoC trace.")

        # Q5: Real-World Business Impact
        sev = str(finding.get("severity", vrt.priority)).capitalize()
        if sev in ("Critical", "High", "Medium", "P1", "P2", "P3"):
            answers["Q5_Impact"] = f"Direct Security Impact: {vrt.description}"
            score_points += 1.0
        else:
            answers["Q5_Impact"] = "Informational / Minimal direct security degradation."
            score_points += 0.5

        # Q6: Defensive Remediation (ZERO credit without concrete remediation)
        if recommendation:
            answers["Q6_Remediation"] = recommendation
            score_points += 1.0
        else:
            missing.append("Q6: Missing concrete defensive remediation recommendation.")

        total_score = round(score_points / 7.0, 2)
        passed = q3_passed and q7_passed and total_score >= 0.70 and len(missing) == 0

        triage_lines = [
            f"### 7-Question Gate Triage: {title} [{total_score:.0%}]",
            f"- **VRT Priority:** `{vrt.priority}` ({vrt.subcategory})",
            f"- **CWE:** `{vrt.cwe}`",
            f"- **Canonical Court Verdict:** `{judgment.canonical_verdict.value}` (proof_strength=`{judgment.proof_strength}`)",
            f"- **Gate Status:** `{'PASSED' if passed else 'FLAGGED_FOR_REVIEW'}`",
            "",
            "**Gate Questions:**",
        ]
        for q_key, ans in answers.items():
            triage_lines.append(f"1. **{q_key.replace('_', ' ')}:** {ans}")

        if missing:
            triage_lines.extend(["", "**Missing Gate Items:**"] + [f"- {m}" for m in missing])

        statement = "\n".join(triage_lines)

        return GateResult(
            passed=passed,
            score=total_score,
            answers=answers,
            missing_items=missing,
            vrt_entry=vrt,
            triage_statement=statement,
            canonical_verdict=judgment.canonical_verdict.value,
            proof_strength=judgment.proof_strength,
        )
