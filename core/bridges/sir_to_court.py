"""Bridge from Security Intermediate Representation (SIRGraph) to EvidenceCourt.

Filters SIR entities/nodes by confidence threshold, converts each qualifying
entity into a canonical ``Claim`` (``core.evidence_os.unified_model.Claim``),
and submits them for adjudication to ``EvidenceCourt``, ``EvidenceCourtV2``,
or a duck-typed/mock court implementing ``adjudicate(claim)``.
"""
from __future__ import annotations

import hashlib
import inspect
from typing import Any, Dict, List, Optional, Tuple

from core.court.evidence_court_v2 import EvidenceCourtV2, TribunalRuling
from core.evidence_court import CourtJudgment, CourtVerdict, EvidenceCourt
from core.evidence_os.unified_model import Claim

_DISPROVED_VERDICT = getattr(CourtVerdict, "DISPROVED", CourtVerdict.FALSE_POSITIVE)
_INCONCLUSIVE_VERDICT = getattr(CourtVerdict, "INCONCLUSIVE", CourtVerdict.FALSE_POSITIVE)


def _get_field(node: Any, name: str, default: Any = None) -> Any:
    if isinstance(node, dict):
        return node.get(name, default)
    return getattr(node, name, default)


def _get_confidence(node: Any) -> float:
    raw = _get_field(node, "confidence", 0.0)
    if raw is None:
        return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _get_attrs(node: Any) -> Dict[str, Any]:
    attrs = _get_field(node, "attributes", None)
    return dict(attrs) if isinstance(attrs, dict) else {}


def _get_entity_type_str(node: Any) -> str:
    etype = _get_field(node, "entity_type", "UNKNOWN")
    if hasattr(etype, "value"):
        return str(etype.value)
    return str(etype or "UNKNOWN")


def _get_sources(node: Any) -> List[str]:
    raw_sources = _get_field(node, "observed_sources", ())
    if isinstance(raw_sources, (set, list, tuple)):
        return sorted(str(s) for s in raw_sources)
    if raw_sources:
        return [str(raw_sources)]
    return []


def _get_evidence_refs(node: Any) -> List[str]:
    raw_refs = _get_field(node, "evidence_refs", ())
    if isinstance(raw_refs, (set, list, tuple)):
        return [str(r) for r in raw_refs]
    if raw_refs:
        return [str(raw_refs)]
    return []


def _iter_sir_nodes(sir_graph: Any) -> List[Any]:
    """Extracts entity/node objects from SIRGraph or compatible mock graphs."""
    if sir_graph is None:
        return []

    entities = getattr(sir_graph, "entities", None)
    if isinstance(entities, dict):
        return list(entities.values())
    if isinstance(entities, (list, tuple, set)):
        return list(entities)

    nodes = getattr(sir_graph, "nodes", None)
    if isinstance(nodes, dict):
        return list(nodes.values())
    if isinstance(nodes, (list, tuple, set)):
        return list(nodes)

    if isinstance(sir_graph, dict):
        return list(sir_graph.values())
    if isinstance(sir_graph, (list, tuple, set)):
        return list(sir_graph)

    return []


def _build_graph_index(sir_graph: Any) -> Dict[str, Any]:
    """Indexes endpoint and parameter relationships on a SIRGraph for context resolution."""
    target_host = getattr(sir_graph, "target_host", "")
    if not isinstance(target_host, str):
        target_host = ""

    entities = getattr(sir_graph, "entities", None)
    entities_map: Dict[str, Any] = entities if isinstance(entities, dict) else {}

    relationships = getattr(sir_graph, "relationships", None)
    parent_endpoint: Dict[str, Any] = {}
    endpoint_params: Dict[str, List[str]] = {}

    if isinstance(relationships, (list, tuple, set)):
        for rel in relationships:
            src_id = getattr(rel, "source_id", None)
            dst_id = getattr(rel, "target_id", None)
            rel_type = getattr(rel, "rel_type", "")
            if not isinstance(src_id, str) or not isinstance(dst_id, str):
                continue
            src_ent = entities_map.get(src_id)
            dst_ent = entities_map.get(dst_id)
            if src_ent is not None and _get_entity_type_str(src_ent) == "ENDPOINT":
                parent_endpoint.setdefault(dst_id, src_ent)
                if rel_type == "ACCEPTS_PARAMETER" and dst_ent is not None:
                    p_name = str(_get_field(dst_ent, "name", "") or "")
                    if p_name:
                        endpoint_params.setdefault(src_id, []).append(p_name)

    return {
        "target_host": target_host,
        "parent_endpoint": parent_endpoint,
        "endpoint_params": endpoint_params,
    }


def _resolve_vuln_class(node: Any, attrs: Dict[str, Any]) -> str:
    for candidate in (
        attrs.get("vuln_class"),
        attrs.get("vulnerability_class"),
        attrs.get("signal_type"),
        _get_field(node, "vulnerability_class", None),
        _get_field(node, "vuln_class", None),
    ):
        if candidate:
            return str(candidate)
    return _get_entity_type_str(node)


def sir_entity_to_claim(entity: Any, sir_graph: Optional[Any] = None) -> Claim:
    """Converts a SIR entity/node into a canonical EvidenceOS ``Claim``."""
    entity_id = str(_get_field(entity, "entity_id", "") or _get_field(entity, "id", "") or "")
    name = str(_get_field(entity, "name", "") or entity_id or "unnamed_entity")
    entity_type = _get_entity_type_str(entity)
    attrs = _get_attrs(entity)
    confidence = _get_confidence(entity)
    sources = _get_sources(entity)
    evidence_refs = _get_evidence_refs(entity)

    evidence_id = (
        evidence_refs[0]
        if evidence_refs
        else (entity_id or f"SIR-{hashlib.sha256(name.encode('utf-8')).hexdigest()[:8].upper()}")
    )
    vuln_class = _resolve_vuln_class(entity, attrs)

    if attrs.get("rationale"):
        rationale = str(attrs["rationale"])
    else:
        sources_label = ", ".join(sources) if sources else "SIR"
        refs_label = f", refs={','.join(evidence_refs)}" if evidence_refs else ""
        host = getattr(sir_graph, "target_host", "") if sir_graph is not None else ""
        host_label = f", host={host}" if isinstance(host, str) and host else ""
        rationale = (
            f"SIR {entity_type} '{name}' "
            f"(id={entity_id or 'n/a'}, sources={sources_label}, "
            f"confidence={confidence:.2f}{host_label}{refs_label})"
        )

    chain_material = (
        f"{entity_id}:{evidence_id}:{vuln_class}:{confidence:.6f}:{','.join(sources)}"
    )
    provenance_hash_chain = hashlib.sha256(chain_material.encode("utf-8")).hexdigest()[:16]

    return Claim(
        evidence_id=evidence_id,
        vulnerability_class=vuln_class,
        confidence_score=confidence,
        rationale=rationale,
        provenance_hash_chain=provenance_hash_chain,
    )


def _format_url(host: str, path: str) -> str:
    clean_host = host.strip().rstrip("/")
    clean_path = path.strip()
    if clean_host and not clean_host.startswith(("http://", "https://")):
        clean_host = f"https://{clean_host}"
    if clean_host and clean_path:
        if not clean_path.startswith("/"):
            clean_path = f"/{clean_path}"
        return f"{clean_host}{clean_path}"
    return clean_host or clean_path


def _extract_court_context(
    entity: Any,
    claim: Claim,
    graph_index: Dict[str, Any],
) -> Dict[str, Any]:
    """Builds structured adjudication context for EvidenceCourt / EvidenceCourtV2."""
    entity_id = str(_get_field(entity, "entity_id", "") or _get_field(entity, "id", "") or "")
    name = str(_get_field(entity, "name", "") or entity_id or "")
    entity_type = _get_entity_type_str(entity)
    attrs = _get_attrs(entity)
    sources = _get_sources(entity)
    evidence_refs = _get_evidence_refs(entity)
    raw_evidence = attrs.get("raw_evidence") if isinstance(attrs.get("raw_evidence"), dict) else {}

    parent_ep = graph_index["parent_endpoint"].get(entity_id)
    parent_attrs = _get_attrs(parent_ep) if parent_ep is not None else {}

    # 1. Target URL resolution
    target_url = (
        attrs.get("target_url")
        or attrs.get("url")
        or attrs.get("page_url")
        or attrs.get("matched_at")
        or raw_evidence.get("url")
        or raw_evidence.get("matched_at")
        or parent_attrs.get("target_url")
        or parent_attrs.get("url")
    )
    if not target_url:
        host = (
            attrs.get("asset")
            or attrs.get("host")
            or parent_attrs.get("asset")
            or parent_attrs.get("host")
            or graph_index["target_host"]
        )
        path = (
            attrs.get("endpoint")
            or attrs.get("path")
            or parent_attrs.get("endpoint")
            or parent_attrs.get("path")
            or ""
        )
        target_url = _format_url(str(host or ""), str(path or "")) or name or entity_id or "unknown"

    # 2. Parameter resolution
    parameter = (
        attrs.get("parameter")
        or attrs.get("param")
        or raw_evidence.get("parameter")
        or raw_evidence.get("param")
        or ""
    )
    if not parameter and entity_type == "PARAMETER":
        parameter = name
    if not parameter and parent_ep is not None:
        parent_id = str(_get_field(parent_ep, "entity_id", "") or "")
        params = graph_index["endpoint_params"].get(parent_id, [])
        if params:
            parameter = params[0]
    if not parameter and entity_id in graph_index["endpoint_params"]:
        parameter = graph_index["endpoint_params"][entity_id][0]

    # 3. Finder claim dictionary carrying Claim lineage & SIR metadata
    finder_claim: Dict[str, Any] = {
        "claim_id": claim.claim_id,
        "evidence_id": claim.evidence_id,
        "vulnerability_class": claim.vulnerability_class,
        "confidence_score": claim.confidence_score,
        "rationale": claim.rationale,
        "provenance_hash_chain": claim.provenance_hash_chain,
        "sir_entity_id": entity_id,
        "sir_entity_type": entity_type,
        "sir_entity_name": name,
        "observed_sources": sources,
        "evidence_refs": evidence_refs,
        "claim": claim.rationale,
    }
    if isinstance(attrs.get("finder_claim"), dict):
        finder_claim.update(attrs["finder_claim"])

    # 4. Optional verification artifacts
    verifier_result: Optional[Dict[str, Any]] = None
    if isinstance(attrs.get("verifier_result"), dict):
        verifier_result = dict(attrs["verifier_result"])
    elif "reproduced" in attrs:
        verifier_result = {
            "reproduced": bool(attrs["reproduced"]),
            "confidence": claim.confidence_score,
        }

    return {
        "target_url": str(target_url),
        "parameter": str(parameter),
        "vuln_class": claim.vulnerability_class,
        "finder_claim": finder_claim,
        "verifier_result": verifier_result,
        "is_in_scope": bool(attrs.get("is_in_scope", True)),
        "is_blocked_by_waf": bool(attrs.get("is_blocked_by_waf", False)),
        "provenance_chain": attrs.get("provenance_chain"),
        "causal_triad": attrs.get("causal_triad"),
        "causal_evidence": attrs.get("causal_evidence"),
        "negative_evidence": attrs.get("negative_evidence"),
        "negative_observables": attrs.get("negative_observables"),
        "execution_evidence": attrs.get("execution_evidence"),
        "provenance_trace": attrs.get("provenance_trace"),
        "proof_payload": attrs.get("proof_payload"),
        "allow_declared_proof": bool(attrs.get("allow_declared_proof", False)),
        "attrs": attrs,
    }


def _tribunal_ruling_to_judgment(
    ruling: TribunalRuling,
    ctx: Dict[str, Any],
    confidence_score: float,
) -> CourtJudgment:
    """Adapts an EvidenceCourtV2 ``TribunalRuling`` into a ``CourtJudgment``."""
    verdict_map = {
        "CONFIRMED": CourtVerdict.CONFIRMED,
        "REFUTED": _DISPROVED_VERDICT,
        "INCONCLUSIVE": _INCONCLUSIVE_VERDICT,
    }
    verdict = verdict_map.get(ruling.final_verdict, _INCONCLUSIVE_VERDICT)
    is_confirmed = verdict == CourtVerdict.CONFIRMED

    if is_confirmed:
        severity = "Medium"
        v_lower = ctx["vuln_class"].lower()
        if any(k in v_lower for k in ("rce", "cmd", "sqli", "sql_injection")):
            severity = "Critical"
        elif any(k in v_lower for k in ("idor", "bola", "ssrf", "xxe", "auth_bypass")):
            severity = "High"
    elif verdict == _DISPROVED_VERDICT:
        severity = "Info"
    else:
        severity = "Low"

    return CourtJudgment(
        judgment_id=ruling.court_judgment_id or f"judg_{ruling.case_id}",
        target_url=ruling.target_endpoint or ctx["target_url"],
        parameter=ctx["parameter"],
        vuln_class=ctx["vuln_class"],
        verdict=verdict,
        calibrated_severity=severity,
        confidence_score=confidence_score if is_confirmed else (0.35 if verdict == _INCONCLUSIVE_VERDICT else 0.10),
        reportable=is_confirmed,
        finder_claim=ctx["finder_claim"],
        verifier_result=ctx["verifier_result"] or {},
        adjudication_rationale=ruling.chief_justification,
        epistemic_state=ruling.epistemic_state,
        proof_strength=ruling.proof_strength,
    )


def _call_evidence_court_v1(court: Any, ctx: Dict[str, Any]) -> Any:
    kwargs: Dict[str, Any] = {
        "target_url": ctx["target_url"],
        "parameter": ctx["parameter"],
        "vuln_class": ctx["vuln_class"],
        "finder_claim": ctx["finder_claim"],
        "verifier_result": ctx["verifier_result"],
        "is_in_scope": ctx["is_in_scope"],
        "is_blocked_by_waf": ctx["is_blocked_by_waf"],
    }
    for optional_key in (
        "provenance_chain",
        "causal_triad",
        "causal_evidence",
        "negative_evidence",
        "negative_observables",
        "execution_evidence",
        "provenance_trace",
        "proof_payload",
    ):
        if ctx[optional_key] is not None:
            kwargs[optional_key] = ctx[optional_key]
    if ctx["allow_declared_proof"]:
        kwargs["allow_declared_proof"] = True

    return court.adjudicate(**kwargs)


def _call_evidence_court_v2(court: Any, claim: Claim, ctx: Dict[str, Any]) -> Any:
    attrs = ctx["attrs"]
    vr = dict(ctx["verifier_result"] or {})
    vr.setdefault("parameter", ctx["parameter"])
    vr.setdefault("vuln_class", ctx["vuln_class"])
    reproduced = bool(vr.get("reproduced", False))
    reproductions_count = int(attrs.get("reproductions_count", 2 if reproduced else 0))
    causal_ev = ctx["causal_evidence"]
    causal_verified = bool(
        attrs.get(
            "causal_chain_verified",
            causal_ev is not None and bool(getattr(causal_ev, "invariant_passed", False)),
        )
    )

    ruling = court.adjudicate_case(
        case_id=claim.claim_id,
        endpoint=ctx["target_url"],
        proof_nonce_proven=bool(attrs.get("proof_nonce_proven", False)),
        reproductions_count=reproductions_count,
        causal_chain_verified=causal_verified,
        baseline_stable=bool(attrs.get("baseline_stable", True)),
        waf_clean=not ctx["is_blocked_by_waf"],
        proof_payload=ctx["proof_payload"],
        verifier_result=vr,
        allow_declared_proof=ctx["allow_declared_proof"],
    )
    if isinstance(ruling, TribunalRuling):
        return _tribunal_ruling_to_judgment(ruling, ctx, claim.confidence_score)
    return ruling


def _inspect_callable_params(fn: Any) -> Tuple[List[inspect.Parameter], bool]:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return [], True
    named = [
        p
        for p in sig.parameters.values()
        if p.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        )
    ]
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    return named, has_var_kw


def _adjudicate_claim(
    court: Any,
    claim: Claim,
    entity: Any,
    graph_index: Dict[str, Any],
) -> Any:
    is_v1 = (
        court is EvidenceCourt
        or (isinstance(court, type) and issubclass(court, EvidenceCourt))
        or isinstance(court, EvidenceCourt)
    )
    if is_v1:
        ctx = _extract_court_context(entity, claim, graph_index)
        return _call_evidence_court_v1(court, ctx)

    is_v2 = (
        court is EvidenceCourtV2
        or (isinstance(court, type) and issubclass(court, EvidenceCourtV2))
        or isinstance(court, EvidenceCourtV2)
    )
    if is_v2:
        ctx = _extract_court_context(entity, claim, graph_index)
        return _call_evidence_court_v2(court, claim, ctx)

    adjudicate_fn = getattr(court, "adjudicate", None)
    if callable(adjudicate_fn):
        named_params, has_var_kw = _inspect_callable_params(adjudicate_fn)
        param_names = {p.name for p in named_params}
        if {"target_url", "parameter", "vuln_class"}.issubset(param_names) or (
            "target_url" in param_names and len(named_params) >= 3
        ):
            ctx = _extract_court_context(entity, claim, graph_index)
            all_kwargs = {
                "target_url": ctx["target_url"],
                "parameter": ctx["parameter"],
                "vuln_class": ctx["vuln_class"],
                "finder_claim": ctx["finder_claim"],
                "verifier_result": ctx["verifier_result"],
                "is_in_scope": ctx["is_in_scope"],
                "is_blocked_by_waf": ctx["is_blocked_by_waf"],
                "provenance_chain": ctx["provenance_chain"],
                "causal_triad": ctx["causal_triad"],
                "causal_evidence": ctx["causal_evidence"],
                "negative_evidence": ctx["negative_evidence"],
                "negative_observables": ctx["negative_observables"],
                "execution_evidence": ctx["execution_evidence"],
                "provenance_trace": ctx["provenance_trace"],
                "proof_payload": ctx["proof_payload"],
                "allow_declared_proof": ctx["allow_declared_proof"],
            }
            if has_var_kw:
                return adjudicate_fn(**all_kwargs)
            filtered = {k: v for k, v in all_kwargs.items() if k in param_names}
            return adjudicate_fn(**filtered)

        return adjudicate_fn(claim)

    adjudicate_case_fn = getattr(court, "adjudicate_case", None)
    if callable(adjudicate_case_fn):
        named_params, has_var_kw = _inspect_callable_params(adjudicate_case_fn)
        param_names = {p.name for p in named_params}
        if "claim" in param_names or len(named_params) == 1:
            return adjudicate_case_fn(claim)
        ctx = _extract_court_context(entity, claim, graph_index)
        return _call_evidence_court_v2(court, claim, ctx)

    raise TypeError(
        f"Unsupported court object {court!r}: expected 'adjudicate' or 'adjudicate_case' method."
    )


def submit_sir_to_court(
    sir_graph: Any,
    court: Any,
    threshold: float = 0.8,
) -> List[CourtJudgment]:
    """Submits high-confidence SIR entities to EvidenceCourt for adjudication.

    Args:
        sir_graph: A ``SIRGraph`` (or duck-typed graph exposing ``.entities`` or ``.nodes``).
        court: ``EvidenceCourt``, ``EvidenceCourtV2``, or a duck-typed/mock court
            implementing ``adjudicate(claim)`` or ``adjudicate(...)``.
        threshold: Minimum ``confidence`` required to submit an entity (inclusive).

    Returns:
        List of adjudication results (``CourtJudgment`` instances for real courts).
    """
    nodes = _iter_sir_nodes(sir_graph)
    if not nodes:
        return []

    graph_index = _build_graph_index(sir_graph)
    judgments: List[CourtJudgment] = []

    for node in nodes:
        if _get_confidence(node) < threshold:
            continue
        claim = sir_entity_to_claim(node, sir_graph=sir_graph)
        judgment = _adjudicate_claim(court, claim, node, graph_index)
        judgments.append(judgment)

    return judgments
