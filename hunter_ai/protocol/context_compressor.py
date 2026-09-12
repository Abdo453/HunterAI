"""
Hunter Agent Protocol v1: Context Compression & Handoff Engine
===============================================================
Solves LLM Context Window Exhaustion & Cognitive Degradation.
When Qwen 2.5 Coder analyzes 300 JS files or massive DOM traces, it compresses
findings into a concise, high-density knowledge contract with pointers to raw artifacts.
This allows WhiteRabbitNeo to receive synthesized intelligence rather than raw noise.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.context_compressor")


@dataclass
class CompressedKnowledgePackage:
    """
    Standardized Inter-Model Handoff Contract:
    Produced by specialized workers (e.g. Qwen Coder / xploiter)
    Consumed by strategic reasoners (e.g. WhiteRabbitNeo / Orchestrator)
    """
    package_id: str = field(default_factory=lambda: f"pkg_{uuid.uuid4().hex[:8]}")
    asset: str = ""
    interesting_endpoints: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)  # [{"name": "id", "location": "query", "pattern": "int"}]
    technologies: List[str] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)      # Masked secret tokens
    auth_context: List[str] = field(default_factory=list)            # Session, JWT, Bearer headers discovered
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)   # [{"vuln": "IDOR", "target": "/api/user"}]
    evidence_refs: List[str] = field(default_factory=list)           # Disk paths to raw files for on-demand drill-down
    recommended_next_actions: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ContextCompressor:
    """
    Distills voluminous reconnaissance and code audit artifacts into
    concise, token-efficient intelligence packages for downstream LLMs.
    """

    @classmethod
    def compress_js_recon(
        cls,
        asset: str,
        raw_endpoints: List[str],
        discovered_params: List[str],
        detected_secrets: List[Dict[str, Any]],
        technologies: List[str],
        raw_artifacts_path: str = ""
    ) -> CompressedKnowledgePackage:
        """Compresses JS crawling outputs into an optimal handoff envelope"""
        # Deduplicate and sort endpoints
        clean_eps = sorted(list(set(raw_endpoints)))[:40]
        
        # Structure parameters
        param_objs = []
        for p in sorted(list(set(discovered_params)))[:30]:
            param_objs.append({
                "name": p,
                "location": "query" if "?" in p else "body_or_param",
                "suspected_classes": ["IDOR", "SQLi"] if any(k in p.lower() for k in ["id", "user", "account", "num"]) else ["SSRF"] if "url" in p.lower() else ["Generic"]
            })

        # Generate initial candidate hypotheses
        hypotheses = []
        for ep in clean_eps:
            if "/api/" in ep or "/v1/" in ep or "/v2/" in ep:
                hypotheses.append({
                    "vuln_class": "BOLA/IDOR",
                    "target_endpoint": ep,
                    "rationale": "REST API endpoint without explicit parameter typing"
                })

        actions = [
            f"Test top {min(5, len(clean_eps))} API routes for unauthorized object reference",
            "Verify token revocation on identified authentication endpoints",
            "Correlate discovered parameter candidates with baseline responses"
        ]

        pkg = CompressedKnowledgePackage(
            asset=asset,
            interesting_endpoints=clean_eps,
            parameters=param_objs,
            technologies=technologies,
            secrets=detected_secrets,
            auth_context=["Bearer Token Header", "Session Cookie"],
            hypotheses=hypotheses[:10],
            evidence_refs=[raw_artifacts_path] if raw_artifacts_path else [],
            recommended_next_actions=actions
        )
        return pkg

    @classmethod
    def prepare_white_rabbit_prompt(cls, pkg: CompressedKnowledgePackage) -> str:
        """
        Formats the compressed package into a clean, dense prompt for WhiteRabbitNeo.
        Keeps token usage minimal while providing complete tactical context.
        """
        return f"""TACTICAL TARGET INTELLIGENCE:
- Target Asset: {pkg.asset}
- Technologies: {', '.join(pkg.technologies) or 'Standard Web Stack'}
- High-Value Endpoints ({len(pkg.interesting_endpoints)}):
{json.dumps(pkg.interesting_endpoints[:15], indent=2)}

- Prioritized Parameter Candidates ({len(pkg.parameters)}):
{json.dumps(pkg.parameters[:10], indent=2)}

- Suspected Hypotheses:
{json.dumps(pkg.hypotheses[:5], indent=2)}

- Recommended Strategic Actions:
{json.dumps(pkg.recommended_next_actions, indent=2)}

TASK FOR WHITERABBITNEO:
Select the #1 highest-priority hypothesis above. Formulate a non-destructive verification plan and exact curl command.
"""
