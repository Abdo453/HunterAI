"""
HunterAI Multi-Agent Teams Package
==================================
Exports specialized squad agents across all 5 key investigation areas:
  - Recon Team (Asset Discovery, DNS, Recon Review)
  - Web Team (HTTP Analysis, Content Discovery, Web Review)
  - Network Team (Network Discovery, Service Analysis, Network Review)
  - API Team (API Discovery, Parameter Intelligence, API Review)
  - JavaScript Team (Route Extraction, Secret Triage, JS Review)
  - Verification Team (Counterexample, Reproduction, Causal Verification, Evidence Court Review)
"""
from core.teams.recon_team import (
    AssetDiscoveryAgent,
    DNSIntelligenceAgent,
    ReconReviewAgent,
)
from core.teams.web_team import (
    HTTPAnalysisAgent,
    ContentDiscoveryAgent,
    WebReviewAgent,
)
from core.teams.network_team import (
    NetworkDiscoveryAgent,
    ServiceAnalysisAgent,
    NetworkReviewAgent,
)
from core.teams.api_team import (
    APIDiscoveryAgent,
    ParameterIntelligenceAgent,
    APIReviewAgent,
)
from core.teams.javascript_team import (
    RouteExtractionAgent,
    SecretTriageAgent,
    JSReviewAgent,
)
from core.teams.verification_team import (
    CounterexampleAgent,
    ReproductionAgent,
    CausalVerificationAgent,
    EvidenceCourtReviewer,
)

__all__ = [
    # Recon Team
    "AssetDiscoveryAgent",
    "DNSIntelligenceAgent",
    "ReconReviewAgent",
    # Web Team
    "HTTPAnalysisAgent",
    "ContentDiscoveryAgent",
    "WebReviewAgent",
    # Network Team
    "NetworkDiscoveryAgent",
    "ServiceAnalysisAgent",
    "NetworkReviewAgent",
    # API Team
    "APIDiscoveryAgent",
    "ParameterIntelligenceAgent",
    "APIReviewAgent",
    # JavaScript Team
    "RouteExtractionAgent",
    "SecretTriageAgent",
    "JSReviewAgent",
    # Verification Team
    "CounterexampleAgent",
    "ReproductionAgent",
    "CausalVerificationAgent",
    "EvidenceCourtReviewer",
]
