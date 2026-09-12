"""
HunterAI Agent Contracts
Abstract Base Classes and Typed Contracts for each Stage in the Pipeline
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from hunter_ai.pipeline.schemas import (
    ScopeConfig,
    SubdomainRecord,
    LiveAssetRecord,
    EndpointRecord,
    ParameterRecord,
    SecretFindingRecord,
    HunterFinding,
    VerificationEvidence,
)


class IScopeAgent(ABC):
    @abstractmethod
    async def evaluate_scope(self, target: str, in_scope: Optional[List[str]] = None, out_scope: Optional[List[str]] = None) -> ScopeConfig:
        """Validate target against scope policy and rate limits"""
        pass


class IReconAgent(ABC):
    @abstractmethod
    async def run_recon(self, scope: ScopeConfig) -> List[SubdomainRecord]:
        """Perform passive and active subdomain enumeration across multiple sources"""
        pass


class IAssetNormalizationAgent(ABC):
    @abstractmethod
    def normalize_and_deduplicate(self, raw_subdomains: List[Dict[str, Any]]) -> List[SubdomainRecord]:
        """Merge multiple source results, deduplicate, calculate confidence, classify"""
        pass


class IHTTPLiveAgent(ABC):
    @abstractmethod
    async def probe_alive_assets(self, assets: List[SubdomainRecord]) -> List[LiveAssetRecord]:
        """Probe HTTP/HTTPS, extract status, title, tech fingerprint, redirects"""
        pass


class IDiscoveryAgent(ABC):
    @abstractmethod
    async def discover_surface(self, live_assets: List[LiveAssetRecord]) -> Tuple[List[EndpointRecord], List[str]]:
        """Harvest URLs, endpoints, directories, and discover query/form parameters"""
        pass


class IJavaScriptAgent(ABC):
    @abstractmethod
    async def analyze_javascript(self, js_urls: List[str]) -> Tuple[List[EndpointRecord], List[SecretFindingRecord]]:
        """Download JS, extract API routes, and scan for leaked credentials/secrets"""
        pass


class IParameterIntelligenceAgent(ABC):
    @abstractmethod
    def build_parameter_db(self, endpoints: List[EndpointRecord]) -> List[ParameterRecord]:
        """Classify parameters semantically and map to candidate vulnerability classes"""
        pass


class IVulnRouter(ABC):
    @abstractmethod
    def route_tasks(self, params: List[ParameterRecord], tech_stack: List[str]) -> List[Dict[str, Any]]:
        """Route mapped parameters to specialized skills based on relevance and context"""
        pass


class IVerificationEngine(ABC):
    @abstractmethod
    async def verify_finding(self, unverified_finding: Dict[str, Any], baseline_context: Dict[str, Any]) -> Tuple[bool, List[VerificationEvidence], float]:
        """
        Execute multi-layer verification:
        Enforces: Reflection != Injection != Execution
        Arithmetic proofs, differential checks, and baseline comparison.
        Returns: (is_verified, evidence_list, cvss_score)
        """
        pass


class IReportAgent(ABC):
    @abstractmethod
    async def generate_reports(self, findings: List[HunterFinding], output_dir: str) -> Dict[str, str]:
        """Generate Executive HTML, Markdown Bug Bounty Report, and JSON Summary"""
        pass
