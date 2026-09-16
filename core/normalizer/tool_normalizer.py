"""
HunterAI Unified Tool Output Normalizer
=======================================
Normalizes disparate outputs from industry-standard reconnaissance, crawling,
fuzzing, and scanning tools into canonical Security Intermediate Representation (SIR)
entities and signals:

Supported Tool Ingestors:
1. subfinder: Subdomain discovery line stream
2. httpx: Probed endpoints, status codes, titles, tech stacks (JSONL)
3. katana: Web crawler endpoints, forms, parameters (JSONL)
4. gau / waybackurls: Passive URL archives
5. nuclei: Vulnerability templates, matched endpoints, curl reproductions (JSON/JSONL)
6. ffuf: Web fuzzer endpoints, word counts, HTTP status (JSON)
7. sqlmap: DBMS detection, injection points, vulnerable parameters
8. dalfox: Cross-Site Scripting verified reflections and DOM sinks (JSONL)

All tool findings enter the system at Evidence Level E0 (Recon) or E1 (Differential/Candidate),
strictly requiring verification by HunterAI Evidence Court before becoming Confirmed Findings.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

from core.compiler.security_ir import SIRGraph, SIREntity, SIREntityType, SIRRelationship
from core.evidence.evidence_level import EvidenceLevel

logger = logging.getLogger("hunter_ai.normalizer")


@dataclass
class NormalizedSecuritySignal:
    """Standardized Canonical Data Model for any external tool signal"""
    signal_id: str
    source_tool: str
    source_fidelity: float                 # 0.0 to 1.0 (e.g. nuclei = 0.5 unverified, sqlmap = 0.8, burp = 1.0)
    initial_evidence_level: EvidenceLevel
    entity_type: SIREntityType
    asset: str
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None
    signal_type: str = "DISCOVERY"         # DISCOVERY, SQLI, BOLA, XSS, SSRF, INFO, etc.
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    provenance: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["initial_evidence_level"] = int(self.initial_evidence_level)
        d["entity_type"] = self.entity_type.value
        return d


class ToolOutputNormalizer:
    """Universal Adapter: Normalizes raw outputs into canonical NormalizedSecuritySignal list and SIRGraph"""

    @classmethod
    def normalize_subfinder(cls, raw_text: str, target_domain: str = "target.local") -> List[NormalizedSecuritySignal]:
        """Normalizes plain-text subfinder output (one domain per line)"""
        signals = []
        for line in raw_text.splitlines():
            sub = line.strip().lower()
            if not sub or sub.startswith("#") or " " in sub:
                continue
            sig_id = f"sig_sub_{hashlib.md5(sub.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="subfinder",
                source_fidelity=0.9,
                initial_evidence_level=EvidenceLevel.E0_OBSERVATION,
                entity_type=SIREntityType.RESOURCE,
                asset=sub,
                endpoint="/",
                method="GET",
                signal_type="SUBDOMAIN_DISCOVERY",
                raw_evidence={"subdomain": sub, "parent_domain": target_domain},
                provenance=f"subfinder -d {target_domain}"
            ))
        return signals

    @classmethod
    def normalize_httpx(cls, raw_jsonl: str) -> List[NormalizedSecuritySignal]:
        """Normalizes httpx JSON Lines output"""
        signals = []
        for line in raw_jsonl.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            url = data.get("url", "")
            if not url:
                continue
            parsed = urlparse(url)
            host = parsed.netloc or "target.local"
            path = parsed.path or "/"
            status = data.get("status_code", 200)
            techs = data.get("technologies", [])
            title = data.get("title", "")

            sig_id = f"sig_httpx_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="httpx",
                source_fidelity=0.95,
                initial_evidence_level=EvidenceLevel.E0_OBSERVATION,
                entity_type=SIREntityType.ENDPOINT,
                asset=host,
                endpoint=path,
                method="GET",
                signal_type="WEB_SERVICE_DISCOVERY",
                raw_evidence={
                    "url": url,
                    "status_code": status,
                    "title": title,
                    "technologies": techs,
                    "webserver": data.get("webserver", "")
                },
                provenance=f"httpx -u {url} -title -tech-detect"
            ))
        return signals

    @classmethod
    def normalize_katana(cls, raw_jsonl_or_text: str) -> List[NormalizedSecuritySignal]:
        """Normalizes katana crawler output (JSONL or plain URL stream)"""
        signals = []
        for line in raw_jsonl_or_text.splitlines():
            line = line.strip()
            if not line:
                continue
            url = ""
            method = "GET"
            params = []
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    req = data.get("request", {})
                    url = req.get("endpoint", "") or data.get("endpoint", "") or data.get("url", "")
                    method = (req.get("method", "GET") or "GET").upper()
                except Exception:
                    continue
            else:
                url = line

            if not url or not url.startswith("http"):
                continue

            parsed = urlparse(url)
            host = parsed.netloc or "target.local"
            path = parsed.path or "/"
            query_params = list(parse_qs(parsed.query).keys())

            sig_id = f"sig_ktn_{hashlib.md5(f'{method}:{url}'.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="katana",
                source_fidelity=0.90,
                initial_evidence_level=EvidenceLevel.E0_OBSERVATION,
                entity_type=SIREntityType.ENDPOINT,
                asset=host,
                endpoint=path,
                method=method,
                parameter=query_params[0] if query_params else None,
                signal_type="CRAWLED_ENDPOINT",
                raw_evidence={"url": url, "discovered_params": query_params},
                provenance="katana -u target"
            ))
        return signals

    @classmethod
    def normalize_nuclei(cls, raw_json_or_jsonl: str) -> List[NormalizedSecuritySignal]:
        """Normalizes nuclei vulnerability finding reports"""
        signals = []
        items = []
        raw_str = raw_json_or_jsonl.strip()
        if raw_str.startswith("["):
            try:
                items = json.loads(raw_str)
            except Exception:
                pass
        else:
            for line in raw_str.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        items.append(json.loads(line))
                    except Exception:
                        continue

        for item in items:
            template_id = item.get("template-id", "unknown-template")
            info = item.get("info", {})
            name = info.get("name", template_id)
            severity = info.get("severity", "info").upper()
            matched_at = item.get("matched-at", "") or item.get("host", "")
            extracted = item.get("extracted-results", [])
            curl_cmd = item.get("curl-command", "")

            parsed = urlparse(matched_at)
            host = parsed.netloc or "target.local"
            path = parsed.path or "/"

            # Classify vulnerability family
            vuln_type = "GENERAL_VULN"
            t_lower = (template_id + " " + name).lower()
            if "sqli" in t_lower or "sql-injection" in t_lower:
                vuln_type = "SQLI"
            elif "xss" in t_lower:
                vuln_type = "XSS"
            elif "ssrf" in t_lower:
                vuln_type = "SSRF"
            elif "bola" in t_lower or "idor" in t_lower:
                vuln_type = "BOLA"
            elif "rce" in t_lower or "cmdi" in t_lower:
                vuln_type = "CMDI"

            sig_id = f"sig_nuc_{hashlib.md5(f'{template_id}:{matched_at}'.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="nuclei",
                source_fidelity=0.55,  # Nuclei alerts are unverified differential candidates
                initial_evidence_level=EvidenceLevel.E1_DIFFERENTIAL_SIGNAL,
                entity_type=SIREntityType.ENDPOINT,
                asset=host,
                endpoint=path,
                method="GET",
                signal_type=vuln_type,
                raw_evidence={
                    "template_id": template_id,
                    "vulnerability_name": name,
                    "severity": severity,
                    "matched_at": matched_at,
                    "extracted_results": extracted,
                    "curl_command": curl_cmd,
                },
                provenance=f"nuclei -t {template_id} -u {matched_at}"
            ))
        return signals

    @classmethod
    def normalize_sqlmap(cls, raw_text_or_json: str, target_url: str = "") -> List[NormalizedSecuritySignal]:
        """Normalizes sqlmap injection output"""
        signals = []
        param = "id"
        dbms = "Unknown DBMS"
        is_vuln = False
        tech = "Boolean-based blind"

        for line in raw_text_or_json.splitlines():
            line_str = line.strip()
            if "is vulnerable" in line_str or "parameter" in line_str.lower():
                is_vuln = True
                import re
                m = re.search(r"parameter\s*[:\s]*['\"]?([a-zA-Z0-9_\-]+)['\"]?", line_str, re.IGNORECASE)
                if m:
                    param = m.group(1)
            if "back-end DBMS:" in line_str:
                dbms = line_str.split("back-end DBMS:")[1].strip()
            if "Type:" in line_str:
                tech = line_str.split("Type:")[1].strip()

        if is_vuln:
            parsed = urlparse(target_url) if target_url else urlparse("https://target.local/api")
            host = parsed.netloc or "target.local"
            path = parsed.path or "/api"
            sig_id = f"sig_sqlm_{hashlib.md5(f'{host}:{path}:{param}'.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="sqlmap",
                source_fidelity=0.85,
                initial_evidence_level=EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR,
                entity_type=SIREntityType.SINK,
                asset=host,
                endpoint=path,
                method="GET",
                parameter=param,
                signal_type="SQLI",
                raw_evidence={"dbms": dbms, "injection_technique": tech, "parameter": param},
                provenance=f"sqlmap -u '{target_url}' -p {param} --batch"
            ))
        return signals

    @classmethod
    def normalize_ffuf(cls, raw_json: str) -> List[NormalizedSecuritySignal]:
        """Normalizes ffuf directory/parameter fuzzing output"""
        signals = []
        try:
            data = json.loads(raw_json)
        except Exception:
            return signals

        results = data.get("results", [])
        for r in results:
            url = r.get("url", "")
            status = r.get("status", 200)
            words = r.get("words", 0)
            parsed = urlparse(url)
            host = parsed.netloc or "target.local"
            path = parsed.path or "/"

            sig_id = f"sig_ffuf_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="ffuf",
                source_fidelity=0.80,
                initial_evidence_level=EvidenceLevel.E0_OBSERVATION,
                entity_type=SIREntityType.ENDPOINT,
                asset=host,
                endpoint=path,
                method="GET",
                signal_type="FUZZED_ENDPOINT",
                raw_evidence={"url": url, "status_code": status, "words": words},
                provenance=f"ffuf -u {url} -w wordlist.txt"
            ))
        return signals

    @classmethod
    def normalize_dalfox(cls, raw_jsonl: str) -> List[NormalizedSecuritySignal]:
        """Normalizes dalfox XSS scanner output"""
        signals = []
        for line in raw_jsonl.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            url = data.get("url", "")
            param = data.get("param", "q")
            evidence = data.get("evidence", "")
            parsed = urlparse(url)
            host = parsed.netloc or "target.local"
            path = parsed.path or "/"

            sig_id = f"sig_dlf_{hashlib.md5(url.encode()).hexdigest()[:8]}"
            signals.append(NormalizedSecuritySignal(
                signal_id=sig_id,
                source_tool="dalfox",
                source_fidelity=0.75,
                initial_evidence_level=EvidenceLevel.E1_DIFFERENTIAL_SIGNAL,
                entity_type=SIREntityType.SINK,
                asset=host,
                endpoint=path,
                method="GET",
                parameter=param,
                signal_type="XSS",
                raw_evidence={"url": url, "param": param, "poc": data.get("poc", ""), "evidence": evidence},
                provenance=f"dalfox url {url}"
            ))
        return signals

    @classmethod
    def ingest_to_sir(cls, signals: List[NormalizedSecuritySignal], graph: Optional[SIRGraph] = None) -> SIRGraph:
        """Compiles normalized security signals into canonical SIR entities and relationships"""
        if graph is None:
            host = signals[0].asset if signals else "target.local"
            graph = SIRGraph(target_host=host)

        for sig in signals:
            ep_id = f"ep_{sig.method.upper()}_{sig.endpoint.replace('/', '_').strip('_')}"
            if not ep_id.strip("_"):
                ep_id = f"ep_{sig.method.upper()}_root"

            # 1. Endpoint Entity
            ep_entity = SIREntity(
                entity_id=ep_id,
                entity_type=SIREntityType.ENDPOINT,
                name=f"{sig.method.upper()} {sig.endpoint}",
                attributes={
                    "asset": sig.asset,
                    "endpoint": sig.endpoint,
                    "method": sig.method.upper(),
                    "signal_type": sig.signal_type,
                },
                observed_sources={sig.source_tool.upper()},
                evidence_refs=[sig.signal_id],
                confidence=sig.source_fidelity,
            )
            graph.add_entity(ep_entity)

            # 2. Parameter Entity (if present)
            if sig.parameter:
                param_id = f"param_{sig.parameter}_{ep_id}"
                param_entity = SIREntity(
                    entity_id=param_id,
                    entity_type=SIREntityType.PARAMETER,
                    name=sig.parameter,
                    attributes={"in": "query", "signal_type": sig.signal_type},
                    observed_sources={sig.source_tool.upper()},
                    evidence_refs=[sig.signal_id],
                    confidence=sig.source_fidelity,
                )
                graph.add_entity(param_entity)
                graph.add_relationship(ep_id, param_id, "ACCEPTS_PARAMETER")

            # 3. Vulnerability Sink Entity (if signal is an active vulnerability alert)
            if sig.signal_type not in ("DISCOVERY", "SUBDOMAIN_DISCOVERY", "WEB_SERVICE_DISCOVERY", "CRAWLED_ENDPOINT", "FUZZED_ENDPOINT"):
                sink_id = f"sink_{sig.signal_type.lower()}_{ep_id}"
                sink_entity = SIREntity(
                    entity_id=sink_id,
                    entity_type=SIREntityType.SINK,
                    name=f"{sig.signal_type} Sink on {sig.endpoint}",
                    attributes={
                        "vuln_class": sig.signal_type,
                        "initial_evidence_level": int(sig.initial_evidence_level),
                        "raw_evidence": sig.raw_evidence,
                    },
                    observed_sources={sig.source_tool.upper()},
                    evidence_refs=[sig.signal_id],
                    confidence=sig.source_fidelity,
                )
                graph.add_entity(sink_entity)
                graph.add_relationship(ep_id, sink_id, "POTENTIAL_SINK", {"evidence_level": sig.initial_evidence_level.code})

        return graph
