"""HunterAI Detectors Package.

Legacy targeted detectors (``SQLiDetector``, ``XSSDetector``) are kept for the
existing lab pipeline.  The safe verification lab adds:

* ``SQLiBooleanDetector`` -- two-pair read-only boolean differential;
* ``XSSReflectedDetector`` -- unique-nonce reflection with an encoding control;
* ``IDORDetector`` -- two-identity differential with an owner-only canary;
* ``HttpTransport`` -- GET/HEAD only, no proxies, no redirects, policy-gated;
* ``EvidenceChain`` -- hash-linked, tamper-evident evidence records;
* ``LocalFakeTarget`` -- loopback fake target for hermetic tests and demos.
"""
from core.detectors.xss_detector import XSSDetector
from core.detectors.sqli_detector import SQLiDetector
from core.detectors.contract import (
    Detection,
    DetectionContext,
    Detector,
    Probe,
    ProbeExchange,
)
from core.detectors.transport import (
    HttpTransport,
    PolicyViolation,
    TransportConfig,
    TransportError,
)
from core.detectors.evidence_chain import EvidenceChain
from core.detectors.sqli_boolean import SQLiBooleanDetector
from core.detectors.xss_reflected import XSSReflectedDetector
from core.detectors.idor import IDORDetector
from core.detectors.ssrf import SSRFDetector
from core.detectors.open_redirect import OpenRedirectDetector
from core.detectors.canary import LoopbackCanary
from core.detectors.local_target import LocalFakeTarget
from core.detectors.pipeline import HypothesisPipeline, PipelineResult
from core.detectors.validation import LabValidationGate

__all__ = [
    "Detection",
    "DetectionContext",
    "Detector",
    "EvidenceChain",
    "HttpTransport",
    "HypothesisPipeline",
    "IDORDetector",
    "LabValidationGate",
    "LocalFakeTarget",
    "LoopbackCanary",
    "OpenRedirectDetector",
    "PipelineResult",
    "PolicyViolation",
    "Probe",
    "ProbeExchange",
    "SQLiBooleanDetector",
    "SQLiDetector",
    "SSRFDetector",
    "TransportConfig",
    "TransportError",
    "XSSDetector",
    "XSSReflectedDetector",
]
