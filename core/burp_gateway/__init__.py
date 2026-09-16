"""
HunterAI Burp Gateway Subsystem (V26.0)
======================================
Bidirectional bridge connecting Burp Suite with HunterAI:
- CaptureStore: structured engagement persistence
- TaskQueue: context-menu task dispatcher
- BurpGateway: local REST API on 127.0.0.1:8085
- BurpIssueExporter: converts confirmed findings to Burp IScanIssue
- BurpCorrelationContext: causal headers & provenance tracking
- BurpTrafficNormalizer: canonical multi-source telemetry normalization
- BurpExperimentQueue: EIG-prioritized scientific experiment scheduler
- BurpLiveEventStream: real-time streaming bridge
"""
from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction
from core.burp_gateway.task_queue import TaskQueue, BurpTask, TaskAction, TaskStatus
from core.burp_gateway.issue_exporter import BurpIssueExporter
from core.burp_gateway.gateway import BurpGateway
from core.burp_gateway.provenance import (
    ProvenanceStage,
    ProvenanceStep,
    ProvenanceTrace,
    EvidenceProvenanceEngine,
)
from core.burp_gateway.handoff_contract import AgentHandoffContract
from core.burp_gateway.experiment_engine import (
    ExperimentEngine,
    ExperimentStage,
    ExperimentStep,
    ReasoningExperiment,
    CrossSensorCorrelator,
)
from core.burp_gateway.correlation import (
    BurpCorrelationContext,
    HDR_ENGAGEMENT_ID,
    HDR_TRANSACTION_ID,
    HDR_HYPOTHESIS_ID,
    HDR_EXPERIMENT_ID,
    HDR_PARENT_ID,
    HDR_IDENTITY_ID,
    HDR_INTENT,
    HDR_ACTION_TYPE,
)
from core.burp_gateway.traffic_normalizer import (
    BurpTrafficNormalizer,
    TrafficSource,
    CanonicalRequest,
    CanonicalResponse,
    CanonicalTransaction,
    CanonicalIdentity,
    TargetStateContext,
)
from core.burp_gateway.experiment_queue import (
    BurpExperimentQueue,
    BurpExperimentItem,
    ExperimentStatus,
    TokenBucketRateLimiter,
)
from core.burp_gateway.event_stream import (
    BurpLiveEventStream,
    StreamEvent,
)

__all__ = [
    "CaptureStore",
    "CapturedTransaction",
    "TaskQueue",
    "BurpTask",
    "TaskAction",
    "TaskStatus",
    "BurpIssueExporter",
    "BurpGateway",
    "ProvenanceStage",
    "ProvenanceStep",
    "ProvenanceTrace",
    "EvidenceProvenanceEngine",
    "AgentHandoffContract",
    "ExperimentEngine",
    "ExperimentStage",
    "ExperimentStep",
    "ReasoningExperiment",
    "CrossSensorCorrelator",
    "BurpCorrelationContext",
    "HDR_ENGAGEMENT_ID",
    "HDR_TRANSACTION_ID",
    "HDR_HYPOTHESIS_ID",
    "HDR_EXPERIMENT_ID",
    "HDR_PARENT_ID",
    "HDR_IDENTITY_ID",
    "HDR_INTENT",
    "HDR_ACTION_TYPE",
    "BurpTrafficNormalizer",
    "TrafficSource",
    "CanonicalRequest",
    "CanonicalResponse",
    "CanonicalTransaction",
    "CanonicalIdentity",
    "TargetStateContext",
    "BurpExperimentQueue",
    "BurpExperimentItem",
    "ExperimentStatus",
    "TokenBucketRateLimiter",
    "BurpLiveEventStream",
    "StreamEvent",
]
