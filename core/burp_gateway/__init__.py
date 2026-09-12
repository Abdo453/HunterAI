"""
HunterAI Burp Gateway Subsystem
===============================
Bidirectional bridge connecting Burp Suite with HunterAI:
- CaptureStore: structured engagement persistence
- TaskQueue: context-menu task dispatcher
- BurpGateway: local REST API on 127.0.0.1:8085
- BurpIssueExporter: converts confirmed findings to Burp IScanIssue
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
]

