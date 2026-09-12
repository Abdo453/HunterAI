"""
Operational Security Checklists Engine
Comprehensive phase and bug-class operational checklists.
Inspired by 0xN0RMXL/BugBountySkills CHECKLISTS directory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ChecklistItem:
    item_id: str
    title: str
    phase: str
    description: str
    verification_method: str
    risk_if_missing: str


@dataclass
class SecurityChecklist:
    category: str
    description: str
    items: List[ChecklistItem] = field(default_factory=list)


CHECKLIST_CATALOG: Dict[str, SecurityChecklist] = {
    "web_security": SecurityChecklist(
        category="Web Application Surface",
        description="Comprehensive checks for web application authorization, input handling, and session controls.",
        items=[
            ChecklistItem(
                item_id="WEB-01",
                title="Object-Level Access Control (IDOR / BOLA)",
                phase="Authorization",
                description="Verify that accessing numeric or UUID object references enforces tenant & user ownership.",
                verification_method="Query endpoints with Session A using object IDs created by Session B.",
                risk_if_missing="Unauthorized data exfiltration or state tampering across tenant accounts."
            ),
            ChecklistItem(
                item_id="WEB-02",
                title="CORS Origin Reflection with Credentials",
                phase="Configuration",
                description="Ensure the server does not reflect arbitrary `Origin` headers alongside `Access-Control-Allow-Credentials: true`.",
                verification_method="Send request with `Origin: https://evil.attacker.com` and inspect response headers.",
                risk_if_missing="Cross-origin reading of authenticated session responses via victim browsers."
            ),
            ChecklistItem(
                item_id="WEB-03",
                title="Strict Content-Type & MIME Sniffing Defense",
                phase="Headers",
                description="Ensure `X-Content-Type-Options: nosniff` is enforced on all dynamic file endpoints.",
                verification_method="Inspect response headers on upload, download, and dynamic rendering routes.",
                risk_if_missing="MIME confusion attacks executing HTML/JS uploaded in media files."
            ),
        ]
    ),
    "api_security": SecurityChecklist(
        category="API & GraphQL",
        description="Checklist for REST, GraphQL, and microservice integration endpoints.",
        items=[
            ChecklistItem(
                item_id="API-01",
                title="GraphQL Production Introspection",
                phase="Schema Analysis",
                description="Verify that GraphQL introspection query is disabled in public production environments.",
                verification_method="Send `{\"query\": \"{ __schema { types { name } } }\"}` to `/graphql`.",
                risk_if_missing="Full revelation of hidden types, internal mutations, and administrative fields."
            ),
            ChecklistItem(
                item_id="API-02",
                title="Mass Assignment / Property Injection",
                phase="Input Validation",
                description="Ensure API serializers do not blindly bind client JSON fields to backend ORM models.",
                verification_method="Inject administrative attributes (e.g. `{\"is_admin\": true, \"role\": \"superuser\"}`) into PUT/PATCH.",
                risk_if_missing="Direct privilege escalation by overwriting privileged entity fields."
            ),
            ChecklistItem(
                item_id="API-03",
                title="API Rate Limiting & Resource Exhaustion",
                phase="Resilience",
                description="Confirm rate limiting on intensive routes (e.g. password resets, search, OTP verification).",
                verification_method="Issue 50 concurrent requests and verify HTTP 429 Too Many Requests enforcement.",
                risk_if_missing="Brute-forcing of authentication credentials or denial of service."
            ),
        ]
    ),
    "cloud_infrastructure": SecurityChecklist(
        category="Cloud & Container Infrastructure",
        description="Audit checklist for cloud metadata, IAM boundaries, and container environments.",
        items=[
            ChecklistItem(
                item_id="CLOUD-01",
                title="AWS IMDSv2 Mandatory Enforcement",
                phase="Metadata Protection",
                description="Verify EC2 instances require IMDSv2 session tokens and restrict hop limits to 1.",
                verification_method="Check EC2 instance metadata options for `HttpTokens=required`.",
                risk_if_missing="SSRF vulnerabilities can directly dump IAM role temporary access credentials."
            ),
            ChecklistItem(
                item_id="CLOUD-02",
                title="Public Storage Bucket Exposure (S3 / GCS / Blob)",
                phase="Storage Security",
                description="Audit cloud storage buckets to confirm S3 Block Public Access is globally enabled.",
                verification_method="Test anonymous `GET` / `LIST` operations on discovered bucket names.",
                risk_if_missing="Public data leakage of database backups, logs, and customer assets."
            ),
        ]
    ),
    "source_code_audit": SecurityChecklist(
        category="Source Code Review",
        description="Static review checklist for backend application codebases.",
        items=[
            ChecklistItem(
                item_id="SRC-01",
                title="Static Secrets & Production Token Detection",
                phase="Secret Management",
                description="Ensure no hardcoded API keys, private certificates, or database passwords exist in source.",
                verification_method="Run high-entropy regex scanners across code repositories.",
                risk_if_missing="Compromise of backend databases, third-party APIs, and cloud services."
            ),
            ChecklistItem(
                item_id="SRC-02",
                title="Unsafe Deserialization & Dynamic Evaluation",
                phase="Code Execution",
                description="Verify absence of `pickle.loads()`, `eval()`, `unserialize()`, or `yaml.unsafe_load()` on untrusted input.",
                verification_method="Static pattern search across input processing pipelines.",
                risk_if_missing="Remote Code Execution (RCE) via serialized object tampering."
            ),
        ]
    ),
    "ai_llm_security": SecurityChecklist(
        category="AI & LLM Security",
        description="Checklist for applications integrating Large Language Models and AI Agents.",
        items=[
            ChecklistItem(
                item_id="AI-01",
                title="Indirect Prompt Injection Mitigation",
                phase="Input Sanitation",
                description="Ensure external content (web pages, user uploads) ingested into LLM context is demarcated and sanitized.",
                verification_method="Audit system prompt delimiter architecture and guardrail validation layers.",
                risk_if_missing="Attacker manipulates agent instructions to exfiltrate private conversation history."
            ),
            ChecklistItem(
                item_id="AI-02",
                title="Agent Tool Authorization & Blast Radius Limitation",
                phase="Tool Execution",
                description="Ensure autonomous AI agents operate with least-privilege tool access and mandatory human-in-the-loop approvals for destructive actions.",
                verification_method="Review agent tool execution permissions and confirmation gating.",
                risk_if_missing="Unintended database deletions, unauthorized external network calls, or configuration alteration."
            ),
        ]
    ),
}


class SecurityChecklistEngine:
    """
    محرك إدارة واستعراض القوائم المرجعية الأمنية (Checklists)
    """

    @staticmethod
    def get_checklist(category_key: str) -> Optional[SecurityChecklist]:
        k = category_key.lower().replace("-", "_").replace(" ", "_")
        if k in CHECKLIST_CATALOG:
            return CHECKLIST_CATALOG[k]
        for name, cl in CHECKLIST_CATALOG.items():
            if name in k or k in name or cl.category.lower() in k:
                return cl
        return None

    @staticmethod
    def list_all_categories() -> Dict[str, str]:
        return {k: cl.category for k, cl in CHECKLIST_CATALOG.items()}

    @staticmethod
    def export_markdown_summary() -> str:
        lines = ["# 📋 Unified Security & Bug Bounty Checklists\n"]
        for key, cl in CHECKLIST_CATALOG.items():
            lines.extend([
                f"## {cl.category}",
                f"*{cl.description}*",
                "",
                "| ID | Phase | Checkpoint | Risk if Missing |",
                "|---|---|---|---|",
            ])
            for item in cl.items:
                lines.append(f"| `{item.item_id}` | {item.phase} | **{item.title}** | {item.risk_if_missing} |")
            lines.append("\n---\n")
        return "\n".join(lines)
