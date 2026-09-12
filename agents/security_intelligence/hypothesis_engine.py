"""
Hypothesis Generation Engine
Translates observed security phenomena into structured, ranked attack hypotheses (H1, H2, H3...).
"""
import re
from typing import List, Dict, Any, Optional
from agents.security_intelligence.schemas import SecurityObservation, SecurityHypothesis, HypothesisStatus
from agents.security_intelligence.knowledge_engine import KnowledgeEngine


class HypothesisEngine:
    """محرك توليد الفرضيات الأمنية: التفكير كباحث أمني وتحويل الملاحظات إلى سيناريوهات قابلة للاختبار"""

    def __init__(self, knowledge_engine: Optional[KnowledgeEngine] = None):
        self.kb = knowledge_engine or KnowledgeEngine()

    def generate_hypotheses(self, observation: SecurityObservation) -> List[SecurityHypothesis]:
        data = observation.data
        path = data.get("path", "") or data.get("url", "")
        method = data.get("method", "GET").upper()
        params = data.get("parameters", []) or []
        body = str(data.get("body", ""))
        headers = data.get("headers", {})

        # Normalize parameters to string list
        if isinstance(params, dict):
            param_names = list(params.keys())
        elif isinstance(params, list):
            param_names = [str(p) for p in params]
        else:
            param_names = []

        hypotheses: List[SecurityHypothesis] = []

        # 1. BOLA / IDOR Detection Logic across primary path & discovered endpoints
        id_pattern = re.compile(r"/(id|user_id|account|order|invoice|item|profile|doc|document|customer|ticket|record|users|orders|invoices|accounts|profiles|items|resources)/(\d+|[a-f0-9\-]{8,})|/([a-zA-Z0-9_\-]+)/(\d+|[a-f0-9\-]{8,})", re.I)
        numeric_id_param = [p for p in param_names if re.search(r"(id|account|order|user|invoice|number|key|uuid)", p, re.I)]
        
        paths_to_check = [path]
        for ep in data.get("endpoints", []):
            if isinstance(ep, str) and ep:
                paths_to_check.append(ep)
            elif isinstance(ep, dict) and ep.get("url"):
                paths_to_check.append(ep.get("url"))

        matched_path = None
        for p in paths_to_check:
            if id_pattern.search(p):
                matched_path = p
                break

        if matched_path or numeric_id_param:
            target_id = numeric_id_param[0] if numeric_id_param else "URL path ID"
            chosen_path = matched_path or path
            kb_bola = self.kb.get_vulnerability("bola")
            hypotheses.append(SecurityHypothesis(
                title=f"Potential BOLA / IDOR on {method} {chosen_path} via '{target_id}'",
                vulnerability_type="BOLA",
                cwe_id="CWE-639",
                target_endpoint=chosen_path,
                parameters=param_names,
                confidence=0.65,

                evidence_required=kb_bola.get("required_evidence", []) if kb_bola else [
                    "User-controlled identifier in request",
                    "Authenticated endpoint",
                    "Different user accessing object without authorization"
                ],
                reasoning_steps=[
                    f"Endpoint exposes object identifier '{target_id}' controlled by client",
                    "Endpoint operates in authenticated context",
                    "Possible missing server-side authorization check for object ownership"
                ],
                counter_arguments=[
                    "Server may enforce strict object ownership in ORM/SQL query",
                    "Endpoint might be globally public read-only content"
                ]
            ))

        # 2. BFLA / Privilege Escalation Logic
        admin_pattern = re.compile(r"/(admin|manage|internal|dashboard|settings|config|roles)", re.I)
        if admin_pattern.search(path):
            kb_bfla = self.kb.get_vulnerability("bfla")
            hypotheses.append(SecurityHypothesis(
                title=f"Potential Broken Function Level Authorization (BFLA) on {method} {path}",
                vulnerability_type="BFLA",
                cwe_id="CWE-285",
                target_endpoint=path,
                parameters=param_names,
                confidence=0.60,
                evidence_required=kb_bfla.get("required_evidence", []) if kb_bfla else [
                    "Privileged function accessed by low-privileged role",
                    "State change or sensitive action allowed without 403 Forbidden"
                ],
                reasoning_steps=[
                    f"Endpoint path '{path}' indicates an administrative or privileged function",
                    "Verifying if low-privileged role or token can access or manipulate this function"
                ],
                counter_arguments=[
                    "Role-based access control (RBAC) middleware may block low-privileged users",
                    "Path name may be decorative without holding administrative privileges"
                ]
            ))

        # 3. SQL Injection Logic
        query_text = (path + " " + body + " " + " ".join(param_names)).lower()
        if any(indicator in query_text for indicator in ["select", "query", "filter", "search", "sort", "order_by", "sql", "where"]):
            kb_sqli = self.kb.get_vulnerability("sqli")
            hypotheses.append(SecurityHypothesis(
                title=f"Potential SQL Injection on parameter in {method} {path}",
                vulnerability_type="SQLi",
                cwe_id="CWE-89",
                target_endpoint=path,
                parameters=param_names,
                confidence=0.55,
                evidence_required=kb_sqli.get("required_evidence", []) if kb_sqli else [
                    "Database error message disclosure",
                    "Boolean response differential on injected syntax",
                    "Time-delay difference on sleep/delay payloads"
                ],
                reasoning_steps=[
                    "Endpoint processes dynamic filter/search/sort parameters",
                    "Backend could be constructing dynamic SQL query strings without parameterization"
                ],
                counter_arguments=[
                    "Application uses parameterized queries or type-safe ORM",
                    "Input is validated against strict alphanumeric whitelist"
                ]
            ))

        # 4. SSRF Logic
        ssrf_param = [p for p in param_names if re.search(r"(url|dest|target|redirect|fetch|uri|link|webhook|feed)", p, re.I)]
        if ssrf_param:
            kb_ssrf = self.kb.get_vulnerability("ssrf")
            hypotheses.append(SecurityHypothesis(
                title=f"Potential Server-Side Request Forgery (SSRF) via '{ssrf_param[0]}' on {path}",
                vulnerability_type="SSRF",
                cwe_id="CWE-918",
                target_endpoint=path,
                parameters=ssrf_param,
                confidence=0.62,
                evidence_required=kb_ssrf.get("required_evidence", []) if kb_ssrf else [
                    "Server initiates outbound HTTP/network connection to user-supplied URI",
                    "Internal network response or metadata reflected back"
                ],
                reasoning_steps=[
                    f"Parameter '{ssrf_param[0]}' suggests server-side URL fetching functionality",
                    "Risk of requesting internal IP ranges (127.0.0.1, 169.254.169.254) or intranet ports"
                ],
                counter_arguments=[
                    "Server validates URL against domain whitelist",
                    "Outbound requests routed through isolated proxy with RFC1918 blocking"
                ]
            ))

        # 5. Mass Assignment Logic
        if method in ["POST", "PUT", "PATCH"] and ("/api/" in path or "application/json" in str(headers)):
            kb_ma = self.kb.get_vulnerability("mass_assignment")
            hypotheses.append(SecurityHypothesis(
                title=f"Potential Mass Assignment / Property Injection on {method} {path}",
                vulnerability_type="Mass_Assignment",
                cwe_id="CWE-915",
                target_endpoint=path,
                parameters=param_names,
                confidence=0.50,
                evidence_required=kb_ma.get("required_evidence", []) if kb_ma else [
                    "Extra JSON fields accepted and persisted by server without DTO rejection",
                    "Privileged field (role, balance, verified) successfully modified"
                ],
                reasoning_steps=[
                    "Endpoint accepts structured JSON payloads for resource mutation",
                    "Backend may bind JSON body directly to ORM model without strict attribute whitelisting"
                ],
                counter_arguments=[
                    "Backend validates request schema with strict DTOs (Data Transfer Objects)",
                    "ORM ignores non-defined entity properties"
                ]
            ))

        # If no specific patterns matched, add a generic observation hypothesis
        if not hypotheses:
            hypotheses.append(SecurityHypothesis(
                title=f"General Attack Surface Exploration for {method} {path}",
                vulnerability_type="Info_Disclosure",
                target_endpoint=path,
                parameters=param_names,
                confidence=0.30,
                evidence_required=["Observe server response status and headers"],
                reasoning_steps=["Endpoint recorded in application attack surface graph"]
            ))

        # Sort hypotheses by confidence descending
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses
