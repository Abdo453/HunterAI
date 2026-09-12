"""
Model Context Protocol (MCP) Server Interface for PentestAI Unified
واجهة بروتوكول MCP العالمي — تتيح لأي ذكاء اصطناعي خارجي (Claude Desktop, Cursor, Antigravity)
الاتصال بمشروعك واستخدام جميع أدواته وموديلاته وقواعد معرفته كـ MCP Tools!
"""
import asyncio
import json
import sys
from typing import Dict, Any, List

from tools.tool_manager import ToolManager
from tools.waf_evasion import WAFEvasionEngine
from core.http_analyzer import HTTPTrafficAnalyzer
from core.cve_intel import CVEIntelligenceEngine
from core.independent_verifier import IndependentVerifier
from core.methodology_kb import MethodologyKB


class PentestAIMCPServer:
    """
    سيرفر MCP القياسي لمشروع PentestAI Unified
    """

    def __init__(self):
        self.tm = ToolManager()
        self.waf = WAFEvasionEngine()
        self.http_analyzer = HTTPTrafficAnalyzer()
        self.cve_engine = CVEIntelligenceEngine()
        self.verifier = IndependentVerifier()
        self.kb = MethodologyKB()

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """تعريف قائمة الـ MCP Tools المتاحة"""
        return [
            {
                "name": "run_security_tool",
                "description": "Execute a security tool with parameter optimization and fallback (nmap, ffuf, katana, sqlmap, subfinder, nuclei, arjun)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string", "description": "Name of the tool"},
                        "args": {"type": "string", "description": "Command line arguments and target"}
                    },
                    "required": ["tool", "args"]
                }
            },
            {
                "name": "detect_waf_and_rate_limits",
                "description": "Detect WAF protection (Cloudflare, AWS WAF, Akamai, Imperva) and calculate stealth delays",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "Target website URL"}
                    },
                    "required": ["target_url"]
                }
            },
            {
                "name": "analyze_http_traffic",
                "description": "Deep analysis of raw HTTP Request and Response for JWT, CORS, IDOR, and Security Headers",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "raw_request": {"type": "string", "description": "Raw HTTP request string"},
                        "raw_response": {"type": "string", "description": "Optional raw HTTP response string"}
                    },
                    "required": ["raw_request"]
                }
            },
            {
                "name": "lookup_technology_cves",
                "description": "Live online search for known CVE vulnerabilities and CVSS scores for a product/version",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "product": {"type": "string", "description": "Product or vendor name (e.g. apache, wordpress)"},
                        "version": {"type": "string", "description": "Optional version string"}
                    },
                    "required": ["product"]
                }
            },
            {
                "name": "verify_vulnerability_differentially",
                "description": "Independent differential probe to confirm real vulnerabilities and eliminate false positives",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_url": {"type": "string", "description": "Target URL"},
                        "param_name": {"type": "string", "description": "Parameter name"},
                        "vuln_type": {"type": "string", "description": "Vulnerability type (sqli, xss)"}
                    },
                    "required": ["target_url", "param_name", "vuln_type"]
                }
            }
        ]

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """معالجة استدعاء الـ Tool"""
        if tool_name == "run_security_tool":
            res = await self.tm.execute_tool(arguments["tool"], arguments["args"])
            return {"stdout": res.stdout, "stderr": res.stderr, "duration": res.duration, "success": res.success}

        elif tool_name == "detect_waf_and_rate_limits":
            p = await self.waf.detect_waf(arguments["target_url"])
            return {"waf_detected": p.waf_detected, "waf_names": p.waf_names, "recommended_mode": p.recommended_mode}

        elif tool_name == "analyze_http_traffic":
            res = self.http_analyzer.analyze(arguments["raw_request"], arguments.get("raw_response"))
            return res

        elif tool_name == "lookup_technology_cves":
            cves = await self.cve_engine.lookup_technology_cves(arguments["product"], arguments.get("version"))
            return {"cves": cves}

        elif tool_name == "verify_vulnerability_differentially":
            v = await self.verifier.verify_endpoint_vulnerability(arguments["target_url"], arguments["param_name"], arguments["vuln_type"])
            return v

        return {"error": f"Unknown tool: {tool_name}"}


if __name__ == "__main__":
    # Test MCP definitions
    srv = PentestAIMCPServer()
    print(f"PentestAI MCP Server loaded with {len(srv.get_tool_definitions())} universal tools.")
