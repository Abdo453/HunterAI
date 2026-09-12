"""
Autonomous Skills Arsenal Test Suite (SSRF, IDOR, XSS & Brain Integration)
===========================================================================
"""

import pytest
from unittest.mock import AsyncMock, patch

from agents.skills.ssrf_skill import (
    SSRFSkill, SSRFState, CloudProvider,
    CLOUD_METADATA_MATRIX, SSRFFilterBypasser, run_ssrf_skill
)
from agents.skills.idor_skill import (
    IDORSkill, IDORState, IDType,
    IDPermutator, run_idor_skill
)
from agents.skills.xss_skill import (
    XSSSkill, XSSState, XSSContextType,
    CONTEXT_PROBES, run_xss_skill
)
from core.brain.autonomous_brain import TOOL_REGISTRY


# ─── 1. SSRF Skill Tests ──────────────────────────────────────────────────────

class TestSSRFSkill:
    def test_localhost_variants_generation(self):
        variants = SSRFFilterBypasser.generate_localhost_variants(target_port=80)
        assert "http://127.0.0.1" in variants
        assert "http://localhost" in variants
        assert "http://2130706433" in variants  # Decimal IP
        assert "http://0x7f000001" in variants  # Hex IP
        assert "http://0177.0.0.1" in variants  # Octal IP
        assert "http://[::1]" in variants       # IPv6
        assert len(variants) >= 10

    def test_metadata_variants_generation(self):
        variants = SSRFFilterBypasser.generate_metadata_variants("http://169.254.169.254/latest/meta-data/")
        assert "http://2852039166/latest/meta-data/" in variants
        assert "http://0xa9fea9fe/latest/meta-data/" in variants
        assert "http://169.254.169.254.nip.io/latest/meta-data/" in variants

    def test_cloud_metadata_matrix_coverage(self):
        assert CloudProvider.AWS in CLOUD_METADATA_MATRIX
        assert CloudProvider.GCP in CLOUD_METADATA_MATRIX
        assert CloudProvider.AZURE in CLOUD_METADATA_MATRIX
        assert CloudProvider.DIGITALOCEAN in CLOUD_METADATA_MATRIX
        assert CloudProvider.LOCAL_DAEMON in CLOUD_METADATA_MATRIX


# ─── 2. IDOR / BOLA Skill Tests ───────────────────────────────────────────────

class TestIDORSkill:
    def test_classify_numeric(self):
        id_type, meta = IDPermutator.classify("1050")
        assert id_type == IDType.NUMERIC_SEQUENTIAL
        assert meta == 1050
        perms = IDPermutator.generate_permutations("1050")
        assert "1049" in perms
        assert "1051" in perms
        assert "1" in perms

    def test_classify_uuid(self):
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        id_type, _ = IDPermutator.classify(uuid_str)
        assert id_type == IDType.UUID_V4

    def test_classify_base64(self):
        import base64
        b64_str = base64.b64encode(b"100").decode()
        id_type, decoded = IDPermutator.classify(b64_str)
        assert id_type == IDType.BASE64_ENCODED
        assert decoded == "100"
        perms = IDPermutator.generate_permutations(b64_str)
        assert len(perms) > 0


# ─── 3. XSS Skill Tests ───────────────────────────────────────────────────────

class TestXSSSkill:
    def test_context_inference_html_body(self):
        skill = XSSSkill()
        html = "<div>Search results for: canary123</div>"
        ctx = skill._infer_reflection_context(html, "canary123")
        assert ctx == XSSContextType.HTML_BODY

    def test_context_inference_attribute_double_quote(self):
        skill = XSSSkill()
        html = '<input type="text" name="q" value="canary123" />'
        ctx = skill._infer_reflection_context(html, "canary123")
        assert ctx == XSSContextType.HTML_ATTR_DOUBLE_Q

    def test_context_inference_js_string(self):
        skill = XSSSkill()
        html = '<script>var query = "canary123"; console.log(query);</script>'
        ctx = skill._infer_reflection_context(html, "canary123")
        assert ctx == XSSContextType.JS_STRING_DOUBLE_Q

    def test_context_inference_href_src(self):
        skill = XSSSkill()
        html = '<a href="canary123">Click here</a>'
        ctx = skill._infer_reflection_context(html, "canary123")
        assert ctx == XSSContextType.HREF_SRC_URI

    def test_probes_configured_for_all_contexts(self):
        assert XSSContextType.HTML_BODY in CONTEXT_PROBES
        assert XSSContextType.HTML_ATTR_DOUBLE_Q in CONTEXT_PROBES
        assert XSSContextType.JS_STRING_DOUBLE_Q in CONTEXT_PROBES
        assert XSSContextType.HREF_SRC_URI in CONTEXT_PROBES


# ─── 4. Tool Registry Brain Integration Tests ─────────────────────────────────

class TestToolRegistryIntegration:
    def test_all_skills_registered_in_brain(self):
        assert "SQLiSkill" in TOOL_REGISTRY
        assert "SSRFSkill" in TOOL_REGISTRY
        assert "IDORSkill" in TOOL_REGISTRY
        assert "XSSSkill" in TOOL_REGISTRY
        assert "SmartPoC" in TOOL_REGISTRY
        assert callable(TOOL_REGISTRY["SSRFSkill"])
        assert callable(TOOL_REGISTRY["IDORSkill"])
        assert callable(TOOL_REGISTRY["XSSSkill"])
