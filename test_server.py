"""
Basic tests for CloakLLM MCP Server tools.

Tests the sanitize/desanitize/analyze functions directly (they're plain
Python functions decorated with @mcp.tool()).

Run: pytest test_server.py -v
"""

import os
import sys
import tempfile
import types
from unittest.mock import MagicMock

# --- Mock the mcp package before importing server ---
mcp_mock = types.ModuleType("mcp")
mcp_server_mock = types.ModuleType("mcp.server")
mcp_fastmcp_mock = types.ModuleType("mcp.server.fastmcp")

# FastMCP mock that stores decorated functions and passes them through
class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass
    def tool(self):
        def decorator(fn):
            return fn
        return decorator
    def run(self):
        pass

mcp_fastmcp_mock.FastMCP = _FakeFastMCP
mcp_server_mock.fastmcp = mcp_fastmcp_mock
mcp_mock.server = mcp_server_mock

sys.modules["mcp"] = mcp_mock
sys.modules["mcp.server"] = mcp_server_mock
sys.modules["mcp.server.fastmcp"] = mcp_fastmcp_mock

# Disable audit logging during tests
os.environ["CLOAKLLM_AUDIT_ENABLED"] = "false"
os.environ["CLOAKLLM_LOG_DIR"] = tempfile.mkdtemp()

from server import sanitize, desanitize, analyze, _TOKEN_MAPS


class TestSanitize:

    def test_sanitize_detects_email(self):
        result = sanitize("Contact john@acme.com for details")
        assert "error" not in result
        assert "[EMAIL_0]" in result["sanitized"]
        assert result["entity_count"] >= 1
        assert "EMAIL" in result["categories"]
        assert result["token_map_id"] in _TOKEN_MAPS

    def test_sanitize_no_pii(self):
        result = sanitize("The weather is nice today")
        assert "error" not in result
        assert result["entity_count"] == 0
        assert result["sanitized"] == "The weather is nice today"

    def test_sanitize_multiple_entities(self):
        result = sanitize("Email john@acme.com, SSN 123-45-6789")
        assert "error" not in result
        assert result["entity_count"] >= 2
        assert "[EMAIL_0]" in result["sanitized"]
        assert "[SSN_0]" in result["sanitized"]


class TestDesanitize:

    def test_roundtrip(self):
        original = "Send report to john@acme.com"
        san_result = sanitize(original)
        assert "error" not in san_result

        des_result = desanitize(san_result["sanitized"], san_result["token_map_id"])
        assert "error" not in des_result
        assert des_result["restored"] == original

    def test_invalid_map_id(self):
        result = desanitize("some text", "nonexistent-id")
        assert "error" in result
        assert "not found" in result["error"]

    def test_roundtrip_multiple_entities(self):
        original = "Email john@acme.com, SSN 123-45-6789"
        san_result = sanitize(original)

        des_result = desanitize(san_result["sanitized"], san_result["token_map_id"])
        assert "error" not in des_result
        assert "john@acme.com" in des_result["restored"]
        assert "123-45-6789" in des_result["restored"]


class TestAnalyze:

    def test_analyze_detects_email(self):
        result = analyze("Contact john@acme.com")
        assert "error" not in result
        assert result["entity_count"] >= 1
        assert any(e["category"] == "EMAIL" for e in result["entities"])

    def test_analyze_no_pii(self):
        result = analyze("Just a normal sentence")
        assert "error" not in result
        assert result["entity_count"] == 0
        assert result["entities"] == []

    def test_analyze_entity_fields(self):
        result = analyze("Email: test@example.com")
        assert "error" not in result
        entity = next(e for e in result["entities"] if e["category"] == "EMAIL")
        assert entity["text"] == "test@example.com"
        assert isinstance(entity["start"], int)
        assert isinstance(entity["end"], int)
        assert isinstance(entity["confidence"], (int, float))
        assert entity["source"] == "regex"
