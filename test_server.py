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

from server import sanitize, sanitize_batch, desanitize, analyze, _TOKEN_MAPS


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


class TestMultiTurn:

    def test_reuse_token_map_across_turns(self):
        """Same token_map_id across sanitize calls produces consistent tokens."""
        result1 = sanitize("Contact john@acme.com for details")
        assert "error" not in result1
        map_id = result1["token_map_id"]

        result2 = sanitize(
            "Also email john@acme.com about the update",
            token_map_id=map_id,
        )
        assert "error" not in result2
        # Same map ID should be returned
        assert result2["token_map_id"] == map_id
        # Same email should get same token
        assert "[EMAIL_0]" in result2["sanitized"]
        # Entity count should still be 1 (same entity)
        assert result2["entity_count"] == 1

    def test_reuse_token_map_new_entity(self):
        """Reusing token map with a new entity adds to existing map."""
        result1 = sanitize("Contact john@acme.com")
        assert "error" not in result1
        map_id = result1["token_map_id"]

        result2 = sanitize(
            "Also email jane@corp.io",
            token_map_id=map_id,
        )
        assert "error" not in result2
        assert "[EMAIL_" in result2["sanitized"]
        assert result2["entity_count"] == 2

    def test_invalid_token_map_id_returns_error(self):
        result = sanitize("Some text", token_map_id="nonexistent-id")
        assert "error" in result
        assert "not found" in result["error"]

    def test_desanitize_after_multi_turn(self):
        """Desanitize works with a map built across multiple turns."""
        result1 = sanitize("Contact john@acme.com")
        map_id = result1["token_map_id"]

        result2 = sanitize("SSN is 123-45-6789", token_map_id=map_id)

        des = desanitize(
            "Emailing [EMAIL_0] about SSN [SSN_0]",
            token_map_id=map_id,
        )
        assert "error" not in des
        assert "john@acme.com" in des["restored"]
        assert "123-45-6789" in des["restored"]


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


class TestEntityDetails:

    def test_sanitize_includes_entity_details(self):
        result = sanitize("Email john@acme.com, SSN 123-45-6789")
        assert "error" not in result
        assert "entity_details" in result
        assert isinstance(result["entity_details"], list)
        assert len(result["entity_details"]) >= 2
        for d in result["entity_details"]:
            assert "category" in d
            assert "token" in d
            assert "text" not in d

    def test_sanitize_redact_mode_includes_entity_details(self):
        result = sanitize("Email john@acme.com", mode="redact")
        assert "error" not in result
        assert "entity_details" in result
        assert len(result["entity_details"]) >= 1
        assert result["entity_details"][0]["token"] == "[EMAIL_REDACTED]"


class TestBatchSanitize:

    def test_basic_batch(self):
        result = sanitize_batch(["Email john@acme.com", "SSN 123-45-6789"])
        assert "error" not in result
        assert len(result["sanitized"]) == 2
        assert "[EMAIL_0]" in result["sanitized"][0]
        assert "[SSN_0]" in result["sanitized"][1]
        assert result["token_map_id"] in _TOKEN_MAPS

    def test_shared_tokens(self):
        result = sanitize_batch([
            "Contact john@acme.com about project",
            "Follow up with john@acme.com",
        ])
        assert "error" not in result
        assert "[EMAIL_0]" in result["sanitized"][0]
        assert "[EMAIL_0]" in result["sanitized"][1]
        # Same email should use same token (entity_count may include NER detections)
        assert "EMAIL" in result["categories"]

    def test_reuse_token_map_id(self):
        result1 = sanitize("Email john@acme.com")
        map_id = result1["token_map_id"]
        result2 = sanitize_batch(
            ["Remind john@acme.com", "Also jane@acme.com"],
            token_map_id=map_id,
        )
        assert "error" not in result2
        assert result2["token_map_id"] == map_id
        assert "[EMAIL_0]" in result2["sanitized"][0]

    def test_empty_list(self):
        result = sanitize_batch([])
        assert "error" not in result
        assert result["sanitized"] == []
        assert result["entity_count"] == 0
