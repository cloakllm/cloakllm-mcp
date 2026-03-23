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

from server import sanitize, sanitize_batch, desanitize, desanitize_batch, analyze, analyze_batch, _TOKEN_MAPS


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
        # text field is NOT included by default (security: PII removal)
        assert "text" not in entity
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


class TestCustomLlmCategories:

    def test_sanitize_accepts_custom_llm_categories_param(self):
        """sanitize accepts custom_llm_categories param without error."""
        import json
        cats = json.dumps([["PATIENT_ID", "Hospital patient ID"]])
        result = sanitize("Contact john@acme.com", custom_llm_categories=cats)
        assert "error" not in result
        # Still detects regex-based PII normally
        assert "[EMAIL_0]" in result["sanitized"]

    def test_sanitize_invalid_json_returns_error(self):
        """Invalid JSON in custom_llm_categories returns error."""
        result = sanitize("Some text", custom_llm_categories="not valid json")
        assert "error" in result

    def test_analyze_accepts_custom_llm_categories_param(self):
        """analyze accepts custom_llm_categories param without error."""
        import json
        cats = json.dumps([["PATIENT_ID", "Hospital patient ID"]])
        result = analyze("Contact john@acme.com", custom_llm_categories=cats)
        assert "error" not in result


class TestEntityHashing:

    def test_sanitize_with_entity_hashing(self):
        """entity_hash should appear in entity_details when hashing enabled."""
        result = sanitize(
            "Contact john@acme.com",
            entity_hashing=True,
            entity_hash_key="test-key",
        )
        assert "error" not in result
        assert "entity_details" in result
        assert len(result["entity_details"]) >= 1
        for detail in result["entity_details"]:
            assert "entity_hash" in detail
            assert len(detail["entity_hash"]) == 64

    def test_sanitize_without_hashing_no_hash(self):
        """entity_hash should not appear when hashing is disabled (default)."""
        result = sanitize("Contact john@acme.com")
        assert "error" not in result
        assert "entity_details" in result
        for detail in result["entity_details"]:
            assert "entity_hash" not in detail


class TestDesanitizeBatch:

    def test_batch_roundtrip(self):
        """sanitize_batch → desanitize_batch round-trip restores all texts."""
        originals = ["Email john@acme.com", "SSN 123-45-6789"]
        san = sanitize_batch(originals)
        assert "error" not in san

        des = desanitize_batch(san["sanitized"], san["token_map_id"])
        assert "error" not in des
        assert des["restored"] == originals

    def test_single_text_roundtrip(self):
        """desanitize_batch works with a single text."""
        original = "Contact john@acme.com"
        san = sanitize(original)
        des = desanitize_batch([san["sanitized"]], san["token_map_id"])
        assert "error" not in des
        assert des["restored"] == [original]

    def test_invalid_map_id(self):
        result = desanitize_batch(["some text"], "nonexistent-id")
        assert "error" in result
        assert "not found" in result["error"]

    def test_with_metadata(self):
        """desanitize_batch accepts metadata parameter."""
        import json
        san = sanitize("Email john@acme.com")
        des = desanitize_batch(
            [san["sanitized"]],
            san["token_map_id"],
            metadata=json.dumps({"session": "test-123"}),
        )
        assert "error" not in des
        assert "john@acme.com" in des["restored"][0]


class TestAnalyzeBatch:

    def test_basic_batch(self):
        """analyze_batch returns results per text."""
        result = analyze_batch(["Email john@acme.com", "SSN 123-45-6789"])
        assert "error" not in result
        assert len(result["results"]) == 2
        assert result["total_entity_count"] >= 2
        assert any(e["category"] == "EMAIL" for e in result["results"][0]["entities"])
        assert any(e["category"] == "SSN" for e in result["results"][1]["entities"])

    def test_no_pii(self):
        """analyze_batch with clean texts returns zero entities."""
        result = analyze_batch(["Hello world", "Nice weather"])
        assert "error" not in result
        assert result["total_entity_count"] == 0
        assert all(r["entity_count"] == 0 for r in result["results"])

    def test_empty_list(self):
        result = analyze_batch([])
        assert "error" not in result
        assert result["results"] == []
        assert result["total_entity_count"] == 0

    def test_entity_fields(self):
        """analyze_batch entity fields match analyze output format."""
        result = analyze_batch(["Contact test@example.com about the project"])
        assert "error" not in result
        email_entity = next(
            e for e in result["results"][0]["entities"] if e["category"] == "EMAIL"
        )
        # text field is NOT included by default (security: PII removal)
        assert "text" not in email_entity
        assert isinstance(email_entity["start"], int)
        assert isinstance(email_entity["end"], int)
        assert isinstance(email_entity["confidence"], (int, float))
        assert email_entity["source"] == "regex"


class TestDesanitizeMetadata:

    def test_desanitize_accepts_metadata(self):
        """desanitize accepts metadata parameter without error."""
        import json
        san = sanitize("Email john@acme.com")
        des = desanitize(
            san["sanitized"],
            san["token_map_id"],
            metadata=json.dumps({"user_id": "u-42"}),
        )
        assert "error" not in des
        assert des["restored"] == "Email john@acme.com"
