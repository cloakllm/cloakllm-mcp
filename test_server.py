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

import pytest

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

# v0.6.3 NEW-2: enable audit logging during tests (was disabled — same I2-class
# bug that prompted the v0.6.2 hotfix). Without enabling audit, the always-on
# B3 schema validator never executes in any MCP test, and the B4 invariant
# ("MCP defaults to compliance mode AND writes audit entries") is only checked
# for config presence, never for actual log writing.
_TEST_LOG_DIR = tempfile.mkdtemp(prefix="cloakllm_mcp_test_audit_")
os.environ["CLOAKLLM_AUDIT_ENABLED"] = "true"
os.environ["CLOAKLLM_LOG_DIR"] = _TEST_LOG_DIR

from server import sanitize, sanitize_batch, desanitize, desanitize_batch, analyze, analyze_batch, analyze_context_risk, _TOKEN_MAPS, _shield, _resolve_compliance_mode


# v0.6.1 (B4): MCP defaults to Article 12 compliance mode unless overridden
def test_mcp_defaults_to_compliance_mode_eu_ai_act_article12():
    """Without CLOAKLLM_COMPLIANCE_MODE set, the global Shield must default
    to compliance_mode='eu_ai_act_article12' so the runtime invariant guard
    fires on every audit write."""
    assert _shield.config.compliance_mode == "eu_ai_act_article12", (
        f"MCP default compliance_mode should be 'eu_ai_act_article12', "
        f"got {_shield.config.compliance_mode!r}. This is the v0.6.1 B4 invariant."
    )


# v0.6.2 (I1) hotfix: documented opt-out paths must not crash the server.
# Tests target the pure helper `_resolve_compliance_mode` so we don't have to
# reload the server module (which disrupts other tests' module-level refs).
# We also do an end-to-end smoke test by constructing ShieldConfig directly
# with the resolved value to confirm the validator accepts it.

from cloakllm import ShieldConfig

class TestComplianceModeOptOut:
    """Each documented opt-out value must yield None and not crash ShieldConfig."""

    def test_resolve_off(self):
        assert _resolve_compliance_mode("off") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("off"))  # no raise

    def test_resolve_OFF_uppercase(self):
        assert _resolve_compliance_mode("OFF") is None  # case-insensitive

    def test_resolve_empty_string(self):
        assert _resolve_compliance_mode("") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode(""))

    def test_resolve_none_string(self):
        assert _resolve_compliance_mode("none") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("none"))

    def test_resolve_false_string(self):
        assert _resolve_compliance_mode("false") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("false"))

    def test_resolve_None_value(self):
        assert _resolve_compliance_mode(None) is None

    def test_resolve_eu_ai_act_article12_passes_through(self):
        assert _resolve_compliance_mode("eu_ai_act_article12") == "eu_ai_act_article12"
        cfg = ShieldConfig(compliance_mode=_resolve_compliance_mode("eu_ai_act_article12"))
        assert cfg.compliance_mode == "eu_ai_act_article12"

    def test_resolve_unknown_value_passed_through_for_validator_to_reject(self):
        # Helper does not validate — that's ShieldConfig's job.
        # An unknown value should be passed through unchanged so the user
        # gets a clear ValueError from ShieldConfig.__post_init__.
        assert _resolve_compliance_mode("bogus_mode") == "bogus_mode"
        with pytest.raises(ValueError, match="Invalid compliance_mode"):
            ShieldConfig(compliance_mode=_resolve_compliance_mode("bogus_mode"))

    # --- v0.6.3 NEW-4: whitespace handling (I1-class crash prevention) ---

    def test_resolve_whitespace_only(self):
        """' ' (space-only) opts out cleanly — was previously crashing."""
        assert _resolve_compliance_mode(" ") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode(" "))  # no raise

    def test_resolve_off_with_trailing_space(self):
        """'off ' (Docker ENV trailing space) opts out cleanly."""
        assert _resolve_compliance_mode("off ") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("off "))

    def test_resolve_off_with_crlf(self):
        """'\\noff\\n' (CRLF leakage) opts out cleanly."""
        assert _resolve_compliance_mode("\noff\n") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("\noff\n"))

    def test_resolve_explicit_value_with_surrounding_whitespace(self):
        """'  eu_ai_act_article12  ' is stripped and accepted."""
        assert _resolve_compliance_mode("  eu_ai_act_article12  ") == "eu_ai_act_article12"
        cfg = ShieldConfig(compliance_mode=_resolve_compliance_mode("  eu_ai_act_article12  "))
        assert cfg.compliance_mode == "eu_ai_act_article12"

    # --- v0.6.3 P0-3: Unicode whitespace + zero-width strip ---
    # str.strip() handles ASCII WS + NBSP + ideographic space + line/para sep.
    # The regex stripper additionally handles ZWSP, ZWNJ, ZWJ, BOM — the
    # bypass paths that would otherwise crash ShieldConfig at import.

    def test_resolve_strips_nbsp(self):
        """NBSP (\\u00a0) — already handled by str.strip but verify."""
        assert _resolve_compliance_mode("\u00a0off\u00a0") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("\u00a0off\u00a0"))

    def test_resolve_strips_zero_width_space(self):
        """ZWSP (\\u200b) — NOT stripped by str.strip(), must be handled by regex."""
        assert _resolve_compliance_mode("\u200boff\u200b") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("\u200boff\u200b"))

    def test_resolve_strips_bom(self):
        """BOM (\\ufeff) — common from UTF-8-with-BOM Notepad saves."""
        assert _resolve_compliance_mode("\ufeffoff") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("\ufeffoff"))

    def test_resolve_strips_zwj(self):
        """ZWJ (\\u200d) and ZWNJ (\\u200c) also handled."""
        assert _resolve_compliance_mode("\u200doff\u200c") is None
        ShieldConfig(compliance_mode=_resolve_compliance_mode("\u200doff\u200c"))

    def test_resolve_bom_with_real_value(self):
        """BOM-prefixed valid value: stripped, then accepted."""
        assert _resolve_compliance_mode("\ufeffeu_ai_act_article12") == "eu_ai_act_article12"
        cfg = ShieldConfig(compliance_mode=_resolve_compliance_mode("\ufeffeu_ai_act_article12"))
        assert cfg.compliance_mode == "eu_ai_act_article12"


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


class TestAnalyzeContextRisk:

    def test_low_risk_no_tokens(self):
        """Text without tokens should have low risk."""
        result = analyze_context_risk("The weather is nice today.")
        assert "error" not in result
        assert result["risk_level"] == "low"
        assert result["risk_score"] == 0.0
        assert result["token_density"] == 0.0

    def test_high_risk_descriptors_near_tokens(self):
        """Identifying descriptors near tokens should increase risk."""
        text = "The CEO of [ORG_0], who founded [ORG_1] in 2003, lives in [GPE_0]"
        result = analyze_context_risk(text)
        assert "error" not in result
        assert result["identifying_descriptors"] >= 1
        assert result["risk_score"] > 0
        assert len(result["warnings"]) > 0

    def test_relationship_edges(self):
        """Relationship phrases connecting tokens should be detected."""
        text = "[PERSON_0] works at [ORG_0] and lives in [GPE_0]"
        result = analyze_context_risk(text)
        assert "error" not in result
        assert result["relationship_edges"] >= 1

    def test_empty_text(self):
        """Empty text should return zero risk."""
        result = analyze_context_risk("")
        assert "error" not in result
        assert result["risk_level"] == "low"
        assert result["risk_score"] == 0.0

    def test_token_density(self):
        """Token density should be calculated correctly."""
        text = "[EMAIL_0] [PERSON_0] hello world"
        result = analyze_context_risk(text)
        assert "error" not in result
        assert result["token_density"] == 0.5  # 2 tokens / 4 words

    def test_redacted_tokens_detected(self):
        """REDACTED tokens should also be detected."""
        text = "[EMAIL_REDACTED] [PERSON_REDACTED] hello world"
        result = analyze_context_risk(text)
        assert "error" not in result
        assert result["token_density"] == 0.5

    def test_result_fields(self):
        """Result should contain all expected fields."""
        result = analyze_context_risk("Hello [EMAIL_0]")
        assert "error" not in result
        assert "token_density" in result
        assert "identifying_descriptors" in result
        assert "relationship_edges" in result
        assert "risk_score" in result
        assert "risk_level" in result
        assert "warnings" in result
        assert result["risk_level"] in ("low", "medium", "high")

    def test_sanitize_then_analyze_risk(self):
        """End-to-end: sanitize text, then analyze the sanitized output for risk."""
        san = sanitize("The CEO of Acme Corp, john@acme.com, founded it in 2003")
        assert "error" not in san
        risk = analyze_context_risk(san["sanitized"])
        assert "error" not in risk
        # Should detect some risk from the context
        assert isinstance(risk["risk_score"], float)


# --- v0.6.3 NEW-2: verify the audit invariant the v0.6.1 B3+B4 release was meant to deliver ---
# Without these tests, the always-on schema validator and the MCP compliance-mode
# default both have ZERO end-to-end coverage on the MCP surface — same gap class
# as I2 (missing JS audit schema test) that prompted v0.6.2 hotfix.

import json as _json
import glob as _glob
import os as _os
from cloakllm.audit import _validate_audit_entry_schema as _b3_validate


def _read_audit_entries():
    """Read all entries written by the global _shield to _TEST_LOG_DIR."""
    entries = []
    for path in sorted(_glob.glob(_os.path.join(_TEST_LOG_DIR, "audit_*.jsonl"))):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(_json.loads(line))
    return entries


def test_mcp_writes_audit_entry_on_sanitize():
    """A sanitize call MUST produce an audit entry on disk (NEW-2)."""
    before = len(_read_audit_entries())
    sanitize("Trace this: john@example.com")
    after_entries = _read_audit_entries()
    assert len(after_entries) > before, (
        "MCP sanitize did not write an audit entry. "
        "This is the I2-class gap NEW-2 was meant to close."
    )
    # Most recent entry should be a sanitize event with our fingerprint
    sanitize_entries = [e for e in after_entries if e.get("event_type") == "sanitize"]
    assert sanitize_entries, "No sanitize event_type entries found"


def test_mcp_audit_entry_passes_b3_schema_validation():
    """Every MCP-written audit entry MUST pass the always-on B3 validator (NEW-2)."""
    sanitize("schema test: jane@x.com")
    entries = _read_audit_entries()
    assert entries, "no audit entries written"
    for i, e in enumerate(entries):
        # Strip the entry_hash field (added AFTER validation in audit.log()).
        e_for_validation = {k: v for k, v in e.items() if k != "entry_hash"}
        try:
            _b3_validate(e_for_validation)
        except Exception as exc:
            raise AssertionError(
                f"Audit entry {i} failed B3 schema validation: {exc}\n"
                f"entry: {e_for_validation}"
            ) from exc
