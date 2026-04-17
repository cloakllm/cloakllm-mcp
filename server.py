"""
CloakLLM MCP Server.

Exposes CloakLLM's Python SDK as 7 MCP tools for Claude Desktop and other
MCP-compatible clients:

  - sanitize               — Detect & cloak PII, return sanitized text + token map ID
  - sanitize_batch         — Detect & cloak PII in multiple texts with a shared token map
  - desanitize             — Restore original values using a token map ID
  - desanitize_batch       — Restore original values in multiple texts using a token map ID
  - analyze                — Detect PII without cloaking (pure analysis)
  - analyze_batch          — Detect PII in multiple texts without cloaking
  - analyze_context_risk   — Analyze sanitized text for context-based PII leakage risk

Run:
  python -m mcp run server.py
  # or: uvx mcp run server.py
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from cloakllm import Shield, ShieldConfig
from cloakllm.context_analyzer import ContextAnalyzer

logger = logging.getLogger("cloakllm.mcp")

MAX_TEXT_LENGTH = 1_000_000   # 1 MB max input text
MAX_BATCH_SIZE = 100          # Max texts in a batch
MAX_TOKEN_MAPS = 10_000       # Max stored token maps
MAX_METADATA_LENGTH = 10_000  # Max metadata JSON length
MAX_SHIELD_CACHE = 50         # Max cached Shield instances

# ── Server setup ─────────────────────────────────────────────────

mcp = FastMCP(
    "CloakLLM",
    description="PII cloaking and analysis for LLM prompts. "
    "Detects sensitive data (emails, names, SSNs, etc.), replaces with tokens, "
    "and restores originals in responses.",
)

# ── Shield instance (env-based config) ───────────────────────────

_shield_config_kwargs = dict(
    audit_enabled=os.getenv("CLOAKLLM_AUDIT_ENABLED", "true").lower() == "true",
    log_dir=os.getenv("CLOAKLLM_LOG_DIR", "./cloakllm_audit"),
)

# v0.6.1 (B4): MCP defaults to Article 12 compliance mode. The MCP layer is the
# layer most likely to receive untrusted input, so it should be the strictest
# deployment surface. Operators can opt out by setting CLOAKLLM_COMPLIANCE_MODE
# to an empty string, "off", "none", or "false".
#
# v0.6.2 (I1) hotfix: ALWAYS set compliance_mode explicitly in kwargs (helper
# extracted for testability). Otherwise ShieldConfig.default_factory reads
# CLOAKLLM_COMPLIANCE_MODE from the environment directly and __post_init__
# rejects "off"/"none"/"false"/"" as invalid values, crashing the server on
# the documented opt-out paths.
def _resolve_compliance_mode(env_value):
    """Map a CLOAKLLM_COMPLIANCE_MODE env value to the validated ShieldConfig
    field value. None / empty / "off" / "none" / "false" all opt out and
    return None. Any other non-empty value is passed through unchanged
    (ShieldConfig.__post_init__ does the final validation)."""
    if not env_value:
        return None
    if env_value.lower() in ("off", "none", "false"):
        return None
    return env_value

_shield_config_kwargs["compliance_mode"] = _resolve_compliance_mode(
    os.getenv("CLOAKLLM_COMPLIANCE_MODE", "eu_ai_act_article12")
)
_retention_hint_env = os.getenv("CLOAKLLM_RETENTION_HINT_DAYS", "")
if _retention_hint_env:
    try:
        _shield_config_kwargs["retention_hint_days"] = int(_retention_hint_env)
    except ValueError:
        pass  # ShieldConfig validates; keep default 180

# Attestation: if signing key path is set, load the keypair
_signing_key_path = os.getenv("CLOAKLLM_SIGNING_KEY_PATH", "")
if _signing_key_path:
    _shield_config_kwargs["attestation_key_path"] = _signing_key_path

_shield = Shield(config=ShieldConfig(**_shield_config_kwargs))

# ── In-memory token map store with TTL ───────────────────────────

# NOTE: Token maps are stored in a global dict without session scoping.
# This server is designed for single-user, single-client deployments (e.g., Claude Desktop).
# Do NOT expose this server to multiple untrusted clients.

_TOKEN_MAPS: dict[str, dict[str, Any]] = {}
_MAP_TTL_SECONDS = 3600  # 1 hour
_token_maps_lock = threading.Lock()

# Shield instance cache for non-default configurations
_SHIELD_CACHE: dict[tuple, any] = {}


def _cleanup_expired():
    """Remove token maps older than TTL."""
    now = time.time()
    expired = [k for k, v in _TOKEN_MAPS.items() if now - v["created"] > _MAP_TTL_SECONDS]
    for k in expired:
        del _TOKEN_MAPS[k]


def _store_token_map(token_map) -> str:
    """Store a token map with TTL and return its ID."""
    with _token_maps_lock:
        _cleanup_expired()
        # Evict oldest if at capacity
        if len(_TOKEN_MAPS) >= MAX_TOKEN_MAPS:
            oldest_key = min(_TOKEN_MAPS, key=lambda k: _TOKEN_MAPS[k]["created"])
            del _TOKEN_MAPS[oldest_key]
        map_id = str(uuid.uuid4())
        _TOKEN_MAPS[map_id] = {"token_map": token_map, "created": time.time()}
        return map_id


# ── Input validation helpers ─────────────────────────────────────

def _validate_text_input(text: str) -> dict | None:
    """Validate text input size. Returns error dict or None."""
    if len(text) > MAX_TEXT_LENGTH:
        return {"error": f"Text exceeds maximum length ({MAX_TEXT_LENGTH} chars)."}
    return None


def _validate_batch_input(texts: list) -> dict | None:
    """Validate batch input size. Returns error dict or None."""
    if len(texts) > MAX_BATCH_SIZE:
        return {"error": f"Batch exceeds maximum size ({MAX_BATCH_SIZE} texts)."}
    for t in texts:
        if len(t) > MAX_TEXT_LENGTH:
            return {"error": f"Text in batch exceeds maximum length ({MAX_TEXT_LENGTH} chars)."}
    return None


def _validate_metadata(metadata: str) -> tuple[dict | None, dict | None]:
    """Validate and parse metadata. Returns (parsed_dict_or_None, error_dict_or_None)."""
    if not metadata:
        return None, None
    if len(metadata) > MAX_METADATA_LENGTH:
        return None, {"error": f"Metadata exceeds maximum length ({MAX_METADATA_LENGTH} chars)."}
    try:
        parsed = json.loads(metadata)
        if not isinstance(parsed, dict):
            return None, {"error": "Metadata must be a JSON object."}
        return parsed, None
    except json.JSONDecodeError:
        return None, {"error": "Invalid metadata JSON."}


# ── Shield caching helper ────────────────────────────────────────

def _get_cached_shield(mode="tokenize", entity_hashing=False, custom_llm_categories=None):
    """Get or create a cached Shield instance for the given configuration."""
    _cats = tuple(tuple(c) if isinstance(c, list) else (c.get("name", ""), c.get("description", "")) if isinstance(c, dict) else c for c in (custom_llm_categories or []))
    cache_key = (mode, entity_hashing, _cats)
    if cache_key in _SHIELD_CACHE:
        return _SHIELD_CACHE[cache_key]
    config_kwargs = dict(_shield_config_kwargs)
    config_kwargs["mode"] = mode
    config_kwargs["entity_hashing"] = entity_hashing
    if custom_llm_categories:
        config_kwargs["custom_llm_categories"] = custom_llm_categories
    shield = Shield(config=ShieldConfig(**config_kwargs))
    if len(_SHIELD_CACHE) >= MAX_SHIELD_CACHE:
        _SHIELD_CACHE.pop(next(iter(_SHIELD_CACHE)))
    _SHIELD_CACHE[cache_key] = shield
    return shield


# ── MCP Tools ────────────────────────────────────────────────────

@mcp.tool()
def sanitize(
    text: str,
    model: str = "",
    provider: str = "",
    metadata: str = "",
    token_map_id: str = "",
    mode: str = "",
    custom_llm_categories: str = "",
    entity_hashing: bool = False,
    entity_hash_key: str = "",
) -> dict:
    """
    Detect and cloak PII in text.

    Replaces sensitive data (emails, names, SSNs, API keys, etc.) with
    deterministic tokens like [EMAIL_0], [PERSON_0]. Returns the sanitized
    text and a token_map_id for later desanitization.

    For multi-turn conversations, pass the token_map_id from a previous
    sanitize call to reuse the same token map (consistent tokenization).

    Set mode to "redact" for irreversible PII removal — replaces with
    [EMAIL_REDACTED], [PERSON_REDACTED], etc. No token map is stored.

    Args:
        text: The text to sanitize.
        model: Optional LLM model name (for audit logging).
        provider: Optional LLM provider name (for audit logging).
        metadata: Optional metadata string (for audit logging).
        token_map_id: Optional ID from a previous sanitize call to reuse the token map.
        mode: Optional mode — "tokenize" (default, reversible) or "redact" (irreversible).

    Returns:
        dict with sanitized text, token_map_id, entity_count, and categories.
    """
    try:
        err = _validate_text_input(text)
        if err:
            return json.dumps(err)

        # Use a separate shield instance if mode is "redact"
        effective_mode = mode if mode in ("tokenize", "redact") else "tokenize"

        # Parse custom LLM categories
        parsed_categories = []
        if custom_llm_categories:
            try:
                parsed_categories = json.loads(custom_llm_categories)
                if not isinstance(parsed_categories, list):
                    return {"error": "custom_llm_categories must be a JSON array of [name, description] pairs."}
            except json.JSONDecodeError:
                return {"error": "custom_llm_categories must be valid JSON."}

        effective_hash_key = entity_hash_key or os.getenv("CLOAKLLM_ENTITY_HASH_KEY", "")

        if effective_mode == "redact" or parsed_categories or entity_hashing:
            if effective_hash_key:
                # Custom hash key — create fresh Shield (don't cache by key)
                config_kwargs = dict(_shield_config_kwargs)
                config_kwargs["mode"] = effective_mode
                config_kwargs["entity_hashing"] = entity_hashing
                config_kwargs["entity_hash_key"] = effective_hash_key
                if parsed_categories:
                    config_kwargs["custom_llm_categories"] = parsed_categories
                shield = Shield(config=ShieldConfig(**config_kwargs))
            else:
                shield = _get_cached_shield(
                    mode=effective_mode,
                    entity_hashing=entity_hashing,
                    custom_llm_categories=parsed_categories or None,
                )
        else:
            shield = _shield

        existing_map = None
        reuse_id = ""

        if token_map_id and effective_mode != "redact":
            with _token_maps_lock:
                entry = _TOKEN_MAPS.get(token_map_id)
                if entry is None:
                    return {"error": f"Token map not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
                existing_map = entry["token_map"]
                reuse_id = token_map_id

        metadata_dict, meta_err = _validate_metadata(metadata)
        if meta_err:
            return json.dumps(meta_err)

        sanitized, token_map = shield.sanitize(
            text, model=model or None, provider=provider or None,
            metadata=metadata_dict, token_map=existing_map
        )

        # In redact mode, don't store a token map (nothing to reverse)
        if effective_mode == "redact":
            result = {
                "sanitized": sanitized,
                "entity_count": len(token_map.detections),
                "categories": token_map.categories,
                "mode": "redact",
                "entity_details": token_map.entity_details,
            }
            if token_map.certificate is not None:
                result["certificate"] = token_map.certificate.to_dict()
            return result

        if reuse_id:
            # Refresh timestamp to prevent TTL expiry during active conversations
            with _token_maps_lock:
                _TOKEN_MAPS[reuse_id]["token_map"] = token_map
                _TOKEN_MAPS[reuse_id]["created"] = time.time()
            map_id = reuse_id
        else:
            map_id = _store_token_map(token_map)

        result = {
            "sanitized": sanitized,
            "token_map_id": map_id,
            "entity_count": token_map.entity_count,
            "categories": token_map.categories,
            "entity_details": token_map.entity_details,
        }
        if token_map.certificate is not None:
            result["certificate"] = token_map.certificate.to_dict()
        return result
    except Exception as e:
        logger.error("sanitize tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Sanitization failed. Check server logs for details."}


@mcp.tool()
def sanitize_batch(
    texts: list[str],
    model: str = "",
    provider: str = "",
    metadata: str = "",
    token_map_id: str = "",
    custom_llm_categories: str = "",
    mode: str = "",
    entity_hashing: bool = False,
    entity_hash_key: str = "",
) -> dict:
    """
    Detect and cloak PII in multiple texts with a shared token map.

    Same entities across texts get the same token. Returns a single
    token_map_id for later desanitization of any text in the batch.

    Args:
        texts: List of texts to sanitize.
        model: Optional LLM model name (for audit logging).
        provider: Optional LLM provider name (for audit logging).
        metadata: Optional metadata string (for audit logging).
        token_map_id: Optional ID from a previous call to reuse the token map.

    Returns:
        dict with sanitized texts, token_map_id, entity_count, and categories.
    """
    try:
        err = _validate_batch_input(texts)
        if err:
            return json.dumps(err)

        # Parse custom LLM categories
        parsed_categories = []
        if custom_llm_categories:
            try:
                parsed_categories = json.loads(custom_llm_categories)
                if not isinstance(parsed_categories, list):
                    return {"error": "custom_llm_categories must be a JSON array of [name, description] pairs."}
            except json.JSONDecodeError:
                return {"error": "custom_llm_categories must be valid JSON."}

        effective_mode = mode if mode in ("tokenize", "redact") else "tokenize"
        effective_hash_key = entity_hash_key or os.getenv("CLOAKLLM_ENTITY_HASH_KEY", "")

        if parsed_categories or effective_mode == "redact" or entity_hashing:
            if effective_hash_key:
                config_kwargs = dict(_shield_config_kwargs)
                config_kwargs["mode"] = effective_mode
                config_kwargs["entity_hashing"] = entity_hashing
                config_kwargs["entity_hash_key"] = effective_hash_key
                if parsed_categories:
                    config_kwargs["custom_llm_categories"] = parsed_categories
                shield = Shield(config=ShieldConfig(**config_kwargs))
            else:
                shield = _get_cached_shield(
                    mode=effective_mode,
                    entity_hashing=entity_hashing,
                    custom_llm_categories=parsed_categories or None,
                )
        else:
            shield = _shield

        existing_map = None
        reuse_id = ""

        if token_map_id and effective_mode != "redact":
            with _token_maps_lock:
                entry = _TOKEN_MAPS.get(token_map_id)
                if entry is None:
                    return {"error": f"Token map not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
                existing_map = entry["token_map"]
                reuse_id = token_map_id

        metadata_dict, meta_err = _validate_metadata(metadata)
        if meta_err:
            return json.dumps(meta_err)

        sanitized_texts, token_map = shield.sanitize_batch(
            texts, model=model or None, provider=provider or None,
            metadata=metadata_dict, token_map=existing_map
        )

        # In redact mode, don't store a token map (nothing to reverse)
        if effective_mode == "redact":
            result = {
                "sanitized": sanitized_texts,
                "entity_count": len(token_map.detections),
                "categories": token_map.categories,
                "mode": "redact",
                "entity_details": token_map.entity_details,
            }
            if token_map.certificate is not None:
                result["certificate"] = token_map.certificate.to_dict()
            return result

        if reuse_id:
            with _token_maps_lock:
                _TOKEN_MAPS[reuse_id]["token_map"] = token_map
                _TOKEN_MAPS[reuse_id]["created"] = time.time()
            map_id = reuse_id
        else:
            map_id = _store_token_map(token_map)

        result = {
            "sanitized": sanitized_texts,
            "token_map_id": map_id,
            "entity_count": token_map.entity_count,
            "categories": token_map.categories,
            "entity_details": token_map.entity_details,
        }
        if token_map.certificate is not None:
            result["certificate"] = token_map.certificate.to_dict()
        return result
    except Exception as e:
        logger.error("sanitize_batch tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Batch sanitization failed. Check server logs for details."}


@mcp.tool()
def desanitize(
    text: str,
    token_map_id: str,
    metadata: str = "",
) -> dict:
    """
    Restore original values in text using a token map.

    Replaces tokens like [EMAIL_0] back to the original values.
    Requires a token_map_id from a previous sanitize call.

    Args:
        text: The text containing tokens to restore.
        token_map_id: The ID returned by a previous sanitize call.
        metadata: Optional metadata string (for audit logging).

    Returns:
        dict with the restored text.
    """
    try:
        err = _validate_text_input(text)
        if err:
            return json.dumps(err)

        with _token_maps_lock:
            entry = _TOKEN_MAPS.get(token_map_id)
            if entry is None:
                return {"error": f"Token map not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
            token_map = entry["token_map"]

        metadata_dict, meta_err = _validate_metadata(metadata)
        if meta_err:
            return json.dumps(meta_err)

        restored = _shield.desanitize(text, token_map, metadata=metadata_dict)
        return {"restored": restored}
    except Exception as e:
        logger.error("desanitize tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Desanitization failed. Check server logs for details."}


@mcp.tool()
def desanitize_batch(
    texts: list[str],
    token_map_id: str,
    metadata: str = "",
) -> dict:
    """
    Restore original values in multiple texts using a shared token map.

    Replaces tokens like [EMAIL_0] back to the original values in each text.
    Requires a token_map_id from a previous sanitize or sanitize_batch call.

    Args:
        texts: List of texts containing tokens to restore.
        token_map_id: The ID returned by a previous sanitize call.
        metadata: Optional metadata string (for audit logging).

    Returns:
        dict with list of restored texts.
    """
    try:
        err = _validate_batch_input(texts)
        if err:
            return json.dumps(err)

        with _token_maps_lock:
            entry = _TOKEN_MAPS.get(token_map_id)
            if entry is None:
                return {"error": f"Token map not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
            token_map = entry["token_map"]

        metadata_dict, meta_err = _validate_metadata(metadata)
        if meta_err:
            return json.dumps(meta_err)

        restored = _shield.desanitize_batch(texts, token_map, metadata=metadata_dict)
        return {"restored": restored}
    except Exception as e:
        logger.error("desanitize_batch tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Batch desanitization failed. Check server logs for details."}


@mcp.tool()
def analyze(text: str, custom_llm_categories: str = "", include_text: bool = False) -> dict:
    """
    Analyze text for PII without cloaking.

    Returns detected entities with their categories, positions,
    confidence scores, and detection method. Does not modify the text.

    Args:
        text: The text to analyze for PII.
        include_text: If True, include the matched PII text in each entity. Defaults to False.

    Returns:
        dict with entity_count and list of detected entities.
    """
    try:
        err = _validate_text_input(text)
        if err:
            return json.dumps(err)

        # Parse custom LLM categories
        parsed_categories = []
        if custom_llm_categories:
            try:
                parsed_categories = json.loads(custom_llm_categories)
                if not isinstance(parsed_categories, list):
                    return {"error": "custom_llm_categories must be a JSON array of [name, description] pairs."}
            except json.JSONDecodeError:
                return {"error": "custom_llm_categories must be valid JSON."}

        if parsed_categories:
            shield = _get_cached_shield(custom_llm_categories=parsed_categories)
        else:
            shield = _shield

        result = shield.analyze(text, redact_values=not include_text)
        entities = []
        for e in result["entities"]:
            entity_info = {
                "category": e["category"],
                "start": e["start"],
                "end": e["end"],
                "confidence": e["confidence"],
                "source": e["source"],
            }
            if include_text:
                entity_info["text"] = e["text"]
            entities.append(entity_info)

        return {
            "entity_count": result["entity_count"],
            "entities": entities,
        }
    except Exception as e:
        logger.error("analyze tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Analysis failed. Check server logs for details."}


@mcp.tool()
def analyze_batch(texts: list[str], custom_llm_categories: str = "", include_text: bool = False) -> dict:
    """
    Analyze multiple texts for PII without cloaking.

    Returns detected entities per text with their categories, positions,
    confidence scores, and detection method. Does not modify the texts.

    Args:
        texts: List of texts to analyze for PII.
        custom_llm_categories: Optional JSON array of [name, description] pairs.
        include_text: If True, include the matched PII text in each entity. Defaults to False.

    Returns:
        dict with results per text and total entity count.
    """
    try:
        err = _validate_batch_input(texts)
        if err:
            return json.dumps(err)

        # Parse custom LLM categories
        parsed_categories = []
        if custom_llm_categories:
            try:
                parsed_categories = json.loads(custom_llm_categories)
                if not isinstance(parsed_categories, list):
                    return {"error": "custom_llm_categories must be a JSON array of [name, description] pairs."}
            except json.JSONDecodeError:
                return {"error": "custom_llm_categories must be valid JSON."}

        if parsed_categories:
            shield = _get_cached_shield(custom_llm_categories=parsed_categories)
        else:
            shield = _shield

        results = []
        total_count = 0
        for text in texts:
            result = shield.analyze(text, redact_values=not include_text)
            total_count += result["entity_count"]
            entities = []
            for e in result["entities"]:
                entity_info = {
                    "category": e["category"],
                    "start": e["start"],
                    "end": e["end"],
                    "confidence": e["confidence"],
                    "source": e["source"],
                }
                if include_text:
                    entity_info["text"] = e["text"]
                entities.append(entity_info)

            results.append({
                "entity_count": result["entity_count"],
                "entities": entities,
            })

        return {
            "results": results,
            "total_entity_count": total_count,
        }
    except Exception as e:
        logger.error("analyze_batch tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Batch analysis failed. Check server logs for details."}


@mcp.tool()
def analyze_context_risk(sanitized_text: str) -> dict:
    """
    Analyze sanitized text for context-based PII leakage risk.

    Even after tokenization, surrounding context (e.g., "The CEO of [ORG_0]
    who founded it in 2003") can reveal identity. This tool scores that risk.

    Three signals are analyzed:
    - Token density: ratio of tokens to total words
    - Identifying descriptors: words like "CEO", "founder" near tokens
    - Relationship edges: phrases like "works at" connecting two tokens

    Args:
        sanitized_text: Text containing [CATEGORY_N] tokens (output of sanitize).

    Returns:
        dict with token_density, identifying_descriptors, relationship_edges,
        risk_score (0-1), risk_level (low/medium/high), and warnings.
    """
    try:
        err = _validate_text_input(sanitized_text)
        if err:
            return json.dumps(err)

        analyzer = ContextAnalyzer()
        result = analyzer.analyze(sanitized_text)
        return result.to_dict()
    except Exception as e:
        logger.error("analyze_context_risk tool failed: %s: %s", type(e).__name__, e)
        return {"error": "Context risk analysis failed. Check server logs for details."}


# ── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
