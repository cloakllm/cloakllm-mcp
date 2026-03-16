"""
CloakLLM MCP Server.

Exposes CloakLLM's Python SDK as 6 MCP tools for Claude Desktop and other
MCP-compatible clients:

  - sanitize          — Detect & cloak PII, return sanitized text + token map ID
  - sanitize_batch    — Detect & cloak PII in multiple texts with a shared token map
  - desanitize        — Restore original values using a token map ID
  - desanitize_batch  — Restore original values in multiple texts using a token map ID
  - analyze           — Detect PII without cloaking (pure analysis)
  - analyze_batch     — Detect PII in multiple texts without cloaking

Run:
  python -m mcp run server.py
  # or: uvx mcp run server.py
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from cloakllm import Shield, ShieldConfig

logger = logging.getLogger("cloakllm.mcp")

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
    log_original_values=False,
)

# Attestation: if signing key path is set, load the keypair
_signing_key_path = os.getenv("CLOAKLLM_SIGNING_KEY_PATH", "")
if _signing_key_path:
    _shield_config_kwargs["attestation_key_path"] = _signing_key_path

_shield = Shield(config=ShieldConfig(**_shield_config_kwargs))

# ── In-memory token map store with TTL ───────────────────────────

_TOKEN_MAPS: dict[str, dict[str, Any]] = {}
_MAP_TTL_SECONDS = 3600  # 1 hour


def _cleanup_expired():
    """Remove token maps older than TTL."""
    now = time.time()
    expired = [k for k, v in _TOKEN_MAPS.items() if now - v["created"] > _MAP_TTL_SECONDS]
    for k in expired:
        del _TOKEN_MAPS[k]


def _store_token_map(token_map) -> str:
    """Store a token map and return its ID."""
    _cleanup_expired()
    map_id = str(uuid.uuid4())
    _TOKEN_MAPS[map_id] = {
        "token_map": token_map,
        "created": time.time(),
    }
    return map_id


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

        if effective_mode == "redact":
            config_kwargs = dict(
                mode="redact",
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
                entity_hashing=entity_hashing,
                entity_hash_key=entity_hash_key,
            )
            if parsed_categories:
                config_kwargs["custom_llm_categories"] = parsed_categories
            shield = Shield(config=ShieldConfig(**config_kwargs))
        elif parsed_categories or entity_hashing:
            config_kwargs = dict(
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
                entity_hashing=entity_hashing,
                entity_hash_key=entity_hash_key,
            )
            if parsed_categories:
                config_kwargs["custom_llm_categories"] = parsed_categories
            shield = Shield(config=ShieldConfig(**config_kwargs))
        else:
            shield = _shield

        existing_map = None
        reuse_id = ""

        if token_map_id and effective_mode != "redact":
            entry = _TOKEN_MAPS.get(token_map_id)
            if entry is None:
                return {"error": f"Token map '{token_map_id}' not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
            existing_map = entry["token_map"]
            reuse_id = token_map_id

        metadata_dict = json.loads(metadata) if metadata else None

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
        logger.exception("sanitize tool failed")
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

        if parsed_categories or effective_mode == "redact" or entity_hashing:
            config_kwargs = dict(
                mode=effective_mode,
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
                entity_hashing=entity_hashing,
                entity_hash_key=entity_hash_key,
            )
            if parsed_categories:
                config_kwargs["custom_llm_categories"] = parsed_categories
            shield = Shield(config=ShieldConfig(**config_kwargs))
        else:
            shield = _shield

        existing_map = None
        reuse_id = ""

        if token_map_id and effective_mode != "redact":
            entry = _TOKEN_MAPS.get(token_map_id)
            if entry is None:
                return {"error": f"Token map '{token_map_id}' not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}
            existing_map = entry["token_map"]
            reuse_id = token_map_id

        metadata_dict = json.loads(metadata) if metadata else None

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
        logger.exception("sanitize_batch tool failed")
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
        entry = _TOKEN_MAPS.get(token_map_id)
        if entry is None:
            return {"error": f"Token map '{token_map_id}' not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}

        metadata_dict = json.loads(metadata) if metadata else None

        token_map = entry["token_map"]
        restored = _shield.desanitize(text, token_map, metadata=metadata_dict)
        return {"restored": restored}
    except Exception as e:
        logger.exception("desanitize tool failed")
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
        entry = _TOKEN_MAPS.get(token_map_id)
        if entry is None:
            return {"error": f"Token map '{token_map_id}' not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}

        metadata_dict = json.loads(metadata) if metadata else None

        token_map = entry["token_map"]
        restored = _shield.desanitize_batch(texts, token_map, metadata=metadata_dict)
        return {"restored": restored}
    except Exception as e:
        logger.exception("desanitize_batch tool failed")
        return {"error": "Batch desanitization failed. Check server logs for details."}


@mcp.tool()
def analyze(text: str, custom_llm_categories: str = "") -> dict:
    """
    Analyze text for PII without cloaking.

    Returns detected entities with their categories, positions,
    confidence scores, and detection method. Does not modify the text.

    Args:
        text: The text to analyze for PII.

    Returns:
        dict with entity_count and list of detected entities.
    """
    try:
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
            shield = Shield(config=ShieldConfig(
                custom_llm_categories=parsed_categories,
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
            ))
        else:
            shield = _shield

        result = shield.analyze(text)
        return {
            "entity_count": result["entity_count"],
            "entities": [
                {
                    "text": e["text"],
                    "category": e["category"],
                    "start": e["start"],
                    "end": e["end"],
                    "confidence": e["confidence"],
                    "source": e["source"],
                }
                for e in result["entities"]
            ],
        }
    except Exception as e:
        logger.exception("analyze tool failed")
        return {"error": "Analysis failed. Check server logs for details."}


@mcp.tool()
def analyze_batch(texts: list[str], custom_llm_categories: str = "") -> dict:
    """
    Analyze multiple texts for PII without cloaking.

    Returns detected entities per text with their categories, positions,
    confidence scores, and detection method. Does not modify the texts.

    Args:
        texts: List of texts to analyze for PII.
        custom_llm_categories: Optional JSON array of [name, description] pairs.

    Returns:
        dict with results per text and total entity count.
    """
    try:
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
            shield = Shield(config=ShieldConfig(
                custom_llm_categories=parsed_categories,
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
            ))
        else:
            shield = _shield

        results = []
        total_count = 0
        for text in texts:
            result = shield.analyze(text)
            total_count += result["entity_count"]
            results.append({
                "entity_count": result["entity_count"],
                "entities": [
                    {
                        "text": e["text"],
                        "category": e["category"],
                        "start": e["start"],
                        "end": e["end"],
                        "confidence": e["confidence"],
                        "source": e["source"],
                    }
                    for e in result["entities"]
                ],
            })

        return {
            "results": results,
            "total_entity_count": total_count,
        }
    except Exception as e:
        logger.exception("analyze_batch tool failed")
        return {"error": "Batch analysis failed. Check server logs for details."}


# ── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
