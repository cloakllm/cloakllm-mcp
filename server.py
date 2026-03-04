"""
CloakLLM MCP Server.

Exposes CloakLLM's Python SDK as 3 MCP tools for Claude Desktop and other
MCP-compatible clients:

  - sanitize  — Detect & cloak PII, return sanitized text + token map ID
  - desanitize — Restore original values using a token map ID
  - analyze   — Detect PII without cloaking (pure analysis)

Run:
  python -m mcp run server.py
  # or: uvx mcp run server.py
"""

from __future__ import annotations

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

_shield = Shield(config=ShieldConfig(
    audit_enabled=os.getenv("CLOAKLLM_AUDIT_ENABLED", "true").lower() == "true",
    log_dir=os.getenv("CLOAKLLM_LOG_DIR", "./cloakllm_audit"),
    log_original_values=False,
))

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
        if effective_mode == "redact":
            shield = Shield(config=ShieldConfig(
                mode="redact",
                audit_enabled=_shield.config.audit_enabled,
                log_dir=_shield.config.log_dir,
                log_original_values=False,
            ))
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

        sanitized, token_map = shield.sanitize(
            text, model=model or None, token_map=existing_map
        )

        # In redact mode, don't store a token map (nothing to reverse)
        if effective_mode == "redact":
            categories = {}
            for det in token_map.detections:
                categories[det.category] = categories.get(det.category, 0) + 1
            return {
                "sanitized": sanitized,
                "entity_count": len(token_map.detections),
                "categories": categories,
                "mode": "redact",
            }

        if reuse_id:
            # Refresh timestamp to prevent TTL expiry during active conversations
            _TOKEN_MAPS[reuse_id]["token_map"] = token_map
            _TOKEN_MAPS[reuse_id]["created"] = time.time()
            map_id = reuse_id
        else:
            map_id = _store_token_map(token_map)

        categories = {}
        for token_str in token_map.reverse:
            cat = token_str.strip("[]").rsplit("_", 1)[0]
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "sanitized": sanitized,
            "token_map_id": map_id,
            "entity_count": token_map.entity_count,
            "categories": categories,
        }
    except Exception as e:
        logger.exception("sanitize tool failed")
        return {"error": "Sanitization failed. Check server logs for details."}


@mcp.tool()
def desanitize(
    text: str,
    token_map_id: str,
) -> dict:
    """
    Restore original values in text using a token map.

    Replaces tokens like [EMAIL_0] back to the original values.
    Requires a token_map_id from a previous sanitize call.

    Args:
        text: The text containing tokens to restore.
        token_map_id: The ID returned by a previous sanitize call.

    Returns:
        dict with the restored text.
    """
    try:
        entry = _TOKEN_MAPS.get(token_map_id)
        if entry is None:
            return {"error": f"Token map '{token_map_id}' not found or expired (TTL: {_MAP_TTL_SECONDS}s)."}

        token_map = entry["token_map"]
        restored = _shield.desanitize(text, token_map)
        return {"restored": restored}
    except Exception as e:
        logger.exception("desanitize tool failed")
        return {"error": "Desanitization failed. Check server logs for details."}


@mcp.tool()
def analyze(text: str) -> dict:
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
        result = _shield.analyze(text)
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


# ── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
