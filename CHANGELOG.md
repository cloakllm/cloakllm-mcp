# Changelog

All notable changes to CloakLLM MCP Server will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-04-16

### Changed

- Version bump to sync with cloakllm v0.6.0 (Article 12 Compliance Mode + Enterprise Key Management)
- Dependency updated to `cloakllm>=0.6.0`

### Notes

- All compliance-mode features are accessible from MCP via the underlying `cloakllm` SDK call paths (no new MCP tools required for v0.6).

## [0.5.2] - 2026-04-06

### Changed

- Version bump to sync with cloakllm v0.5.2 (Pluggable Detection Backends)
- Dependency updated to `cloakllm>=0.5.2`

## [0.5.1] - 2026-03-31

### Changed

- Version bump to sync with cloakllm v0.5.1 (Normalized Token Standard)
- Dependency updated to `cloakllm>=0.5.1`

## [0.5.0] - 2026-03-30

### Added

- **`analyze_context_risk` tool** — analyze sanitized text for context-based PII leakage risk
  - Returns token density, identifying descriptors, relationship edges, risk score/level, and warnings
  - Server now exposes 7 MCP tools (was 6)

## [0.4.0] - 2026-03-23

### Added

- Input validation: `MAX_TEXT_LENGTH` (1MB), `MAX_BATCH_SIZE` (100), `MAX_METADATA_LENGTH` (10KB)
- Token map capacity limits with LRU eviction (`MAX_TOKEN_MAPS=1000`)
- Shield instance caching to avoid per-request construction
- `include_text` opt-in parameter for `analyze` and `analyze_batch` tools
- `CLOAKLLM_ENTITY_HASH_KEY` env var fallback for entity hash key

### Security

- **PII leakage fix** — `analyze()` and `analyze_batch()` no longer return raw PII text by default
- **Thread-safe token maps** — all `_TOKEN_MAPS` access wrapped with `threading.Lock`
- **Error message hardening** — token map IDs no longer echoed in error responses
- **Logger security** — replaced `logger.exception()` with `logger.error()` to avoid stack trace PII leakage
- **Metadata validation** — type checking and size limits for metadata parameter
- Removed `log_original_values` from ShieldConfig construction

## [0.3.2] - 2026-03-15

### Added

- Cryptographic attestation support: `sanitize` and `sanitize_batch` responses include signed certificates when `CLOAKLLM_SIGNING_KEY_PATH` env var is set

## [0.3.1] - 2026-03-15

### Changed

- Version bump to keep all packages in sync (benchmark suite added to Python and JS SDKs)

## [0.3.0] - 2026-03-15

### Changed

- Version bump to keep all packages in sync (no code changes; streaming changes are in the SDK)

## [0.2.5] - 2026-03-15

### Added

- `desanitize_batch` tool — restore original values in multiple texts using a shared token map
- `analyze_batch` tool — analyze multiple texts for PII without cloaking
- `metadata` parameter on `desanitize` tool (for audit logging, matching sanitize behavior)

## [0.2.4] - 2026-03-15

### Changed

- Bumped `cloakllm` dependency to `>=0.2.4` (includes desanitize metrics thread-safety fix)

## [0.2.3] - 2026-03-13

### Changed

- Bumped `cloakllm` dependency to `>=0.2.3` (includes LiteLLM multi-choice security fix)

## [0.2.2] - 2026-03-10

### Fixed

- `provider` and `metadata` parameters silently dropped in `sanitize` tool — now forwarded to Shield
- `metadata` string parameter now parsed as JSON dict before passing to Shield
- `sanitize_batch` missing `mode`, `entity_hashing`, `entity_hash_key` parameters — now supports all modes
- Inconsistent category counting between redact and tokenize modes — now uses `token_map.categories` consistently
- `sanitize_batch` missing `entity_details` in response — now included
- Module docstring listing 3 tools instead of 4 — updated to include `sanitize_batch`

## [0.2.1] - 2026-03-10

### Added

- `entity_hashing` and `entity_hash_key` parameters on `sanitize` tool
- Entity hashes included in returned `entity_details` when enabled
- 2 new tests (total: 24 tests)

## [0.2.0] - 2026-03-09

### Added

- `custom_llm_categories` parameter on `sanitize`, `sanitize_batch`, and `analyze` tools — JSON array of `[name, description]` pairs for domain-specific PII types
- 3 new tests for custom LLM categories (total: 22 tests)

## [0.1.9] - 2026-03-08

### Changed

- Version bump to stay in sync with cloakllm 0.1.9 (performance & observability)

## [0.1.8] - 2026-03-07

### Added

- `sanitize_batch` tool — sanitize multiple texts with a shared token map in one call
- 4 new tests for batch sanitization (total: 19 tests)

## [0.1.7] - 2026-03-06

### Added

- `entity_details` array in sanitize tool response (both tokenize and redact modes)
- 2 new tests for entity_details in sanitize response

## [0.1.6] - 2026-03-04

### Added

- `mode` parameter on `sanitize` tool: set to `"redact"` for irreversible PII removal (no token_map_id returned)

## [0.1.5] - 2026-03-04

### Changed

- Version bump to stay in sync with cloakllm 0.1.5 (Python OpenAI SDK middleware)

## [0.1.4] - 2026-03-04

### Added

- Multi-turn conversation support: `sanitize` tool now accepts optional `token_map_id` to reuse a token map across turns, ensuring consistent tokenization within a conversation

## [0.1.3] - 2026-03-02

### Changed

- Version bump to stay in sync with cloakllm 0.1.3 (custom pattern priority fix)

## [0.1.2] - 2026-03-01

### Fixed

- Added `py-modules` to setuptools config for correct module discovery

## [0.1.1] - 2026-03-01

### Added

- MCP server exposing 3 tools: `sanitize`, `desanitize`, `analyze`
- In-memory token map store with 1-hour TTL and auto-cleanup
- Environment-based configuration (`CLOAKLLM_AUDIT_ENABLED`, `CLOAKLLM_LOG_DIR`)
- LICENSE, .gitignore, SECURITY.md
- Basic test suite

### Fixed

- Sanitized error messages (no PII leaks in MCP tool responses)
- Removed broken `[project.scripts]` entry point

[0.2.2]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.2.2
[0.2.1]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.2.1
[0.2.0]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.2.0
[0.1.9]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.9
[0.1.8]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.8
[0.1.7]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.7
[0.1.6]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.6
[0.1.5]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.5
[0.1.4]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.4
[0.1.3]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.3
[0.1.2]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.2
[0.1.1]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.1
