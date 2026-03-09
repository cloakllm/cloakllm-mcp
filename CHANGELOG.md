# Changelog

All notable changes to CloakLLM MCP Server will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
