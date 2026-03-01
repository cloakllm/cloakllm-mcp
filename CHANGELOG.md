# Changelog

All notable changes to CloakLLM MCP Server will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.1]: https://github.com/cloakllm/cloakllm-mcp/releases/tag/v0.1.1
