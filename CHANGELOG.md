# Changelog

All notable changes to CloakLLM MCP Server will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioned per [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.4] - 2026-04-20

Polish release — v0.6.4 round-up of items the v0.6.3 review pass parked.
Floor bumped to `cloakllm>=0.6.4` so MCP installs receive the new
typed-exception, derived allow-list, and timing-safe hash compare.

### Hardening

- **G13 — Server log hygiene.** All seven MCP tool exception handlers
  now log only `type(e).__name__` by default. Set `CLOAKLLM_DEBUG=1`
  to opt back in to full message logging (`str(e)`). Defends server
  logs against accidental PII leakage via cloakllm-py exception text.
  New `_log_tool_error()` helper standardizes the call shape.

### Correctness

- **BUG-4 — MCP tool error returns standardized to dict.** Eleven
  validation-error sites previously returned `json.dumps(err)` (a string)
  while exception handlers returned dicts. Callers type-checking
  `isinstance(result, dict)` would silently miss validation errors.
  All paths now return `{"error": "..."}` dicts uniformly.

### Performance

- **MCP `_TOKEN_MAPS` O(1) eviction.** Switched backing dict to
  `collections.OrderedDict` and replaced the
  `min(_TOKEN_MAPS, key=lambda k: ...)` capacity-eviction (O(n) over
  up to 10,000 entries inside the lock) with `popitem(last=False)`
  (O(1)). Negligible for small deployments, meaningful for any MCP
  server pushed near `MAX_TOKEN_MAPS`.

### Dependency

- `cloakllm` floor bumped to `>=0.6.4,<0.7.0`.

## [0.6.3] - 2026-04-19

MCP-side share of the cloakllm-py / cloakllm-js v0.6.3 security release.
Floor bumped to `cloakllm>=0.6.3` so MCP installations inherit the full
hardening surface.

### Security — high severity

- **H8 — MCP metadata PII scan.** New `_scan_metadata_for_pii` recursively
  rejects metadata string values matching unambiguous PII patterns
  (EMAIL, SSN, CREDIT_CARD, IBAN, JWT) before they reach the audit log.
  Wired into `sanitize`, `sanitize_batch`, `desanitize`, `desanitize_batch`.
- **G5 — `custom_llm_categories` prompt-injection scan.** New
  `_validate_category_description` rejects descriptions matching prompt-
  injection patterns ("ignore all previous instructions", ChatML markers,
  Anthropic chat markers, oversized strings, embedded newlines) before
  they flow into the Ollama detector system prompt.
- **SEC-2 — Same scan applied to `analyze` and `analyze_batch`.** The G5
  wiring was missed for the analyze tools in the initial pass; closed
  the parity gap.
- **SEC-4 — `model` and `provider` PII scan.** New `_validate_short_string`
  rejects PII patterns + NUL bytes + oversized strings (>128 chars) in
  these MCP tool params before they reach the audit logger. Closes a
  silent no-PII-in-logs invariant violation: a client passing
  `model="alice@example.com"` previously landed the email in the audit
  log via the `model` field.

### Test coverage

- **NEW-2** — Re-enabled audit logging in MCP tests (was disabled,
  same I2-class regression as v0.6.2). The B3 schema validator now
  fires on every audit write during tests, not just the config-presence
  check.
- New tests for SEC-2 / SEC-4 / G5 / H8 (incl. end-to-end verification
  via the MCP tool surface), plus regression coverage for B3 validator
  on MCP-written entries.

### Plumbing

- **NEW-9** — `pip-audit` is CI-blocking. Tracked exceptions in
  `CloakLLM/SECURITY_WAIVERS.md`.
- **I6** — OIDC trusted publishing for PyPI; long-lived `PYPI_API_TOKEN`
  removed.
- **NEW-1** — `setuptools.build_meta` build-backend (was the invalid
  `setuptools.backends.legacy:build` from a prior typo).

### Dependency

- `cloakllm` floor bumped to `>=0.6.3,<0.7.0` so MCP installs receive
  the full v0.6.3 hardening surface (SSRF redirect close, sanitized_hash
  oracle close, audit chain typed exceptions, audit file 0o600 perms,
  etc.). Pinning to 0.6.2 explicitly is rejected by the resolver.

## [0.6.2] - 2026-04-17

### Fixed

- **I1 (critical) — `CLOAKLLM_COMPLIANCE_MODE` opt-out crashed the server.** v0.6.1 documented `=off` / `=""` / `=none` / `=false` as the way to disable compliance mode, but the implementation accidentally let `ShieldConfig`'s `default_factory` read the same env var directly, causing `__post_init__` to reject the value and the server to crash on import. The kwargs builder now always passes `compliance_mode` explicitly so the env value never reaches the default_factory unfiltered.
- 5 new tests cover the four documented opt-out values and the default-on path.

### Changed

- Bumped `cloakllm>=0.6.2,<0.7.0` to ensure I1 fix is present.

## [0.6.1] - 2026-04-16

### Changed

- **B4 (security):** MCP server now defaults `compliance_mode="eu_ai_act_article12"`. The Article 12 invariant guard now fires on every audit write through the MCP path. Operators who require the old behavior can set `CLOAKLLM_COMPLIANCE_MODE=` (empty) or `=off`.
- **H6:** Dependency floor raised to `cloakllm>=0.6.1,<0.7.0` and `mcp[cli]>=1.0.0,<2.0.0` (capped). Pulls in all v0.6.1 security fixes.
- **F4:** internal `shield.analyze()` calls updated to pass `redact_values=` explicitly so the v0.6.1 deprecation warning does not fire from MCP code paths.

### Notes

- The B3 always-on audit schema validator from `cloakllm` 0.6.1 applies to all MCP audit writes too. If you were relying on passing arbitrary `metadata` keys through MCP tool calls, those calls now fail fast with a clear error.

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
