# CloakLLM MCP Server

MCP server that wraps CloakLLM's Python SDK as tools for Claude Desktop and other MCP-compatible clients.

## Tools

| Tool | Description |
|------|-------------|
| `sanitize` | Detect & cloak PII, return sanitized text + token map ID. Pass `mode: "redact"` for irreversible PII removal (no token_map_id returned). |
| `desanitize` | Restore original values using a token map ID |
| `analyze` | Detect PII without cloaking (pure analysis) |

## Install

```bash
cd cloakllm-mcp
pip install -e .
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloakllm": {
      "command": "python",
      "args": ["/path/to/cloakllm-mcp/server.py"],
      "env": {
        "CLOAKLLM_LOG_DIR": "./cloakllm_audit",
        "CLOAKLLM_LLM_DETECTION": "false"
      }
    }
  }
}
```

Or using `uvx`:

```json
{
  "mcpServers": {
    "cloakllm": {
      "command": "uvx",
      "args": ["mcp", "run", "/path/to/cloakllm-mcp/server.py"]
    }
  }
}
```

## Usage Examples

### Sanitize text before sending to an LLM

**Tool call:** `sanitize`
```json
{
  "text": "Email john@acme.com about the meeting with Sarah Johnson at 742 Evergreen Terrace",
  "model": "claude-sonnet-4-20250514",
  "token_map_id": "optional-id-for-multi-turn"
}
```

> **Multi-turn:** Pass the `token_map_id` from a previous `sanitize` response to reuse the same token map across conversation turns. The same PII will always map to the same token.

**Response:**
```json
{
  "sanitized": "Email [EMAIL_0] about the meeting with [PERSON_0] at 742 Evergreen Terrace",
  "token_map_id": "a1b2c3d4-...",
  "entity_count": 2,
  "categories": {"EMAIL": 1, "PERSON": 1}
}
```

### Restore original values

**Tool call:** `desanitize`
```json
{
  "text": "I've drafted an email to [EMAIL_0] regarding [PERSON_0]'s request.",
  "token_map_id": "a1b2c3d4-..."
}
```

**Response:**
```json
{
  "restored": "I've drafted an email to john@acme.com regarding Sarah Johnson's request."
}
```

### Analyze text for PII (no cloaking)

**Tool call:** `analyze`
```json
{
  "text": "Contact john@acme.com, SSN 123-45-6789"
}
```

**Response:**
```json
{
  "entity_count": 2,
  "entities": [
    {"text": "john@acme.com", "category": "EMAIL", "start": 8, "end": 21, "confidence": 0.95, "source": "regex"},
    {"text": "123-45-6789", "category": "SSN", "start": 27, "end": 38, "confidence": 0.95, "source": "regex"}
  ]
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOAKLLM_LOG_DIR` | `./cloakllm_audit` | Audit log directory |
| `CLOAKLLM_AUDIT_ENABLED` | `true` | Enable/disable audit logging |
| `CLOAKLLM_SPACY_MODEL` | `en_core_web_sm` | spaCy model for NER |
| `CLOAKLLM_LLM_DETECTION` | `false` | Enable LLM-based detection |
| `CLOAKLLM_LLM_MODEL` | `llama3.2` | Ollama model for LLM detection |
| `CLOAKLLM_OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint |

## Testing

```bash
# Test with MCP inspector
python -m mcp dev server.py

# Or run directly
python server.py
```

## See Also

- [CloakLLM Hub](https://github.com/cloakllm/CloakLLM) — project overview, architecture, and links
- [CloakLLM Python SDK](https://github.com/cloakllm/CloakLLM-PY) — Python library with spaCy NER + OpenAI / LiteLLM middleware
- [CloakLLM JS SDK](https://github.com/cloakllm/CloakLLM-JS) — JavaScript library with OpenAI + Vercel AI middleware

## License

MIT
