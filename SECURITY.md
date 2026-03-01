# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in CloakLLM, please report it responsibly through **GitHub Security Advisories**:

1. Go to the [Security Advisories page](https://github.com/cloakllm/cloakllm-mcp/security/advisories/new)
2. Click **"New draft security advisory"**
3. Fill in the details of the vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

## What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an assessment and timeline
- **Fix or mitigation** as soon as feasible, typically within 30 days

## Scope

The following are in scope for security reports:

- Token map leaks (PII persisting in memory after TTL expiry)
- MCP tool response containing unsanitized PII in error messages
- Audit log tampering or integrity bypass

## Out of Scope

- False positives in PII detection (report as a regular issue)
- Denial-of-service via large inputs (known limitation)
