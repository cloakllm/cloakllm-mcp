# Contributing to CloakLLM MCP Server

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/cloakllm/CloakLLM-MCP.git
cd CloakLLM-MCP
pip install -e .
```

## Running Tests

```bash
python -m pytest
```

All tests should pass. Python 3.10+ is required.

## Running the Server

```bash
# Run with MCP inspector for interactive testing
python -m mcp dev server.py

# Or run directly
python server.py
```

## Project Structure

```
server.py          # MCP server — tool definitions and handlers
test_server.py     # Tests (pytest)
pyproject.toml     # Package metadata and dependencies
```

## Making Changes

1. Fork the repo and create a feature branch from `main`.
2. Make your changes in `server.py`.
3. Add or update tests in `test_server.py` for any new behavior.
4. Run `python -m pytest` and ensure all tests pass.
5. Update `README.md` if you changed tool signatures or behavior.
6. Open a pull request with a clear description of the change.

## Code Style

- Use type hints on all public functions.
- Follow PEP 8 conventions.
- Keep dependencies minimal (cloakllm + mcp only).
- Use `logging` instead of `print()` for debug output.
- Follow existing naming conventions (snake_case for functions, UPPER_SNAKE for constants).

## Reporting Issues

Open an issue at [github.com/cloakllm/CloakLLM-MCP/issues](https://github.com/cloakllm/CloakLLM-MCP/issues) with:

- A clear description of the problem or suggestion.
- Steps to reproduce (if reporting a bug).
- Your Python version (`python --version`) and OS.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
