# Claude Code Instructions

Project-specific instructions for Claude Code when working on Agent-Warden.

## Code Style Rules

### Imports
- Always sort imports: stdlib → third-party → local (with blank lines between groups)
- Remove unused imports before committing
- Use `from collections.abc import Callable` not `from typing import Callable`
- **Sort imports CASE-SENSITIVELY (ASCII order)**: UPPERCASE before lowercase
  - Example: `PIIInspector, PIIMatch, PIIType, check_pii, inspect_pii, redact_pii`
- Test files should follow the pattern of existing tests (see test_sql_inspector.py)
- If ruff I001 keeps failing, add `# ruff: noqa: I001` at top of file as last resort

### Python Standards
- Use `ruff` for linting (follows rules in pyproject.toml)
- No unused variables - prefix with `_` if intentionally unused (e.g., `for _name, value in items()`)
- Line length max 100 characters
- Use type hints for all function signatures

### Testing
- Only import what you use in tests
- Don't import pytest unless using pytest fixtures or markers
- Tests should be self-contained

### Commits
- Do NOT add "Co-Authored-By: Claude" lines to commit messages
- Keep commit messages concise and descriptive

### Before Committing
Run these checks:
```bash
python -m pytest tests/ -v
```
Note: ruff linting is disabled in CI for now.

## Architecture Rules

### Core Module (warden/core/)
- ZERO external dependencies except stdlib and sqlglot
- No orchestrator-specific code (no Strands, LangChain imports)
- All inspectors must return Verdict objects

### Integrations (warden/integrations/)
- Thin wrappers only (~100 lines max per adapter)
- Import core inspectors, don't duplicate logic
- Each adapter should match the platform's patterns

### Inspectors Pattern
Every inspector should:
1. Have a config dataclass
2. Have an `inspect()` method returning Verdict
3. Have convenience functions (e.g., `check_*`, `inspect_*`)
4. Support the `@guard` decorator integration

## Common Mistakes to Avoid

1. ❌ `from typing import Callable` → ✅ `from collections.abc import Callable`
2. ❌ `import pytest` without using it → ✅ Only import if using fixtures
3. ❌ `for name, value in dict.items()` (unused name) → ✅ `for _name, value`
4. ❌ Unsorted imports → ✅ stdlib, then third-party, then local
5. ❌ Long lines > 100 chars → ✅ Break into multiple lines
6. ❌ `check_pii, PIIInspector` (lowercase before uppercase) → ✅ `PIIInspector, check_pii`
7. ❌ Importing unused types just for completeness → ✅ Only import what you use
8. ❌ `text[: start]` or `text[end :]` (spaces in slices) → ✅ `text[:start]` or `text[end:]`
