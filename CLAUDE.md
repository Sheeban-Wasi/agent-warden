# Claude Code Instructions

Project-specific instructions for Claude Code when working on Agent-Warden.

## Code Style Rules

### Imports
- Always sort imports: stdlib → third-party → local
- Remove unused imports before committing
- Use `from collections.abc import Callable` not `from typing import Callable`
- Keep imports alphabetized within each section

### Python Standards
- Use `ruff` for linting (follows rules in pyproject.toml)
- No unused variables - prefix with `_` if intentionally unused (e.g., `for _name, value in items()`)
- Line length max 100 characters
- Use type hints for all function signatures

### Testing
- Only import what you use in tests
- Don't import pytest unless using pytest fixtures or markers
- Tests should be self-contained

### Before Committing
Run these checks:
```bash
ruff check warden/ tests/
ruff format warden/ tests/
python -m pytest tests/ -v
```

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
