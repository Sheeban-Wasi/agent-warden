# Agent-Warden Examples

This directory contains working examples demonstrating Agent-Warden features.

## Prerequisites

```bash
pip install agent-warden
```

## Examples

### 1. Basic Usage (`01_basic_usage.py`)

The simplest way to use Agent-Warden. Shows:
- `check_sql()` - Quick True/False check
- `inspect_sql()` - Full inspection with details
- `SQLInspector` - Different modes (read-only, safe-write)

```bash
python examples/01_basic_usage.py
```

### 2. AWS Strands Integration (`02_strands_integration.py`)

How to protect your Strands agent tools with the `@guard` decorator. Shows:
- Basic `@guard` protection
- Safe-write mode with allowed tables
- Return error instead of raising exceptions

```bash
python examples/02_strands_integration.py
```

### 3. Audit Logging (`03_audit_logging.py`)

Set up audit logging for compliance (SOC2, HIPAA, GDPR). Shows:
- Console logging
- File-based JSON Lines logging
- Block-only logging
- Integration with `@guard` decorator

```bash
python examples/03_audit_logging.py
```

### 4. Production Setup (`04_production_setup.py`)

Complete production-ready configuration. Shows:
- Environment-based configuration
- Centralized audit logger
- Blocked tables for sensitive data
- Proper error handling patterns
- Both read-only and safe-write guards

```bash
# With defaults
python examples/04_production_setup.py

# With custom config
WARDEN_LOG_DIR=/tmp/logs \
WARDEN_AUDIT_LEVEL=block \
WARDEN_SQL_DIALECT=mysql \
python examples/04_production_setup.py
```

## Quick Reference

### Check a Query

```python
from warden import check_sql, inspect_sql

# Quick check
if check_sql("SELECT * FROM users"):
    execute_query(query)

# Full inspection
verdict = inspect_sql("DROP TABLE users")
print(verdict.blocked)  # True
print(verdict.reason)   # "Critical operation blocked: Drop"
```

### Protect a Function

```python
from warden import guard

@guard(mode="read-only", on_block="return_error")
def query(sql: str) -> dict:
    return db.execute(sql)
```

### Audit Logging

```python
from warden import AuditLogger, LogDestination

logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file="audit.jsonl",
)
```

## More Information

See the main [README.md](../readme.md) for complete documentation.
