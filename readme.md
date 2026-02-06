# Agent-Warden

**The security moat for AI agents.** Deterministic, AST-based protection that blocks SQL injection, destructive operations, and policy violations before they reach your database.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-180%20passing-brightgreen.svg)]()
[![AWS Strands Compatible](https://img.shields.io/badge/AWS%20Strands-Native-orange)](https://aws.amazon.com/)

---

## Why Agent-Warden?

AI agents generate SQL, but **prompt injection can turn your agent into an attacker**. Regex-based filters are easily bypassed. Agent-Warden uses **AST parsing** to understand SQL structure, not text patterns.

```python
# Regex sees: "DR" + "OP" (two harmless strings)
# Agent-Warden sees: DROP TABLE (blocked!)
"DROP/**/TABLE/**/users"  # Blocked
"DROP\tTABLE\tusers"      # Blocked
"dRoP tAbLe UsErS"        # Blocked
```

**Built for:** Fintech, Healthcare, and Enterprise SOC2 environments.

---

## Quick Start

### Installation

```bash
pip install agent-warden
```

### 30-Second Example

```python
from warden import guard

# Protect any function with a single decorator
@guard
def execute_query(query: str) -> list:
    return db.execute(query)

# Safe queries work normally
execute_query("SELECT * FROM users")  # Works!

# Dangerous queries are blocked before execution
execute_query("DROP TABLE users")     # Raises CriticalViolation
```

---

## Core Features

### 1. SQL Inspector (The Moat)

```python
from warden import check_sql, inspect_sql

# Quick check - returns True/False
if check_sql("SELECT * FROM users WHERE id = 1"):
    execute_query(query)

# Full inspection with details
verdict = inspect_sql("DROP TABLE users")
print(verdict.blocked)     # True
print(verdict.reason)      # "Critical operation blocked: Drop"
print(verdict.rule)        # "critical_node_detected"
print(verdict.latency_ms)  # 0.45
```

#### Inspection Modes

```python
from warden import SQLInspector

# Read-only (default) - only SELECT allowed
inspector = SQLInspector(mode="read-only")

# Safe-write - allow writes to specific tables
inspector = SQLInspector(
    mode="safe-write",
    allowed_tables={"logs", "events"}
)

# Block sensitive tables
inspector = SQLInspector(
    blocked_tables={"credentials", "api_keys"}
)
```

---

### 2. @guard Decorator

```python
from warden import guard

# Basic protection
@guard
def query(sql: str) -> list:
    return db.execute(sql)

# With configuration
@guard(
    mode="safe-write",
    allowed_tables={"logs"},
    on_block="return_error",  # or "raise", "return_none"
    dialect="postgres",
)
def write_log(sql: str) -> dict:
    return db.execute(sql)
```

#### With AWS Strands SDK

```python
from strands import Agent, tool
from warden import guard

@tool
@guard(mode="read-only")
def database_query(query: str) -> str:
    """Execute a read-only SQL query."""
    return json.dumps(db.execute(query))

agent = Agent(tools=[database_query])
```

#### Block Actions

```python
# Raise exception (default)
@guard(on_block="raise")
def query(sql: str): ...

# Return error dict (good for agents)
@guard(on_block="return_error")
def query(sql: str): ...
# Returns: {"error": True, "blocked": True, "reason": "..."}

# Return None silently
@guard(on_block="return_none")
def query(sql: str): ...
```

#### Async Support

```python
@guard
async def async_query(sql: str) -> list:
    return await db.execute_async(sql)
```

---

### 3. Audit Logger

Structured JSON logging for compliance (SOC2, HIPAA, GDPR):

```python
from warden import AuditLogger, LogDestination, inspect_sql

logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file="audit.jsonl",
)

verdict = inspect_sql("DROP TABLE users")
logger.log(verdict, context={
    "user_id": "user-123",
    "agent": "sql-agent",
})
```

Output:
```json
{
  "event_id": "a1b2c3d4-...",
  "timestamp": "2024-01-15T10:30:00Z",
  "verdict": "BLOCK",
  "inspector": "sql_inspector",
  "reason": "Critical operation blocked: Drop",
  "rule": "critical_node_detected",
  "latency_ms": 0.45,
  "context": {"user_id": "user-123", "agent": "sql-agent"}
}
```

---

## What Gets Blocked?

| Category | Operations |
|----------|-----------|
| **Always Blocked** | `DROP`, `TRUNCATE`, `ALTER`, `CREATE`, `GRANT`, `REVOKE`, `EXEC` |
| **Read-Only Mode** | `INSERT`, `UPDATE`, `DELETE`, `MERGE` |
| **Bypass Attempts** | Comment obfuscation, case tricks, stacked queries, UNION injection |

---

## Production Example

```python
from warden import guard, AuditLogger, LogDestination

# Centralized audit logger
audit_logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file="/var/log/warden/audit.jsonl",
    async_logging=True,
)

@guard(
    mode="read-only",
    dialect="postgres",
    blocked_tables={"credentials", "api_keys"},
    on_block="return_error",
    audit=True,
    audit_logger=audit_logger,
)
def database_query(sql: str) -> dict:
    return {"data": db.execute(sql)}
```

---

## Error Handling

```python
from warden import guard, PolicyViolation, CriticalViolation

@guard
def query(sql: str):
    return db.execute(sql)

try:
    query("DROP TABLE users")
except CriticalViolation as e:
    print(f"Critical: {e.message}")
    print(f"Verdict: {e.verdict}")
except PolicyViolation as e:
    print(f"Policy: {e.message}")
```

---

## Performance

| Operation | Time |
|-----------|------|
| Simple SELECT check | ~0.3ms |
| Complex query check | ~0.5ms |
| Audit log write | ~0.1ms |

---

## Contributing

```bash
git clone https://github.com/anthropics/agent-warden.git
cd agent-warden
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT License
