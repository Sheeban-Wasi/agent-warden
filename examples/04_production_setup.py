"""
Example 4: Production Setup

This example shows a complete production-ready configuration
with all security best practices enabled.
"""

import os
from pathlib import Path

from warden import (
    guard,
    SQLInspector,
    AuditLogger,
    LogDestination,
    AuditLevel,
    PolicyViolation,
    CriticalViolation,
)

# =============================================================================
# CONFIGURATION FROM ENVIRONMENT
# =============================================================================

# Load config from environment (or use defaults)
LOG_DIR = os.getenv("WARDEN_LOG_DIR", "/var/log/warden")
AUDIT_LEVEL = os.getenv("WARDEN_AUDIT_LEVEL", "all")  # "all", "block", "none"
SQL_DIALECT = os.getenv("WARDEN_SQL_DIALECT", "postgres")
BLOCKED_TABLES = os.getenv("WARDEN_BLOCKED_TABLES", "credentials,api_keys,secrets")

# Parse blocked tables from comma-separated string
blocked_tables_set = set(t.strip() for t in BLOCKED_TABLES.split(",") if t.strip())

# =============================================================================
# CENTRALIZED AUDIT LOGGER
# =============================================================================

# Create log directory if it doesn't exist
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

# Production audit logger with:
# - File output (JSON Lines format for easy parsing)
# - Async logging (non-blocking)
# - All events logged (for compliance)
audit_logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file=f"{LOG_DIR}/audit.jsonl",
    min_level=AuditLevel.ALL if AUDIT_LEVEL == "all" else AuditLevel.BLOCK,
    async_logging=True,  # Non-blocking writes
)

# =============================================================================
# REUSABLE INSPECTOR
# =============================================================================

# Create a shared inspector for manual checks
inspector = SQLInspector(
    mode="read-only",
    dialect=SQL_DIALECT,
    blocked_tables=blocked_tables_set,
)

# =============================================================================
# PROTECTED DATABASE FUNCTIONS
# =============================================================================

@guard(
    mode="read-only",
    dialect=SQL_DIALECT,
    blocked_tables=blocked_tables_set,
    on_block="return_error",
    audit=True,
    audit_logger=audit_logger,
    audit_context={"service": "my-api", "version": "1.0"},
    error_message="Query blocked by security policy: {reason}",
)
def read_query(query: str) -> dict:
    """Execute a read-only SQL query.

    This function is protected by Agent-Warden:
    - Only SELECT statements allowed
    - Blocked tables cannot be accessed
    - All queries are audited
    - On block, returns error dict (safe for agents)
    """
    # In production, this would execute the query
    return {"success": True, "data": f"Results for: {query}"}


@guard(
    mode="safe-write",
    allowed_tables={"audit_logs", "user_preferences", "events"},
    dialect=SQL_DIALECT,
    blocked_tables=blocked_tables_set,
    on_block="raise",
    audit=True,
    audit_logger=audit_logger,
    audit_context={"service": "my-api", "version": "1.0"},
)
def write_query(query: str) -> dict:
    """Execute a write query to allowed tables only.

    This function allows INSERT/UPDATE/DELETE but only to:
    - audit_logs
    - user_preferences
    - events

    All other tables are blocked. Critical operations (DROP, TRUNCATE)
    are always blocked regardless of table.
    """
    # In production, this would execute the query
    return {"success": True, "affected_rows": 1}


# =============================================================================
# ERROR HANDLING WRAPPER
# =============================================================================

def safe_execute(query: str, write: bool = False) -> dict:
    """
    High-level wrapper with proper error handling.

    Args:
        query: SQL query to execute
        write: If True, use write_query; otherwise use read_query

    Returns:
        Dict with success/error status and data/message
    """
    try:
        if write:
            return write_query(query)
        else:
            return read_query(query)

    except CriticalViolation as e:
        # Critical violations are severe (DROP, TRUNCATE, etc.)
        return {
            "success": False,
            "error": "critical_violation",
            "message": str(e),
            "severity": "critical",
        }

    except PolicyViolation as e:
        # Policy violations are less severe but still blocked
        return {
            "success": False,
            "error": "policy_violation",
            "message": str(e),
            "severity": "warning",
        }

    except Exception as e:
        # Unexpected errors
        return {
            "success": False,
            "error": "unexpected_error",
            "message": str(e),
            "severity": "error",
        }


# =============================================================================
# DEMO
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Production Setup Demo")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  Log directory: {LOG_DIR}")
    print(f"  Audit level: {AUDIT_LEVEL}")
    print(f"  SQL dialect: {SQL_DIALECT}")
    print(f"  Blocked tables: {blocked_tables_set}")

    # Test queries
    test_cases = [
        # (query, is_write, description)
        ("SELECT * FROM users WHERE id = 1", False, "Safe SELECT"),
        ("SELECT * FROM credentials", False, "SELECT from blocked table"),
        ("DROP TABLE users", False, "Critical DROP operation"),
        ("INSERT INTO events (type) VALUES ('login')", True, "Write to allowed table"),
        ("INSERT INTO users (name) VALUES ('test')", True, "Write to disallowed table"),
        ("DELETE FROM events WHERE id = 1", True, "Delete from allowed table"),
    ]

    print("\n" + "-" * 60)
    print("Test Results:")
    print("-" * 60)

    for query, is_write, description in test_cases:
        result = safe_execute(query, write=is_write)
        status = "PASS" if result.get("success") else "BLOCK"
        print(f"\n{description}:")
        print(f"  Query: {query[:50]}...")
        print(f"  Status: {status}")
        if not result.get("success"):
            print(f"  Reason: {result.get('message', 'Unknown')[:60]}")

    # Cleanup
    audit_logger.close()

    print("\n" + "=" * 60)
    print(f"Done! Check {LOG_DIR}/audit.jsonl for audit logs.")
    print("=" * 60)
