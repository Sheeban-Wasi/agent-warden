"""
Example 1: Basic Usage

This example shows the simplest way to use Agent-Warden
to protect your SQL queries.
"""

from warden import check_sql, inspect_sql

# =============================================================================
# QUICK CHECK - Returns True/False
# =============================================================================

queries = [
    "SELECT * FROM users WHERE id = 1",
    "SELECT name, email FROM customers",
    "DROP TABLE users",
    "DELETE FROM orders",
    "INSERT INTO logs (msg) VALUES ('test')",
]

print("Quick Check Results:")
print("-" * 50)

for query in queries:
    is_safe = check_sql(query)
    status = "SAFE" if is_safe else "BLOCKED"
    print(f"{status}: {query[:40]}...")

# =============================================================================
# FULL INSPECTION - Returns Verdict with details
# =============================================================================

print("\n\nFull Inspection:")
print("-" * 50)

# Inspect a dangerous query
verdict = inspect_sql("DROP TABLE users")

print(f"Query: DROP TABLE users")
print(f"Blocked: {verdict.blocked}")
print(f"Reason: {verdict.reason}")
print(f"Rule: {verdict.rule}")
print(f"Latency: {verdict.latency_ms:.2f}ms")

# =============================================================================
# DIFFERENT MODES
# =============================================================================

print("\n\nMode Comparison:")
print("-" * 50)

from warden import SQLInspector

# Read-only mode (default) - only SELECT allowed
readonly = SQLInspector(mode="read-only")
v = readonly.inspect("INSERT INTO logs (msg) VALUES ('test')")
print(f"Read-only mode + INSERT: {'BLOCKED' if v.blocked else 'ALLOWED'}")

# Safe-write mode - allows INSERT/UPDATE to specific tables
safe_write = SQLInspector(mode="safe-write", allowed_tables={"logs"})
v = safe_write.inspect("INSERT INTO logs (msg) VALUES ('test')")
print(f"Safe-write mode + INSERT to 'logs': {'BLOCKED' if v.blocked else 'ALLOWED'}")

# But DROP is always blocked
v = safe_write.inspect("DROP TABLE logs")
print(f"Safe-write mode + DROP: {'BLOCKED' if v.blocked else 'ALLOWED'}")

# =============================================================================
# OUTPUT
# =============================================================================
#
# Quick Check Results:
# --------------------------------------------------
# SAFE: SELECT * FROM users WHERE id = 1...
# SAFE: SELECT name, email FROM customers...
# BLOCKED: DROP TABLE users...
# BLOCKED: DELETE FROM orders...
# BLOCKED: INSERT INTO logs (msg) VALUES ('test...
#
# Full Inspection:
# --------------------------------------------------
# Query: DROP TABLE users
# Blocked: True
# Reason: Critical operation blocked: Drop
# Rule: critical_node_detected
# Latency: 0.45ms
#
# Mode Comparison:
# --------------------------------------------------
# Read-only mode + INSERT: BLOCKED
# Safe-write mode + INSERT to 'logs': ALLOWED
# Safe-write mode + DROP: BLOCKED
