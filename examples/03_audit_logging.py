"""
Example 3: Audit Logging

This example shows how to set up audit logging for compliance
(SOC2, HIPAA, GDPR) with structured JSON output.
"""

import json
import tempfile
from pathlib import Path

from warden import (
    AuditLogger,
    AuditLevel,
    LogDestination,
    inspect_sql,
    create_audit_logger,
)

# =============================================================================
# BASIC AUDIT LOGGING
# =============================================================================

print("=" * 60)
print("1. Basic Audit Logging (stdout)")
print("=" * 60)

# Create logger that outputs to console
logger = AuditLogger(destinations=[LogDestination.STDOUT])

# Inspect some queries
verdict1 = inspect_sql("SELECT * FROM users")
verdict2 = inspect_sql("DROP TABLE users")

# Log the verdicts
print("\nLogging verdicts:")
logger.log(verdict1, context={"user": "alice", "action": "view_users"})
logger.log(verdict2, context={"user": "bob", "action": "attempted_drop"})

logger.close()

# =============================================================================
# FILE-BASED LOGGING
# =============================================================================

print("\n" + "=" * 60)
print("2. File-Based Logging (JSON Lines)")
print("=" * 60)

# Create a temporary file for this example
with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
    log_file = f.name

print(f"\nLog file: {log_file}")

# Create file logger
file_logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file=log_file,
)

# Log some events
queries = [
    ("SELECT * FROM orders", {"agent": "order-bot"}),
    ("UPDATE users SET name='test'", {"agent": "user-bot"}),
    ("DROP DATABASE production", {"agent": "rogue-bot"}),
]

for query, context in queries:
    verdict = inspect_sql(query)
    file_logger.log(verdict, context=context)

file_logger.close()

# Read and display the log file
print("\nLog file contents:")
with open(log_file) as f:
    for line in f:
        record = json.loads(line)
        print(f"  [{record['verdict']}] {record['context'].get('agent', 'unknown')}")

# =============================================================================
# BLOCK-ONLY LOGGING
# =============================================================================

print("\n" + "=" * 60)
print("3. Block-Only Logging (for production)")
print("=" * 60)

# Only log blocked requests (reduces log volume)
block_logger = AuditLogger(
    destinations=[LogDestination.STDOUT],
    min_level=AuditLevel.BLOCK,
)

print("\nLogging only blocked requests:")

# This won't be logged (it passes)
v = inspect_sql("SELECT 1")
result = block_logger.log(v)
print(f"  SELECT 1 -> logged: {result is not None}")

# This will be logged (it's blocked)
v = inspect_sql("DROP TABLE x")
result = block_logger.log(v)
print(f"  DROP TABLE -> logged: {result is not None}")

block_logger.close()

# =============================================================================
# AUDIT WITH @GUARD DECORATOR
# =============================================================================

print("\n" + "=" * 60)
print("4. Integrated with @guard decorator")
print("=" * 60)

from warden import guard

# Create a shared logger
with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
    guard_log_file = f.name

guard_logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file=guard_log_file,
)

@guard(
    mode="read-only",
    on_block="return_error",
    audit=True,
    audit_logger=guard_logger,
    audit_context={"service": "my-api", "version": "1.0"},
)
def execute_query(sql: str) -> dict:
    return {"data": "query results"}

# Use the protected function
print("\nExecuting queries through @guard:")
execute_query("SELECT * FROM users")
execute_query("DROP TABLE users")
execute_query("DELETE FROM orders")

guard_logger.close()

# Show what was logged
print("\nAudit log entries:")
with open(guard_log_file) as f:
    for line in f:
        record = json.loads(line)
        print(f"  [{record['verdict']}] tool={record['context'].get('tool')} service={record['context'].get('service')}")

# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

print("\n" + "=" * 60)
print("5. Using create_audit_logger helper")
print("=" * 60)

# Quick setup for common scenarios
dev_logger = create_audit_logger(console=True, level="all")
prod_logger = create_audit_logger(log_file="/tmp/warden.jsonl", console=False, level="block")

print("\nDev logger (console, all levels):")
v = inspect_sql("SELECT 1")
dev_logger.log(v)

dev_logger.close()
prod_logger.close()

print("\n" + "=" * 60)
print("Done! Check the log files for full JSON output.")
print("=" * 60)
