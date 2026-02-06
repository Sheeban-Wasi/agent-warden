"""
Agent-Warden: Security middleware for AI agents.

The active defense layer for Transactional AI Agents.

Quick Start:
    from warden import check_sql, inspect_sql, AuditLogger

    # Simple check
    if check_sql("SELECT * FROM users"):
        execute_query(query)

    # Full inspection with audit trail
    verdict = inspect_sql("DROP TABLE users")
    if verdict.blocked:
        print(verdict.to_audit_log())

    # With audit logging
    logger = AuditLogger(log_file="audit.jsonl")
    verdict = inspect_sql(query)
    logger.log(verdict, context={"agent": "my-agent"})
"""

__version__ = "0.1.0"

from warden.core.audit import (
    AuditLevel,
    AuditLogger,
    AuditRecord,
    LogDestination,
    create_audit_logger,
)
from warden.core.inspectors.sql import (
    SQLInspector,
    SQLMode,
    check_sql,
    inspect_sql,
)
from warden.core.policy import (
    AgentPolicy,
    Policy,
    PolicyEngine,
    RateLimits,
    SQLPolicy,
)
from warden.core.verdict import (
    Verdict,
    VerdictType,
    create_block_verdict,
    create_pass_verdict,
)
from warden.exceptions import (
    ConfigurationError,
    CriticalViolation,
    ParseError,
    PolicyViolation,
    WardenError,
)
from warden.integrations.strands import (
    GuardConfig,
    PolicyGuard,
    ToolGuard,
    create_policy_guard,
    create_sql_guard,
    guard,
)

__all__ = [
    # Version
    "__version__",
    # Verdict
    "Verdict",
    "VerdictType",
    "create_pass_verdict",
    "create_block_verdict",
    # SQL Inspector
    "SQLInspector",
    "SQLMode",
    "check_sql",
    "inspect_sql",
    # Audit Logger
    "AuditLogger",
    "AuditLevel",
    "AuditRecord",
    "LogDestination",
    "create_audit_logger",
    # Exceptions
    "WardenError",
    "PolicyViolation",
    "CriticalViolation",
    "ConfigurationError",
    "ParseError",
    # Policy Engine
    "Policy",
    "PolicyEngine",
    "SQLPolicy",
    "AgentPolicy",
    "RateLimits",
    # Strands Integration
    "guard",
    "ToolGuard",
    "PolicyGuard",
    "GuardConfig",
    "create_sql_guard",
    "create_policy_guard",
]
