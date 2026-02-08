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
from warden.core.inspectors.api import (
    APIInspector,
    APIMatch,
    APIMode,
    APIRequest,
    APIResult,
    APIViolationType,
    check_api_call,
    inspect_api_call,
)
from warden.core.inspectors.file import (
    FileInspector,
    FileMatch,
    FileMode,
    FileResult,
    FileViolationType,
    check_file,
    inspect_file,
)
from warden.core.inspectors.pii import (
    PIIInspector,
    PIIMatch,
    PIIResult,
    PIIStrategy,
    PIIType,
    check_pii,
    inspect_pii,
    redact_pii,
)
from warden.core.inspectors.rag import (
    RAGContext,
    RAGDocument,
    RAGInspector,
    RAGMatch,
    RAGMode,
    RAGResult,
    RAGViolationType,
    check_rag_documents,
    filter_rag_documents,
    inspect_rag_documents,
)
from warden.core.inspectors.shell import (
    ShellInspector,
    ShellMatch,
    ShellMode,
    ShellResult,
    ShellViolationType,
    check_shell,
    inspect_shell,
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
from warden.core.hitl import (
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
    HITLGuard,
    RiskLevel,
    approval_required,
    create_auto_approve_callback,
    create_auto_deny_callback,
    create_cli_approval_callback,
)
from warden.core.rate_limiter import (
    RateLimiter,
    RateLimitMode,
    RateLimitResult,
    check_rate_limit,
    clear_all_rate_limiters,
    get_rate_limiter,
    reset_rate_limits,
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
    # API Inspector
    "APIInspector",
    "APIMode",
    "APIViolationType",
    "APIRequest",
    "APIMatch",
    "APIResult",
    "check_api_call",
    "inspect_api_call",
    # SQL Inspector
    "SQLInspector",
    "SQLMode",
    "check_sql",
    "inspect_sql",
    # PII Inspector
    "PIIInspector",
    "PIIType",
    "PIIStrategy",
    "PIIMatch",
    "PIIResult",
    "check_pii",
    "inspect_pii",
    "redact_pii",
    # File Inspector
    "FileInspector",
    "FileMode",
    "FileViolationType",
    "FileMatch",
    "FileResult",
    "check_file",
    "inspect_file",
    # Shell Inspector
    "ShellInspector",
    "ShellMode",
    "ShellViolationType",
    "ShellMatch",
    "ShellResult",
    "check_shell",
    "inspect_shell",
    # RAG Inspector
    "RAGInspector",
    "RAGMode",
    "RAGViolationType",
    "RAGDocument",
    "RAGContext",
    "RAGMatch",
    "RAGResult",
    "check_rag_documents",
    "inspect_rag_documents",
    "filter_rag_documents",
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
    # Rate Limiter
    "RateLimiter",
    "RateLimitMode",
    "RateLimitResult",
    "check_rate_limit",
    "get_rate_limiter",
    "reset_rate_limits",
    "clear_all_rate_limiters",
    # HITL
    "HITLGuard",
    "ApprovalRequest",
    "ApprovalResult",
    "ApprovalStatus",
    "RiskLevel",
    "approval_required",
    "create_cli_approval_callback",
    "create_auto_deny_callback",
    "create_auto_approve_callback",
]
