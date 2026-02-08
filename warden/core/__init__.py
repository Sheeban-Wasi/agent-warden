"""
Warden Core - Framework-agnostic security logic.

The Hub in the Hub-and-Spoke architecture.
This module contains all security logic and knows nothing about
specific frameworks like LangChain or AWS Strands.
"""

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
from warden.core.inspectors.sql import SQLInspector, SQLMode, check_sql, inspect_sql
from warden.core.rate_limiter import (
    RateLimiter,
    RateLimitMode,
    RateLimitResult,
    check_rate_limit,
    clear_all_rate_limiters,
    get_rate_limiter,
    reset_rate_limits,
)
from warden.core.verdict import Verdict, VerdictType, create_block_verdict, create_pass_verdict

__all__ = [
    "Verdict",
    "VerdictType",
    "create_pass_verdict",
    "create_block_verdict",
    "SQLInspector",
    "SQLMode",
    "check_sql",
    "inspect_sql",
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
