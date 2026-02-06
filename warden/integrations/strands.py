"""
AWS Strands SDK Integration.

Provides the @guard decorator for protecting AI agent tools with Warden inspections.

The @guard decorator intercepts tool inputs, runs security inspections, and blocks
dangerous operations before they reach your database or API.

Example:
    from warden.integrations.strands import guard

    # Simple usage - protect a SQL tool
    @guard(sql=True)
    def execute_query(query: str) -> list[dict]:
        return db.execute(query)

    # With custom configuration
    @guard(
        sql=True,
        mode="read-only",
        on_block="raise",  # or "return_error"
        audit=True,
    )
    def run_sql(query: str) -> list[dict]:
        return db.execute(query)

    # The agent can now safely use this tool:
    result = execute_query("SELECT * FROM users")  # Works
    result = execute_query("DROP TABLE users")     # Blocked!

For AWS Strands SDK:
    from strands import Agent, tool
    from warden.integrations.strands import guard

    @tool
    @guard(sql=True)
    def database_query(query: str) -> str:
        '''Execute a SQL query and return results.'''
        return json.dumps(db.execute(query))

    agent = Agent(tools=[database_query])
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, ParamSpec, TypeVar, overload

from warden.core.audit import AuditLevel, AuditLogger, LogDestination
from warden.core.inspectors.sql import SQLInspector
from warden.core.policy import Policy, PolicyEngine
from warden.core.verdict import Verdict
from warden.exceptions import CriticalViolation, PolicyViolation

P = ParamSpec("P")
R = TypeVar("R")


class BlockAction(Enum):
    """Action to take when a guard blocks an operation."""

    RAISE = "raise"  # Raise PolicyViolation exception
    RETURN_ERROR = "return_error"  # Return error dict to agent
    RETURN_NONE = "return_none"  # Return None


@dataclass
class GuardConfig:
    """
    Configuration for the @guard decorator.

    Attributes:
        sql: Enable SQL injection protection
        sql_mode: SQL inspection mode (read-only, safe-write, strict, monitor)
        sql_dialect: SQL dialect for parsing (mysql, postgres, etc.)
        sql_allowed_tables: Tables allowed for writes in safe-write mode
        sql_blocked_tables: Tables that are never allowed

        on_block: Action when blocked (raise, return_error, return_none)
        error_message: Custom error message template

        audit: Enable audit logging
        audit_logger: Custom audit logger instance
        audit_level: Minimum level to log (all, block, none)
        audit_context: Static context to include in all logs

        param_name: Name of parameter to inspect (default: first string param)
    """

    # SQL inspection settings
    sql: bool = True
    sql_mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only"
    sql_dialect: str | None = None
    sql_allowed_tables: set[str] | None = None
    sql_blocked_tables: set[str] | None = None

    # Block handling
    on_block: Literal["raise", "return_error", "return_none"] = "raise"
    error_message: str = "Operation blocked by security policy: {reason}"

    # Audit logging
    audit: bool = True
    audit_logger: AuditLogger | None = None
    audit_level: Literal["all", "block", "none"] = "all"
    audit_context: dict[str, Any] = field(default_factory=dict)

    # Parameter selection
    param_name: str | None = None  # If None, uses first string parameter


class ToolGuard:
    """
    Reusable guard instance for protecting multiple tools with the same config.

    Example:
        # Create a shared guard
        sql_guard = ToolGuard(
            sql=True,
            mode="read-only",
            audit_logger=my_logger,
        )

        # Apply to multiple tools
        @sql_guard
        def query_users(sql: str): ...

        @sql_guard
        def query_orders(sql: str): ...
    """

    def __init__(
        self,
        sql: bool = True,
        mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
        dialect: str | None = None,
        allowed_tables: set[str] | None = None,
        blocked_tables: set[str] | None = None,
        on_block: Literal["raise", "return_error", "return_none"] = "raise",
        error_message: str = "Operation blocked by security policy: {reason}",
        audit: bool = True,
        audit_logger: AuditLogger | None = None,
        audit_level: Literal["all", "block", "none"] = "all",
        audit_context: dict[str, Any] | None = None,
        param_name: str | None = None,
    ) -> None:
        self.config = GuardConfig(
            sql=sql,
            sql_mode=mode,
            sql_dialect=dialect,
            sql_allowed_tables=allowed_tables,
            sql_blocked_tables=blocked_tables,
            on_block=on_block,
            error_message=error_message,
            audit=audit,
            audit_logger=audit_logger,
            audit_level=audit_level,
            audit_context=audit_context or {},
            param_name=param_name,
        )

        # Initialize SQL inspector if needed
        self._sql_inspector: SQLInspector | None = None
        if sql:
            self._sql_inspector = SQLInspector(
                mode=mode,
                dialect=dialect,
                allowed_tables=allowed_tables,
                blocked_tables=blocked_tables,
            )

        # Initialize audit logger if needed
        self._audit_logger: AuditLogger | None = None
        if audit and audit_logger is None:
            level_map = {"all": AuditLevel.ALL, "block": AuditLevel.BLOCK, "none": AuditLevel.NONE}
            self._audit_logger = AuditLogger(
                destinations=[LogDestination.STDOUT],
                min_level=level_map.get(audit_level, AuditLevel.ALL),
            )
        elif audit_logger:
            self._audit_logger = audit_logger

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Decorate a function with this guard."""
        return self._wrap_function(func)

    def _wrap_function(self, func: Callable[P, R]) -> Callable[P, R]:
        """Wrap a sync or async function with guard protection."""

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return await self._execute_async(func, args, kwargs)

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return self._execute_sync(func, args, kwargs)

            return sync_wrapper  # type: ignore

    def _execute_sync(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute sync function with guard protection."""
        # Extract the value to inspect
        value = self._extract_value(func, args, kwargs)

        # Run inspections
        verdict = self._inspect(value, func.__name__)

        # Handle result
        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        # Execute the original function
        return func(*args, **kwargs)

    async def _execute_async(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute async function with guard protection."""
        # Extract the value to inspect
        value = self._extract_value(func, args, kwargs)

        # Run inspections
        verdict = self._inspect(value, func.__name__)

        # Handle result
        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        # Execute the original function
        return await func(*args, **kwargs)

    def _extract_value(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> str | None:
        """Extract the value to inspect from function arguments."""

        # If param_name specified, use that
        if self.config.param_name:
            if self.config.param_name in kwargs:
                return kwargs[self.config.param_name]

            # Check positional args by parameter name
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if self.config.param_name in params:
                idx = params.index(self.config.param_name)
                if idx < len(args):
                    return args[idx]

            return None

        # Auto-detect: use first string argument
        # Check kwargs first
        for value in kwargs.values():
            if isinstance(value, str):
                return value

        # Check positional args
        for arg in args:
            if isinstance(arg, str):
                return arg

        return None

    def _inspect(self, value: str | None, func_name: str) -> Verdict | None:
        """Run inspections on the value."""

        if value is None:
            return None

        verdict: Verdict | None = None

        # SQL inspection
        if self._sql_inspector and self.config.sql:
            verdict = self._sql_inspector.inspect(value)

            # Audit log
            if self._audit_logger:
                context = {
                    "tool": func_name,
                    "inspector": "sql",
                    **self.config.audit_context,
                }
                self._audit_logger.log(verdict, context=context)

        return verdict

    def _handle_block(self, verdict: Verdict, func_name: str) -> Any:
        """Handle a blocked operation based on config."""

        error_msg = self.config.error_message.format(
            reason=verdict.reason,
            rule=verdict.rule,
            inspector=verdict.inspector,
            tool=func_name,
        )

        action = BlockAction(self.config.on_block)

        if action == BlockAction.RAISE:
            # Raise exception for critical violations
            if verdict.rule in {"critical_node_detected", "schema_change_blocked"}:
                raise CriticalViolation(error_msg, verdict=verdict)
            raise PolicyViolation(error_msg, verdict=verdict)

        elif action == BlockAction.RETURN_ERROR:
            # Return error dict that agent can understand
            return {
                "error": True,
                "message": error_msg,
                "blocked": True,
                "reason": verdict.reason,
                "rule": verdict.rule,
            }

        elif action == BlockAction.RETURN_NONE:
            return None

        # Default: raise
        raise PolicyViolation(error_msg, verdict=verdict)


# =============================================================================
# THE @guard DECORATOR
# =============================================================================


@overload
def guard(func: Callable[P, R]) -> Callable[P, R]: ...


@overload
def guard(
    *,
    sql: bool = True,
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
    allowed_tables: set[str] | None = None,
    blocked_tables: set[str] | None = None,
    on_block: Literal["raise", "return_error", "return_none"] = "raise",
    error_message: str = "Operation blocked by security policy: {reason}",
    audit: bool = True,
    audit_logger: AuditLogger | None = None,
    audit_level: Literal["all", "block", "none"] = "all",
    audit_context: dict[str, Any] | None = None,
    param_name: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def guard(
    func: Callable[P, R] | None = None,
    *,
    sql: bool = True,
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
    allowed_tables: set[str] | None = None,
    blocked_tables: set[str] | None = None,
    on_block: Literal["raise", "return_error", "return_none"] = "raise",
    error_message: str = "Operation blocked by security policy: {reason}",
    audit: bool = True,
    audit_logger: AuditLogger | None = None,
    audit_level: Literal["all", "block", "none"] = "all",
    audit_context: dict[str, Any] | None = None,
    param_name: str | None = None,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to protect AI agent tools with Warden security inspections.

    Can be used with or without arguments:

        @guard
        def my_tool(query: str): ...

        @guard(mode="safe-write")
        def my_tool(query: str): ...

    Args:
        sql: Enable SQL injection protection (default: True)
        mode: SQL inspection mode
            - "read-only": Only SELECT allowed (safest)
            - "safe-write": SELECT, INSERT, UPDATE to allowed tables
            - "strict": Block all schema changes
            - "monitor": Log only, don't block
        dialect: SQL dialect (mysql, postgres, snowflake, etc.)
        allowed_tables: Tables allowed for writes (safe-write mode)
        blocked_tables: Tables never allowed
        on_block: What to do when blocked
            - "raise": Raise PolicyViolation exception
            - "return_error": Return error dict to agent
            - "return_none": Return None
        error_message: Custom error message template
        audit: Enable audit logging
        audit_logger: Custom AuditLogger instance
        audit_level: Minimum level to log (all, block, none)
        audit_context: Static context for all audit logs
        param_name: Specific parameter to inspect (default: first string)

    Example:
        from warden.integrations.strands import guard

        # Basic usage - read-only SQL protection
        @guard
        def query_database(sql: str) -> list[dict]:
            return db.execute(sql)

        # Allow writes to specific tables
        @guard(mode="safe-write", allowed_tables={"logs", "events"})
        def write_log(sql: str) -> None:
            db.execute(sql)

        # Return error to agent instead of raising
        @guard(on_block="return_error")
        def safe_query(sql: str) -> dict:
            return {"data": db.execute(sql)}

        # With AWS Strands @tool decorator
        from strands import tool

        @tool
        @guard(mode="read-only")
        def database_query(query: str) -> str:
            '''Execute a read-only SQL query.'''
            return json.dumps(db.execute(query))
    """

    # Create the guard instance
    tool_guard = ToolGuard(
        sql=sql,
        mode=mode,
        dialect=dialect,
        allowed_tables=allowed_tables,
        blocked_tables=blocked_tables,
        on_block=on_block,
        error_message=error_message,
        audit=audit,
        audit_logger=audit_logger,
        audit_level=audit_level,
        audit_context=audit_context,
        param_name=param_name,
    )

    # Handle both @guard and @guard(...) syntax
    if func is not None:
        # Called as @guard without parentheses
        return tool_guard(func)
    else:
        # Called as @guard(...) with arguments
        return tool_guard


# =============================================================================
# POLICY-BASED GUARD
# =============================================================================


class PolicyGuard:
    """
    Guard that uses a PolicyEngine for configuration.

    This allows defining security rules in YAML files instead of code,
    with support for agent-specific rules.

    Example:
        from warden import PolicyEngine
        from warden.integrations.strands import PolicyGuard

        # Load policy from file
        engine = PolicyEngine.from_file("policy.yaml")

        # Create guard for specific agent
        guard = PolicyGuard(engine, agent="analytics-bot")

        @guard
        def query_reports(sql: str) -> list:
            return db.execute(sql)
    """

    def __init__(
        self,
        policy: PolicyEngine | Policy | str,
        agent: str | None = None,
        on_block: Literal["raise", "return_error", "return_none"] = "raise",
        error_message: str = "Operation blocked by security policy: {reason}",
        audit: bool = True,
        audit_logger: AuditLogger | None = None,
        audit_level: Literal["all", "block", "none"] = "all",
        audit_context: dict[str, Any] | None = None,
        param_name: str | None = None,
    ) -> None:
        """
        Initialize PolicyGuard.

        Args:
            policy: PolicyEngine instance, Policy instance, or path to YAML file
            agent: Agent name for agent-specific rules
            on_block: Action when blocked (raise, return_error, return_none)
            error_message: Custom error message template
            audit: Enable audit logging
            audit_logger: Custom audit logger instance
            audit_level: Minimum level to log
            audit_context: Static context for audit logs
            param_name: Specific parameter to inspect
        """
        # Handle different policy input types
        if isinstance(policy, str):
            self._engine = PolicyEngine.from_file(policy)
        elif isinstance(policy, Policy):
            self._engine = PolicyEngine(policy)
        else:
            self._engine = policy

        self._agent = agent
        self._on_block = on_block
        self._error_message = error_message
        self._param_name = param_name
        self._audit_context = audit_context or {}

        # Initialize audit logger
        self._audit_logger: AuditLogger | None = None
        if audit and audit_logger is None:
            level_map = {
                "all": AuditLevel.ALL,
                "block": AuditLevel.BLOCK,
                "none": AuditLevel.NONE,
            }
            self._audit_logger = AuditLogger(
                destinations=[LogDestination.STDOUT],
                min_level=level_map.get(audit_level, AuditLevel.ALL),
            )
        elif audit_logger:
            self._audit_logger = audit_logger

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Decorate a function with this guard."""
        return self._wrap_function(func)

    def _wrap_function(self, func: Callable[P, R]) -> Callable[P, R]:
        """Wrap a sync or async function with guard protection."""
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return await self._execute_async(func, args, kwargs)

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return self._execute_sync(func, args, kwargs)

            return sync_wrapper  # type: ignore

    def _execute_sync(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute sync function with guard protection."""
        value = self._extract_value(func, args, kwargs)
        verdict = self._inspect(value, func.__name__)

        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        return func(*args, **kwargs)

    async def _execute_async(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute async function with guard protection."""
        value = self._extract_value(func, args, kwargs)
        verdict = self._inspect(value, func.__name__)

        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        return await func(*args, **kwargs)

    def _extract_value(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> str | None:
        """Extract the value to inspect from function arguments."""
        if self._param_name:
            if self._param_name in kwargs:
                return kwargs[self._param_name]
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if self._param_name in params:
                idx = params.index(self._param_name)
                if idx < len(args):
                    return args[idx]
            return None

        # Auto-detect: use first string argument
        for value in kwargs.values():
            if isinstance(value, str):
                return value
        for arg in args:
            if isinstance(arg, str):
                return arg
        return None

    def _inspect(self, value: str | None, func_name: str) -> Verdict | None:
        """Run inspections using the policy engine."""
        if value is None:
            return None

        verdict = self._engine.inspect(value, agent=self._agent)

        if self._audit_logger:
            context = {
                "tool": func_name,
                "agent": self._agent,
                "inspector": "sql",
                **self._audit_context,
            }
            self._audit_logger.log(verdict, context=context)

        return verdict

    def _handle_block(self, verdict: Verdict, func_name: str) -> Any:
        """Handle a blocked operation based on config."""
        error_msg = self._error_message.format(
            reason=verdict.reason,
            rule=verdict.rule,
            inspector=verdict.inspector,
            tool=func_name,
        )

        action = BlockAction(self._on_block)

        if action == BlockAction.RAISE:
            if verdict.rule in {"critical_node_detected", "schema_change_blocked"}:
                raise CriticalViolation(error_msg, verdict=verdict)
            raise PolicyViolation(error_msg, verdict=verdict)
        elif action == BlockAction.RETURN_ERROR:
            return {
                "error": True,
                "message": error_msg,
                "blocked": True,
                "reason": verdict.reason,
                "rule": verdict.rule,
            }
        elif action == BlockAction.RETURN_NONE:
            return None

        raise PolicyViolation(error_msg, verdict=verdict)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_policy_guard(
    policy: PolicyEngine | Policy | str,
    agent: str | None = None,
    on_block: Literal["raise", "return_error", "return_none"] = "raise",
    audit_logger: AuditLogger | None = None,
) -> PolicyGuard:
    """
    Create a policy-based guard for protecting tools.

    This is the recommended way to use Warden with multi-agent systems.

    Args:
        policy: PolicyEngine, Policy, or path to YAML file
        agent: Agent name for agent-specific rules
        on_block: Action when blocked
        audit_logger: Custom audit logger

    Example:
        # Load policy
        guard = create_policy_guard("policy.yaml", agent="analytics-bot")

        @guard
        def query_reports(sql: str) -> list:
            return db.execute(sql)
    """
    return PolicyGuard(
        policy=policy,
        agent=agent,
        on_block=on_block,
        audit_logger=audit_logger,
    )


def create_sql_guard(
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
    audit_logger: AuditLogger | None = None,
) -> ToolGuard:
    """
    Create a reusable SQL guard for protecting multiple tools.

    Example:
        sql_guard = create_sql_guard(mode="read-only")

        @sql_guard
        def tool1(query: str): ...

        @sql_guard
        def tool2(query: str): ...
    """
    return ToolGuard(
        sql=True,
        mode=mode,
        dialect=dialect,
        audit_logger=audit_logger,
    )
